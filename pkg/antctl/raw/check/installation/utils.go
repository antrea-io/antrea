// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package installation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/raw/check"
)

const (
	tcpdumpPacketCount         = 10
	tcpdumpTimeout             = 10 * time.Second
	pingResponseTimeoutSeconds = 2
	maxDisplayLines            = 10
)

// deployTcpdumpPod deploys a hostNetwork Pod with tcpdump on the specified Node.
// deploymentName controls the name of the Deployment and Pod created.
// The container is granted NET_RAW and NET_ADMIN capabilities, which are required
// by tcpdump to open raw sockets and enable promiscuous mode on interfaces.
func deployTcpdumpPod(ctx context.Context, testContext *testContext, nodeName, deploymentName string) (*corev1.Pod, error) {
	deployment := check.NewDeployment(check.DeploymentParameters{
		Name:        deploymentName,
		Role:        "tcpdump",
		Image:       testContext.testImage,
		HostNetwork: true,
		Affinity: &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "kubernetes.io/hostname",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{nodeName},
								},
							},
						},
					},
				},
			},
		},
		Tolerations: []corev1.Toleration{
			{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: "Exists",
				Effect:   "NoSchedule",
			},
		},
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_RAW", "NET_ADMIN"},
			},
		},
		Labels: map[string]string{"app": "antrea", "component": "installation-checker", "name": deploymentName},
	})

	if _, err := testContext.client.AppsV1().Deployments(testContext.namespace).Create(ctx, deployment, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("failed to create tcpdump Deployment: %w", err)
	}

	testContext.Log("Waiting for tcpdump Deployment to be ready...")
	if err := check.WaitForDeploymentsReady(ctx, time.Second, podReadyTimeout, false, testContext.client, testContext.clusterName, testContext.namespace, deploymentName); err != nil {
		return nil, fmt.Errorf("tcpdump Deployment did not become ready: %w", err)
	}

	podList, err := testContext.client.CoreV1().Pods(testContext.namespace).List(ctx, metav1.ListOptions{LabelSelector: "name=" + deploymentName})
	if err != nil {
		return nil, fmt.Errorf("failed to list tcpdump Pods: %w", err)
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no tcpdump Pod found")
	}

	return &podList.Items[0], nil
}

// runTcpdump runs tcpdump in the given Pod on the specified interface, capturing at most
// tcpdumpPacketCount packets that match filter. The capture is bounded by tcpdumpTimeout.
// A context.DeadlineExceeded error from tcpdump (i.e. timeout with no packets) is treated
// as a non-error and the (possibly empty) stdout is returned.
func runTcpdump(ctx context.Context, testContext *testContext, podName, iface string, filter ...string) (string, error) {
	cmd := append([]string{"tcpdump", "-n", "-i", iface, "-c", fmt.Sprint(tcpdumpPacketCount)}, filter...)
	ctx, cancel := context.WithTimeout(ctx, tcpdumpTimeout)
	defer cancel()
	stdout, stderr, err := raw.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, podName, "", cmd)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		testContext.Log("tcpdump command stderr: %s", stderr)
		return "", fmt.Errorf("tcpdump command failed: %w", err)
	}
	return stdout, nil
}

// verifyConnectivity sends pings from the client Pod to the target IP to verify connectivity.
func verifyConnectivity(ctx context.Context, testContext *testContext, clientPodName, targetIP string) error {
	cmd := []string{"ping", "-c", "3", "-W", fmt.Sprint(pingResponseTimeoutSeconds), targetIP}
	_, stderr, err := raw.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, clientPodName, "", cmd)
	if err != nil {
		testContext.Log("ping command stderr: %s", stderr)
		return fmt.Errorf("ping command failed: %w", err)
	}
	return nil
}

// startBackgroundPing starts a continuous ping in the background from the client Pod to the
// target IP. It returns a cleanup function that cancels the ping and waits for it to stop.
func startBackgroundPing(ctx context.Context, testContext *testContext, clientPodName, targetIP string) (func(), error) {
	pingCtx, cancelPing := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		cmd := []string{"ping", "-W", fmt.Sprint(pingResponseTimeoutSeconds), targetIP}
		if _, _, err := raw.ExecInPod(pingCtx, testContext.client, testContext.config, testContext.namespace, clientPodName, "", cmd); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			testContext.Warning("ping command failed: %v", err)
		}
	})
	return func() {
		cancelPing()
		wg.Wait()
	}, nil
}

// startBackgroundProbes verifies connectivity to each of the target Pod's IPs and then
// starts a background ping for each IP. It returns a cleanup function that stops all
// background pings and should be called (typically via defer) when captures are done.
func startBackgroundProbes(ctx context.Context, testContext *testContext, clientPodName string, targetPod *corev1.Pod) (func(), error) {
	var cleanups []func()
	for _, podIP := range targetPod.Status.PodIPs {
		targetIP := podIP.IP
		testContext.Log("Verifying connectivity from Pod %q to %s...", clientPodName, targetIP)
		if err := verifyConnectivity(ctx, testContext, clientPodName, targetIP); err != nil {
			for _, cleanup := range cleanups {
				cleanup()
			}
			return nil, fmt.Errorf("initial ping to %s failed: %w", targetIP, err)
		}
		testContext.Log("Ping from Pod %q to %s successful", clientPodName, targetIP)
		testContext.Log("Starting background ping from client Pod to %s...", targetIP)
		stopPing, err := startBackgroundPing(ctx, testContext, clientPodName, targetIP)
		if err != nil {
			for _, cleanup := range cleanups {
				cleanup()
			}
			return nil, fmt.Errorf("failed to start background ping to %s: %w", targetIP, err)
		}
		cleanups = append(cleanups, stopPing)
	}
	return func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}, nil
}

// countNonEmptyLines counts non-empty lines in the output.
func countNonEmptyLines(output string) int {
	if output == "" {
		return 0
	}
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// displayPacketCapture logs the first maxDisplayLines lines of tcpdump output.
func displayPacketCapture(testContext *testContext, output string) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	displayLines := min(len(lines), maxDisplayLines)
	for i := 0; i < displayLines; i++ {
		testContext.Log("  %s", lines[i])
	}
	if len(lines) > displayLines {
		testContext.Log("  ... (%d more lines)", len(lines)-displayLines)
	}
}
