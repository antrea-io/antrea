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

package e2e

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// TestWindowsStressRollout verifies the performance, migration, and recovery times of Antrea on Windows Nodes
// under high Pod density stress. It simulates a Node Rollout scenario:
// 1. Deploys Pods on Windows Node A in exponential scales (10, 20, 40, 80, 160, 250).
// 2. Verifies initial connectivity.
// 3. Cordons Node A, and simultaneously deletes Node A's pods, schedules them on Node B, and rolls out the Antrea Agent.
// 4. Measures and logs precise timing metrics for each phase of the rollout and migration.
func TestWindowsStressRollout(t *testing.T) {
	skipIfNoWindowsNodes(t)

	if len(clusterInfo.windowsNodes) < 2 {
		t.Skip("Skipping test as it requires at least 2 Windows nodes to simulate rollout migration")
	}

	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")
	defer teardownTest(t, data)

	// Identify Node A and Node B
	nodeA := nodeName(clusterInfo.windowsNodes[0])
	nodeB := nodeName(clusterInfo.windowsNodes[1])
	t.Logf("Using Windows Node A: '%s' and Windows Node B: '%s' for rollout migration simulation", nodeA, nodeB)

	// Ensure both nodes are uncordoned at the end of the test
	defer func() {
		t.Logf("Ensuring both Windows nodes are uncordoned at test completion")
		_ = cordonNode(data.clientset, nodeA, false)
		_ = cordonNode(data.clientset, nodeB, false)
	}()

	// Create a Linux client Pod on the control-plane Node to act as the traffic prober.
	linuxNodeName := controlPlaneNodeName()
	linuxPodName := randName("stress-client-linux-")
	clientPodInfo := PodInfo{
		Name:      linuxPodName,
		Namespace: data.testNamespace,
		NodeName:  linuxNodeName,
		OS:        "linux",
	}

	t.Logf("Creating Linux prober Pod %s on Node '%s'", linuxPodName, linuxNodeName)
	err = data.createToolboxPodOnNode(clientPodInfo.Name, clientPodInfo.Namespace, clientPodInfo.NodeName, false)
	require.NoError(t, err, "Failed to create Linux prober Pod")
	defer deletePodWrapper(t, data, clientPodInfo.Namespace, clientPodInfo.Name)

	// Wait for Linux prober Pod to be running and get its IP
	clientIPs, err := data.podWaitForIPs(defaultTimeout, clientPodInfo.Name, clientPodInfo.Namespace)
	require.NoError(t, err, "Failed to wait for Linux prober Pod to get IP")
	t.Logf("Linux prober Pod IP: %v", clientIPs)

	// Define the stress scales (number of pods to migrate)
	scales := []int{100, 130, 160, 200, 250}

	for _, scale := range scales {
		t.Run(fmt.Sprintf("Scale-%d-Pods", scale), func(t *testing.T) {
			// Each round has a maximum timeout of 60 minutes
			roundCtx, roundCancel := context.WithTimeout(context.Background(), 60*time.Minute)
			defer roundCancel()

			t.Logf("=== Starting Round: %d Pods Rollout Migration ===", scale)
			roundStartTime := time.Now()

			// Ensure both nodes are uncordoned at the start of each round
			err = cordonNode(data.clientset, nodeA, false)
			require.NoError(t, err, "Failed to uncordon Node A")
			err = cordonNode(data.clientset, nodeB, false)
			require.NoError(t, err, "Failed to uncordon Node B")

			var nodeAPodNames []string
			var nodeAPodInfos []PodInfo
			var nodeBPodNames []string
			var nodeBPodInfos []PodInfo

			for i := 0; i < scale; i++ {
				podNameA := fmt.Sprintf("win-stress-%d-nodea-%d", scale, i)
				nodeAPodNames = append(nodeAPodNames, podNameA)
				nodeAPodInfos = append(nodeAPodInfos, PodInfo{
					Name:      podNameA,
					Namespace: data.testNamespace,
					NodeName:  nodeA,
					OS:        "windows",
				})

				podNameB := fmt.Sprintf("win-stress-%d-nodeb-%d", scale, i)
				nodeBPodNames = append(nodeBPodNames, podNameB)
				nodeBPodInfos = append(nodeBPodInfos, PodInfo{
					Name:      podNameB,
					Namespace: data.testNamespace,
					NodeName:  nodeB,
					OS:        "windows",
				})
			}

			// Defer cleanup of all Pods created in this round
			defer func() {
				t.Logf("Cleaning up all Windows Pods for scale %d", scale)
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cleanupCancel()

				deleteOptions := metav1.DeleteOptions{
					GracePeriodSeconds: new(int64), // immediate deletion
				}
				listOptions := metav1.ListOptions{
					LabelSelector: fmt.Sprintf("app=windows-stress-test,scale=%d", scale),
				}
				_ = data.clientset.CoreV1().Pods(data.testNamespace).DeleteCollection(cleanupCtx, deleteOptions, listOptions)

				// Wait until all Pods are deleted
				_ = wait.PollUntilContextTimeout(cleanupCtx, 2*time.Second, 2*time.Minute, false, func(ctx context.Context) (bool, error) {
					podList, err := data.clientset.CoreV1().Pods(data.testNamespace).List(ctx, listOptions)
					if err != nil {
						return false, err
					}
					return len(podList.Items) == 0, nil
				})
			}()

			limits := corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("25m"),
				corev1.ResourceMemory: resource.MustParse("40Mi"),
			}

			// 1. Deploy 'scale' agnhost Pods to Windows Node A in parallel
			t.Logf("Step 1: Deploying %d Pods on Windows Node A: '%s'", scale, nodeA)
			nodeACreationStart := time.Now()
			var wg sync.WaitGroup
			var createErrorsA []error
			var muA sync.Mutex

			for _, pi := range nodeAPodInfos {
				wg.Add(1)
				go func(podInfo PodInfo) {
					defer wg.Done()
					err := NewPodBuilder(podInfo.Name, data.testNamespace, agnhostImage).
						OnNode(nodeA).
						WithRestartPolicy(corev1.RestartPolicyAlways).
						WithResources(nil, limits).
						WithLabels(map[string]string{
							"app":   "windows-stress-test",
							"scale": fmt.Sprintf("%d", scale),
							"node":  nodeA,
						}).
						Create(data)
					if err != nil {
						muA.Lock()
						createErrorsA = append(createErrorsA, fmt.Errorf("failed to create Pod %s on Node A: %v", podInfo.Name, err))
						muA.Unlock()
					}
				}(pi)
			}
			wg.Wait()
			if len(createErrorsA) > 0 {
				t.Fatalf("Failed to create Node A Pods: %v", createErrorsA)
			}

			// 2. Wait for all Node A Pods to be Running and have IPs
			t.Logf("Step 2: Waiting for all %d Pods on Node A to be Running...", scale)
			labelSelectorA := fmt.Sprintf("app=windows-stress-test,scale=%d,node=%s", scale, nodeA)
			runningPodsA, err := data.waitForStressPodsRunning(roundCtx, labelSelectorA, scale)
			require.NoError(t, err, "Failed waiting for Node A Pods to be Running")
			nodeAPodsReadyDuration := time.Since(nodeACreationStart)
			t.Logf("All %d Pods on Node A are Running! Time taken: %v", scale, nodeAPodsReadyDuration)

			// Build a map of Pod Name to PodIPs for Node A traffic verification
			podIPsMapA := make(map[string]*PodIPs)
			for _, pod := range runningPodsA {
				podIPsMapA[pod.Name] = &PodIPs{
					IPv4: parseStressIP(pod.Status.PodIP),
				}
			}

			// 3. Verify traffic/connectivity on Node A before rollout migration
			t.Logf("Step 3: Verifying traffic connectivity on Node A...")
			verifyTraffic := func(podInfos []PodInfo, ipMap map[string]*PodIPs, containerName string) error {
				sampleSize := 5
				if len(podInfos) < sampleSize {
					sampleSize = len(podInfos)
				}

				for i := 0; i < sampleSize; i++ {
					targetPod := podInfos[i]
					targetIPs := ipMap[targetPod.Name]
					if targetIPs == nil || targetIPs.IPv4 == nil {
						return fmt.Errorf("Pod %s has no valid IP", targetPod.Name)
					}

					// Ping from Linux prober Pod to Windows Pod
					err := data.RunPingCommandFromTestPod(clientPodInfo, data.testNamespace, targetIPs, toolboxContainerName, 2, 0, false)
					if err != nil {
						return fmt.Errorf("ping Linux -> Windows Pod %s failed: %v", targetPod.Name, err)
					}

					// Ping from Windows Pod back to Linux prober Pod
					err = data.RunPingCommandFromTestPod(targetPod, data.testNamespace, clientIPs, containerName, 2, 0, false)
					if err != nil {
						return fmt.Errorf("ping Windows Pod %s -> Linux failed: %v", targetPod.Name, err)
					}
				}
				return nil
			}

			err = verifyTraffic(nodeAPodInfos, podIPsMapA, "agnhost")
			require.NoError(t, err, "Traffic verification failed on Node A before rollout")
			t.Logf("Traffic verification successful on Node A!")

			// 4. Cordon Node A and trigger simultaneous switchover
			t.Logf("Step 4: Cordoning Node A: '%s' to simulate rollout drain", nodeA)
			err = cordonNode(data.clientset, nodeA, true)
			require.NoError(t, err, "Failed to cordon Node A")

			t.Logf("Step 5: Triggering simultaneous migration and Antrea rollout...")
			switchoverStartTime := time.Now()

			var deleteNodeAPodsDuration time.Duration
			var createNodeBPodsDuration time.Duration
			var rolloutAntreaDuration time.Duration

			var createErrorsB []error
			var muB sync.Mutex

			wg.Add(3)

			// Task A: Delete all test pods on Node A
			go func() {
				defer wg.Done()
				t.Logf("[Switchover] Deleting all test pods on Node A...")
				deleteStart := time.Now()
				deleteOptions := metav1.DeleteOptions{
					GracePeriodSeconds: new(int64), // immediate deletion
				}
				_ = data.clientset.CoreV1().Pods(data.testNamespace).DeleteCollection(roundCtx, deleteOptions, metav1.ListOptions{
					LabelSelector: labelSelectorA,
				})

				// Wait for them to be completely deleted
				_ = wait.PollUntilContextTimeout(roundCtx, 1*time.Second, 2*time.Minute, false, func(ctx context.Context) (bool, error) {
					podList, err := data.clientset.CoreV1().Pods(data.testNamespace).List(ctx, metav1.ListOptions{
						LabelSelector: labelSelectorA,
					})
					if err != nil {
						return false, err
					}
					return len(podList.Items) == 0, nil
				})
				deleteNodeAPodsDuration = time.Since(deleteStart)
				t.Logf("[Switchover] Node A Pods deletion completed in %v", deleteNodeAPodsDuration)
			}()

			// Task B: Deploy 'scale' agnhost Pods to Windows Node B
			go func() {
				defer wg.Done()
				t.Logf("[Switchover] Creating %d test pods on Node B...", scale)
				createStart := time.Now()
				var wgB sync.WaitGroup
				for _, pi := range nodeBPodInfos {
					wgB.Add(1)
					go func(podInfo PodInfo) {
						defer wgB.Done()
						err := NewPodBuilder(podInfo.Name, data.testNamespace, agnhostImage).
							OnNode(nodeB).
							WithRestartPolicy(corev1.RestartPolicyAlways).
							WithResources(nil, limits).
							WithLabels(map[string]string{
								"app":   "windows-stress-test",
								"scale": fmt.Sprintf("%d", scale),
								"node":  nodeB,
							}).
							Create(data)
						if err != nil {
							muB.Lock()
							createErrorsB = append(createErrorsB, fmt.Errorf("failed to create Pod %s on Node B: %v", podInfo.Name, err))
							muB.Unlock()
						}
					}(pi)
				}
				wgB.Wait()
				createNodeBPodsDuration = time.Since(createStart)
				t.Logf("[Switchover] Node B Pods creation completed in %v", createNodeBPodsDuration)
			}()

			// Task C: Rollout/Restart Antrea Agent
			go func() {
				defer wg.Done()
				t.Logf("[Switchover] Rolling out Antrea Agent...")
				rolloutStart := time.Now()
				err := data.RestartAntreaAgentPods(15 * time.Minute)
				if err != nil {
					t.Logf("[Switchover] Antrea Agent rollout failed: %v", err)
				}
				rolloutAntreaDuration = time.Since(rolloutStart)
				t.Logf("[Switchover] Antrea Agent rollout completed in %v", rolloutAntreaDuration)
			}()

			wg.Wait()
			if len(createErrorsB) > 0 {
				t.Fatalf("Failed during switchover creation: %v", createErrorsB)
			}

			// 5. Wait for all Node B Pods to be Running and have IPs
			t.Logf("Step 6: Waiting for all %d Pods on Node B to be Running...", scale)
			labelSelectorB := fmt.Sprintf("app=windows-stress-test,scale=%d,node=%s", scale, nodeB)
			runningPodsB, err := data.waitForStressPodsRunning(roundCtx, labelSelectorB, scale)
			require.NoError(t, err, "Failed waiting for Node B Pods to be Running")
			nodeBPodsReadyDuration := time.Since(switchoverStartTime)
			t.Logf("All %d Pods on Node B are Running! Time taken from switchover start: %v", scale, nodeBPodsReadyDuration)

			// Build a map of Pod Name to PodIPs for Node B traffic verification
			podIPsMapB := make(map[string]*PodIPs)
			for _, pod := range runningPodsB {
				podIPsMapB[pod.Name] = &PodIPs{
					IPv4: parseStressIP(pod.Status.PodIP),
				}
			}

			// 6. Wait for traffic to be fully restored on Node B
			t.Logf("Step 7: Waiting for traffic to be restored on Node B...")
			var trafficRecoveryDuration time.Duration
			err = wait.PollUntilContextTimeout(roundCtx, 5*time.Second, 5*time.Minute, false, func(ctx context.Context) (bool, error) {
				if err := verifyTraffic(nodeBPodInfos, podIPsMapB, "agnhost"); err != nil {
					t.Logf("Traffic not fully restored on Node B yet: %v", err)
					return false, nil
				}
				return true, nil
			})
			require.NoError(t, err, "Traffic failed to restore on Node B after rollout migration")
			trafficRecoveryDuration = time.Since(switchoverStartTime)

			totalRoundDuration := time.Since(roundStartTime)

			// Print extremely rich and structured performance metrics for debugging and analysis
			t.Logf("==========================================================================================")
			t.Logf("PERFORMANCE METRICS SUMMARY - SCALE: %d PODS", scale)
			t.Logf("------------------------------------------------------------------------------------------")
			t.Logf("[Phase 1] Node A (%s) Deployment & Ready Time : %v", nodeA, nodeAPodsReadyDuration)
			t.Logf("[Phase 2] Node A (%s) Pods Deletion Time       : %v", nodeA, deleteNodeAPodsDuration)
			t.Logf("[Phase 3] Node B (%s) Pods Creation Time       : %v", nodeB, createNodeBPodsDuration)
			t.Logf("[Phase 4] Antrea Agent Rollout Time            : %v", rolloutAntreaDuration)
			t.Logf("[Phase 5] Node B (%s) Pods Ready Time (Total)  : %v", nodeB, nodeBPodsReadyDuration)
			t.Logf("[Phase 6] Traffic Fully Restored Time (Total)  : %v", trafficRecoveryDuration)
			t.Logf("[Overall] Total Round Duration                 : %v", totalRoundDuration)
			t.Logf("==========================================================================================")
		})
	}
}

func cordonNode(clientset kubernetes.Interface, nodeName string, cordon bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if node.Spec.Unschedulable == cordon {
			return nil
		}
		node.Spec.Unschedulable = cordon
		_, err = clientset.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
		return err
	})
}

func parseStressIP(ipStr string) *net.IP {
	if ipStr == "" {
		return nil
	}
	ip := net.ParseIP(ipStr)
	return &ip
}

func (data *TestData) waitForStressPodsRunning(ctx context.Context, labelSelector string, expectedCount int) ([]corev1.Pod, error) {
	var runningPods []corev1.Pod
	err := wait.PollUntilContextCancel(ctx, 2*time.Second, false, func(ctx context.Context) (bool, error) {
		podList, err := data.clientset.CoreV1().Pods(data.testNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			return false, err
		}
		if len(podList.Items) < expectedCount {
			return false, nil
		}
		runningPods = nil
		for _, pod := range podList.Items {
			if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
				return false, nil
			}
			runningPods = append(runningPods, pod)
		}
		return true, nil
	})
	return runningPods, err
}
