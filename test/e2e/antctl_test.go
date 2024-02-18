// Copyright 2020 Antrea Authors
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
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"antrea.io/antrea/pkg/antctl"
	"antrea.io/antrea/pkg/antctl/runtime"
)

type cmdAndReturnCode struct {
	args               []string
	expectedReturnCode int
}

// TestAntctl is the top-level test which contains all subtests for
// Antctl related test cases as they can share setup, teardown.
func TestAntctl(t *testing.T) {
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// This is used to determine the Antrea container image being tested. We will use the same
	// image when creating a Pod to run antctl.
	// Note that this is the Linux image, so we will always schedule the antctl Pod on the
	// control-plane Node, which is guaranteed to be a Linux Node.
	ds, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), antreaDaemonSet, metav1.GetOptions{})
	require.NoError(t, err, "Error when getting antrea DaemonSet")
	antreaImage := ds.Spec.Template.Spec.Containers[0].Image

	// This ServiceAccount is granted the antctl ClusterRole and will be used for antctl test
	// Pods. We do not use the "default" ServiceAccount for the test Namespace, as we do not
	// want other test Pods to be granted the antctl ClusterRole.
	antctlServiceAccountName := randName("antctl-antrea-e2e-")
	createAntctlServiceAccount(t, data, antctlServiceAccountName)

	t.Run("testAntctlAgentLocalAccess", func(t *testing.T) {
		testAntctlAgentLocalAccess(t, data)
	})
	t.Run("testAntctlControllerRemoteAccess", func(t *testing.T) {
		testAntctlControllerRemoteAccess(t, data, antctlServiceAccountName, antreaImage)
	})
	t.Run("testAntctlVerboseMode", func(t *testing.T) {
		testAntctlVerboseMode(t, data)
	})
	t.Run("testAntctlProxy", func(t *testing.T) {
		testAntctlProxy(t, data, antctlServiceAccountName, antreaImage)
	})
}

// antctlOutput is a helper function for generating antctl outputs.
func antctlOutput(stdout, stderr string) string {
	return fmt.Sprintf("antctl stdout:\n%s\nantctl stderr:\n%s", stdout, stderr)
}

func antctlName() string {
	if testOptions.enableCoverage {
		return "antctl-coverage"
	}
	return "antctl"
}

// runAntctl runs antctl commands on antrea Pods, the controller, or agents.
func runAntctl(podName string, cmds []string, data *TestData) (string, string, error) {
	var containerName string
	var namespace string
	if strings.Contains(podName, "agent") {
		containerName = "antrea-agent"
		namespace = antreaNamespace
	} else if strings.Contains(podName, "flow-aggregator") {
		containerName = "flow-aggregator"
		namespace = flowAggregatorNamespace
	} else {
		containerName = "antrea-controller"
		namespace = antreaNamespace
	}
	stdout, stderr, err := data.RunCommandFromPod(namespace, podName, containerName, cmds)
	// remove Bincover metadata if needed
	if err == nil {
		index := strings.Index(stdout, "START_BINCOVER_METADATA")
		if index != -1 {
			stdout = stdout[:index]
		}
	}
	return stdout, stderr, err
}

func antctlCoverageArgs(antctlPath string, covDir string) []string {
	const timeFormat = "20060102T150405Z0700"
	timestamp := time.Now().Format(timeFormat)
	covFile := fmt.Sprintf("antctl-%s.out", timestamp)
	if covDir != "" {
		covFile = path.Join(covDir, covFile)
	}
	return []string{antctlPath, "-test.run=TestBincoverRunMain", fmt.Sprintf("-test.coverprofile=%s", covFile)}
}

// testAntctlAgentLocalAccess ensures antctl is accessible in an agent Pod.
func testAntctlAgentLocalAccess(t *testing.T, data *TestData) {
	podName, err := data.getAntreaPodOnNode(controlPlaneNodeName())
	if err != nil {
		t.Fatalf("Error when getting antrea-agent pod name: %v", err)
	}
	for _, c := range antctl.CommandList.GetDebugCommands(runtime.ModeAgent) {
		args := []string{}
		if testOptions.enableCoverage {
			antctlCovArgs := antctlCoverageArgs("antctl-coverage", "")
			args = append(antctlCovArgs, c...)
		} else {
			args = append([]string{"antctl"}, c...)
		}
		t.Logf("args: %s", args)

		cmd := strings.Join(args, " ")
		t.Run(cmd, func(t *testing.T) {
			stdout, stderr, err := runAntctl(podName, args, data)
			// After upgrading from Go v1.19 to Go v1.21, stderr will also include the
			// following warning in the error case:
			//    warning: GOCOVERDIR not set, no coverage data emitted
			// As a result, we temporarily replace strings.HasSuffix with strings.Contains.
			// We can revert this change when the following issue is addressed:
			// https://github.com/antrea-io/antrea/issues/4962
			// if err != nil && !strings.HasSuffix(stderr, "not enabled\n") {
			if err != nil && !strings.Contains(stderr, "not enabled\n") {
				t.Fatalf("Error when running `antctl %s` from %s: %v\n%s", c, podName, err, antctlOutput(stdout, stderr))
			}
		})
	}
}

func runAntctlPod(t *testing.T, data *TestData, podName string, antctlServiceAccountName string, antctlImage string, covDir string) {
	b := NewPodBuilder(podName, data.testNamespace, antctlImage).WithServiceAccountName(antctlServiceAccountName).
		WithContainerName("antctl").WithCommand([]string{"sleep", "3600"}).
		OnNode(controlPlaneNodeName()).InHostNetwork()
	if testOptions.enableCoverage {
		// collectAntctlCovFilesFromControlPlaneNode expects coverage data in this directory
		b = b.MountHostPath(cpNodeCoverageDir, corev1.HostPathDirectory, covDir, "antctl-coverage")
	}
	require.NoError(t, b.Create(data))
	t.Cleanup(func() {
		data.DeletePod(data.testNamespace, podName)
	})
}

func runAntctlCommandFromPod(data *TestData, podName string, cmd []string) (string, string, error) {
	return data.RunCommandFromPod(data.testNamespace, podName, "antctl", cmd)
}

// testAntctlControllerRemoteAccess ensures antctl is able to be run outside of
// the kubernetes cluster. It uses the antctl client binary copied from the controller
// Pod.
func testAntctlControllerRemoteAccess(t *testing.T, data *TestData, antctlServiceAccountName string, antctlImage string) {
	const podName = "antctl"
	const covDir = "/coverage"
	antctlName := antctlName()

	runAntctlPod(t, data, podName, antctlServiceAccountName, antctlImage, covDir)
	require.NoError(t, data.podWaitForRunning(30*time.Second, podName, data.testNamespace), "antctl Pod not in the Running state")

	testCmds := []cmdAndReturnCode{}
	// Add all controller commands.
	for _, c := range antctl.CommandList.GetDebugCommands(runtime.ModeController) {
		cmd := []string{antctlName}
		if testOptions.enableCoverage {
			antctlCovArgs := antctlCoverageArgs(antctlName, covDir)
			cmd = append(antctlCovArgs, c...)
		}
		testCmds = append(testCmds, cmdAndReturnCode{args: cmd, expectedReturnCode: 0})
	}
	testCmds = append(testCmds,
		// Missing Kubeconfig
		cmdAndReturnCode{
			args:               []string{antctlName, "version", "--kubeconfig", "/xyz"},
			expectedReturnCode: 1,
		},
	)

	for _, tc := range testCmds {
		cmd := tc.args
		t.Run(strings.Join(cmd, " "), func(t *testing.T) {
			stdout, stderr, err := runAntctlCommandFromPod(data, podName, cmd)
			if tc.expectedReturnCode == 0 {
				assert.NoError(t, err, "Command was not successful:\n%s", antctlOutput(stdout, stderr))
			} else {
				assert.ErrorContains(t, err, fmt.Sprintf("command terminated with exit code %d", tc.expectedReturnCode), "Command did not fail as expected:\n%s", antctlOutput(stdout, stderr))
			}
		})
	}
}

// testAntctlVerboseMode ensures no unexpected outputs during the execution of
// the antctl client.
func testAntctlVerboseMode(t *testing.T, data *TestData) {
	podName, err := data.getAntreaPodOnNode(controlPlaneNodeName())
	require.Nil(t, err, "Error when retrieving antrea controller pod name")
	for _, tc := range []struct {
		name      string
		hasStderr bool
		commands  []string
	}{
		{name: "RootNonVerbose", hasStderr: false, commands: []string{"antctl"}},
		{name: "RootVerbose", hasStderr: false, commands: []string{"antctl", "-v"}},
		{name: "CommandNonVerbose", hasStderr: false, commands: []string{"antctl", "version"}},
		{name: "CommandVerbose", hasStderr: true, commands: []string{"antctl", "-v", "version"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("Running command `%s` on pod %s", tc.commands, podName)
			stdout, stderr, err := runAntctl(podName, tc.commands, data)
			assert.Nil(t, err, antctlOutput(stdout, stderr))
			if !tc.hasStderr {
				assert.Empty(t, stderr, antctlOutput(stdout, stderr))
			} else {
				assert.NotEmpty(t, stderr, antctlOutput(stdout, stderr))
			}
		})
	}
}

// runAntctProxy runs the antctl reverse proxy as a host network Podon the provided Node; to stop the
// proxy call the returned function.
func runAntctProxy(
	t *testing.T,
	data *TestData,
	podName string,
	serviceAccountName string,
	containerName string,
	containerImage string,
	proxyPort int,
	agentNodeName string,
	address string,
) {
	// Collecting coverage is currently not supported for the proxy command (no coverage data
	// when the process is interrupted).
	antctlName := "antctl"
	proxyCmd := []string{antctlName, "proxy", "--port", fmt.Sprint(proxyPort), "--address", address}
	if agentNodeName == "" {
		proxyCmd = append(proxyCmd, "--controller")
	} else {
		proxyCmd = append(proxyCmd, "--agent-node", agentNodeName)
		// Retry until AntreaAgentInfo is updated by Antrea Agent.
		require.NoError(t, data.checkAntreaAgentInfo(5*time.Second, 2*time.Minute, agentNodeName))
	}

	b := NewPodBuilder(podName, data.testNamespace, containerImage).WithServiceAccountName(serviceAccountName).
		WithContainerName(containerName).WithCommand(proxyCmd).
		OnNode(controlPlaneNodeName()).InHostNetwork().
		WithReadinessProbe(&corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				// Use a TCP probe and not an HTTP probe: GET / will return a 403
				TCPSocket: &corev1.TCPSocketAction{
					Host: address,
					Port: intstr.FromInt(proxyPort),
				},
			},
		})

	t.Logf("Starting antctl proxy")
	require.NoError(t, b.Create(data), "error when creating antctl proxy Pod '%s'", podName)

	t.Cleanup(func() {
		t.Logf("Stopping antctl proxy")
		if err := data.DeletePodAndWait(defaultTimeout, podName, data.testNamespace); err != nil {
			t.Errorf("Error when stopping antctl proxy: %v", err)
		}
	})

	if err := data.podWaitForReady(30*time.Second, podName, data.testNamespace); err != nil {
		logs, err := data.GetPodLogs(context.TODO(), data.testNamespace, podName, "")
		if err != nil {
			logs = "LOGS MISSING"
		}
		require.Fail(t, "proxy not ready", "antctl proxy Pod '%s' never became ready:\n%s", podName, logs)
	}
}

// testAntctlProxy validates "antctl proxy" for both the Antrea Controller and Agent API.
func testAntctlProxy(t *testing.T, data *TestData, antctlServiceAccountName string, antctlImage string) {
	const testPodName = "toolbox"
	const testContainerName = "toolbox"
	const proxyContainerName = "proxy"
	const proxyPort = 8001

	require.NoError(t, NewPodBuilder(testPodName, data.testNamespace, ToolboxImage).WithContainerName(testContainerName).OnNode(controlPlaneNodeName()).InHostNetwork().Create(data))
	defer data.DeletePodAndWait(defaultTimeout, testPodName, data.testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, testPodName, data.testNamespace), "test Pod not in the Running state")

	// getEndpointStatus will return "Success", "Failure", or the empty string when out is not a
	// marshalled metav1.Status object.
	getEndpointStatus := func(out []byte) string {
		var status metav1.Status
		if err := json.Unmarshal(out, &status); err != nil {
			// Output is not JSON or does not encode a metav1.Status object.
			return ""
		}
		return status.Status
	}

	checkEndpointAccess := func(address string, endpoint string, checkStatus bool) error {
		t.Logf("Checking for access to endpoint '/%s' through antctl proxy", endpoint)
		cmd := []string{"curl", fmt.Sprintf("%s/%s", net.JoinHostPort(address, fmt.Sprint(proxyPort)), endpoint)}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, testPodName, testContainerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>", strings.Join(cmd, " "), testPodName, err, stdout, stderr)
		}
		if checkStatus && getEndpointStatus([]byte(stdout)) == "Failure" {
			return fmt.Errorf("failure status when accessing endpoint: <%v>", stdout)
		}
		return nil
	}

	addressV4 := "127.0.0.1"
	addressV6 := "::1"
	testcases := []struct {
		name          string
		agentNodeName string
		ipFamily      int
		address       string
	}{
		{"ControllerIPv4", "", 4, addressV4},
		{"AgentIPv4", controlPlaneNodeName(), 4, addressV4},
		{"ControllerIPv6", "", 6, addressV6},
		{"AgentIPv6", controlPlaneNodeName(), 6, addressV6},
	}

	for idx, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			proxyPodName := fmt.Sprintf("antctl-proxy-%d", idx)
			if clusterInfo.podV4NetworkCIDR == "" && tc.ipFamily == 4 || clusterInfo.podV6NetworkCIDR == "" && tc.ipFamily == 6 {
				t.Skipf("Skipping this testcase since cluster network family doesn't fit")
			}
			runAntctProxy(t, data, proxyPodName, antctlServiceAccountName, proxyContainerName, antctlImage, proxyPort, tc.agentNodeName, tc.address)
			for _, endpoint := range []string{"apis", "metrics", "debug/pprof/"} {
				assert.NoErrorf(t, checkEndpointAccess(tc.address, endpoint, true), "endpoint check failed for '%s'", endpoint)
			}
		})
	}
}

func createAntctlServiceAccount(t *testing.T, data *TestData, name string) {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: data.testNamespace,
			Name:      name,
		},
	}
	_, err := data.clientset.CoreV1().ServiceAccounts(data.testNamespace).Create(context.TODO(), serviceAccount, metav1.CreateOptions{})
	require.NoErrorf(t, err, "failed to create ServiceAccount '%s/%s' for antctl test Pods", data.testNamespace, name)

	t.Cleanup(func() {
		err := data.clientset.CoreV1().ServiceAccounts(data.testNamespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
		assert.NoError(t, err, "Error when deleting ServiceAccount")
	})

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, // we use the same name as for the ServiceAccount
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: data.testNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "antctl",
		},
	}
	_, err = data.clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), clusterRoleBinding, metav1.CreateOptions{})
	require.NoErrorf(t, err, "Failed to create ClusterRoleBinding to grant antctl ClusterRole to ServiceAccount '%s/%s'", data.testNamespace, name)

	t.Cleanup(func() {
		err := data.clientset.RbacV1().ClusterRoleBindings().Delete(context.TODO(), name, metav1.DeleteOptions{})
		assert.NoError(t, err, "Error when deleting ClusterRoleBinding")
	})
}
