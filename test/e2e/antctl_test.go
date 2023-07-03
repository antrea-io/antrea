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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

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

	t.Run("testAntctlAgentLocalAccess", func(t *testing.T) {
		testAntctlAgentLocalAccess(t, data)
	})
	t.Run("testAntctlControllerRemoteAccess", func(t *testing.T) {
		testAntctlControllerRemoteAccess(t, data)
	})
	t.Run("testAntctlVerboseMode", func(t *testing.T) {
		testAntctlVerboseMode(t, data)
	})
	t.Run("testAntctlProxy", func(t *testing.T) {
		testAntctlProxy(t, data)
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

func nodeAntctlPath() string {
	if testOptions.providerName == "kind" {
		if testOptions.enableCoverage {
			return "/root/antctl-coverage"
		}
		return "/root/antctl"
	}
	if testOptions.enableCoverage {
		return "~/antctl-coverage"
	}
	return "~/antctl"
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

func antctlCoverageArgs(antctlPath string) []string {
	const timeFormat = "20060102T150405Z0700"
	timeStamp := time.Now().Format(timeFormat)
	return []string{antctlPath, "-test.run=TestBincoverRunMain", fmt.Sprintf("-test.coverprofile=antctl-%s.out", timeStamp)}
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
			antctlCovArgs := antctlCoverageArgs("antctl-coverage")
			args = append(antctlCovArgs, c...)
		} else {
			args = append([]string{"antctl"}, c...)
		}
		t.Logf("args: %s", args)

		cmd := strings.Join(args, " ")
		t.Run(cmd, func(t *testing.T) {
			stdout, stderr, err := runAntctl(podName, args, data)
			if err != nil && !strings.HasSuffix(stderr, "not enabled\n") {
				t.Fatalf("Error when running `antctl %s` from %s: %v\n%s", c, podName, err, antctlOutput(stdout, stderr))
			}
		})
	}
}

func copyAntctlToNode(data *TestData, nodeName string, antctlName string, nodeAntctlPath string) error {
	pod, err := data.getAntreaController()
	if err != nil {
		return fmt.Errorf("error when retrieving Antrea Controller Pod: %v", err)
	}
	// Just try our best to clean up.
	data.RunCommandOnNode(nodeName, fmt.Sprintf("rm -f %s", nodeAntctlPath))
	// Copy antctl from the controller Pod to the Node.
	cmd := fmt.Sprintf("kubectl cp %s/%s:/usr/local/bin/%s %s", antreaNamespace, pod.Name, antctlName, nodeAntctlPath)
	rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return fmt.Errorf("error when copying %s from %s, stdout: <%v>, stderr: <%v>", antctlName, pod.Name, stdout, stderr)
	}
	// Make sure the antctl binary is executable on the Node.
	cmd = fmt.Sprintf("chmod +x %s", nodeAntctlPath)
	rc, stdout, stderr, err = data.RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return fmt.Errorf("error when making antctl executable on Node, stdout: <%v>, stderr: <%v>", stdout, stderr)
	}
	return nil
}

// copyAntctlKubeconfigToNode writes a Kubeconfig file for the antctl ServiceAccount to the provided
// path on the provided Node.
func copyAntctlKubeconfigToNode(data *TestData, nodeName string, kubeconfigPath string) error {
	// First, we create a Secret to store the Kubeconfig. Then, we use kubectl to write the
	// Secret contents to a file. Ideally, we would use a Pod to run antctl commands instead of
	// running it from the Node (in that case, the Secret would be mounted to the Pod).
	kubeconfigSecretKey := "kubeconfig"
	// No need to worry about deleting the Secret as it is created in the temporary test Namespace.
	kubeconfigSecretName, err := createAntctlKubeconfigSecret(context.TODO(), data, kubeconfigSecretKey)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("kubectl get -n %s secret %s --template='{{ .data.%s | base64decode }}' > %s", data.testNamespace, kubeconfigSecretName, kubeconfigSecretKey, kubeconfigPath)
	if testOptions.providerName == "kind" {
		cmd = "/bin/sh -c " + cmd
	}
	rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return fmt.Errorf("error when getting secret contents, stdout: <%v>, stderr: <%v>", stdout, stderr)
	}
	return nil
}

// testAntctlControllerRemoteAccess ensures antctl is able to be run outside of
// the kubernetes cluster. It uses the antctl client binary copied from the controller
// Pod.
func testAntctlControllerRemoteAccess(t *testing.T, data *TestData) {
	antctlName := antctlName()
	nodeAntctlPath := nodeAntctlPath()
	require.NoError(t, copyAntctlToNode(data, controlPlaneNodeName(), antctlName, nodeAntctlPath), "failed to copy antctl to control-plane Node")
	nodeAntctlKubeconfigPath := "/tmp/antctl-kubeconfig"
	require.NoError(t, copyAntctlKubeconfigToNode(data, controlPlaneNodeName(), nodeAntctlKubeconfigPath), "failed to copy antctl Kubeconfig to control-plane Node")

	testCmds := []cmdAndReturnCode{}
	// Add all controller commands.
	for _, c := range antctl.CommandList.GetDebugCommands(runtime.ModeController) {
		cmd := []string{nodeAntctlPath}
		if testOptions.enableCoverage {
			antctlCovArgs := antctlCoverageArgs(nodeAntctlPath)
			cmd = append(antctlCovArgs, c...)
		}
		// Add global flags after command to ensure they are recognized correctly when using
		// the coverage binary.
		cmd = append(cmd, "-k", nodeAntctlKubeconfigPath)
		testCmds = append(testCmds, cmdAndReturnCode{args: cmd, expectedReturnCode: 0})
	}
	testCmds = append(testCmds,
		// Malformed config
		cmdAndReturnCode{
			args:               []string{nodeAntctlPath, "version", "--kubeconfig", "/dev/null"},
			expectedReturnCode: 1,
		},
	)

	for _, tc := range testCmds {
		cmd := strings.Join(tc.args, " ")
		t.Run(cmd, func(t *testing.T) {
			rc, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
			if err != nil {
				t.Fatalf("Error when running `%s` from %s: %v\n%s", cmd, controlPlaneNodeName(), err, antctlOutput(stdout, stderr))
			}
			assert.Equal(t, tc.expectedReturnCode, rc, "Return code is incorrect: %d\n%s", rc, antctlOutput(stdout, stderr))
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

// runAntctProxy runs the antctl reverse proxy on the provided Node; to stop the
// proxy call the returned function.
func runAntctProxy(
	nodeName string,
	antctlName string,
	nodeAntctlPath string,
	kubeconfigPath string,
	proxyPort int,
	agentNodeName string,
	address string,
	data *TestData,
) (func() error, error) {
	waitCh := make(chan string)
	proxyCmd := []string{nodeAntctlPath, "proxy", "--port", fmt.Sprint(proxyPort), "--address", address}
	if agentNodeName == "" {
		proxyCmd = append(proxyCmd, "--controller")
	} else {
		proxyCmd = append(proxyCmd, "--agent-node", agentNodeName)
		// Retry until AntreaAgentInfo is updated by Antrea Agent.
		err := data.checkAntreaAgentInfo(1*time.Minute, 2*time.Minute, agentNodeName)
		if err != nil {
			return nil, err
		}
	}
	// Add global flags after command to ensure they are recognized correctly when using the
	// coverage binary.
	proxyCmd = append(proxyCmd, "-k", kubeconfigPath)
	go func() {
		_, stdout, stderr, _ := data.RunCommandOnNode(nodeName, strings.Join(proxyCmd, " "))
		waitCh <- antctlOutput(stdout, stderr)
	}()

	// wait for the proxy to be running and retrieve the PID
	cmd := fmt.Sprintf("pgrep %s", antctlName)
	var pid string
	if err := wait.Poll(1*time.Second, 10*time.Second, func() (bool, error) {
		rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
		if err != nil {
			return false, fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
		}
		if rc == 1 {
			// no matching process
			return false, nil
		} else if rc != 0 {
			return false, fmt.Errorf("error when retrieving 'antctl proxy' PID, proxy command: '%s'\n stdout: <%v>, stderr: <%v>",
				strings.Join(proxyCmd, " "), stdout, stderr)
		}
		pid = strings.TrimSpace(stdout)
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout {
			select {
			case out := <-waitCh:
				return nil, fmt.Errorf("'antctl proxy' failed to start:\n%s", out)
			default:
				return nil, err
			}
		}
		return nil, err
	}

	return func() error {
		cmd := fmt.Sprintf("kill -INT %s", pid)
		rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
		}
		if rc != 0 {
			return fmt.Errorf("error when stopping PID %s, stdout: <%v>, stderr: <%v>", pid, stdout, stderr)
		}
		<-waitCh
		return nil
	}, nil
}

// testAntctlProxy validates "antctl proxy" for both the Antrea Controller and
// Agent API.
func testAntctlProxy(t *testing.T, data *TestData) {
	const proxyPort = 8001
	antctlName := antctlName()
	nodeAntctlPath := nodeAntctlPath()
	require.NoError(t, copyAntctlToNode(data, controlPlaneNodeName(), antctlName, nodeAntctlPath), "failed to copy antctl to control-plane Node")
	nodeAntctlKubeconfigPath := "/tmp/antctl-kubeconfig"
	require.NoError(t, copyAntctlKubeconfigToNode(data, controlPlaneNodeName(), nodeAntctlKubeconfigPath), "failed to copy antctl Kubeconfig to control-plane Node")

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
		cmd := fmt.Sprintf("curl %s/%s", net.JoinHostPort(address, fmt.Sprint(proxyPort)), endpoint)
		rc, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
		}
		if rc != 0 {
			return fmt.Errorf("error when accessing endpoint '/%s', stdout: <%v>, stderr: <%v>", endpoint, stdout, stderr)
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

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if clusterInfo.podV4NetworkCIDR == "" && tc.ipFamily == 4 || clusterInfo.podV6NetworkCIDR == "" && tc.ipFamily == 6 {
				t.Skipf("Skipping this testcase since cluster network family doesn't fit")
			}
			t.Logf("Starting antctl proxy")
			stopProxyFn, err := runAntctProxy(controlPlaneNodeName(), antctlName, nodeAntctlPath, nodeAntctlKubeconfigPath, proxyPort, tc.agentNodeName, tc.address, data)
			require.NoError(t, err, "Could not start antctl proxy: %v", err)
			defer func() {
				t.Logf("Stopping antctl proxy")
				if err := stopProxyFn(); err != nil {
					t.Errorf("Error when stopping antctl proxy: %v", err)
				}
			}()

			require.NoError(t, wait.PollImmediate(1*time.Second, 5*time.Second, func() (bool, error) {
				if err := checkEndpointAccess(tc.address, "", false); err != nil {
					return false, err
				}
				return true, nil
			}), "Antctl proxy never became ready")

			for _, endpoint := range []string{"apis", "metrics", "debug/pprof/"} {
				assert.NoErrorf(t, checkEndpointAccess(tc.address, endpoint, true), "endpoint check failed for '%s'", endpoint)
			}
		})
	}
}

func getAntctlServiceAccountToken(ctx context.Context, data *TestData) ([]byte, []byte, error) {
	const secretName = "antctl-service-account-token"
	secret, err := data.clientset.CoreV1().Secrets(antreaNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve secret '%s/%s' containing antctl ServiceAccount token: %w", antreaNamespace, secretName, err)
	}
	return secret.Data["token"], secret.Data["ca.crt"], nil
}

func generateAntctlKubeconfig(ctx context.Context, data *TestData) ([]byte, error) {
	token, ca, err := getAntctlServiceAccountToken(ctx, data)
	if err != nil {
		return nil, err
	}
	// the clusterName is purely cosmetic and does not impact functionality
	const clusterName = "antrea-test-e2e"
	serverURL := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(clusterInfo.k8sServiceHost, fmt.Sprint(clusterInfo.k8sServicePort)),
	}
	config := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   serverURL.String(),
				CertificateAuthorityData: ca,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			clusterName: {
				Cluster:   clusterName,
				Namespace: antreaNamespace,
				AuthInfo:  clusterName,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			clusterName: {
				Token: string(token),
			},
		},
		CurrentContext: clusterName,
	}
	rawConfig, err := clientcmd.Write(config)
	if err != nil {
		return nil, err
	}
	return rawConfig, nil
}

// createAntctlKubeconfigSecret creates a Secret containing the raw Kubeconfig data for the antctl
// ServiceAccount, in the current test Namespace. It returns the randomly-generated Secret name.
func createAntctlKubeconfigSecret(ctx context.Context, data *TestData, key string) (string, error) {
	config, err := generateAntctlKubeconfig(ctx, data)
	if err != nil {
		return "", err
	}
	name := randName("antctl-kubeconfig-")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: data.testNamespace,
			Name:      name,
		},
		Data: map[string][]byte{
			key: config,
		},
	}
	if _, err := data.clientset.CoreV1().Secrets(data.testNamespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("failed to create secret containing antctl Kubeconfig data: %w", err)
	}
	return name, nil
}
