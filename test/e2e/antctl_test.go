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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	skipIfHasWindowsNodes(t)
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

// runAntctl runs antctl commands on antrea Pods, the controller, or agents.
func runAntctl(podName string, cmds []string, data *TestData) (string, string, error) {
	var containerName string
	if strings.Contains(podName, "agent") {
		containerName = "antrea-agent"
	} else {
		containerName = "antrea-controller"
	}
	stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, containerName, cmds)
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
			args = append([]string{"antctl", "-v"}, c...)
		}
		t.Logf("args: %s", args)

		cmd := strings.Join(args, " ")
		t.Run(cmd, func(t *testing.T) {
			stdout, stderr, err := runAntctl(podName, args, data)
			if err != nil {
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
	RunCommandOnNode(nodeName, fmt.Sprintf("rm -f %s", nodeAntctlPath))
	// Copy antctl from the controller Pod to the Node.
	cmd := fmt.Sprintf("kubectl cp %s/%s:/usr/local/bin/%s %s", antreaNamespace, pod.Name, antctlName, nodeAntctlPath)
	rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return fmt.Errorf("error when copying %s from %s, stdout: <%v>, stderr: <%v>", antctlName, pod.Name, stdout, stderr)
	}
	// Make sure the antctl binary is executable on the Node.
	cmd = fmt.Sprintf("chmod +x %s", nodeAntctlPath)
	rc, stdout, stderr, err = RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return fmt.Errorf("error when making antctl executable on Node, stdout: <%v>, stderr: <%v>", stdout, stderr)
	}
	return nil
}

// testAntctlControllerRemoteAccess ensures antctl is able to be run outside of
// the kubernetes cluster. It uses the antctl client binary copied from the controller
// Pod.
func testAntctlControllerRemoteAccess(t *testing.T, data *TestData) {
	antctlName := "antctl"
	nodeAntctlPath := "~/antctl"
	if testOptions.enableCoverage {
		antctlName = "antctl-coverage"
		nodeAntctlPath = "~/antctl-coverage"
	}
	if err := copyAntctlToNode(data, controlPlaneNodeName(), antctlName, nodeAntctlPath); err != nil {
		t.Fatalf("Cannot copy %s on control-plane Node: %v", antctlName, err)
	}

	testCmds := []cmdAndReturnCode{}
	// Add all controller commands.
	for _, c := range antctl.CommandList.GetDebugCommands(runtime.ModeController) {
		cmd := append([]string{nodeAntctlPath, "-v"}, c...)
		if testOptions.enableCoverage {
			antctlCovArgs := antctlCoverageArgs(nodeAntctlPath)
			cmd = append(antctlCovArgs, c...)
		}
		testCmds = append(testCmds, cmdAndReturnCode{args: cmd, expectedReturnCode: 0})
	}
	if testOptions.enableCoverage {
		testCmds = append(testCmds,
			// Malformed config
			cmdAndReturnCode{
				args:               []string{nodeAntctlPath, "version", "--kubeconfig", "/dev/null"},
				expectedReturnCode: 1,
			},
		)

	} else {
		testCmds = append(testCmds,
			// Malformed config
			cmdAndReturnCode{
				args:               []string{nodeAntctlPath, "-v", "version", "--kubeconfig", "/dev/null"},
				expectedReturnCode: 1,
			},
		)
	}

	for _, tc := range testCmds {
		cmd := strings.Join(tc.args, " ")
		t.Run(cmd, func(t *testing.T) {
			rc, stdout, stderr, err := RunCommandOnNode(controlPlaneNodeName(), cmd)
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
			t.Logf("Running commnand `%s` on pod %s", tc.commands, podName)
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
func runAntctProxy(nodeName string, antctlName string, nodeAntctlPath string, proxyPort int, agentNodeName string, address string) (func() error, error) {
	waitCh := make(chan struct{})
	proxyCmd := []string{nodeAntctlPath, "proxy", "--port", fmt.Sprint(proxyPort), "--address", address}
	if agentNodeName == "" {
		proxyCmd = append(proxyCmd, "--controller")
	} else {
		proxyCmd = append(proxyCmd, "--agent-node", agentNodeName)
	}
	go func() {
		RunCommandOnNode(nodeName, strings.Join(proxyCmd, " "))
		waitCh <- struct{}{}
	}()

	// wait for 1 second to make sure the proxy is running and to detect if
	// it errors on start.
	time.Sleep(time.Second)
	cmd := fmt.Sprintf("pgrep %s", antctlName)
	rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return nil, fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return nil, fmt.Errorf("error when retrieving 'antctl proxy' PID, proxy command: '%s'\n stdout: <%v>, stderr: <%v>",
			strings.Join(proxyCmd, " "), stdout, stderr)
	}
	pid := strings.TrimSpace(stdout)
	return func() error {
		cmd := fmt.Sprintf("kill -INT %s", pid)
		rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
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
	antctlName := "antctl"
	nodeAntctlPath := "~/antctl"
	if testOptions.enableCoverage {
		antctlName = "antctl-coverage"
		nodeAntctlPath = "~/antctl-coverage"
	}
	if err := copyAntctlToNode(data, controlPlaneNodeName(), antctlName, nodeAntctlPath); err != nil {
		t.Fatalf("Cannot copy %s on control-plane Node: %v", antctlName, err)
	}

	checkAPIAccess := func(url string) error {
		t.Logf("Checking for API access through antctl proxy")
		cmd := fmt.Sprintf("curl %s/apis", net.JoinHostPort(url, fmt.Sprint(proxyPort)))
		rc, stdout, stderr, err := RunCommandOnNode(controlPlaneNodeName(), cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
		}
		if rc != 0 {
			return fmt.Errorf("error when accessing API, stdout: <%v>, stderr: <%v>", stdout, stderr)
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
			stopProxyFn, err := runAntctProxy(controlPlaneNodeName(), antctlName, nodeAntctlPath, proxyPort, tc.agentNodeName, tc.address)
			assert.NoError(t, err, "Could not start antctl proxy: %v", err)
			if err := checkAPIAccess(tc.address); err != nil {
				t.Errorf("API check failed: %v", err)
			}
			t.Logf("Stopping antctl proxy")
			if err := stopProxyFn(); err != nil {
				t.Errorf("Error when stopping antctl proxy: %v", err)
			}
		})
	}
}
