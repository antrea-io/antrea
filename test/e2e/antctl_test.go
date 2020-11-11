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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/antctl"
	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
)

type cmdAndReturnCode struct {
	args               []string
	expectedReturnCode int
}

// antctlOutput is a helper function for logging antctl outputs.
func antctlOutput(stdout, stderr string, tb testing.TB) {
	tb.Logf("antctl stdout:\n%s", stdout)
	tb.Logf("antctl stderr:\n%s", stderr)
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
	return stdout, stderr, err
}

// TestAntctlAgentLocalAccess ensures antctl is accessible in a agent Pod.
func TestAntctlAgentLocalAccess(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	podName, err := data.getAntreaPodOnNode(masterNodeName())
	if err != nil {
		t.Fatalf("Error when getting antrea-agent pod name: %v", err)
	}
	for _, c := range antctl.CommandList.GetDebugCommands(runtime.ModeAgent) {
		args := append([]string{"antctl", "-v"}, c...)
		cmd := strings.Join(args, " ")
		t.Run(cmd, func(t *testing.T) {
			stdout, stderr, err := runAntctl(podName, args, data)
			antctlOutput(stdout, stderr, t)
			if err != nil {
				t.Fatalf("Error when running `antctl %s` from %s: %v", c, podName, err)
			}
		})
	}
}

func copyAntctlToNode(data *TestData, nodeName string, nodeAntctlPath string) error {
	podName, err := data.getAntreaPodOnNode(masterNodeName())
	if err != nil {
		return fmt.Errorf("error when retrieving Antrea Controller Pod name: %v", err)
	}
	// Just try our best to clean up.
	RunCommandOnNode(nodeName, fmt.Sprintf("rm -f %s", nodeAntctlPath))
	// Copy antctl from the controller Pod to the Node.
	cmd := fmt.Sprintf("kubectl cp %s/%s:/usr/local/bin/antctl %s", antreaNamespace, podName, nodeAntctlPath)
	rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return fmt.Errorf("error when copying antctl from %s, stdout: <%v>, stderr: <%v>", podName, stdout, stderr)
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

// TestAntctlControllerRemoteAccess ensures antctl is able to be run outside of
// the kubernetes cluster. It uses the antctl client binary copied from the controller
// Pod.
func TestAntctlControllerRemoteAccess(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	nodeAntctlPath := "~/antctl"
	if err := copyAntctlToNode(data, masterNodeName(), nodeAntctlPath); err != nil {
		t.Fatalf("Cannot copy antctl on master Node: %v", err)
	}

	testCmds := []cmdAndReturnCode{}
	// Add all controller commands.
	for _, c := range antctl.CommandList.GetDebugCommands(runtime.ModeController) {
		cmd := append([]string{nodeAntctlPath, "-v"}, c...)
		testCmds = append(testCmds, cmdAndReturnCode{args: cmd, expectedReturnCode: 0})
	}
	testCmds = append(testCmds,
		// Malformed config
		cmdAndReturnCode{
			args:               []string{nodeAntctlPath, "-v", "version", "--kubeconfig", "/dev/null"},
			expectedReturnCode: 1,
		},
	)

	for _, tc := range testCmds {
		cmd := strings.Join(tc.args, " ")
		t.Run(cmd, func(t *testing.T) {
			rc, stdout, stderr, err := RunCommandOnNode(masterNodeName(), cmd)
			antctlOutput(stdout, stderr, t)
			assert.Equal(t, tc.expectedReturnCode, rc)
			if err != nil {
				t.Fatalf("Error when running `%s` from %s: %v", cmd, masterNodeName(), err)
			}
		})
	}
}

// TestAntctlVerboseMode ensures no unexpected outputs during the execution of
// the antctl client.
func TestAntctlVerboseMode(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	podName, err := data.getAntreaPodOnNode(masterNodeName())
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
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running commnand `%s` on pod %s", tc.commands, podName)
			stdout, stderr, err := runAntctl(podName, tc.commands, data)
			antctlOutput(stdout, stderr, t)
			assert.Nil(t, err)
			if !tc.hasStderr {
				assert.Empty(t, stderr)
			} else {
				assert.NotEmpty(t, stderr)
			}
		})
	}
}

// runAntctProxy runs the antctl reverse proxy on the provided Node; to stop the
// proxy call the returned function.
func runAntctProxy(nodeName string, nodeAntctlPath string, proxyPort int, agentNodeName string) (func() error, error) {
	waitCh := make(chan struct{})
	go func() {
		proxyCmd := []string{nodeAntctlPath, "proxy"}
		if agentNodeName == "" {
			proxyCmd = append(proxyCmd, "--controller")
		} else {
			proxyCmd = append(proxyCmd, "--agent-node", agentNodeName)
		}
		cmd := strings.Join(proxyCmd, " ")
		RunCommandOnNode(nodeName, cmd)
		waitCh <- struct{}{}
	}()
	// wait for 1 second to make sure the proxy is running and to detect if
	// it errors on start.
	time.Sleep(time.Second)
	cmd := "pgrep antctl"
	rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
	if err != nil {
		return nil, fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
	}
	if rc != 0 {
		return nil, fmt.Errorf("error when retrieving 'antctl proxy' PID, stdout: <%v>, stderr: <%v>", stdout, stderr)
	}
	pid := strings.TrimSpace(stdout)
	return func() error {
		cmd := fmt.Sprintf("kill -INT %s", pid)
		rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
		}
		if rc != 0 {
			return fmt.Errorf("error when killing PID %s, stdout: <%v>, stderr: <%v>", pid, stdout, stderr)
		}
		<-waitCh
		return nil
	}, nil
}

// TestAntctlProxy validates "antctl proxy" for both the Antrea Controller and
// Agent API.
func TestAntctlProxy(t *testing.T) {
	skipIfIPv6Cluster(t)
	const proxyPort = 8001

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	nodeAntctlPath := "~/antctl"
	if err := copyAntctlToNode(data, masterNodeName(), nodeAntctlPath); err != nil {
		t.Fatalf("Cannot copy antctl on master Node: %v", err)
	}

	checkAPIAccess := func() error {
		t.Logf("Checking for API access through antctl proxy")
		cmd := fmt.Sprintf("curl 127.0.0.1:%d/apis", proxyPort)
		rc, stdout, stderr, err := RunCommandOnNode(masterNodeName(), cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Node: %v", cmd, err)
		}
		if rc != 0 {
			return fmt.Errorf("error when accessing API, stdout: <%v>, stderr: <%v>", stdout, stderr)
		}
		return nil
	}

	testcases := []struct {
		name          string
		agentNodeName string
	}{
		{"ControllerProxy", ""},
		{"AgentProxy", masterNodeName()},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Starting antctl proxy")
			stopProxyFn, err := runAntctProxy(masterNodeName(), nodeAntctlPath, proxyPort, "")
			if err != nil {
				t.Fatalf("Could not start antctl proxy: %v", err)
			}
			if err := checkAPIAccess(); err != nil {
				t.Errorf("API check failed: %v", err)
			}
			t.Logf("Stopping antctl proxy")
			if err := stopProxyFn(); err != nil {
				t.Errorf("Error when stopping antctl proxy: %v", err)
			}
		})
	}
}
