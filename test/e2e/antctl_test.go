package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// antctlOutput is a helper function for logging antctl outputs.
func antctlOutput(stdout, stderr string, tb testing.TB) {
	tb.Logf("antctl stdout:\n%s", stdout)
	tb.Logf("antctl stderr:\n%s", stderr)
}

// runAntctl runs antctl commands on antrea Pods, the controller, or agents. It
// always runs the commands with verbose flag enabled.
func runAntctl(podName string, subCMDs []string, data *TestData, tb testing.TB) (string, string, error) {
	var containerName string
	if strings.Contains(podName, "agent") {
		containerName = "antrea-agent"
	} else {
		containerName = "antrea-controller"
	}
	cmds := []string{"antctl", "-v"}
	stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, containerName, append(cmds, subCMDs...))
	antctlOutput(stdout, stderr, tb)
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
	if _, _, err := runAntctl(podName, []string{"version"}, data, t); err != nil {
		t.Fatalf("Error when running `antctl version` from %s: %v", podName, err)
	}
}

// TestAntctlControllerLocalAccess ensures antctl is accessible in the controller Pod.
func TestAntctlControllerLocalAccess(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	podName, err := data.getAntreaController()
	if err != nil {
		t.Fatalf("Error when getting antrea-controller pod name: %v", err)
	}
	if _, _, err := runAntctl(podName, []string{"version"}, data, t); err != nil {
		t.Fatalf("Error when running `antctl version` from %s: %v", podName, err)
	}
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
	podName, err := data.getAntreaController()
	require.Nil(t, err, "Error when retrieving antrea controller pod name")

	// Copy antctl from the controller Pod to the master Node.
	cmd := fmt.Sprintf("kubectl cp %s/%s:/usr/local/bin/antctl ~/antctl", antreaNamespace, podName)
	rc, stdout, stderr, err := RunCommandOnNode(masterNodeName(), cmd)
	require.Zero(t, rc)
	require.Nil(t, err, "Error when copying antctl from %s, stdout: %s, stderr: %s", podName, stdout, stderr)
	// Make sure the antctl binary executable on the master Node.
	rc, stdout, stderr, err = RunCommandOnNode(masterNodeName(), "chmod 0755 ~/antctl")
	require.Zero(t, rc)
	require.Nil(t, err, "Error when make the antctl on master node executable, stdout: %s, stderr: %s", podName, stdout, stderr)

	for k, tc := range map[string]struct {
		commands           string
		expectedReturnCode int
	}{
		"CorrectConfig": {
			commands:           "-v version",
			expectedReturnCode: 0,
		},
		"MalformedConfig": {
			commands:           "-v version --kubeconfig /dev/null",
			expectedReturnCode: 1,
		},
	} {
		t.Run(k, func(t *testing.T) {
			commands := "~/antctl " + tc.commands
			rc, stdout, stderr, err = RunCommandOnNode(masterNodeName(), commands)
			antctlOutput(stdout, stderr, t)
			assert.Equal(t, tc.expectedReturnCode, rc)
			if err != nil {
				t.Fatalf("Error when running `antctl version` from %s: %v", masterNodeName(), err)
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
	podName, err := data.getAntreaController()
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
		{name: "CommandVerbose", hasStderr: true, commands: []string{"antctl", "version", "-v"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running commnad `%s` on pod %s", tc.commands, podName)
			stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, "antrea-controller", tc.commands)
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
