package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func antctlOutput(stdout, stderr string, tb testing.TB) {
	tb.Logf("`antctl version` stdout:\n%s", stdout)
	tb.Logf("`antctl version` stderr:\n%s", stderr)
}

func runAntctl(podName string, subCmds []string, data *TestData, tb testing.TB) (string, string, error) {
	var containerName string
	if strings.Contains(podName, "agent") { // simple hack here
		containerName = "antrea-agent"
	} else {
		containerName = "antrea-controller"
	}

	cmds := []string{"antctl", "-d"}
	stdout, stderr, err := data.runCommandFromPod(AntreaNamespace, podName, containerName, append(cmds, subCmds...))
	antctlOutput(stdout, stderr, tb)

	return stdout, stderr, err
}

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

func TestAntctlControllerRemoteAccess(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	podName, err := data.getAntreaController()
	assert.Nil(t, err, "Error when retrieving antrea controller pod name")

	cmd := fmt.Sprintf("kubectl cp %s/%s:/usr/local/bin/antctl ~/antctl", AntreaNamespace, podName)
	_, _, _, err = RunCommandOnNode(masterNodeName(), cmd)
	assert.Nil(t, err, "Error when copying antctl from %s", podName)

	_, stdout, stderr, err := RunCommandOnNode(masterNodeName(), "~/antctl -d version")
	antctlOutput(stdout, stderr, t)
	if err != nil {
		t.Fatalf("Error when running `antctl version` from %s: %v", masterNodeName(), err)
	}
}

func TestAntctlDebugMode(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	for _, tc := range []struct {
		name      string
		hasStderr bool
		commands  []string
	}{
		{name: "RootNonDebug", hasStderr: false, commands: []string{"antctl"}},
		{name: "RootDebug", hasStderr: false, commands: []string{"antctl", "-d"}},
		{name: "CommandNonDebug", hasStderr: false, commands: []string{"antctl", "version"}},
		{name: "CommandDebug", hasStderr: true, commands: []string{"antctl", "-d", "version"}},
		{name: "CommandDebug", hasStderr: true, commands: []string{"antctl", "version", "-d"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			podName, err := data.getAntreaController()
			assert.Nil(t, err, "Error when retrieving antrea controller pod name")
			t.Logf("Running commnad `%s` on pod %s", tc.commands, podName)
			stdout, stderr, err := data.runCommandFromPod(AntreaNamespace, podName, "antrea-controller", tc.commands)
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
