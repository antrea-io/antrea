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

	"github.com/stretchr/testify/assert"
)

// TestBatchCreatePods verifies there is no FD leak after batched Pod creation.
func TestBatchCreatePods(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	batchNum := 20

	node1 := workerNodeName(1)
	podName, err := data.getAntreaPodOnNode(node1)
	assert.NoError(t, err)

	getFDs := func() string {
		// In case that antrea-agent is not running as Pid 1 in future.
		cmds := []string{"pgrep", "-o", "antrea-agent"}
		pid, _, err := data.runCommandFromPod(antreaNamespace, podName, "antrea-agent", cmds)
		assert.NoError(t, err)

		// Ignore the difference of modification time by specifying "--time-style +".
		cmds = []string{"ls", "-l", "--time-style", "+", fmt.Sprintf("/proc/%s/fd/", strings.TrimSpace(pid))}
		stdout, _, err := data.runCommandFromPod(antreaNamespace, podName, "antrea-agent", cmds)
		assert.NoError(t, err)
		return stdout
	}

	oldFDs := getFDs()

	_, _, cleanupFn := createTestBusyboxPods(t, data, batchNum, testNamespace, node1)
	defer cleanupFn()

	newFDs := getFDs()
	assert.Equal(t, oldFDs, newFDs, "FDs were changed after batched Pod creation")
}
