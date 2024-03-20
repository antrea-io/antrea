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
	"k8s.io/apimachinery/pkg/util/sets"
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

	getFDs := func() sets.Set[string] {
		// In case that antrea-agent is not running as Pid 1 in future.
		cmds := []string{"pgrep", "-o", "antrea-agent"}
		pid, _, err := data.RunCommandFromPod(antreaNamespace, podName, "antrea-agent", cmds)
		require.NoError(t, err)

		// Ignore the difference of modification time by specifying "--time-style +".
		cmds = []string{"ls", "-l", "--time-style", "+", fmt.Sprintf("/proc/%s/fd/", strings.TrimSpace(pid))}
		stdout, _, err := data.RunCommandFromPod(antreaNamespace, podName, "antrea-agent", cmds)
		require.NoError(t, err)

		fds := strings.Split(stdout, "\n")
		return sets.New(fds...)
	}

	oldFDs := getFDs()

	_, _, cleanupFn := createTestToolboxPods(t, data, batchNum, data.testNamespace, node1)
	defer cleanupFn()

	// It is possible for new FDs to be allocated temporarily by the process, for different
	// reasons (health probes, CNI invocations, ...). In that case, the new set of FDs can
	// contain additional entries compared to the old set of FDs. However, eventually, getFDs()
	// should return a subset of oldFDs.
	assert.Eventually(t, func() bool {
		newFDs := getFDs()
		return oldFDs.IsSuperset(newFDs)
	}, 2*time.Second, 100*time.Millisecond, "Batched Pod creation allocated new FDs")
}
