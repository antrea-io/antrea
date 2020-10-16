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

package openflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"

	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	mocks "github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing"
)

func TestOVSFlowOpsCountMetics(t *testing.T) {
	// Initialize OVS metrics (prometheus)
	metrics.InitializeOVSMetrics()

	// Prepare expected metric result
	expectedOVSOpsFlowCount := `
	# HELP antrea_agent_ovs_flow_ops_count [ALPHA] Number of OVS flow operations, partitioned by operation type (add, modify and delete).
	# TYPE antrea_agent_ovs_flow_ops_count counter
	`
	expectedOVSOpsFlowCount = expectedOVSOpsFlowCount + fmt.Sprintf("antrea_agent_ovs_flow_ops_count{operation=\"add\"} %d\n", 3)
	expectedOVSOpsFlowCount = expectedOVSOpsFlowCount + fmt.Sprintf("antrea_agent_ovs_flow_ops_count{operation=\"delete\"} %d\n", 3)
	expectedOVSOpsFlowCount = expectedOVSOpsFlowCount + fmt.Sprintf("antrea_agent_ovs_flow_ops_count{operation=\"modify\"} %d\n", 1)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := createTestClient(ctrl, true)
	// Call 3 add, 3 delte and 1 modify operations
	executeAllFlowOperations(c)

	assert.NoError(t, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedOVSOpsFlowCount), "antrea_agent_ovs_flow_ops_count"))
}

func TestOVSFlowOpsErrorCountMetics(t *testing.T) {
	// Initialize OVS metrics (prometheus)
	metrics.InitializeOVSMetrics()

	// Prepare expected metric result
	expectedOVSOpsFlowErrorCount := `
	# HELP antrea_agent_ovs_flow_ops_error_count [ALPHA] Number of OVS flow operation errors, partitioned by operation type (add, modify and delete).
	# TYPE antrea_agent_ovs_flow_ops_error_count counter
	`
	expectedOVSOpsFlowErrorCount = expectedOVSOpsFlowErrorCount + fmt.Sprintf("antrea_agent_ovs_flow_ops_error_count{operation=\"add\"} %d\n", 3)
	expectedOVSOpsFlowErrorCount = expectedOVSOpsFlowErrorCount + fmt.Sprintf("antrea_agent_ovs_flow_ops_error_count{operation=\"delete\"} %d\n", 3)
	expectedOVSOpsFlowErrorCount = expectedOVSOpsFlowErrorCount + fmt.Sprintf("antrea_agent_ovs_flow_ops_error_count{operation=\"modify\"} %d\n", 1)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := createTestClient(ctrl, false)
	// Call 3 add, 3 delte and 1 modify operations
	executeAllFlowOperations(c)

	assert.NoError(t, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedOVSOpsFlowErrorCount), "antrea_agent_ovs_flow_ops_error_count"))
}

func executeAllFlowOperations(c *client) {
	c.Add(nil)
	c.Delete(nil)
	c.Modify(nil)
	c.AddAll(nil)
	c.DeleteAll(nil)
	c.DeleteOFEntries(nil)
	c.AddOFEntries(nil)
}

func createTestClient(ctrl *gomock.Controller, isSuccessful bool) *client {
	bridge := mocks.NewMockBridge(ctrl)
	if isSuccessful {
		bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		bridge.EXPECT().AddOFEntriesInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	} else {
		bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("Error")).AnyTimes()
		bridge.EXPECT().AddOFEntriesInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("Error")).AnyTimes()
	}
	c := &client{
		pipeline: map[binding.TableIDType]binding.Table{},
		bridge:   bridge,
	}
	c.ofEntryOperations = c
	return c
}
