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

package openflow

import (
	"maps"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/config"
	opstest "antrea.io/antrea/v2/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	mocks "antrea.io/antrea/v2/pkg/ovs/openflow/testing"
)

// TestBatchInstallPolicyRuleFlowsCapFailureRestoresCache verifies that reaching the conjunction match cap
// preserves existing replay contexts and rolls back the changes staged by the batch.
func TestBatchInstallPolicyRuleFlowsCapFailureRestoresCache(t *testing.T) {
	ctrl := gomock.NewController(t)
	ops := opstest.NewMockOFEntryOperations(ctrl)
	bridge := mocks.NewMockBridge(ctrl)
	c := newFakeClient(ops, true, false, config.K8sNode, config.TrafficEncapModeEncap)
	defer resetPipelines()
	f := c.featureNetworkPolicy
	f.bridge = bridge
	f.egressTables = map[uint8]struct{}{EgressRuleTable.GetID(): {}, EgressDefaultTable.GetID(): {}}
	f.globalConjMatchFlowCache = make(map[string]*conjMatchFlowContext)
	f.policyCache = cache.NewIndexer(policyConjKeyFunc, cache.Indexers{priorityIndex: priorityIndexFunc})
	ops.EXPECT().AddAll(gomock.Any()).Return(nil)
	bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	require.NoError(t, c.NewDNSPacketInConjunction(1))
	dnsFlows := getFlowStrings(f.replayFlows())

	fullAddress := NewIPAddress(net.ParseIP("192.168.1.40"))
	match := generateAddressConjMatch(EgressRuleTable.GetID(), fullAddress, types.SrcAddress, nil)
	full := newFullConjMatchFlowContext(f, match)
	f.globalConjMatchFlowCache[match.generateGlobalMapKey()] = full
	before := maps.Clone(f.globalConjMatchFlowCache)
	newRule := func(id uint32, from types.Address) *types.PolicyRule {
		return &types.PolicyRule{
			Direction: v1beta2.DirectionOut,
			From:      []types.Address{from},
			To:        parseAddresses([]string{"0.0.0.0/0"}),
			FlowID:    id,
			TableID:   EgressRuleTable.GetID(),
			PolicyRef: &v1beta2.NetworkPolicyReference{Type: v1beta2.K8sNetworkPolicy, Namespace: "ns1", Name: "np1"},
		}
	}
	// Stage one rule before the next rule hits the cap. No bundle should be submitted.
	err := c.BatchInstallPolicyRuleFlows([]*types.PolicyRule{
		newRule(maxActionsPerConjMatchFlow+1, NewIPAddress(net.ParseIP("192.168.1.41"))),
		newRule(maxActionsPerConjMatchFlow+2, fullAddress),
	})
	require.ErrorContains(t, err, "exceeds the limit")
	assert.Equal(t, before, f.globalConjMatchFlowCache)
	assert.Len(t, full.actions, maxActionsPerConjMatchFlow)
	assert.Len(t, f.policyCache.List(), 1, "only DNS should remain installed")
	for _, flow := range dnsFlows {
		assert.Contains(t, getFlowStrings(f.replayFlows()), flow)
	}
}
