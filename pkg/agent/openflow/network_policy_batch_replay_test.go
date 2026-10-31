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
	"errors"
	"maps"
	"slices"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/config"
	opstest "antrea.io/antrea/v2/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	mocks "antrea.io/antrea/v2/pkg/ovs/openflow/testing"
)

// TestBatchInstallPolicyRuleFlowsFailureRestoresCache verifies that a failed BatchInstallPolicyRuleFlows restores the
// conjunctive match flow contexts which existed before the call (e.g. those of the DNS interception conjunction), so
// that they are still replayed, and drops all the changes made by the batch.
func TestBatchInstallPolicyRuleFlowsFailureRestoresCache(t *testing.T) {
	// Addresses of the pre-existing contexts: one shared with the batch rules, and one which is already at the limit of
	// conjunctive actions.
	sharedAddr := parseAddresses([]string{"192.168.1.41"})[0]
	fullAddr := parseAddresses([]string{"192.168.1.43"})[0]
	for _, tc := range []struct {
		name string
		// ruleFroms holds the From addresses of each egress rule of the batch.
		ruleFroms [][]string
		addAllErr error
		expectErr string
	}{
		{
			name:      "OpenFlow bundle fails",
			ruleFroms: [][]string{{"192.168.1.41", "192.168.1.42"}},
			addAllErr: errors.New("fake error"),
			expectErr: "fake error",
		},
		{
			// The second rule adds itself to the shared context before failing on the full one.
			name: "conjunctive action limit exceeded",
			ruleFroms: [][]string{
				{"192.168.1.41", "192.168.1.42"},
				{"192.168.1.41", "192.168.1.43"},
			},
			expectErr: "exceeds the limit",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			bridge := mocks.NewMockBridge(ctrl)
			c := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()
			f := c.featureNetworkPolicy
			f.bridge = bridge
			f.egressTables = map[uint8]struct{}{EgressRuleTable.GetID(): {}, EgressDefaultTable.GetID(): {}}
			f.globalConjMatchFlowCache = make(map[string]*conjMatchFlowContext)
			f.policyCache = cache.NewIndexer(policyConjKeyFunc, cache.Indexers{priorityIndex: priorityIndexFunc})

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			require.NoError(t, c.NewDNSPacketInConjunction(1))
			dnsContexts := maps.Clone(f.globalConjMatchFlowCache)
			require.Len(t, dnsContexts, 2)

			addContext := func(addr types.Address, firstConjID uint32, nActions int) {
				match := generateAddressConjMatch(EgressRuleTable.GetID(), addr, types.SrcAddress, nil)
				ctx := &conjMatchFlowContext{
					conjunctiveMatch:     match,
					actions:              make(map[uint32]*conjunctiveAction, nActions),
					featureNetworkPolicy: f,
				}
				actions := make([]*conjunctiveAction, 0, nActions)
				for i := range nActions {
					action := &conjunctiveAction{conjID: firstConjID + uint32(i), clauseID: 1, nClause: 2}
					ctx.actions[action.conjID] = action
					actions = append(actions, action)
				}
				ctx.flow = getFlowModMessage(f.conjunctiveMatchFlow(match.tableID, match.matchPairs, match.priority, actions), binding.AddMessage)
				f.globalConjMatchFlowCache[match.generateGlobalMapKey()] = ctx
			}
			addContext(sharedAddr, 1000, 1)
			addContext(fullAddr, 2000, maxActionsPerConjMatchFlow)

			// Record the state of every pre-existing context, as the restored cache holds the same context pointers.
			type contextState struct {
				ctx          *conjMatchFlowContext
				actions      []uint32
				denyAllRules []uint32
				flow         *openflow15.FlowMod
			}
			snapshot := func() map[string]contextState {
				states := make(map[string]contextState, len(f.globalConjMatchFlowCache))
				for key, ctx := range f.globalConjMatchFlowCache {
					states[key] = contextState{
						ctx:          ctx,
						actions:      slices.Sorted(maps.Keys(ctx.actions)),
						denyAllRules: slices.Sorted(maps.Keys(ctx.denyAllRules)),
						flow:         ctx.flow,
					}
				}
				return states
			}
			before := snapshot()

			var rules []*types.PolicyRule
			for i, from := range tc.ruleFroms {
				rules = append(rules, &types.PolicyRule{
					Direction: v1beta2.DirectionOut,
					From:      parseAddresses(from),
					To:        parseAddresses([]string{"0.0.0.0/0"}),
					FlowID:    1001 + uint32(i),
					TableID:   EgressRuleTable.GetID(),
					PolicyRef: &v1beta2.NetworkPolicyReference{Type: v1beta2.K8sNetworkPolicy, Namespace: "ns1", Name: "np1", UID: "id1"},
				})
			}
			if tc.addAllErr != nil {
				m.EXPECT().AddAll(gomock.Any()).Return(tc.addAllErr).Times(1)
			}
			assert.ErrorContains(t, c.BatchInstallPolicyRuleFlows(rules), tc.expectErr)

			after := snapshot()
			require.ElementsMatch(t, slices.Collect(maps.Keys(before)), slices.Collect(maps.Keys(after)))
			for key, want := range before {
				got := after[key]
				assert.Same(t, want.ctx, got.ctx, "context %s must be the pre-existing one", key)
				assert.Equal(t, want.actions, got.actions, "actions of context %s must be restored", key)
				assert.Equal(t, want.denyAllRules, got.denyAllRules, "DENY-ALL rules of context %s must be restored", key)
				assert.Same(t, want.flow, got.flow, "flow of context %s must be restored", key)
			}
			replayed := getFlowStrings(f.replayFlows())
			for key, ctx := range dnsContexts {
				assert.Contains(t, replayed, getFlowStrings([]*openflow15.FlowMod{ctx.flow})[0], "flow of DNS context %s must be replayed", key)
			}
			assert.Len(t, f.policyCache.List(), 1, "only the DNS conjunction should be in policyCache")
		})
	}
}
