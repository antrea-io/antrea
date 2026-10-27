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
	"fmt"
	"maps"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/config"
	opstest "antrea.io/antrea/v2/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	mocks "antrea.io/antrea/v2/pkg/ovs/openflow/testing"
)

func newReconcileTestClient(t *testing.T) (*client, *opstest.MockOFEntryOperations) {
	ctrl := gomock.NewController(t)
	ops := opstest.NewMockOFEntryOperations(ctrl)
	bridge := mocks.NewMockBridge(ctrl)
	c := newFakeClient(ops, true, true, config.K8sNode, config.TrafficEncapModeEncap)
	t.Cleanup(resetPipelines)
	f := c.featureNetworkPolicy
	f.initGroups()
	f.bridge = bridge
	f.deterministic = true
	f.egressTables = map[uint8]struct{}{EgressRuleTable.GetID(): {}, AntreaPolicyEgressRuleTable.GetID(): {}}
	f.globalConjMatchFlowCache = make(map[string]*conjMatchFlowContext)
	f.policyCache = cache.NewIndexer(policyConjKeyFunc, cache.Indexers{priorityIndex: priorityIndexFunc})
	ops.EXPECT().AddAll(gomock.Any()).Return(nil).AnyTimes()
	ops.EXPECT().DeleteAll(gomock.Any()).Return(nil).AnyTimes()
	bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	return c, ops
}

func reconcileTestRule(id uint32, direction v1beta2.Direction, protocol v1beta2.Protocol, port int, ipv6 bool) *types.PolicyRule {
	from, to := "192.168.1.40", "192.168.2.40"
	if ipv6 {
		from, to = "2001:db8::40", "2001:db9::40"
	}
	p := intstr.FromInt(port)
	rule := &types.PolicyRule{
		FlowID: id, Direction: direction, From: parseAddresses([]string{from}), To: parseAddresses([]string{to}),
		Service:   []v1beta2.Service{{Protocol: &protocol, Port: &p}},
		PolicyRef: &v1beta2.NetworkPolicyReference{Type: v1beta2.K8sNetworkPolicy, Namespace: "ns1", Name: "np1"},
		TableID:   EgressRuleTable.GetID(),
	}
	if direction == v1beta2.DirectionIn {
		rule.TableID = IngressRuleTable.GetID()
		rule.To = []types.Address{NewOFPortAddress(1)}
	}
	return rule
}

// fillReconcileContext adds unrelated conjunction actions to model a match already at the wire-size cap.
func fillReconcileContext(t *testing.T, f *featureNetworkPolicy, ctx *conjMatchFlowContext) {
	t.Helper()
	for id := uint32(10000); len(ctx.actions) < maxActionsPerConjMatchFlow; id++ {
		ctx.actions[id] = &conjunctiveAction{conjID: id, clauseID: 1, nClause: 3}
	}
	var actions []*conjunctiveAction
	for _, action := range ctx.actions {
		actions = append(actions, action)
	}
	ctx.flow = getFlowModMessage(f.conjunctiveMatchFlow(ctx.tableID, ctx.matchPairs, ctx.priority, actions), binding.AddMessage)
}

func TestReconcilePolicyRuleFlowsAtCap(t *testing.T) {
	for _, direction := range []v1beta2.Direction{v1beta2.DirectionIn, v1beta2.DirectionOut} {
		for _, ipv6 := range []bool{false, true} {
			for _, protocol := range []v1beta2.Protocol{v1beta2.ProtocolTCP, v1beta2.ProtocolUDP, v1beta2.ProtocolSCTP} {
				for _, retained := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/ipv6=%t/%s/retained=%t", direction, ipv6, protocol, retained), func(t *testing.T) {
						c, ops := newReconcileTestClient(t)
						f := c.featureNetworkPolicy
						old := reconcileTestRule(1, direction, protocol, 80, ipv6)
						replacement := reconcileTestRule(2, direction, protocol, 8080, ipv6)
						require.NoError(t, c.InstallPolicyRuleFlows(old))
						previous := []uint32{old.FlowID}
						var retainedAction, retainedMetric *openflow15.FlowMod
						if retained {
							initial := *replacement
							if direction == v1beta2.DirectionIn {
								initial.To = []types.Address{NewOFPortAddress(2)}
							} else {
								initial.To = parseAddresses([]string{"192.168.2.41"})
							}
							require.NoError(t, c.InstallPolicyRuleFlows(&initial))
							previous = append(previous, initial.FlowID)
							conj := f.getPolicyRuleConjunction(initial.FlowID)
							retainedAction, retainedMetric = conj.actionFlows[0], conj.metricFlows[0]
						}
						// A match that must transfer an action from the old group to the desired group.
						addrType, addr := types.DstAddress, old.To[0]
						if direction == v1beta2.DirectionOut && !retained {
							addrType, addr = types.SrcAddress, old.From[0]
						}
						key := generateAddressConjMatch(old.TableID, addr, addrType, nil).generateGlobalMapKey()
						shared := f.globalConjMatchFlowCache[key]
						require.NotNil(t, shared)
						fillReconcileContext(t, f, shared)
						beforeDrop := shared.dropFlow
						ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(adds, mods, dels []*openflow15.FlowMod) error {
							require.Contains(t, shared.actions, old.FlowID, "live context must remain unchanged before commit")
							require.NotContains(t, shared.actions, replacement.FlowID)
							if beforeDrop != nil {
								assert.NotContains(t, getFlowStrings(dels), getFlowStrings([]*openflow15.FlowMod{beforeDrop})[0], "replacement must preserve isolation")
							}
							// The same match must occur at most once in the whole transaction.
							seen := map[string]bool{}
							for _, messages := range [][]*openflow15.FlowMod{adds, mods, dels} {
								for _, message := range messages {
									k := getFlowDumpKey(message)
									assert.False(t, seen[k], "duplicate flow operation: %s", k)
									seen[k] = true
								}
							}
							return nil
						}).Times(1)
						stale, err := c.ReconcilePolicyRuleFlows(previous, []*types.PolicyRule{replacement})
						require.NoError(t, err)
						assert.Empty(t, stale)
						assert.Same(t, shared, f.globalConjMatchFlowCache[key])
						assert.Len(t, shared.actions, maxActionsPerConjMatchFlow)
						assert.NotContains(t, shared.actions, old.FlowID)
						assert.Contains(t, shared.actions, replacement.FlowID)
						assert.Nil(t, f.getPolicyRuleConjunction(old.FlowID))
						conj := f.getPolicyRuleConjunction(replacement.FlowID)
						require.NotNil(t, conj)
						if retained {
							assert.Same(t, retainedAction, conj.actionFlows[0], "retained rule must keep its action flow")
							assert.Same(t, retainedMetric, conj.metricFlows[0], "retained rule must keep its counters")
						}
						assert.Contains(t, replayFlowStrings(f), getFlowStrings([]*openflow15.FlowMod{shared.flow})[0])
						// No-op reconciliation sends no bundle, even at the cap.
						_, err = c.ReconcilePolicyRuleFlows([]uint32{replacement.FlowID}, []*types.PolicyRule{replacement})
						require.NoError(t, err)
						// Existing incremental APIs must keep working with the committed context references.
						_, err = c.UninstallPolicyRuleFlows(replacement.FlowID)
						require.NoError(t, err)
						assert.Len(t, shared.actions, maxActionsPerConjMatchFlow-1)
						assert.NotContains(t, shared.actions, replacement.FlowID)
					})
				}
			}
		}
	}
}

func TestReconcilePolicyRuleFlowsFailure(t *testing.T) {
	for _, failure := range []string{"cap", "bundle"} {
		t.Run(failure, func(t *testing.T) {
			c, ops := newReconcileTestClient(t)
			f := c.featureNetworkPolicy
			require.NoError(t, c.NewDNSPacketInConjunction(99))
			old := reconcileTestRule(1, v1beta2.DirectionIn, v1beta2.ProtocolTCP, 80, false)
			replacement := reconcileTestRule(2, v1beta2.DirectionIn, v1beta2.ProtocolTCP, 8080, false)
			require.NoError(t, c.InstallPolicyRuleFlows(old))
			if failure == "cap" {
				match := generateServiceConjMatches(old.TableID, replacement.Service[0], nil, f.ipProtocols)[0]
				ctx := &conjMatchFlowContext{conjunctiveMatch: match, actions: map[uint32]*conjunctiveAction{}, featureNetworkPolicy: f}
				fillReconcileContext(t, f, ctx)
				f.globalConjMatchFlowCache[match.generateGlobalMapKey()] = ctx
			}
			beforeFlows := replayFlowStrings(f)
			beforeCache := make(map[string]*conjMatchFlowContext)
			for key, ctx := range f.globalConjMatchFlowCache {
				snapshot := *ctx
				snapshot.actions = maps.Clone(ctx.actions)
				snapshot.denyAllRules = maps.Clone(ctx.denyAllRules)
				beforeCache[key] = &snapshot
			}
			beforeConj := f.getPolicyRuleConjunction(1)
			if failure == "bundle" {
				ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(adds, mods, dels []*openflow15.FlowMod) error {
					// Model the bridge mutating message commands before rejecting the bundle.
					for _, message := range dels {
						message.Command = openflow15.FC_DELETE_STRICT
					}
					return errors.New("bundle rejected")
				})
			}
			_, err := c.ReconcilePolicyRuleFlows([]uint32{1}, []*types.PolicyRule{replacement})
			if failure == "cap" {
				require.ErrorIs(t, err, ErrConjMatchFlowActionsExceeded)
			} else {
				require.ErrorContains(t, err, "bundle rejected")
			}
			assert.ElementsMatch(t, beforeFlows, replayFlowStrings(f), "failure must preserve enforcement and replay, including DNS")
			assert.Equal(t, beforeCache, f.globalConjMatchFlowCache)
			assert.Same(t, beforeConj, f.getPolicyRuleConjunction(1))
			assert.Nil(t, f.getPolicyRuleConjunction(2))
			for _, message := range beforeConj.actionFlows {
				assert.Equal(t, uint8(openflow15.FC_ADD), message.Command)
			}
			// The same operation succeeds after its blocking condition is removed.
			if failure == "cap" {
				key := generateServiceConjMatches(old.TableID, replacement.Service[0], nil, f.ipProtocols)[0].generateGlobalMapKey()
				ctx := f.globalConjMatchFlowCache[key]
				delete(ctx.actions, 10000)
			}
			ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			_, err = c.ReconcilePolicyRuleFlows([]uint32{1}, []*types.PolicyRule{replacement})
			require.NoError(t, err)
		})
	}
}

func TestReconcilePolicyRuleFlowsNativePolicy(t *testing.T) {
	for _, direction := range []v1beta2.Direction{v1beta2.DirectionIn, v1beta2.DirectionOut} {
		for _, action := range []crdv1beta1.RuleAction{crdv1beta1.RuleActionAllow, crdv1beta1.RuleActionDrop, crdv1beta1.RuleActionReject, crdv1beta1.RuleActionPass} {
			t.Run(fmt.Sprintf("%s/%s", direction, action), func(t *testing.T) {
				c, ops := newReconcileTestClient(t)
				rule := reconcileTestRule(1, direction, v1beta2.ProtocolTCP, 80, false)
				priority := uint16(1234)
				rule.Priority, rule.Action = &priority, &action
				rule.PolicyRef.Type = v1beta2.AntreaClusterNetworkPolicy
				rule.TableID = AntreaPolicyIngressRuleTable.GetID()
				if direction == v1beta2.DirectionOut {
					rule.TableID = AntreaPolicyEgressRuleTable.GetID()
				}
				require.NoError(t, c.InstallPolicyRuleFlows(rule))
				replacement := *rule
				replacement.FlowID = 2
				p := intstr.FromInt(8080)
				replacement.Service = []v1beta2.Service{{Protocol: rule.Service[0].Protocol, Port: &p}}
				ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				stale, err := c.ReconcilePolicyRuleFlows([]uint32{1}, []*types.PolicyRule{&replacement})
				require.NoError(t, err)
				assert.Empty(t, stale, "replacement retains its priority")
				for _, ctx := range c.featureNetworkPolicy.globalConjMatchFlowCache {
					assert.Nil(t, ctx.dropFlow, "native policy must not add Kubernetes isolation")
				}
				// Retaining the only conjunction must not report its priority as stale.
				stale, err = c.ReconcilePolicyRuleFlows([]uint32{2}, []*types.PolicyRule{&replacement})
				require.NoError(t, err)
				assert.Empty(t, stale)
				ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				stale, err = c.ReconcilePolicyRuleFlows([]uint32{2}, nil)
				require.NoError(t, err)
				assert.Equal(t, []string{"1234"}, stale)
				assert.Empty(t, c.featureNetworkPolicy.globalConjMatchFlowCache)
			})
		}
	}
}

func TestReconcilePolicyRuleFlowsIsolationAndSharedContexts(t *testing.T) {
	c, ops := newReconcileTestClient(t)
	f := c.featureNetworkPolicy
	old := reconcileTestRule(1, v1beta2.DirectionOut, v1beta2.ProtocolTCP, 80, false)
	unrelated := reconcileTestRule(3, v1beta2.DirectionOut, v1beta2.ProtocolTCP, 443, false)
	require.NoError(t, c.InstallPolicyRuleFlows(old))
	require.NoError(t, c.InstallPolicyRuleFlows(unrelated))
	sourceKey := generateAddressConjMatch(old.TableID, old.From[0], types.SrcAddress, nil).generateGlobalMapKey()
	shared := f.globalConjMatchFlowCache[sourceKey]
	isolation := *old
	isolation.FlowID = 2
	isolation.To = nil
	isolation.Service = nil
	ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	_, err := c.ReconcilePolicyRuleFlows([]uint32{1}, []*types.PolicyRule{&isolation})
	require.NoError(t, err)
	assert.Len(t, shared.actions, 1)
	assert.Contains(t, shared.denyAllRules, uint32(2))
	assert.Same(t, shared, f.getPolicyRuleConjunction(3).fromClause.matches[sourceKey])
	// A separate conjunction can still update the context after the transaction.
	_, err = c.UninstallPolicyRuleFlows(3)
	require.NoError(t, err)
	assert.Empty(t, shared.actions)
	assert.Nil(t, shared.flow)
	require.NotNil(t, shared.dropFlow, "deny-all rule must keep isolation even without conjunction actions")
	ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	_, err = c.ReconcilePolicyRuleFlows([]uint32{2}, nil)
	require.NoError(t, err)
	assert.Empty(t, f.globalConjMatchFlowCache)
}

func TestReconcilePolicyRuleFlowsMultipleGroups(t *testing.T) {
	c, ops := newReconcileTestClient(t)
	f := c.featureNetworkPolicy
	first := reconcileTestRule(1, v1beta2.DirectionIn, v1beta2.ProtocolTCP, 80, false)
	second := reconcileTestRule(2, v1beta2.DirectionIn, v1beta2.ProtocolTCP, 443, false)
	second.To = []types.Address{NewOFPortAddress(2)}
	require.NoError(t, c.InstallPolicyRuleFlows(first))
	require.NoError(t, c.InstallPolicyRuleFlows(second))
	for _, ctx := range f.globalConjMatchFlowCache {
		fillReconcileContext(t, f, ctx)
	}
	// Exchange target Pods between existing service groups. Both destination matches are full.
	nextFirst, nextSecond := *first, *second
	nextFirst.To, nextSecond.To = second.To, first.To
	ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(adds, mods, dels []*openflow15.FlowMod) error {
		assert.Empty(t, adds)
		assert.Empty(t, dels)
		assert.Len(t, mods, 2, "only the two destination match flows should change")
		return nil
	})
	_, err := c.ReconcilePolicyRuleFlows([]uint32{1, 2}, []*types.PolicyRule{&nextFirst, &nextSecond})
	require.NoError(t, err)
	for _, rule := range []*types.PolicyRule{&nextFirst, &nextSecond} {
		key := generateAddressConjMatch(rule.TableID, rule.To[0], types.DstAddress, nil).generateGlobalMapKey()
		assert.Contains(t, f.globalConjMatchFlowCache[key].actions, rule.FlowID)
		assert.Len(t, f.globalConjMatchFlowCache[key].actions, maxActionsPerConjMatchFlow)
	}
}

func TestReconcilePolicyRuleFlowsSpecialMatches(t *testing.T) {
	for _, kind := range []string{"logging", "multicluster", "L7", "duplicate addresses and services", "Service group", "CIDR and port range"} {
		t.Run(kind, func(t *testing.T) {
			c, ops := newReconcileTestClient(t)
			f := c.featureNetworkPolicy
			old := reconcileTestRule(1, v1beta2.DirectionIn, v1beta2.ProtocolTCP, 80, false)
			switch kind {
			case "multicluster":
				old.From = []types.Address{NewLabelIDAddress(100)}
				old.PolicyRef.Type = v1beta2.AntreaClusterNetworkPolicy
				old.Action = &actionAllow
				priority := uint16(1000)
				old.Priority = &priority
				old.TableID = AntreaPolicyIngressRuleTable.GetID()
			case "L7":
				vlan := uint32(100)
				old.L7RuleVlanID = &vlan
			case "duplicate addresses and services":
				old.From = append(old.From, old.From...)
				old.Service = append(old.Service, old.Service...)
			case "Service group":
				old.To = []types.Address{NewServiceGroupIDAddress(123)}
			case "CIDR and port range":
				old.From = parseAddresses([]string{"192.168.1.0/24", "2001:db8::/64"})
				end := int32(85)
				old.Service[0].EndPort = &end
			}
			require.NoError(t, c.InstallPolicyRuleFlows(old))
			replacement := *old
			replacement.FlowID = 2
			if kind == "logging" {
				replacement.EnableLogging = true
			}
			ops.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			_, err := c.ReconcilePolicyRuleFlows([]uint32{1}, []*types.PolicyRule{&replacement})
			require.NoError(t, err)
			actual := replayFlowStrings(f)
			// Compare the final flows with a fresh installation of exactly the desired rule.
			// This exercises the established policy builders as an independent reference.
			resetPipelines()
			other, otherOps := newReconcileTestClient(t)
			require.NoError(t, other.InstallPolicyRuleFlows(&replacement))
			assert.ElementsMatch(t, replayFlowStrings(other.featureNetworkPolicy), actual)
			// A retained rule must remain a no-op for all these match types.
			otherOps.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			_, err = other.ReconcilePolicyRuleFlows([]uint32{2}, []*types.PolicyRule{&replacement})
			require.NoError(t, err)
		})
	}
}
