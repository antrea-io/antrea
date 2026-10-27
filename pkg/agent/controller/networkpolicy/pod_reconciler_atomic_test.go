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

package networkpolicy

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	openflowtest "antrea.io/antrea/v2/pkg/agent/openflow/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/agent/util"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/v2/third_party/proxy"
)

func TestReconcilerAtomicNamedPortUpdate(t *testing.T) {
	for _, direction := range []v1beta2.Direction{v1beta2.DirectionIn, v1beta2.DirectionOut} {
		for _, native := range []bool{false, true} {
			for _, tc := range []struct {
				name  string
				ports []int32
				err   error
			}{
				{name: "replace groups", ports: []int32{9090, 9090}},
				{name: "move to retained group", ports: []int32{8080, 8080}},
				{name: "remove all members"},
				{name: "cap rejection then retry", ports: []int32{9090, 9090}, err: openflow.ErrConjMatchFlowActionsExceeded},
				{name: "bundle rejection then retry", ports: []int32{9090, 9090}, err: errors.New("bundle rejected")},
			} {
				t.Run(fmt.Sprintf("%s/native=%t/%s", direction, native, tc.name), func(t *testing.T) {
					prepareMockTables()
					ctrl := gomock.NewController(t)
					client := openflowtest.NewMockClient(ctrl)
					store := interfacestore.NewInterfaceStore()
					for i, name := range []string{"pod1", "pod2"} {
						store.AddInterface(&interfacestore.InterfaceConfig{
							InterfaceName:            util.GenerateContainerInterfaceName(name, "ns1", name),
							IPs:                      []net.IP{net.ParseIP(fmt.Sprintf("2.2.2.%d", i+1)), net.ParseIP(fmt.Sprintf("2001:db8::%d", i+1))},
							ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: name, PodNamespace: "ns1", ContainerID: name},
							OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: int32(i + 1)},
						})
					}
					r := newTestReconciler(t, ctrl, store, client, true, true)
					defer r.idAllocator.deleteQueue.ShutDown()
					makeRule := func(ports []int32) *CompletedRule {
						ref := &np1
						if native {
							ref = &cnp1
						}
						rule := &CompletedRule{
							rule:          &rule{ID: "named-rule", Name: "http", Direction: direction, Services: []v1beta2.Service{serviceHTTP}, SourceRef: ref},
							FromAddresses: dualAddressGroup1,
							TargetMembers: v1beta2.NewGroupMemberSet(),
							ToAddresses:   v1beta2.NewGroupMemberSet(),
						}
						if native {
							rule.PolicyPriority, rule.TierPriority = &policyPriority, &tierPriority
						}
						for i, port := range ports {
							named := v1beta2.NamedPort{Name: "http", Protocol: protocolTCP, Port: port}
							if direction == v1beta2.DirectionIn {
								rule.TargetMembers.Insert(newAppliedToGroupMemberPod(fmt.Sprintf("pod%d", i+1), "ns1", named))
							} else {
								member := newAddressGroupMember(fmt.Sprintf("1.1.1.%d", i+1), fmt.Sprintf("2001:db9::%d", i+1))
								member.Ports = []v1beta2.NamedPort{named}
								rule.ToAddresses.Insert(member)
							}
						}
						if direction == v1beta2.DirectionOut {
							rule.TargetMembers = appliedToGroup1
						}
						return rule
					}
					original := makeRule([]int32{80, 8080})
					count := 2
					if direction == v1beta2.DirectionOut && !native {
						count++
					}
					client.EXPECT().InstallPolicyRuleFlows(gomock.Any()).Return(nil).Times(count)
					require.NoError(t, r.Reconcile(original))
					value, found := r.lastRealizeds.Load(original.ID)
					require.True(t, found)
					last := value.(*podPolicyLastRealized)
					oldIDs := maps.Clone(last.ofIDs)
					previousIDs := sets.New[uint32]()
					for _, id := range oldIDs {
						previousIDs.Insert(id)
					}
					updated := makeRule(tc.ports)
					var failedIDs []uint32
					var activeIDs []uint32
					var released []string
					if native && len(tc.ports) == 0 {
						for _, id := range oldIDs {
							cached, exists, err := r.GetRuleByFlowID(id)
							require.NoError(t, err)
							require.True(t, exists)
							released = []string{strconv.Itoa(int(*cached.Priority))}
							break
						}
					}
					checkDesired := func(ids []uint32, desired []*types.PolicyRule) {
						assert.Equal(t, previousIDs, sets.New(ids...))
						expectedGroups := 1
						if len(tc.ports) == 0 {
							expectedGroups = 0
						}
						if direction == v1beta2.DirectionOut && !native {
							expectedGroups++
						}
						require.Len(t, desired, expectedGroups)
						for _, ofRule := range desired {
							assert.Equal(t, "http", ofRule.Name)
							assert.Equal(t, updated.SourceRef, ofRule.PolicyRef)
							if native {
								require.NotNil(t, ofRule.Priority)
							} else {
								assert.Nil(t, ofRule.Priority)
							}
							// Unresolvable named ports are filtered out in the original egress isolation group.
							key := normalizeServices(ofRule.Service)
							if len(ofRule.Service) == 0 {
								key = normalizeServices(updated.Services)
							}
							if oldID, retained := oldIDs[key]; retained {
								assert.Equal(t, oldID, ofRule.FlowID)
							}
							if direction == v1beta2.DirectionOut {
								assert.Len(t, ofRule.From, 2, "dual-stack sources must be preserved")
							}
						}
					}
					if tc.err != nil {
						client.EXPECT().ReconcilePolicyRuleFlows(gomock.Any(), gomock.Any()).DoAndReturn(func(ids []uint32, desired []*types.PolicyRule) ([]string, error) {
							checkDesired(ids, desired)
							for _, ofRule := range desired {
								if !previousIDs.Has(ofRule.FlowID) {
									failedIDs = append(failedIDs, ofRule.FlowID)
								}
							}
							return nil, tc.err
						})
						require.ErrorIs(t, r.Reconcile(updated), tc.err)
						assert.Same(t, original, last.CompletedRule)
						assert.Equal(t, oldIDs, last.ofIDs, "failed transaction must preserve all previous service groups")
					}
					client.EXPECT().ReconcilePolicyRuleFlows(gomock.Any(), gomock.Any()).DoAndReturn(func(ids []uint32, desired []*types.PolicyRule) ([]string, error) {
						checkDesired(ids, desired)
						for _, ofRule := range desired {
							activeIDs = append(activeIDs, ofRule.FlowID)
						}
						return released, nil
					})
					require.NoError(t, r.Reconcile(updated))
					assert.Same(t, updated, last.CompletedRule)
					require.Len(t, last.ofIDs, len(activeIDs))
					// Deliver obsolete IDs' delayed cleanup immediately and ensure it cannot remove live rules.
					obsolete := append([]uint32(nil), failedIDs...)
					for key, id := range oldIDs {
						if _, retained := last.ofIDs[key]; !retained {
							obsolete = append(obsolete, id)
						}
					}
					for _, id := range obsolete {
						r.idAllocator.deleteQueue.Add(id)
						require.True(t, r.idAllocator.processDeleteQueueItem())
						_, exists, err := r.GetRuleByFlowID(id)
						require.NoError(t, err)
						assert.False(t, exists)
					}
					for _, id := range activeIDs {
						cached, exists, err := r.GetRuleByFlowID(id)
						require.NoError(t, err)
						require.True(t, exists, "live ID %d must survive failed-attempt cleanup", id)
						assert.Equal(t, id, cached.FlowID)
						if native {
							assert.Contains(t, r.priorityAssigners[r.getOFRuleTable(updated)].assigner.ofPriorityMap, *cached.Priority)
						}
					}
					if len(released) > 0 {
						assert.Empty(t, r.priorityAssigners[r.getOFRuleTable(updated)].assigner.ofPriorityMap)
					}
					// Resyncing the resulting groups, including empty native policies, needs no Openflow calls.
					require.NoError(t, r.Reconcile(makeRule(tc.ports)))
				})
			}
		}
	}
}

func TestReconcilerNamedPortIncrementalUpdate(t *testing.T) {
	for _, direction := range []v1beta2.Direction{v1beta2.DirectionIn, v1beta2.DirectionOut} {
		for _, native := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/native=%t", direction, native), func(t *testing.T) {
				prepareMockTables()
				ctrl := gomock.NewController(t)
				client := openflowtest.NewMockClient(ctrl)
				store := interfacestore.NewInterfaceStore()
				for i := 1; i <= 3; i++ {
					name := fmt.Sprintf("pod%d", i)
					store.AddInterface(&interfacestore.InterfaceConfig{
						InterfaceName:            util.GenerateContainerInterfaceName(name, "ns1", name),
						IPs:                      []net.IP{net.ParseIP(fmt.Sprintf("2.2.2.%d", i))},
						ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: name, PodNamespace: "ns1", ContainerID: name},
						OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: int32(i)},
					})
				}
				r := newTestReconciler(t, ctrl, store, client, true, true)
				defer r.idAllocator.deleteQueue.ShutDown()
				named := v1beta2.NamedPort{Name: "http", Protocol: protocolTCP, Port: 80}
				peers := v1beta2.NewGroupMemberSet()
				for i := 0; i < 10000; i++ {
					member := newAddressGroupMember(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
					member.Ports = []v1beta2.NamedPort{named}
					peers.Insert(member)
				}
				original := &CompletedRule{
					rule: &rule{ID: "incremental-rule", Direction: direction, Services: []v1beta2.Service{serviceHTTP}, SourceRef: &np1},
					TargetMembers: v1beta2.NewGroupMemberSet(
						newAppliedToGroupMemberPod("pod1", "ns1", named), newAppliedToGroupMemberPod("pod2", "ns1", named)),
				}
				if native {
					original.SourceRef = &cnp1
					original.PolicyPriority, original.TierPriority = &policyPriority, &tierPriority
				}
				if direction == v1beta2.DirectionIn {
					original.FromAddresses = peers
				} else {
					original.ToAddresses = peers
				}
				installed := map[uint32]*types.PolicyRule{}
				count := 1
				if direction == v1beta2.DirectionOut && !native {
					count++
				}
				client.EXPECT().InstallPolicyRuleFlows(gomock.Any()).DoAndReturn(func(ofRule *types.PolicyRule) error {
					installed[ofRule.FlowID] = ofRule
					return nil
				}).Times(count)
				require.NoError(t, r.Reconcile(original))
				value, found := r.lastRealizeds.Load(original.ID)
				require.True(t, found)
				last := value.(*podPolicyLastRealized)
				oldIDs := maps.Clone(last.ofIDs)
				// With 10k peers, even a no-op transaction would copy thousands of shared action maps.
				// No ReconcilePolicyRuleFlows call is expected anywhere below.
				require.NoError(t, r.Reconcile(original))

				updated := *original
				updated.TargetMembers = maps.Clone(original.TargetMembers)
				updated.TargetMembers.Insert(newAppliedToGroupMemberPod("pod3", "ns1", named))
				updated.TargetMembers.Delete(newAppliedToGroupMemberPod("pod1", "ns1", named))
				addressType := types.DstAddress
				addedAddresses := []types.Address{openflow.NewOFPortAddress(3)}
				deletedAddresses := []types.Address{openflow.NewOFPortAddress(1)}
				if direction == v1beta2.DirectionOut {
					addressType = types.SrcAddress
					addedAddresses = []types.Address{openflow.NewIPAddress(net.ParseIP("2.2.2.3"))}
					deletedAddresses = []types.Address{openflow.NewIPAddress(net.ParseIP("2.2.2.1"))}
				}
				for id, ofRule := range installed {
					client.EXPECT().AddPolicyRuleAddress(id, addressType, addedAddresses, ofRule.Priority, false, false).Return(nil)
					client.EXPECT().DeletePolicyRuleAddress(id, addressType, deletedAddresses, ofRule.Priority).Return(nil)
				}
				require.NoError(t, r.Reconcile(&updated))
				assert.Equal(t, oldIDs, last.ofIDs)
				require.NoError(t, r.Reconcile(&updated))

				peerUpdate := updated
				newPeers := maps.Clone(peers)
				newPeers.Delete(newAddressGroupMember("10.0.0.0"))
				newPeer := newAddressGroupMember("10.1.0.1")
				newPeer.Ports = []v1beta2.NamedPort{named}
				newPeers.Insert(newPeer)
				addressType = types.SrcAddress
				if direction == v1beta2.DirectionIn {
					peerUpdate.FromAddresses = newPeers
				} else {
					peerUpdate.ToAddresses = newPeers
					addressType = types.DstAddress
				}
				for id, ofRule := range installed {
					if len(ofRule.Service) == 0 {
						continue // The original egress isolation group has no resolved peers.
					}
					client.EXPECT().AddPolicyRuleAddress(id, addressType, []types.Address{openflow.NewIPAddress(net.ParseIP("10.1.0.1"))}, ofRule.Priority, false, false).Return(nil)
					client.EXPECT().DeletePolicyRuleAddress(id, addressType, []types.Address{openflow.NewIPAddress(net.ParseIP("10.0.0.0"))}, ofRule.Priority).Return(nil)
				}
				require.NoError(t, r.Reconcile(&peerUpdate))
				assert.Equal(t, oldIDs, last.ofIDs)
				require.NoError(t, r.Reconcile(&peerUpdate))
				assert.Zero(t, r.idAllocator.deleteQueue.Len(), "incremental updates must not replace rule IDs")
			})
		}
	}
}

func TestReconcilerNamedPortPeerTypes(t *testing.T) {
	for _, kind := range []string{"IPBlock", "FQDN", "ToServices", "Multicluster", "L7"} {
		t.Run(kind, func(t *testing.T) {
			prepareMockTables()
			ctrl := gomock.NewController(t)
			client := openflowtest.NewMockClient(ctrl)
			store := interfacestore.NewInterfaceStore()
			store.AddInterface(&interfacestore.InterfaceConfig{
				InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
				IPs:                      []net.IP{net.ParseIP("2.2.2.2")},
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
				OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
			})
			r := newTestReconciler(t, ctrl, store, client, true, true)
			defer r.idAllocator.deleteQueue.ShutDown()
			ingress := kind == "Multicluster" || kind == "L7"
			makeRule := func(port int32) *CompletedRule {
				rule := &CompletedRule{
					rule: &rule{ID: "special-rule", Direction: v1beta2.DirectionOut, Name: "http", Services: []v1beta2.Service{serviceHTTP, serviceTCP443},
						SourceRef: &cnp1, PolicyPriority: &policyPriority, TierPriority: &tierPriority},
					TargetMembers: appliedToGroup1,
				}
				named := v1beta2.NamedPort{Name: "http", Protocol: protocolTCP, Port: port}
				if ingress {
					rule.Direction = v1beta2.DirectionIn
					rule.TargetMembers = v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1", named))
					rule.FromAddresses = addressGroup1
				} else {
					member := newAddressGroupMember("1.1.1.1")
					member.Ports = []v1beta2.NamedPort{named}
					rule.ToAddresses = v1beta2.NewGroupMemberSet(member)
				}
				switch kind {
				case "IPBlock":
					rule.To.IPBlocks = []v1beta2.IPBlock{{CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(net.ParseIP("10.10.0.0")), PrefixLength: 16}}}
				case "FQDN":
					rule.To.FQDNs = []string{"test.antrea.io"}
				case "ToServices":
					rule.To.ToServices = []v1beta2.ServiceReference{{Namespace: "ns1", Name: "svc1"}}
				case "Multicluster":
					rule.From.LabelIdentities = []uint32{100}
				case "L7":
					vlan := uint32(100)
					rule.L7RuleVlanID = &vlan
					rule.L7Protocols = []v1beta2.L7Protocol{{HTTP: &v1beta2.HTTPProtocol{Host: "example.com"}}}
				}
				return rule
			}
			original := makeRule(80)
			if kind == "FQDN" {
				f, dnsClient := newMockFQDNController(t, ctrl, nil, nil, 0)
				r.fqdnController = f
				dnsClient.EXPECT().AddAddressToDNSConjunction(gomock.Any(), gomock.Any()).Return(nil)
				f.addFQDNSelector(original.ID, original.To.FQDNs)
				resolveFQDNForTest(f, "test.antrea.io", dnsMeta{responseIPs: map[string]ipWithExpiration{"10.20.0.1": {ip: net.ParseIP("10.20.0.1")}}})
			}
			if kind == "ToServices" {
				for _, counter := range r.groupCounters {
					counter.AllocateIfNotExist(proxy.ServicePortName{NamespacedName: k8stypes.NamespacedName{Namespace: "ns1", Name: "svc1"}, Port: "http", Protocol: v1.ProtocolTCP}, true)
				}
			}
			count := 2
			if ingress {
				count = 1
			}
			checkRule := func(t *testing.T, ofRule *types.PolicyRule) {
				t.Helper()
				require.NotNil(t, ofRule.Priority, "every Antrea policy group must keep its priority")
				expectedPriority, registered := r.priorityAssigners[r.getOFRuleTable(original)].assigner.getOFPriority(types.Priority{
					TierPriority: tierPriority, PolicyPriority: policyPriority, RulePriority: original.Priority,
				})
				require.True(t, registered)
				assert.Equal(t, expectedPriority, *ofRule.Priority)
				if ingress {
					if kind == "Multicluster" {
						assert.Contains(t, ofRule.From, openflow.NewLabelIDAddress(100))
					}
					if kind == "L7" {
						assert.Equal(t, original.L7Protocols, ofRule.L7Protocols)
						assert.Equal(t, original.L7RuleVlanID, ofRule.L7RuleVlanID)
					}
				} else if len(ofRule.Service) == 1 {
					assert.Equal(t, []v1beta2.Service{serviceTCP443}, ofRule.Service)
					switch kind {
					case "IPBlock":
						assert.Contains(t, ofRule.To, openflow.NewIPNetAddress(*newCIDR("10.10.0.0/16")))
					case "FQDN":
						assert.Contains(t, ofRule.To, openflow.NewIPAddress(net.ParseIP("10.20.0.1")))
					case "ToServices":
						assert.Contains(t, ofRule.To, openflow.NewServiceGroupIDAddress(1))
					}
				}
			}
			t.Run("add", func(t *testing.T) {
				client.EXPECT().InstallPolicyRuleFlows(gomock.Any()).DoAndReturn(func(ofRule *types.PolicyRule) error {
					checkRule(t, ofRule)
					return nil
				}).Times(count)
				require.NoError(t, r.Reconcile(original))
			})
			t.Run("update", func(t *testing.T) {
				client.EXPECT().ReconcilePolicyRuleFlows(gomock.Any(), gomock.Any()).DoAndReturn(func(previous []uint32, desired []*types.PolicyRule) ([]string, error) {
					require.Len(t, previous, count)
					require.Len(t, desired, count)
					for _, ofRule := range desired {
						checkRule(t, ofRule)
					}
					return nil, nil
				})
				require.NoError(t, r.Reconcile(makeRule(8080)))
			})
		})
	}
}
