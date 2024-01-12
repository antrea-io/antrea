// Copyright 2019 Antrea Authors
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
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/third_party/proxy"
)

var (
	addressGroup1     = v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))
	addressGroup2     = v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.2"))
	ipv6AddressGroup1 = v1beta2.NewGroupMemberSet(newAddressGroupMember("2002:1a23:fb44::1"))
	dualAddressGroup1 = v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1", "2002:1a23:fb44::1"))

	appliedToGroup1                     = v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))
	appliedToGroup2                     = v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod2", "ns1"))
	appliedToGroup3                     = v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod4", "ns1"))
	appliedToGroupWithSameContainerPort = v1beta2.NewGroupMemberSet(
		newAppliedToGroupMemberPod("pod1", "ns1", v1beta2.NamedPort{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 80}),
		newAppliedToGroupMemberPod("pod3", "ns1", v1beta2.NamedPort{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 80}),
	)
	appliedToGroupWithDiffContainerPort = v1beta2.NewGroupMemberSet(
		newAppliedToGroupMemberPod("pod1", "ns1", v1beta2.NamedPort{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 80}),
		newAppliedToGroupMemberPod("pod3", "ns1", v1beta2.NamedPort{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 443}),
	)
	appliedToGroupWithSingleContainerPort = v1beta2.NewGroupMemberSet(
		newAppliedToGroupMemberPod("pod1", "ns1", v1beta2.NamedPort{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 80}))

	protocolTCP = v1beta2.ProtocolTCP

	port80    = intstr.FromInt(80)
	port443   = intstr.FromInt(443)
	port8080  = intstr.FromInt(8080)
	portHTTP  = intstr.FromString("http")
	portHTTPS = intstr.FromString("https")

	serviceTCP80          = v1beta2.Service{Protocol: &protocolTCP, Port: &port80}
	serviceTCP443         = v1beta2.Service{Protocol: &protocolTCP, Port: &port443}
	serviceTCP8080        = v1beta2.Service{Protocol: &protocolTCP, Port: &port8080}
	serviceTCP            = v1beta2.Service{Protocol: &protocolTCP}
	serviceHTTPNoProtocol = v1beta2.Service{Port: &portHTTP}
	serviceHTTP           = v1beta2.Service{Protocol: &protocolTCP, Port: &portHTTP}
	serviceHTTPS          = v1beta2.Service{Protocol: &protocolTCP, Port: &portHTTPS}

	services1    = []v1beta2.Service{serviceTCP80}
	servicesKey1 = normalizeServices(services1)
	services2    = []v1beta2.Service{serviceTCP}
	servicesKey2 = normalizeServices(services2)

	policyPriority = float64(1)
	tierPriority   = int32(1)

	np1 = v1beta2.NetworkPolicyReference{
		Type:      v1beta2.K8sNetworkPolicy,
		Namespace: "ns1",
		Name:      "name1",
		UID:       "uid1",
	}
	cnp1 = v1beta2.NetworkPolicyReference{
		Type: v1beta2.AntreaClusterNetworkPolicy,
		Name: "name1",
		UID:  "uid1",
	}
	anp1 = v1beta2.NetworkPolicyReference{
		Type: v1beta2.AdminNetworkPolicy,
		Name: "anp1",
		UID:  "uid2",
	}

	transientError = errors.New("Transient OVS error")
)

func newCIDR(cidrStr string) *net.IPNet {
	_, tmpIPNet, _ := net.ParseCIDR(cidrStr)
	return tmpIPNet
}

func newTestReconciler(t *testing.T, controller *gomock.Controller, ifaceStore interfacestore.InterfaceStore, ofClient *openflowtest.MockClient, v4Enabled, v6Enabled bool) *podReconciler {
	f, _ := newMockFQDNController(t, controller, nil)
	ch := make(chan string, 100)
	groupIDAllocator := openflow.NewGroupAllocator()
	groupCounters := []proxytypes.GroupCounter{proxytypes.NewGroupCounter(groupIDAllocator, ch)}
	r := newPodReconciler(ofClient, ifaceStore, newIDAllocator(testAsyncDeleteInterval), f, groupCounters, v4Enabled, v6Enabled, true, false)
	return r
}

func TestReconcilerForget(t *testing.T) {
	prepareMockTables()
	tests := []struct {
		name              string
		lastRealizeds     map[string]*podPolicyLastRealized
		args              string
		expectedOFRuleIDs []uint32
		wantErr           bool
	}{
		{
			"unknown-rule",
			map[string]*podPolicyLastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta2.DirectionIn, SourceRef: &np1},
					},
				},
			},
			"unknown-rule-id",
			nil,
			false,
		},
		{
			"known-single-ofrule",
			map[string]*podPolicyLastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta2.DirectionIn, SourceRef: &np1},
					},
				},
			},
			"foo",
			[]uint32{8},
			false,
		},
		{
			"known-multiple-ofrule",
			map[string]*podPolicyLastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8, servicesKey2: 9},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta2.DirectionIn, SourceRef: &np1},
					},
				},
			},
			"foo",
			[]uint32{8, 9},
			false,
		},
		{
			"known-multiple-ofrule-cnp",
			map[string]*podPolicyLastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8, servicesKey2: 9},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, SourceRef: &cnp1},
					},
				},
			},
			"foo",
			[]uint32{8, 9},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			ifaceStore := interfacestore.NewInterfaceStore()
			mockOFClient := openflowtest.NewMockClient(controller)
			if len(tt.expectedOFRuleIDs) == 0 {
				mockOFClient.EXPECT().UninstallPolicyRuleFlows(gomock.Any()).Times(0)
			} else {
				for _, ofID := range tt.expectedOFRuleIDs {
					mockOFClient.EXPECT().UninstallPolicyRuleFlows(ofID)
				}
			}
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, false)
			for key, value := range tt.lastRealizeds {
				r.lastRealizeds.Store(key, value)
			}
			if err := r.Forget(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("Forget() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReconcilerReconcile(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IPs:                      []net.IP{net.ParseIP("2.2.2.2")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
		IPs:                      []net.IP{net.ParseIP("3.3.3.3")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	ipNet1 := newCIDR("10.10.0.0/16")
	ipNet2 := newCIDR("10.20.0.0/16")
	ipNet3 := newCIDR("10.20.1.0/24")
	ipNet4 := newCIDR("10.20.2.0/28")
	ipNet5 := newCIDR("234.10.10.100/32")
	diffNet1 := newCIDR("10.20.128.0/17")
	diffNet2 := newCIDR("10.20.64.0/18")
	diffNet3 := newCIDR("10.20.32.0/19")
	diffNet4 := newCIDR("10.20.16.0/20")
	diffNet5 := newCIDR("10.20.8.0/21")
	diffNet6 := newCIDR("10.20.4.0/22")
	diffNet7 := newCIDR("10.20.0.0/24")
	diffNet8 := newCIDR("10.20.3.0/24")
	diffNet9 := newCIDR("10.20.2.128/25")
	diffNet10 := newCIDR("10.20.2.64/26")
	diffNet11 := newCIDR("10.20.2.32/27")
	diffNet12 := newCIDR("10.20.2.16/28")

	ipBlock1 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet1.IP), PrefixLength: 16},
	}
	ipBlock2 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet2.IP), PrefixLength: 16},
		Except: []v1beta2.IPNet{
			{IP: v1beta2.IPAddress(ipNet3.IP), PrefixLength: 24},
			{IP: v1beta2.IPAddress(ipNet4.IP), PrefixLength: 28},
		},
	}
	ipBlock3 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet5.IP), PrefixLength: 32},
	}

	tests := []struct {
		name            string
		args            *CompletedRule
		expectedOFRules []*types.PolicyRule
		wantErr         bool
	}{
		{
			"ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, Services: []v1beta2.Service{serviceTCP80, serviceTCP}, SourceRef: &np1},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1")),
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-missing-ofport",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup2,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From:      v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2}},
					Services:  []v1beta2.Service{serviceTCP80, serviceTCP},
					SourceRef: &np1,
				},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From: []types.Address{
						openflow.NewIPAddress(net.ParseIP("1.1.1.1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
					},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-no-ports",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-unresolvable-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-same-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithSameContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1, 3)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-namedport-no-protocol",
			&CompletedRule{
				rule: &rule{
					ID:             "ingress-rule",
					Direction:      v1beta2.DirectionIn,
					Services:       []v1beta2.Service{serviceHTTPNoProtocol},
					SourceRef:      &anp1,
					TierPriority:   &tierPriority,
					PolicyPriority: &policyPriority,
					Priority:       1,
				},
				TargetMembers: appliedToGroupWithSameContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1, 3)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &anp1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-diff-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithDiffContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](3)),
					Service:   []v1beta2.Service{serviceTCP443},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-deny-all",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-label-identity",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From:      v1beta2.NetworkPolicyPeer{LabelIdentities: []uint32{1}},
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      labelIDToOFAddresses([]uint32{1}),
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				FromAddresses: nil,
				ToAddresses:   addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
					To:        ipsToOFAddresses(sets.New[string]("1.1.1.1")),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To:        v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2}},
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
					To: []types.Address{
						openflow.NewIPAddress(net.ParseIP("1.1.1.1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-deny-all",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-for-mcast-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To:        v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock3}},
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
					To: []types.Address{
						openflow.NewIPNetAddress(*ipNet5),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(controller)
			// TODO: mock idAllocator and priorityAssigner
			for i := 0; i < len(tt.expectedOFRules); i++ {
				mockOFClient.EXPECT().InstallPolicyRuleFlows(newPolicyRulesMatcher(tt.expectedOFRules[i]))
			}
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, false)
			if err := r.Reconcile(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReconcilerReconcileServiceRelatedRule(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IPs:                      []net.IP{net.ParseIP("1.1.1.1")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})

	ipNet := newCIDR("10.10.0.0/16")
	ipBlock := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet.IP), PrefixLength: 16},
	}

	svc1Ref := v1beta2.ServiceReference{
		Name:      "svc1",
		Namespace: "ns1",
	}
	svc2Ref := v1beta2.ServiceReference{
		Name:      "svc2",
		Namespace: "ns2",
	}

	appliedToGroupWithServices := v1beta2.NewGroupMemberSet(
		newAppliedToGroupMemberService(svc1Ref.Name, svc1Ref.Namespace),
		newAppliedToGroupMemberService(svc2Ref.Name, svc2Ref.Namespace),
	)

	svc1PortName := proxy.ServicePortName{
		NamespacedName: k8stypes.NamespacedName{
			Namespace: svc1Ref.Namespace,
			Name:      svc1Ref.Name,
		},
		Port:     "80",
		Protocol: v1.ProtocolTCP,
	}
	svc2PortName := proxy.ServicePortName{
		NamespacedName: k8stypes.NamespacedName{
			Namespace: svc2Ref.Namespace,
			Name:      svc2Ref.Name,
		},
		Port:     "80",
		Protocol: v1.ProtocolTCP,
	}

	tests := []struct {
		name            string
		completeRule    *CompletedRule
		existSvc        []proxy.ServicePortName
		expectedOFRules []*types.PolicyRule
		wantErr         bool
	}{
		{
			"applied-to-services-no-exist",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From: v1beta2.NetworkPolicyPeer{
						IPBlocks: []v1beta2.IPBlock{ipBlock},
					},
					Services:  nil,
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithServices,
			},
			[]proxy.ServicePortName{},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{openflow.NewCTIPNetAddress(*ipNet)},
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"applied-to-services-one-exist",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From: v1beta2.NetworkPolicyPeer{
						IPBlocks: []v1beta2.IPBlock{ipBlock},
					},
					Services:  nil,
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithServices,
			},
			[]proxy.ServicePortName{
				svc1PortName,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{openflow.NewCTIPNetAddress(*ipNet)},
					To: []types.Address{
						openflow.NewServiceGroupIDAddress(1),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"applied-to-services-all-exist",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From: v1beta2.NetworkPolicyPeer{
						IPBlocks: []v1beta2.IPBlock{ipBlock},
					},
					Services:  nil,
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithServices,
			},
			[]proxy.ServicePortName{
				svc1PortName,
				svc2PortName,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{openflow.NewCTIPNetAddress(*ipNet)},
					To: []types.Address{
						openflow.NewServiceGroupIDAddress(1),
						openflow.NewServiceGroupIDAddress(2),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"to-services-no-exist",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To: v1beta2.NetworkPolicyPeer{
						ToServices: []v1beta2.ServiceReference{svc1Ref, svc2Ref},
					},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]proxy.ServicePortName{},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"to-services-one-exist",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To: v1beta2.NetworkPolicyPeer{
						ToServices: []v1beta2.ServiceReference{svc1Ref, svc2Ref},
					},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]proxy.ServicePortName{svc1PortName},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1")),
					To: []types.Address{
						openflow.NewServiceGroupIDAddress(1),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"to-services-all-exist",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To: v1beta2.NetworkPolicyPeer{
						ToServices: []v1beta2.ServiceReference{svc1Ref, svc2Ref},
					},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]proxy.ServicePortName{svc1PortName, svc2PortName},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1")),
					To: []types.Address{
						openflow.NewServiceGroupIDAddress(1),
						openflow.NewServiceGroupIDAddress(2),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(controller)
			// TODO: mock idAllocator and priorityAssigner
			for i := 0; i < len(tt.expectedOFRules); i++ {
				mockOFClient.EXPECT().InstallPolicyRuleFlows(newPolicyRulesMatcher(tt.expectedOFRules[i]))
			}
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, false)
			for _, counter := range r.groupCounters {
				for _, svc := range tt.existSvc {
					counter.AllocateIfNotExist(svc, true)
				}
			}
			if err := r.Reconcile(tt.completeRule); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestReconcileWithTransientError ensures the podReconciler can reconcile a rule properly after the first attempt meets
// transient error.
// The input rule is an egress rule with named port, applying to 3 Pods and 1 IPBlock. The first 2 Pods have different
// port numbers for the named port and the 3rd Pod cannot resolve it.
// The first reconciling is supposed to fail without any openflow IDs persisted.
// The second reconciling is supposed to succeed with proper PolicyRules installed and all openflow IDs persisted.
// The third reconciling is supposed to do nothing.
func TestReconcileWithTransientError(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
			IPs:                      []net.IP{net.ParseIP("2.2.2.2")},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1}})

	ipNet := *newCIDR("10.10.0.0/16")
	ipBlock := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet.IP), PrefixLength: 16},
	}
	// The 3 pods should result in 3 PolicyRules.
	// The IPBlock should be in the same PolicyRule as member3 as they cannot resolve the named port.
	member1 := &v1beta2.GroupMember{
		IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.1"))},
		Ports: []v1beta2.NamedPort{{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 80}},
	}
	member2 := &v1beta2.GroupMember{
		IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.2"))},
		Ports: []v1beta2.NamedPort{{Name: "http", Protocol: v1beta2.ProtocolTCP, Port: 443}},
	}
	member3 := &v1beta2.GroupMember{
		IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.3"))},
	}

	egressRule := &CompletedRule{
		rule: &rule{
			ID:        "egress-rule",
			Direction: v1beta2.DirectionOut,
			SourceRef: &np1,
			Services:  []v1beta2.Service{serviceHTTP, serviceTCP8080},
			To: v1beta2.NetworkPolicyPeer{
				IPBlocks: []v1beta2.IPBlock{ipBlock},
			},
		},
		ToAddresses:   v1beta2.NewGroupMemberSet(member1, member2, member3),
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")),
	}

	controller := gomock.NewController(t)
	mockOFClient := openflowtest.NewMockClient(controller)
	r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, true)
	// Set deleteInterval to verify openflow ID is released immediately.
	r.idAllocator.deleteInterval = 0

	// Make the first call fail.
	mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any()).Return(transientError).Times(1)
	err := r.Reconcile(egressRule)
	assert.Error(t, err)
	// Ensure the openflow ID is not persistent in podPolicyLastRealized and is released to idAllocator upon error.
	value, exists := r.lastRealizeds.Load(egressRule.ID)
	assert.True(t, exists)
	assert.Empty(t, value.(*podPolicyLastRealized).ofIDs)
	assert.Equal(t, 1, r.idAllocator.deleteQueue.Len())

	// Make the second call success.
	// The following PolicyRules are expected to be installed.
	policyRules := []*types.PolicyRule{
		{
			Direction: v1beta2.DirectionOut,
			From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			To:        ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			Service:   []v1beta2.Service{serviceTCP80, serviceTCP8080},
			PolicyRef: &np1,
			TableID:   openflow.EgressRuleTable.GetID(),
		},
		{
			Direction: v1beta2.DirectionOut,
			From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			To:        ipsToOFAddresses(sets.New[string]("1.1.1.2")),
			Service:   []v1beta2.Service{serviceTCP443, serviceTCP8080},
			PolicyRef: &np1,
			TableID:   openflow.EgressRuleTable.GetID(),
		},
		{
			Direction: v1beta2.DirectionOut,
			From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			To:        append(ipsToOFAddresses(sets.New[string]("1.1.1.3")), openflow.NewIPNetAddress(ipNet)),
			Service:   []v1beta2.Service{serviceTCP8080},
			PolicyRef: &np1,
			TableID:   openflow.EgressRuleTable.GetID(),
		},
	}
	for _, policyRule := range policyRules {
		mockOFClient.EXPECT().InstallPolicyRuleFlows(newPolicyRulesMatcher(policyRule)).Return(nil).Times(1)
	}
	err = r.Reconcile(egressRule)
	assert.NoError(t, err)
	// Ensure the openflow IDs are persistent in podPolicyLastRealized and are not released to idAllocator upon success.
	value, exists = r.lastRealizeds.Load(egressRule.ID)
	assert.True(t, exists)
	assert.Len(t, value.(*podPolicyLastRealized).ofIDs, 3)
	// Ensure the number of released IDs doesn't change.
	assert.Equal(t, 1, r.idAllocator.deleteQueue.Len())

	// Reconciling the same rule should be idempotent.
	err = r.Reconcile(egressRule)
	assert.NoError(t, err)
}

func TestReconcilerBatchReconcile(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IPs:                      []net.IP{net.ParseIP("2.2.2.2")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
		IPs:                      []net.IP{net.ParseIP("3.3.3.3")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	completedRules := []*CompletedRule{
		{
			rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, Services: []v1beta2.Service{serviceTCP80, serviceTCP}, SourceRef: &np1},
			FromAddresses: addressGroup1,
			ToAddresses:   nil,
			TargetMembers: appliedToGroup1,
		},
		{
			rule:          &rule{ID: "ingress-rule-no-ports", Direction: v1beta2.DirectionIn, Services: []v1beta2.Service{}, SourceRef: &np1},
			TargetMembers: appliedToGroup1,
		},
		{
			rule:          &rule{ID: "ingress-rule-diff-named-port", Direction: v1beta2.DirectionIn, Services: []v1beta2.Service{serviceHTTP}, SourceRef: &np1},
			TargetMembers: appliedToGroupWithDiffContainerPort,
		},
		{
			rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
			FromAddresses: nil,
			ToAddresses:   addressGroup1,
			TargetMembers: appliedToGroup1,
		},
	}
	expectedOFRules := []*types.PolicyRule{
		{
			Direction: v1beta2.DirectionIn,
			From:      ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			To:        ofPortsToOFAddresses(sets.New[int32](1)),
			Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
			PolicyRef: &np1,
		},
		{
			Direction: v1beta2.DirectionIn,
			From:      []types.Address{},
			To:        ofPortsToOFAddresses(sets.New[int32](1)),
			Service:   nil,
			PolicyRef: &np1,
		},
		{
			Direction: v1beta2.DirectionIn,
			From:      []types.Address{},
			To:        ofPortsToOFAddresses(sets.New[int32](1)),
			Service:   []v1beta2.Service{serviceTCP80},
			PolicyRef: &np1,
		},
		{
			Direction: v1beta2.DirectionIn,
			From:      []types.Address{},
			To:        ofPortsToOFAddresses(sets.New[int32](3)),
			Service:   []v1beta2.Service{serviceTCP443},
			PolicyRef: &np1,
		},
		{
			Direction: v1beta2.DirectionOut,
			From:      ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			To:        ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			Service:   nil,
			PolicyRef: &np1,
		},
	}
	tests := []struct {
		name              string
		args              []*CompletedRule
		expectedOFRules   []*types.PolicyRule
		numInstalledRules int
		wantErr           bool
	}{
		{
			"batch-install",
			completedRules,
			expectedOFRules,
			0,
			false,
		},
		{
			"batch-install-partial",
			completedRules,
			expectedOFRules,
			1,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(controller)
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, true)
			if tt.numInstalledRules > 0 {
				// BatchInstall should skip rules already installed
				r.lastRealizeds.Store(tt.args[0].ID, newPodPolicyLastRealized(tt.args[0]))
			}
			// TODO: mock idAllocator and priorityAssigner
			mockOFClient.EXPECT().BatchInstallPolicyRuleFlows(gomock.Any()).
				Do(func(rules []*types.PolicyRule) {
					if tt.numInstalledRules == 0 {
						assert.Equalf(t, len(rules), len(tt.expectedOFRules),
							"Expect to install %v flows while %v flows were installed",
							len(tt.expectedOFRules), len(rules))
					} else if tt.numInstalledRules > 0 {
						assert.Equalf(t, len(rules), len(tt.expectedOFRules)-tt.numInstalledRules,
							"Expect to install %v flows while %v flows were installed",
							len(tt.expectedOFRules)-tt.numInstalledRules, len(rules))
					}
				})
			err := r.BatchReconcile(tt.args)
			assert.Equalf(t, err != nil, tt.wantErr, "BatchReconcile() error = %v, wantErr %v", err, tt.wantErr)
		})
	}
}

func TestReconcilerUpdate(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
			IPs:                      []net.IP{net.ParseIP("2.2.2.2")},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1}})
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod2", "ns1", "container2"),
			IPs:                      []net.IP{net.ParseIP("3.3.3.3")},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod2", PodNamespace: "ns1", ContainerID: "container2"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 2}})
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
			IPs:                      []net.IP{net.ParseIP("4.4.4.4")},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3}})
	tests := []struct {
		name                string
		originalRule        *CompletedRule
		updatedRule         *CompletedRule
		expectedAddedFrom   []types.Address
		expectedAddedTo     []types.Address
		expectedDeletedFrom []types.Address
		expectedDeletedTo   []types.Address
		expectUninstall     bool
		isMCNPRule          bool
		wantErr             bool
	}{
		{
			"updating-ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: addressGroup2,
				TargetMembers: appliedToGroup2,
			},
			ipsToOFAddresses(sets.New[string]("1.1.1.2")),
			ofPortsToOFAddresses(sets.New[int32](2)),
			ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			ofPortsToOFAddresses(sets.New[int32](1)),
			false,
			false,
			false,
		},
		{
			"updating-egress-rule",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses:   addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses:   addressGroup2,
				TargetMembers: appliedToGroup2,
			},
			ipsToOFAddresses(sets.New[string]("3.3.3.3")),
			ipsToOFAddresses(sets.New[string]("1.1.1.2")),
			ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			false,
			false,
			false,
		},
		{
			"updating-ingress-rule-with-missing-ofport",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: addressGroup2,
				TargetMembers: appliedToGroup3,
			},
			ipsToOFAddresses(sets.New[string]("1.1.1.2")),
			[]types.Address{},
			ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			ofPortsToOFAddresses(sets.New[int32](1)),
			false,
			false,
			false,
		},
		{
			"updating-egress-rule-with-missing-ip",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses:   addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses:   addressGroup2,
				TargetMembers: appliedToGroup3,
			},
			[]types.Address{},
			ipsToOFAddresses(sets.New[string]("1.1.1.2")),
			ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			false,
			false,
			false,
		},
		{
			"updating-egress-rule-with-duplicate-ip",
			&CompletedRule{
				rule: &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses: v1beta2.NewGroupMemberSet(
					newAddressGroupPodMember("pod1", "ns1", "1.1.1.1"),
					newAddressGroupPodMember("pod2", "ns1", "1.1.1.1"),
					newAddressGroupPodMember("pod3", "ns1", "1.1.1.2"),
					newAddressGroupPodMember("pod4", "ns1", "1.1.1.2"),
					newAddressGroupPodMember("pod5", "ns1", "1.1.1.3"),
					newAddressGroupPodMember("pod6", "ns1", "1.1.1.3"),
					newAddressGroupPodMember("pod7", "ns1", "1.1.1.4"),
				),
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule: &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses: v1beta2.NewGroupMemberSet(
					newAddressGroupPodMember("pod1", "ns1", "1.1.1.1"),
					newAddressGroupPodMember("pod5", "ns1", "1.1.1.5"),
					newAddressGroupPodMember("pod8", "ns1", "1.1.1.4"),
				),
				TargetMembers: appliedToGroup2,
			},
			ipsToOFAddresses(sets.New[string]("3.3.3.3")),
			ipsToOFAddresses(sets.New[string]("1.1.1.5")),
			ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			ipsToOFAddresses(sets.New[string]("1.1.1.2", "1.1.1.3")),
			false,
			false,
			false,
		},
		{
			"updating-egress-rule-deny-all",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				ToAddresses:   nil,
				TargetMembers: appliedToGroup2,
			},
			ipsToOFAddresses(sets.New[string]("3.3.3.3")),
			[]types.Address{},
			ipsToOFAddresses(sets.New[string]("2.2.2.2")),
			[]types.Address{},
			false,
			false,
			false,
		},
		{
			"updating-cnp-ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, SourceRef: &cnp1},
				FromAddresses: addressGroup1,
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, SourceRef: &cnp1},
				FromAddresses: addressGroup2,
				TargetMembers: appliedToGroup2,
			},
			ipsToOFAddresses(sets.New[string]("1.1.1.2")),
			ofPortsToOFAddresses(sets.New[int32](2)),
			ipsToOFAddresses(sets.New[string]("1.1.1.1")),
			ofPortsToOFAddresses(sets.New[int32](1)),
			false,
			false,
			false,
		},
		{
			"updating-cnp-ingress-rule-uninstall",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, Services: []v1beta2.Service{serviceHTTP}, SourceRef: &cnp1},
				FromAddresses: addressGroup1,
				TargetMembers: appliedToGroupWithDiffContainerPort,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, Services: []v1beta2.Service{serviceHTTP}, SourceRef: &cnp1},
				FromAddresses: addressGroup1,
				TargetMembers: appliedToGroupWithSingleContainerPort,
			},
			[]types.Address{},
			[]types.Address{},
			[]types.Address{},
			[]types.Address{},
			true,
			false,
			false,
		},
		{
			"updating-mcnp-ingress",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, From: v1beta2.NetworkPolicyPeer{LabelIdentities: []uint32{1}}, SourceRef: &cnp1},
				TargetMembers: appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, From: v1beta2.NetworkPolicyPeer{LabelIdentities: []uint32{1}}, SourceRef: &cnp1},
				TargetMembers: appliedToGroup2,
			},
			[]types.Address{},
			ofPortsToOFAddresses(sets.New[int32](2)),
			[]types.Address{},
			ofPortsToOFAddresses(sets.New[int32](1)),
			false,
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(controller)
			mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any()).MaxTimes(2)
			priority := gomock.Any()
			if !tt.originalRule.isAntreaNetworkPolicyRule() {
				priority = nil
			}
			if tt.expectUninstall {
				mockOFClient.EXPECT().UninstallPolicyRuleFlows(gomock.Any())
			}
			if len(tt.expectedAddedFrom) > 0 {
				mockOFClient.EXPECT().AddPolicyRuleAddress(gomock.Any(), types.SrcAddress, gomock.InAnyOrder(tt.expectedAddedFrom), priority, false, tt.isMCNPRule)
			}
			if len(tt.expectedAddedTo) > 0 {
				mockOFClient.EXPECT().AddPolicyRuleAddress(gomock.Any(), types.DstAddress, gomock.InAnyOrder(tt.expectedAddedTo), priority, false, tt.isMCNPRule)
			}
			if len(tt.expectedDeletedFrom) > 0 {
				mockOFClient.EXPECT().DeletePolicyRuleAddress(gomock.Any(), types.SrcAddress, gomock.InAnyOrder(tt.expectedDeletedFrom), priority)
			}
			if len(tt.expectedDeletedTo) > 0 {
				mockOFClient.EXPECT().DeletePolicyRuleAddress(gomock.Any(), types.DstAddress, gomock.InAnyOrder(tt.expectedDeletedTo), priority)
			}
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, true)
			if err := r.Reconcile(tt.originalRule); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := r.Reconcile(tt.updatedRule); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGroupMembersByServices(t *testing.T) {
	numberedServices := []v1beta2.Service{serviceTCP80, serviceTCP443}
	numberedServicesKey := normalizeServices(numberedServices)
	namedServices := []v1beta2.Service{serviceHTTP, serviceHTTPS}

	tests := []struct {
		name                     string
		services                 []v1beta2.Service
		members                  v1beta2.GroupMemberSet
		wantMembersByServicesMap map[servicesKey]v1beta2.GroupMemberSet
		wantServicesMap          map[servicesKey][]v1beta2.Service
	}{
		{
			name:     "numbered ports",
			services: numberedServices,
			members: v1beta2.NewGroupMemberSet(
				&v1beta2.GroupMember{
					IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.1"))},
				},
				&v1beta2.GroupMember{
					IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.2"))},
				},
			),
			wantMembersByServicesMap: map[servicesKey]v1beta2.GroupMemberSet{
				numberedServicesKey: v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.1"))},
					},
					&v1beta2.GroupMember{
						IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.2"))},
					},
				),
			},
			wantServicesMap: map[servicesKey][]v1beta2.Service{
				numberedServicesKey: numberedServices,
			},
		},
		{
			name:     "named ports",
			services: namedServices,
			members: v1beta2.NewGroupMemberSet(
				&v1beta2.GroupMember{
					IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.1"))},
					Ports: []v1beta2.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
				},
				&v1beta2.GroupMember{
					IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.2"))},
					Ports: []v1beta2.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
				},
				&v1beta2.GroupMember{
					IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.3"))},
					Ports: []v1beta2.NamedPort{{Port: 8080, Name: "http", Protocol: protocolTCP}},
				},
				&v1beta2.GroupMember{
					IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.4"))},
					Ports: []v1beta2.NamedPort{{Port: 443, Name: "https", Protocol: protocolTCP}},
				},
				&v1beta2.GroupMember{
					IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.5"))},
				},
				&v1beta2.GroupMember{
					IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.6"))},
					Ports: []v1beta2.NamedPort{{Port: 443, Name: "foo", Protocol: protocolTCP}},
				},
			),
			wantMembersByServicesMap: map[servicesKey]v1beta2.GroupMemberSet{
				normalizeServices([]v1beta2.Service{serviceTCP80, serviceHTTPS}): v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.1"))},
						Ports: []v1beta2.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
					},
					&v1beta2.GroupMember{
						IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.2"))},
						Ports: []v1beta2.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
					},
				),
				normalizeServices([]v1beta2.Service{serviceTCP8080, serviceHTTPS}): v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.3"))},
						Ports: []v1beta2.NamedPort{{Port: 8080, Name: "http", Protocol: protocolTCP}},
					},
				),
				normalizeServices([]v1beta2.Service{serviceHTTP, serviceTCP443}): v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.4"))},
						Ports: []v1beta2.NamedPort{{Port: 443, Name: "https", Protocol: protocolTCP}},
					},
				),
				normalizeServices([]v1beta2.Service{serviceHTTP, serviceHTTPS}): v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.5"))},
					},
					&v1beta2.GroupMember{
						IPs:   []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("1.1.1.6"))},
						Ports: []v1beta2.NamedPort{{Port: 443, Name: "foo", Protocol: protocolTCP}},
					},
				),
			},
			wantServicesMap: map[servicesKey][]v1beta2.Service{
				normalizeServices([]v1beta2.Service{serviceTCP80, serviceHTTPS}):   {serviceTCP80, serviceHTTPS},
				normalizeServices([]v1beta2.Service{serviceTCP8080, serviceHTTPS}): {serviceTCP8080, serviceHTTPS},
				normalizeServices([]v1beta2.Service{serviceHTTP, serviceTCP443}):   {serviceHTTP, serviceTCP443},
				normalizeServices([]v1beta2.Service{serviceHTTP, serviceHTTPS}):    {serviceHTTP, serviceHTTPS},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMembersByServicesMap, gotServicesMap := groupMembersByServices(tt.services, tt.members)
			assert.Equal(t, tt.wantMembersByServicesMap, gotMembersByServicesMap)
			assert.Equal(t, tt.wantServicesMap, gotServicesMap)
		})
	}
}

func TestReconcilerReconcileIPv6Only(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IPs:                      []net.IP{net.ParseIP("2002:1a23:fb45::2")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
		IPs:                      []net.IP{net.ParseIP("2002:1a23:fb46::3")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	ipNet1 := newCIDR("2002:1a23:fb46::10:0/112")
	ipNet2 := newCIDR("2002:1a23:fb46::11:0/112")
	ipNet3 := newCIDR("2002:1a23:fb46::11:100/120")
	ipNet4 := newCIDR("2002:1a23:fb46::11:200/124")
	ipNet5 := newCIDR("10.10.0.0/16")
	diffNet1 := newCIDR("2002:1a23:fb46::11:8000/113")
	diffNet2 := newCIDR("2002:1a23:fb46::11:4000/114")
	diffNet3 := newCIDR("2002:1a23:fb46::11:2000/115")
	diffNet4 := newCIDR("2002:1a23:fb46::11:1000/116")
	diffNet5 := newCIDR("2002:1a23:fb46::11:800/117")
	diffNet6 := newCIDR("2002:1a23:fb46::11:400/118")
	diffNet7 := newCIDR("2002:1a23:fb46::11:0/120")
	diffNet8 := newCIDR("2002:1a23:fb46::11:300/120")
	diffNet9 := newCIDR("2002:1a23:fb46::11:280/121")
	diffNet10 := newCIDR("2002:1a23:fb46::11:240/122")
	diffNet11 := newCIDR("2002:1a23:fb46::11:220/123")
	diffNet12 := newCIDR("2002:1a23:fb46::11:210/124")
	diffNet13 := newCIDR("10.10.0.0/24")

	ipBlock1 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet1.IP), PrefixLength: 112},
	}
	ipBlock2 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet2.IP), PrefixLength: 112},
		Except: []v1beta2.IPNet{
			{IP: v1beta2.IPAddress(ipNet3.IP), PrefixLength: 120},
			{IP: v1beta2.IPAddress(ipNet4.IP), PrefixLength: 124},
		},
	}
	ipBlock3 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet5.IP), PrefixLength: 16},
		Except: []v1beta2.IPNet{
			{IP: v1beta2.IPAddress(diffNet13.IP), PrefixLength: 24},
		},
	}

	tests := []struct {
		name            string
		args            *CompletedRule
		expectedOFRules []*types.PolicyRule
		wantErr         bool
	}{
		{
			"ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, Services: []v1beta2.Service{serviceTCP80, serviceTCP}, SourceRef: &np1},
				FromAddresses: ipv6AddressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb44::1")),
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-missing-ofport",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: ipv6AddressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup2,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb44::1")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From:      v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2}},
					Services:  []v1beta2.Service{serviceTCP80, serviceTCP},
					SourceRef: &np1,
				},
				FromAddresses: ipv6AddressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From: []types.Address{
						openflow.NewIPAddress(net.ParseIP("2002:1a23:fb44::1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
					},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-no-ports",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-unresolvable-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-same-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithSameContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1, 3)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-diff-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithDiffContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](3)),
					Service:   []v1beta2.Service{serviceTCP443},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-deny-all",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				FromAddresses: nil,
				ToAddresses:   ipv6AddressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2")),
					To:        ipsToOFAddresses(sets.New[string]("2002:1a23:fb44::1")),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To:        v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2}},
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   ipv6AddressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2")),
					To: []types.Address{
						openflow.NewIPAddress(net.ParseIP("2002:1a23:fb44::1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-deny-all",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-with-dual-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To:        v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2, ipBlock3}},
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   ipv6AddressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2")),
					To: []types.Address{
						openflow.NewIPAddress(net.ParseIP("2002:1a23:fb44::1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(controller)
			// TODO: mock idAllocator and priorityAssigner
			for i := 0; i < len(tt.expectedOFRules); i++ {
				mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any())
			}
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, false, true)
			if err := r.Reconcile(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReconcilerReconcileDualStack(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IPs:                      []net.IP{net.ParseIP("2.2.2.2"), net.ParseIP("2002:1a23:fb45::2")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
		IPs:                      []net.IP{net.ParseIP("3.3.3.3"), net.ParseIP("2002:1a23:fb46::3")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	ipNet1 := newCIDR("2002:1a23:fb46::10:0/112")
	ipNet2 := newCIDR("2002:1a23:fb46::11:0/112")
	ipNet3 := newCIDR("2002:1a23:fb46::11:100/120")
	ipNet4 := newCIDR("2002:1a23:fb46::11:200/124")
	diffNet1 := newCIDR("2002:1a23:fb46::11:8000/113")
	diffNet2 := newCIDR("2002:1a23:fb46::11:4000/114")
	diffNet3 := newCIDR("2002:1a23:fb46::11:2000/115")
	diffNet4 := newCIDR("2002:1a23:fb46::11:1000/116")
	diffNet5 := newCIDR("2002:1a23:fb46::11:800/117")
	diffNet6 := newCIDR("2002:1a23:fb46::11:400/118")
	diffNet7 := newCIDR("2002:1a23:fb46::11:0/120")
	diffNet8 := newCIDR("2002:1a23:fb46::11:300/120")
	diffNet9 := newCIDR("2002:1a23:fb46::11:280/121")
	diffNet10 := newCIDR("2002:1a23:fb46::11:240/122")
	diffNet11 := newCIDR("2002:1a23:fb46::11:220/123")
	diffNet12 := newCIDR("2002:1a23:fb46::11:210/124")
	ipNet5 := newCIDR("10.10.0.0/16")
	ipNet6 := newCIDR("10.20.0.0/16")
	ipNet7 := newCIDR("10.20.1.0/24")
	diffNet13 := newCIDR("10.20.128.0/17")
	diffNet14 := newCIDR("10.20.64.0/18")
	diffNet15 := newCIDR("10.20.32.0/19")
	diffNet16 := newCIDR("10.20.16.0/20")
	diffNet17 := newCIDR("10.20.8.0/21")
	diffNet18 := newCIDR("10.20.4.0/22")
	diffNet19 := newCIDR("10.20.2.0/23")
	diffNet20 := newCIDR("10.20.0.0/24")

	ipBlock1 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet1.IP), PrefixLength: 112},
	}
	ipBlock2 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet2.IP), PrefixLength: 112},
		Except: []v1beta2.IPNet{
			{IP: v1beta2.IPAddress(ipNet3.IP), PrefixLength: 120},
			{IP: v1beta2.IPAddress(ipNet4.IP), PrefixLength: 124},
		},
	}
	ipBlock3 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet5.IP), PrefixLength: 16},
	}
	ipBlock4 := v1beta2.IPBlock{
		CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet6.IP), PrefixLength: 16},
		Except: []v1beta2.IPNet{
			{IP: v1beta2.IPAddress(ipNet7.IP), PrefixLength: 24},
		},
	}

	tests := []struct {
		name            string
		args            *CompletedRule
		expectedOFRules []*types.PolicyRule
		wantErr         bool
	}{
		{
			"ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, Services: []v1beta2.Service{serviceTCP80, serviceTCP}, SourceRef: &np1},
				FromAddresses: dualAddressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1", "2002:1a23:fb44::1")),
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-missing-ofport",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: dualAddressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup2,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("1.1.1.1", "2002:1a23:fb44::1")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					From:      v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2, ipBlock3, ipBlock4}},
					Services:  []v1beta2.Service{serviceTCP80, serviceTCP},
					SourceRef: &np1,
				},
				FromAddresses: dualAddressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From: []types.Address{
						openflow.NewIPAddress(net.ParseIP("1.1.1.1")),
						openflow.NewIPAddress(net.ParseIP("2002:1a23:fb44::1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*ipNet5),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
						openflow.NewIPNetAddress(*diffNet13),
						openflow.NewIPNetAddress(*diffNet14),
						openflow.NewIPNetAddress(*diffNet15),
						openflow.NewIPNetAddress(*diffNet16),
						openflow.NewIPNetAddress(*diffNet17),
						openflow.NewIPNetAddress(*diffNet18),
						openflow.NewIPNetAddress(*diffNet19),
						openflow.NewIPNetAddress(*diffNet20),
					},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80, serviceTCP},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-no-ports",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-unresolvable-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-same-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithSameContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1, 3)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-with-diff-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithDiffContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](3)),
					Service:   []v1beta2.Service{serviceTCP443},
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"ingress-rule-deny-all",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta2.DirectionIn, SourceRef: &np1},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.New[int32](1)),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta2.DirectionOut, SourceRef: &np1},
				FromAddresses: nil,
				ToAddresses:   dualAddressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb44::1", "1.1.1.1")),
					To:        ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2", "2.2.2.2")),
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					To:        v1beta2.NetworkPolicyPeer{IPBlocks: []v1beta2.IPBlock{ipBlock1, ipBlock2, ipBlock3, ipBlock4}},
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   dualAddressGroup1,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2", "2.2.2.2")),
					To: []types.Address{
						openflow.NewIPAddress(net.ParseIP("2002:1a23:fb44::1")),
						openflow.NewIPAddress(net.ParseIP("1.1.1.1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*ipNet5),
						openflow.NewIPNetAddress(*diffNet1),
						openflow.NewIPNetAddress(*diffNet2),
						openflow.NewIPNetAddress(*diffNet3),
						openflow.NewIPNetAddress(*diffNet4),
						openflow.NewIPNetAddress(*diffNet5),
						openflow.NewIPNetAddress(*diffNet6),
						openflow.NewIPNetAddress(*diffNet7),
						openflow.NewIPNetAddress(*diffNet8),
						openflow.NewIPNetAddress(*diffNet9),
						openflow.NewIPNetAddress(*diffNet10),
						openflow.NewIPNetAddress(*diffNet11),
						openflow.NewIPNetAddress(*diffNet12),
						openflow.NewIPNetAddress(*diffNet13),
						openflow.NewIPNetAddress(*diffNet14),
						openflow.NewIPNetAddress(*diffNet15),
						openflow.NewIPNetAddress(*diffNet16),
						openflow.NewIPNetAddress(*diffNet17),
						openflow.NewIPNetAddress(*diffNet18),
						openflow.NewIPNetAddress(*diffNet19),
						openflow.NewIPNetAddress(*diffNet20),
					},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-deny-all",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionOut,
					SourceRef: &np1,
				},
				FromAddresses: nil,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2", "2.2.2.2")),
					To:        []types.Address{},
					Service:   nil,
					PolicyRef: &np1,
				},
			},
			false,
		},
		{
			"egress-rule-with-same-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta2.DirectionIn,
					Services:  []v1beta2.Service{serviceHTTP},
					SourceRef: &np1,
				},
				TargetMembers: appliedToGroupWithSameContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      ipsToOFAddresses(sets.New[string]("2002:1a23:fb45::2", "2.2.2.2", "3.3.3.3", "2002:1a23:fb46::3")),
					To:        []types.Address{},
					Service:   []v1beta2.Service{serviceTCP80},
					PolicyRef: &np1,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(controller)
			// TODO: mock idAllocator and priorityAssigner
			for i := 0; i < len(tt.expectedOFRules); i++ {
				mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any())
			}
			r := newTestReconciler(t, controller, ifaceStore, mockOFClient, true, true)
			if err := r.Reconcile(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkNormalizeServices(b *testing.B) {
	services := []v1beta2.Service{serviceTCP80, serviceTCP8080}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeServices(services)
	}
}

func benchmarkGroupMembersByServices(b *testing.B, withNamedPort bool) {
	serviceHTTP := v1beta2.Service{Protocol: &protocolTCP}
	if withNamedPort {
		serviceHTTP.Port = &portHTTP
	} else {
		serviceHTTP.Port = &port80
	}

	services := []v1beta2.Service{serviceHTTP}
	pods := v1beta2.NewGroupMemberSet()
	// 50,000 Pods in this group.
	for i1 := 1; i1 <= 100; i1++ {
		for i2 := 1; i2 <= 50; i2++ {
			for i3 := 1; i3 <= 10; i3++ {
				pod := &v1beta2.GroupMember{
					IPs: []v1beta2.IPAddress{
						v1beta2.IPAddress(net.ParseIP(fmt.Sprintf("1.%d.%d.%d", i1, i2, i3))),
					},
				}
				if withNamedPort {
					pod.Ports = []v1beta2.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}}
				}
				pods.Insert(pod)
			}
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		groupMembersByServices(services, pods)
	}
}

func BenchmarkGroupPodsByServicesWithNamedPort(b *testing.B) {
	benchmarkGroupMembersByServices(b, true)
}

func BenchmarkGroupPodsByServicesWithoutNamedPort(b *testing.B) {
	benchmarkGroupMembersByServices(b, false)
}

// policyRuleMatcher implements gomock.Matcher.
// It is used to check whether the argument of the mocked method is expected. It ignores differences in slice element
// order and some fields including "Priority" and "FlowID" which are a little difficult to predict.
type policyRuleMatcher struct {
	ofPolicyRule *types.PolicyRule
}

func newPolicyRulesMatcher(ofRule *types.PolicyRule) gomock.Matcher {
	return policyRuleMatcher{ofPolicyRule: ofRule}
}

// Matches checks if predictable fields of *types.PolicyRule match.
func (m policyRuleMatcher) Matches(x interface{}) bool {
	b, ok := x.(*types.PolicyRule)
	if !ok {
		return false
	}
	a := m.ofPolicyRule
	if !sliceEqual(a.Service, b.Service) ||
		!sliceEqual(a.From, b.From) ||
		!sliceEqual(a.To, b.To) ||
		a.PolicyRef != b.PolicyRef ||
		a.Direction != b.Direction ||
		a.EnableLogging != b.EnableLogging ||
		a.LogLabel != b.LogLabel {
		return false
	}
	return true
}

func sliceEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	aKind := reflect.TypeOf(a).Kind()
	bKind := reflect.TypeOf(b).Kind()
	if aKind != reflect.Slice || bKind != reflect.Slice {
		return false
	}
	aValue := reflect.ValueOf(a)
	bValue := reflect.ValueOf(b)
	if aValue.Len() != bValue.Len() {
		return false
	}

	visited := make([]bool, aValue.Len())
	for i := 0; i < aValue.Len(); i++ {
		found := false
		for j := 0; j < bValue.Len(); j++ {
			if visited[j] {
				continue
			}
			if reflect.DeepEqual(aValue.Index(i).Interface(), bValue.Index(j).Interface()) {
				visited[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (m policyRuleMatcher) String() string {
	return fmt.Sprintf("is equal to %v", m.ofPolicyRule)
}
