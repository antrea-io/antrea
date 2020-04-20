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
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

var (
	addressGroup1 = v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"))
	addressGroup2 = v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.2"))

	appliedToGroup1                     = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"))
	appliedToGroup2                     = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod2", "ns1"))
	appliedToGroup3                     = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod3", "ns1"))
	appliedToGroupWithSameContainerPort = v1beta1.NewGroupMemberPodSet(
		newAppliedToGroupMember("pod1", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}),
		newAppliedToGroupMember("pod3", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}),
	)
	appliedToGroupWithDiffContainerPort = v1beta1.NewGroupMemberPodSet(
		newAppliedToGroupMember("pod1", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}),
		newAppliedToGroupMember("pod3", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 443}),
	)

	protocolTCP   = v1beta1.ProtocolTCP
	port80        = intstr.FromInt(80)
	port443       = intstr.FromInt(443)
	portHTTP      = intstr.FromString("http")
	serviceTCP80  = v1beta1.Service{Protocol: &protocolTCP, Port: &port80}
	serviceTCP443 = v1beta1.Service{Protocol: &protocolTCP, Port: &port443}
	serviceTCP    = v1beta1.Service{Protocol: &protocolTCP}
	serviceHTTP   = v1beta1.Service{Protocol: &protocolTCP, Port: &portHTTP}

	services1     = []v1beta1.Service{serviceTCP80}
	servicesHash1 = hashServices(services1)
	services2     = []v1beta1.Service{serviceTCP}
	servicesHash2 = hashServices(services2)
)

func TestReconcilerForget(t *testing.T) {
	tests := []struct {
		name              string
		lastRealizeds     map[string]*lastRealized
		args              string
		expectedOFRuleIDs []uint32
		wantErr           bool
	}{
		{
			"unknown-rule",
			map[string]*lastRealized{"foo": {ofIDs: map[servicesHash]uint32{servicesHash1: 8}}},
			"unknown-rule-id",
			nil,
			false,
		},
		{
			"known-single-ofrule",
			map[string]*lastRealized{"foo": {ofIDs: map[servicesHash]uint32{servicesHash1: 8}}},
			"foo",
			[]uint32{8},
			false,
		},
		{
			"known-multiple-ofrule",
			map[string]*lastRealized{"foo": {ofIDs: map[servicesHash]uint32{servicesHash1: 8, servicesHash2: 9}}},
			"foo",
			[]uint32{8, 9},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			ifaceStore := interfacestore.NewInterfaceStore()
			mockOFClient := openflowtest.NewMockClient(controller)
			if len(tt.expectedOFRuleIDs) == 0 {
				mockOFClient.EXPECT().UninstallPolicyRuleFlows(gomock.Any()).Times(0)
			} else {
				for _, ofID := range tt.expectedOFRuleIDs {
					mockOFClient.EXPECT().UninstallPolicyRuleFlows(ofID)
				}
			}
			r := newReconciler(mockOFClient, ifaceStore)
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
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1"),
		IP:                       net.ParseIP("2.2.2.2"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1"),
		IP:                       net.ParseIP("3.3.3.3"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	_, ipNet1, _ := net.ParseCIDR("10.10.0.0/16")
	_, ipNet2, _ := net.ParseCIDR("10.20.0.0/16")
	_, ipNet3, _ := net.ParseCIDR("10.20.1.0/24")
	_, ipNet4, _ := net.ParseCIDR("10.20.2.0/28")
	ipBlock1 := v1beta1.IPBlock{
		CIDR: v1beta1.IPNet{IP: v1beta1.IPAddress(ipNet1.IP), PrefixLength: 16},
	}
	ipBlock2 := v1beta1.IPBlock{
		CIDR: v1beta1.IPNet{IP: v1beta1.IPAddress(ipNet2.IP), PrefixLength: 16},
		Except: []v1beta1.IPNet{
			{IP: v1beta1.IPAddress(ipNet3.IP), PrefixLength: 24},
			{IP: v1beta1.IPAddress(ipNet4.IP), PrefixLength: 28},
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
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, Services: []v1beta1.Service{serviceTCP80, serviceTCP}},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				Pods:          appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction:  v1beta1.DirectionIn,
					From:       ipsToOFAddresses(sets.NewString("1.1.1.1")),
					ExceptFrom: nil,
					To:         ofPortsToOFAddresses(sets.NewInt32(1)),
					ExceptTo:   nil,
					Service:    []v1beta1.Service{serviceTCP80, serviceTCP},
				},
			},
			false,
		},
		{
			"ingress-rule-with-missing-ofport",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				Pods:          appliedToGroup2,
			},
			[]*types.PolicyRule{
				{
					Direction:  v1beta1.DirectionIn,
					From:       ipsToOFAddresses(sets.NewString("1.1.1.1")),
					ExceptFrom: nil,
					To:         []types.Address{},
					ExceptTo:   nil,
					Service:    nil,
				},
			},
			false,
		},
		{
			"ingress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta1.DirectionIn,
					From:      v1beta1.NetworkPolicyPeer{IPBlocks: []v1beta1.IPBlock{ipBlock1, ipBlock2}},
					Services:  []v1beta1.Service{serviceTCP80, serviceTCP},
				},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				Pods:          appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta1.DirectionIn,
					From: []types.Address{
						openflow.NewIPAddress(net.ParseIP("1.1.1.1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*ipNet2),
					},
					ExceptFrom: []types.Address{
						openflow.NewIPNetAddress(*ipNet3),
						openflow.NewIPNetAddress(*ipNet4),
					},
					To:       ofPortsToOFAddresses(sets.NewInt32(1)),
					ExceptTo: nil,
					Service:  []v1beta1.Service{serviceTCP80, serviceTCP},
				},
			},
			false,
		},
		{
			"ingress-rule-with-no-ports",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta1.DirectionIn,
					Services:  []v1beta1.Service{},
				},
				Pods: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta1.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.NewInt32(1)),
					Service:   nil,
				},
			},
			false,
		},
		{
			"ingress-rule-with-unresolvable-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta1.DirectionIn,
					Services:  []v1beta1.Service{serviceHTTP},
				},
				Pods: appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta1.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.NewInt32(1)),
					Service:   []v1beta1.Service{},
				},
			},
			false,
		},
		{
			"ingress-rule-with-same-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta1.DirectionIn,
					Services:  []v1beta1.Service{serviceHTTP},
				},
				Pods: appliedToGroupWithSameContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta1.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.NewInt32(1, 3)),
					Service:   []v1beta1.Service{serviceTCP80},
				},
			},
			false,
		},
		{
			"ingress-rule-with-diff-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta1.DirectionIn,
					Services:  []v1beta1.Service{serviceHTTP},
				},
				Pods: appliedToGroupWithDiffContainerPort,
			},
			[]*types.PolicyRule{
				{
					Direction: v1beta1.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.NewInt32(1)),
					Service:   []v1beta1.Service{serviceTCP80},
				},
				{
					Direction: v1beta1.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.NewInt32(3)),
					Service:   []v1beta1.Service{serviceTCP443},
				},
			},
			false,
		},
		{
			"ingress-rule-deny-all",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn},
				FromAddresses: nil,
				ToAddresses:   nil,
				Pods:          appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction:  v1beta1.DirectionIn,
					From:       []types.Address{},
					ExceptFrom: nil,
					To:         ofPortsToOFAddresses(sets.NewInt32(1)),
					ExceptTo:   nil,
					Service:    nil,
				},
			},
			false,
		},
		{
			"egress-rule",
			&CompletedRule{
				rule:          &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				FromAddresses: nil,
				ToAddresses:   addressGroup1,
				Pods:          appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction:  v1beta1.DirectionOut,
					From:       ipsToOFAddresses(sets.NewString("2.2.2.2")),
					ExceptFrom: nil,
					To:         ipsToOFAddresses(sets.NewString("1.1.1.1")),
					ExceptTo:   nil,
					Service:    nil,
				},
			},
			false,
		},
		{
			"egress-rule-with-ipblocks",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta1.DirectionOut,
					To:        v1beta1.NetworkPolicyPeer{IPBlocks: []v1beta1.IPBlock{ipBlock1, ipBlock2}},
				},
				FromAddresses: nil,
				ToAddresses:   addressGroup1,
				Pods:          appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction:  v1beta1.DirectionOut,
					From:       ipsToOFAddresses(sets.NewString("2.2.2.2")),
					ExceptFrom: nil,
					To: []types.Address{
						openflow.NewIPAddress(net.ParseIP("1.1.1.1")),
						openflow.NewIPNetAddress(*ipNet1),
						openflow.NewIPNetAddress(*ipNet2),
					},
					ExceptTo: []types.Address{
						openflow.NewIPNetAddress(*ipNet3),
						openflow.NewIPNetAddress(*ipNet4),
					},
					Service: nil,
				},
			},
			false,
		},
		{
			"egress-rule-deny-all",
			&CompletedRule{
				rule: &rule{
					ID:        "egress-rule",
					Direction: v1beta1.DirectionOut,
				},
				FromAddresses: nil,
				ToAddresses:   nil,
				Pods:          appliedToGroup1,
			},
			[]*types.PolicyRule{
				{
					Direction:  v1beta1.DirectionOut,
					From:       ipsToOFAddresses(sets.NewString("2.2.2.2")),
					ExceptFrom: nil,
					To:         []types.Address{},
					ExceptTo:   nil,
					Service:    nil,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			mockOFClient := openflowtest.NewMockClient(controller)
			for _, ofRule := range tt.expectedOFRules {
				mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any(), gomock.Eq(ofRule))
			}
			r := newReconciler(mockOFClient, ifaceStore)
			if err := r.Reconcile(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReconcilerUpdate(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1"),
			IP:                       net.ParseIP("2.2.2.2"),
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1}})
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod2", "ns1"),
			IP:                       net.ParseIP("3.3.3.3"),
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod2", PodNamespace: "ns1"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 2}})
	tests := []struct {
		name                string
		originalRule        *CompletedRule
		updatedRule         *CompletedRule
		expectedAddedFrom   []types.Address
		expectedAddedTo     []types.Address
		expectedDeletedFrom []types.Address
		expectedDeletedTo   []types.Address
		wantErr             bool
	}{
		{
			"updating-ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn},
				FromAddresses: addressGroup1,
				Pods:          appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn},
				FromAddresses: addressGroup2,
				Pods:          appliedToGroup2,
			},
			ipsToOFAddresses(sets.NewString("1.1.1.2")),
			ofPortsToOFAddresses(sets.NewInt32(2)),
			ipsToOFAddresses(sets.NewString("1.1.1.1")),
			ofPortsToOFAddresses(sets.NewInt32(1)),
			false,
		},
		{
			"updating-egress-rule",
			&CompletedRule{
				rule:        &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				ToAddresses: addressGroup1,
				Pods:        appliedToGroup1,
			},
			&CompletedRule{
				rule:        &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				ToAddresses: addressGroup2,
				Pods:        appliedToGroup2,
			},
			ipsToOFAddresses(sets.NewString("3.3.3.3")),
			ipsToOFAddresses(sets.NewString("1.1.1.2")),
			ipsToOFAddresses(sets.NewString("2.2.2.2")),
			ipsToOFAddresses(sets.NewString("1.1.1.1")),
			false,
		},
		{
			"updating-ingress-rule-with-missing-ofport",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn},
				FromAddresses: addressGroup1,
				Pods:          appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn},
				FromAddresses: addressGroup2,
				Pods:          appliedToGroup3,
			},
			ipsToOFAddresses(sets.NewString("1.1.1.2")),
			[]types.Address{},
			ipsToOFAddresses(sets.NewString("1.1.1.1")),
			ofPortsToOFAddresses(sets.NewInt32(1)),
			false,
		},
		{
			"updating-egress-rule-with-missing-ip",
			&CompletedRule{
				rule:        &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				ToAddresses: addressGroup1,
				Pods:        appliedToGroup1,
			},
			&CompletedRule{
				rule:        &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				ToAddresses: addressGroup2,
				Pods:        appliedToGroup3,
			},
			[]types.Address{},
			ipsToOFAddresses(sets.NewString("1.1.1.2")),
			ipsToOFAddresses(sets.NewString("2.2.2.2")),
			ipsToOFAddresses(sets.NewString("1.1.1.1")),
			false,
		},
		{
			"updating-egress-rule-deny-all",
			&CompletedRule{
				rule:        &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				ToAddresses: nil,
				Pods:        appliedToGroup1,
			},
			&CompletedRule{
				rule:        &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
				ToAddresses: nil,
				Pods:        appliedToGroup2,
			},
			ipsToOFAddresses(sets.NewString("3.3.3.3")),
			[]types.Address{},
			ipsToOFAddresses(sets.NewString("2.2.2.2")),
			[]types.Address{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			mockOFClient := openflowtest.NewMockClient(controller)
			mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any(), gomock.Any())
			if len(tt.expectedAddedFrom) > 0 {
				mockOFClient.EXPECT().AddPolicyRuleAddress(gomock.Any(), types.SrcAddress, gomock.Eq(tt.expectedAddedFrom))
			}
			if len(tt.expectedAddedTo) > 0 {
				mockOFClient.EXPECT().AddPolicyRuleAddress(gomock.Any(), types.DstAddress, gomock.Eq(tt.expectedAddedTo))
			}
			if len(tt.expectedDeletedFrom) > 0 {
				mockOFClient.EXPECT().DeletePolicyRuleAddress(gomock.Any(), types.SrcAddress, gomock.Eq(tt.expectedDeletedFrom))
			}
			if len(tt.expectedDeletedTo) > 0 {
				mockOFClient.EXPECT().DeletePolicyRuleAddress(gomock.Any(), types.DstAddress, gomock.Eq(tt.expectedDeletedTo))
			}
			r := newReconciler(mockOFClient, ifaceStore)
			if err := r.Reconcile(tt.originalRule); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := r.Reconcile(tt.updatedRule); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
