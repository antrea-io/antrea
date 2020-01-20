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
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

var (
	addressGroup1   = v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"))
	addressGroup2   = v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.2"))
	appliedToGroup1 = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"))
	appliedToGroup2 = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod2", "ns1"))
	appliedToGroup3 = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod3", "ns1"))
)

func TestReconcilerForget(t *testing.T) {
	tests := []struct {
		name             string
		lastRealizeds    map[string]*lastRealized
		args             string
		expectedOFRuleID uint32
		wantErr          bool
	}{
		{
			"unknown-rule",
			map[string]*lastRealized{"foo": {ofID: 8}},
			"unknown-rule-id",
			0,
			false,
		},
		{
			"known-rule",
			map[string]*lastRealized{"foo": {ofID: 8}},
			"foo",
			uint32(8),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			ifaceStore := interfacestore.NewInterfaceStore()
			mockOFClient := openflowtest.NewMockClient(controller)
			if tt.expectedOFRuleID == 0 {
				mockOFClient.EXPECT().UninstallPolicyRuleFlows(gomock.Any()).Times(0)
			} else {
				mockOFClient.EXPECT().UninstallPolicyRuleFlows(tt.expectedOFRuleID)
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
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1}})
	protocolTCP := v1beta1.ProtocolTCP
	port80 := intstr.FromInt(80)
	// It represents named port that we can't resolve for now.
	portHTTP := intstr.FromString("http")
	service1 := v1beta1.Service{Protocol: &protocolTCP, Port: &port80}
	service2 := v1beta1.Service{Protocol: &protocolTCP}
	service3 := v1beta1.Service{Protocol: &protocolTCP, Port: &portHTTP}
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
		name           string
		args           *CompletedRule
		expectedOFRule *types.PolicyRule
		wantErr        bool
	}{
		{
			"ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, Services: []v1beta1.Service{service1, service2}},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				Pods:          appliedToGroup1,
			},
			&types.PolicyRule{
				ID:         1,
				Direction:  networkingv1.PolicyTypeIngress,
				From:       []types.Address{ipStringToOFAddress("1.1.1.1")},
				ExceptFrom: nil,
				To:         []types.Address{openflow.NewOFPortAddress(1)},
				ExceptTo:   nil,
				Service:    servicesToNetworkPolicyPort([]v1beta1.Service{service1, service2}),
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
			&types.PolicyRule{
				ID:         1,
				Direction:  networkingv1.PolicyTypeIngress,
				From:       []types.Address{ipStringToOFAddress("1.1.1.1")},
				ExceptFrom: nil,
				To:         []types.Address{},
				ExceptTo:   nil,
				Service:    nil,
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
					Services:  []v1beta1.Service{service1, service2},
				},
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				Pods:          appliedToGroup1,
			},
			&types.PolicyRule{
				ID:        1,
				Direction: networkingv1.PolicyTypeIngress,
				From: []types.Address{
					ipStringToOFAddress("1.1.1.1"),
					openflow.NewIPNetAddress(*ipNet1),
					openflow.NewIPNetAddress(*ipNet2),
				},
				ExceptFrom: []types.Address{
					openflow.NewIPNetAddress(*ipNet3),
					openflow.NewIPNetAddress(*ipNet4),
				},
				To:       []types.Address{openflow.NewOFPortAddress(1)},
				ExceptTo: nil,
				Service:  servicesToNetworkPolicyPort([]v1beta1.Service{service1, service2}),
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
			&types.PolicyRule{
				ID:        1,
				Direction: networkingv1.PolicyTypeIngress,
				From:      []types.Address{},
				To:        []types.Address{openflow.NewOFPortAddress(1)},
				Service:   nil,
			},
			false,
		},
		{
			"ingress-rule-with-unsupported-namedport",
			&CompletedRule{
				rule: &rule{
					ID:        "ingress-rule",
					Direction: v1beta1.DirectionIn,
					Services:  []v1beta1.Service{service3},
				},
				Pods: appliedToGroup1,
			},
			&types.PolicyRule{
				ID:        1,
				Direction: networkingv1.PolicyTypeIngress,
				From:      []types.Address{},
				To:        []types.Address{openflow.NewOFPortAddress(1)},
				Service:   []*networkingv1.NetworkPolicyPort{},
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
			&types.PolicyRule{
				ID:         1,
				Direction:  networkingv1.PolicyTypeEgress,
				From:       []types.Address{ipStringToOFAddress("2.2.2.2")},
				ExceptFrom: nil,
				To:         []types.Address{ipStringToOFAddress("1.1.1.1")},
				ExceptTo:   nil,
				Service:    nil,
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
			&types.PolicyRule{
				ID:         1,
				Direction:  networkingv1.PolicyTypeEgress,
				From:       []types.Address{ipStringToOFAddress("2.2.2.2")},
				ExceptFrom: nil,
				To: []types.Address{
					ipStringToOFAddress("1.1.1.1"),
					openflow.NewIPNetAddress(*ipNet1),
					openflow.NewIPNetAddress(*ipNet2),
				},
				ExceptTo: []types.Address{
					openflow.NewIPNetAddress(*ipNet3),
					openflow.NewIPNetAddress(*ipNet4),
				},
				Service: nil,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			mockOFClient := openflowtest.NewMockClient(controller)
			mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Eq(tt.expectedOFRule))
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
			[]types.Address{ipStringToOFAddress("1.1.1.2")},
			[]types.Address{openflow.NewOFPortAddress(2)},
			[]types.Address{ipStringToOFAddress("1.1.1.1")},
			[]types.Address{openflow.NewOFPortAddress(1)},
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
			[]types.Address{ipStringToOFAddress("3.3.3.3")},
			[]types.Address{ipStringToOFAddress("1.1.1.2")},
			[]types.Address{ipStringToOFAddress("2.2.2.2")},
			[]types.Address{ipStringToOFAddress("1.1.1.1")},
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
			[]types.Address{ipStringToOFAddress("1.1.1.2")},
			[]types.Address{},
			[]types.Address{ipStringToOFAddress("1.1.1.1")},
			[]types.Address{openflow.NewOFPortAddress(1)},
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
			[]types.Address{ipStringToOFAddress("1.1.1.2")},
			[]types.Address{ipStringToOFAddress("2.2.2.2")},
			[]types.Address{ipStringToOFAddress("1.1.1.1")},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			mockOFClient := openflowtest.NewMockClient(controller)
			mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any())
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
