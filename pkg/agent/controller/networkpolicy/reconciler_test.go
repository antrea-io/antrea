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
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
)

var (
	addressGroup1 = v1beta1.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))
	addressGroup2 = v1beta1.NewGroupMemberSet(newAddressGroupMember("1.1.1.2"))

	appliedToGroup1                     = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"))
	appliedToGroup2                     = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod2", "ns1"))
	appliedToGroup3                     = v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod4", "ns1"))
	appliedToGroupWithSameContainerPort = v1beta1.NewGroupMemberPodSet(
		newAppliedToGroupMember("pod1", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}),
		newAppliedToGroupMember("pod3", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}),
	)
	appliedToGroupWithDiffContainerPort = v1beta1.NewGroupMemberPodSet(
		newAppliedToGroupMember("pod1", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}),
		newAppliedToGroupMember("pod3", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 443}),
	)
	appliedToGroupWithSingleContainerPort = v1beta1.NewGroupMemberPodSet(
		newAppliedToGroupMember("pod1", "ns1", v1beta1.NamedPort{Name: "http", Protocol: v1beta1.ProtocolTCP, Port: 80}))

	protocolTCP = v1beta1.ProtocolTCP

	port80    = intstr.FromInt(80)
	port443   = intstr.FromInt(443)
	port8080  = intstr.FromInt(8080)
	portHTTP  = intstr.FromString("http")
	portHTTPS = intstr.FromString("https")

	serviceTCP80   = v1beta1.Service{Protocol: &protocolTCP, Port: &port80}
	serviceTCP443  = v1beta1.Service{Protocol: &protocolTCP, Port: &port443}
	serviceTCP8080 = v1beta1.Service{Protocol: &protocolTCP, Port: &port8080}
	serviceTCP     = v1beta1.Service{Protocol: &protocolTCP}
	serviceHTTP    = v1beta1.Service{Protocol: &protocolTCP, Port: &portHTTP}
	serviceHTTPS   = v1beta1.Service{Protocol: &protocolTCP, Port: &portHTTPS}

	services1    = []v1beta1.Service{serviceTCP80}
	servicesKey1 = normalizeServices(services1)
	services2    = []v1beta1.Service{serviceTCP}
	servicesKey2 = normalizeServices(services2)

	policyPriority = float64(1)
	tierPriority   = v1beta1.TierPriority(1)
)

func newCIDR(cidrStr string) *net.IPNet {
	_, tmpIpNet, _ := net.ParseCIDR(cidrStr)
	return tmpIpNet
}

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
			map[string]*lastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta1.DirectionIn, PolicyPriority: nil},
					},
				},
			},
			"unknown-rule-id",
			nil,
			false,
		},
		{
			"known-single-ofrule",
			map[string]*lastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta1.DirectionIn, PolicyPriority: nil},
					},
				},
			},
			"foo",
			[]uint32{8},
			false,
		},
		{
			"known-multiple-ofrule",
			map[string]*lastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8, servicesKey2: 9},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta1.DirectionIn, PolicyPriority: nil},
					},
				},
			},
			"foo",
			[]uint32{8, 9},
			false,
		},
		{
			"known-multiple-ofrule-cnp",
			map[string]*lastRealized{
				"foo": {
					ofIDs: map[servicesKey]uint32{servicesKey1: 8, servicesKey2: 9},
					CompletedRule: &CompletedRule{
						rule: &rule{Direction: v1beta1.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority},
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
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IP:                       net.ParseIP("2.2.2.2"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
		IP:                       net.ParseIP("3.3.3.3"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	ipNet1 := newCIDR("10.10.0.0/16")
	ipNet2 := newCIDR("10.20.0.0/16")
	ipNet3 := newCIDR("10.20.1.0/24")
	ipNet4 := newCIDR("10.20.2.0/28")
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
					Direction: v1beta1.DirectionIn,
					From:      ipsToOFAddresses(sets.NewString("1.1.1.1")),
					To:        ofPortsToOFAddresses(sets.NewInt32(1)),
					Service:   []v1beta1.Service{serviceTCP80, serviceTCP},
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
					Direction: v1beta1.DirectionIn,
					From:      ipsToOFAddresses(sets.NewString("1.1.1.1")),
					To:        []types.Address{},
					Service:   nil,
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
					To:      ofPortsToOFAddresses(sets.NewInt32(1)),
					Service: []v1beta1.Service{serviceTCP80, serviceTCP},
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
					Direction: v1beta1.DirectionIn,
					From:      []types.Address{},
					To:        ofPortsToOFAddresses(sets.NewInt32(1)),
					Service:   nil,
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
					Direction: v1beta1.DirectionOut,
					From:      ipsToOFAddresses(sets.NewString("2.2.2.2")),
					To:        ipsToOFAddresses(sets.NewString("1.1.1.1")),
					Service:   nil,
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
					Direction: v1beta1.DirectionOut,
					From:      ipsToOFAddresses(sets.NewString("2.2.2.2")),
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
					Direction: v1beta1.DirectionOut,
					From:      ipsToOFAddresses(sets.NewString("2.2.2.2")),
					To:        []types.Address{},
					Service:   nil,
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
			// TODO: mock idAllocator and priorityAssigner
			for i := 0; i < len(tt.expectedOFRules); i++ {
				mockOFClient.EXPECT().InstallPolicyRuleFlows(gomock.Any())
			}
			r := newReconciler(mockOFClient, ifaceStore)
			if err := r.Reconcile(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReconcilerBatchReconcile(t *testing.T) {
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "container1"),
		IP:                       net.ParseIP("2.2.2.2"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
		IP:                       net.ParseIP("3.3.3.3"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
	})
	completedRules := []*CompletedRule{
		{
			rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, Services: []v1beta1.Service{serviceTCP80, serviceTCP}},
			FromAddresses: addressGroup1,
			ToAddresses:   nil,
			Pods:          appliedToGroup1,
		},
		{
			rule: &rule{ID: "ingress-rule-no-ports", Direction: v1beta1.DirectionIn, Services: []v1beta1.Service{}},
			Pods: appliedToGroup1,
		},
		{
			rule: &rule{ID: "ingress-rule-diff-named-port", Direction: v1beta1.DirectionIn, Services: []v1beta1.Service{serviceHTTP}},
			Pods: appliedToGroupWithDiffContainerPort,
		},
		{
			rule:          &rule{ID: "egress-rule", Direction: v1beta1.DirectionOut},
			FromAddresses: nil,
			ToAddresses:   addressGroup1,
			Pods:          appliedToGroup1,
		},
	}
	expectedOFRules := []*types.PolicyRule{
		{
			Direction: v1beta1.DirectionIn,
			From:      ipsToOFAddresses(sets.NewString("1.1.1.1")),
			To:        ofPortsToOFAddresses(sets.NewInt32(1)),
			Service:   []v1beta1.Service{serviceTCP80, serviceTCP},
		},
		{
			Direction: v1beta1.DirectionIn,
			From:      []types.Address{},
			To:        ofPortsToOFAddresses(sets.NewInt32(1)),
			Service:   nil,
		},
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
		{
			Direction: v1beta1.DirectionOut,
			From:      ipsToOFAddresses(sets.NewString("2.2.2.2")),
			To:        ipsToOFAddresses(sets.NewString("1.1.1.1")),
			Service:   nil,
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
			defer controller.Finish()
			mockOFClient := openflowtest.NewMockClient(controller)
			r := newReconciler(mockOFClient, ifaceStore)
			if tt.numInstalledRules > 0 {
				// BatchInstall should skip rules already installed
				r.lastRealizeds.Store(tt.args[0].ID, newLastRealized(tt.args[0]))
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
			IP:                       net.ParseIP("2.2.2.2"),
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "container1"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1}})
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod2", "ns1", "container2"),
			IP:                       net.ParseIP("3.3.3.3"),
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod2", PodNamespace: "ns1", ContainerID: "container2"},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 2}})
	ifaceStore.AddInterface(
		&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName("pod3", "ns1", "container3"),
			IP:                       net.ParseIP("4.4.4.4"),
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
			false,
		},
		{
			"updating-cnp-ingress-rule",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority},
				FromAddresses: addressGroup1,
				Pods:          appliedToGroup1,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority},
				FromAddresses: addressGroup2,
				Pods:          appliedToGroup2,
			},
			ipsToOFAddresses(sets.NewString("1.1.1.2")),
			ofPortsToOFAddresses(sets.NewInt32(2)),
			ipsToOFAddresses(sets.NewString("1.1.1.1")),
			ofPortsToOFAddresses(sets.NewInt32(1)),
			false,
			false,
		},
		{
			"updating-cnp-ingress-rule-uninstall",
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, Services: []v1beta1.Service{serviceHTTP}},
				FromAddresses: addressGroup1,
				Pods:          appliedToGroupWithDiffContainerPort,
			},
			&CompletedRule{
				rule:          &rule{ID: "ingress-rule", Direction: v1beta1.DirectionIn, PolicyPriority: &policyPriority, TierPriority: &tierPriority, Services: []v1beta1.Service{serviceHTTP}},
				FromAddresses: addressGroup1,
				Pods:          appliedToGroupWithSingleContainerPort,
			},
			[]types.Address{},
			[]types.Address{},
			[]types.Address{},
			[]types.Address{},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
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
				mockOFClient.EXPECT().AddPolicyRuleAddress(gomock.Any(), types.SrcAddress, gomock.Eq(tt.expectedAddedFrom), priority)
			}
			if len(tt.expectedAddedTo) > 0 {
				mockOFClient.EXPECT().AddPolicyRuleAddress(gomock.Any(), types.DstAddress, gomock.Eq(tt.expectedAddedTo), priority)
			}
			if len(tt.expectedDeletedFrom) > 0 {
				mockOFClient.EXPECT().DeletePolicyRuleAddress(gomock.Any(), types.SrcAddress, gomock.Eq(tt.expectedDeletedFrom), priority)
			}
			if len(tt.expectedDeletedTo) > 0 {
				mockOFClient.EXPECT().DeletePolicyRuleAddress(gomock.Any(), types.DstAddress, gomock.Eq(tt.expectedDeletedTo), priority)
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

func TestGroupPodsByServices(t *testing.T) {
	numberedServices := []v1beta1.Service{serviceTCP80, serviceTCP443}
	numberedServicesKey := normalizeServices(numberedServices)
	namedServices := []v1beta1.Service{serviceHTTP, serviceHTTPS}

	tests := []struct {
		name                  string
		services              []v1beta1.Service
		pods                  v1beta1.GroupMemberPodSet
		wantPodsByServicesMap map[servicesKey]v1beta1.GroupMemberPodSet
		wantServicesMap       map[servicesKey][]v1beta1.Service
	}{
		{
			name:     "numbered ports",
			services: numberedServices,
			pods: v1beta1.NewGroupMemberPodSet(
				&v1beta1.GroupMemberPod{
					IP: v1beta1.IPAddress(net.ParseIP("1.1.1.1")),
				},
				&v1beta1.GroupMemberPod{
					IP: v1beta1.IPAddress(net.ParseIP("1.1.1.2")),
				},
			),
			wantPodsByServicesMap: map[servicesKey]v1beta1.GroupMemberPodSet{
				numberedServicesKey: v1beta1.NewGroupMemberPodSet(
					&v1beta1.GroupMemberPod{
						IP: v1beta1.IPAddress(net.ParseIP("1.1.1.1")),
					},
					&v1beta1.GroupMemberPod{
						IP: v1beta1.IPAddress(net.ParseIP("1.1.1.2")),
					},
				),
			},
			wantServicesMap: map[servicesKey][]v1beta1.Service{
				numberedServicesKey: numberedServices,
			},
		},
		{
			name:     "named ports",
			services: namedServices,
			pods: v1beta1.NewGroupMemberPodSet(
				&v1beta1.GroupMemberPod{
					IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.1")),
					Ports: []v1beta1.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
				},
				&v1beta1.GroupMemberPod{
					IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.2")),
					Ports: []v1beta1.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
				},
				&v1beta1.GroupMemberPod{
					IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.3")),
					Ports: []v1beta1.NamedPort{{Port: 8080, Name: "http", Protocol: protocolTCP}},
				},
				&v1beta1.GroupMemberPod{
					IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.4")),
					Ports: []v1beta1.NamedPort{{Port: 443, Name: "https", Protocol: protocolTCP}},
				},
				&v1beta1.GroupMemberPod{
					IP: v1beta1.IPAddress(net.ParseIP("1.1.1.5")),
				},
				&v1beta1.GroupMemberPod{
					IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.6")),
					Ports: []v1beta1.NamedPort{{Port: 443, Name: "foo", Protocol: protocolTCP}},
				},
			),
			wantPodsByServicesMap: map[servicesKey]v1beta1.GroupMemberPodSet{
				normalizeServices([]v1beta1.Service{serviceTCP80, serviceHTTPS}): v1beta1.NewGroupMemberPodSet(
					&v1beta1.GroupMemberPod{
						IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.1")),
						Ports: []v1beta1.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
					},
					&v1beta1.GroupMemberPod{
						IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.2")),
						Ports: []v1beta1.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}},
					},
				),
				normalizeServices([]v1beta1.Service{serviceTCP8080, serviceHTTPS}): v1beta1.NewGroupMemberPodSet(
					&v1beta1.GroupMemberPod{
						IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.3")),
						Ports: []v1beta1.NamedPort{{Port: 8080, Name: "http", Protocol: protocolTCP}},
					},
				),
				normalizeServices([]v1beta1.Service{serviceHTTP, serviceTCP443}): v1beta1.NewGroupMemberPodSet(
					&v1beta1.GroupMemberPod{
						IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.4")),
						Ports: []v1beta1.NamedPort{{Port: 443, Name: "https", Protocol: protocolTCP}},
					},
				),
				normalizeServices([]v1beta1.Service{serviceHTTP, serviceHTTPS}): v1beta1.NewGroupMemberPodSet(
					&v1beta1.GroupMemberPod{
						IP: v1beta1.IPAddress(net.ParseIP("1.1.1.5")),
					},
					&v1beta1.GroupMemberPod{
						IP:    v1beta1.IPAddress(net.ParseIP("1.1.1.6")),
						Ports: []v1beta1.NamedPort{{Port: 443, Name: "foo", Protocol: protocolTCP}},
					},
				),
			},
			wantServicesMap: map[servicesKey][]v1beta1.Service{
				normalizeServices([]v1beta1.Service{serviceTCP80, serviceHTTPS}):   {serviceTCP80, serviceHTTPS},
				normalizeServices([]v1beta1.Service{serviceTCP8080, serviceHTTPS}): {serviceTCP8080, serviceHTTPS},
				normalizeServices([]v1beta1.Service{serviceHTTP, serviceTCP443}):   {serviceHTTP, serviceTCP443},
				normalizeServices([]v1beta1.Service{serviceHTTP, serviceHTTPS}):    {serviceHTTP, serviceHTTPS},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPodsByServicesMap, gotServicesMap := groupPodsByServices(tt.services, tt.pods)
			assert.Equal(t, tt.wantPodsByServicesMap, gotPodsByServicesMap)
			assert.Equal(t, tt.wantServicesMap, gotServicesMap)
		})
	}
}

func BenchmarkNormalizeServices(b *testing.B) {
	services := []v1beta1.Service{serviceTCP80, serviceTCP8080}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeServices(services)
	}
}

func benchmarkGroupPodsByServices(b *testing.B, withNamedPort bool) {
	serviceHTTP := v1beta1.Service{Protocol: &protocolTCP}
	if withNamedPort {
		serviceHTTP.Port = &portHTTP
	} else {
		serviceHTTP.Port = &port80
	}

	services := []v1beta1.Service{serviceHTTP}
	pods := v1beta1.NewGroupMemberPodSet()
	// 50,000 Pods in this group.
	for i1 := 1; i1 <= 100; i1++ {
		for i2 := 1; i2 <= 50; i2++ {
			for i3 := 1; i3 <= 10; i3++ {
				pod := &v1beta1.GroupMemberPod{
					IP: v1beta1.IPAddress(net.ParseIP(fmt.Sprintf("1.%d.%d.%d", i1, i2, i3))),
				}
				if withNamedPort {
					pod.Ports = []v1beta1.NamedPort{{Port: 80, Name: "http", Protocol: protocolTCP}}
				}
				pods.Insert(pod)
			}
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		groupPodsByServices(services, pods)
	}
}

func BenchmarkGroupPodsByServicesWithNamedPort(b *testing.B) {
	benchmarkGroupPodsByServices(b, true)
}

func BenchmarkGroupPodsByServicesWithoutNamedPort(b *testing.B) {
	benchmarkGroupPodsByServices(b, false)
}
