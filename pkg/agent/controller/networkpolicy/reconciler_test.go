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
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy/v1beta1"
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
			ifaceStore := agent.NewInterfaceStore()
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
	addressGroup1 := sets.NewString("1.1.1.1")
	appliedToGroup1 := newPodSet(v1beta1.PodReference{"pod1", "ns1"})
	appliedToGroup2 := newPodSet(v1beta1.PodReference{"pod2", "ns1"})
	ifaceStore := agent.NewInterfaceStore()
	ifaceStore.AddInterface(util.GenerateContainerInterfaceName("pod1", "ns1"),
		&agent.InterfaceConfig{IP: net.ParseIP("2.2.2.2"), OVSPortConfig: &agent.OVSPortConfig{OFPort: 1}})
	protocolTCP := v1beta1.ProtocolTCP
	port80 := int32(80)
	service1 := v1beta1.Service{Protocol: &protocolTCP, Port: &port80}
	service2 := v1beta1.Service{Protocol: &protocolTCP}
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
				From:       []types.Address{openflow.NewIPAddress(net.ParseIP("1.1.1.1"))},
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
				From:       []types.Address{openflow.NewIPAddress(net.ParseIP("1.1.1.1"))},
				ExceptFrom: nil,
				To:         []types.Address{},
				ExceptTo:   nil,
				Service:    nil,
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
				From:       []types.Address{openflow.NewIPAddress(net.ParseIP("2.2.2.2"))},
				ExceptFrom: nil,
				To:         []types.Address{openflow.NewIPAddress(net.ParseIP("1.1.1.1"))},
				ExceptTo:   nil,
				Service:    nil,
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
				t.Fatalf("Forget() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
