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

package querier

import (
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/config"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

const ovsVersion = "2.10.0"

func getIPNet(ip string) *net.IPNet {
	_, ipNet, _ := net.ParseCIDR(ip)
	return ipNet
}

func TestAgentQuerierGetAgentInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	interfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	interfaceStore.EXPECT().GetContainerInterfaceNum().Return(2).AnyTimes()

	ofClient := openflowtest.NewMockClient(ctrl)
	ofClient.EXPECT().GetFlowTableStatus().Return([]binding.TableStatus{
		{
			ID:        1,
			FlowCount: 2,
		},
	}).AnyTimes()
	ofClient.EXPECT().IsConnected().Return(true).AnyTimes()

	ovsBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	ovsBridgeClient.EXPECT().GetOVSVersion().Return(ovsVersion, nil).AnyTimes()

	networkPolicyInfoQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	networkPolicyInfoQuerier.EXPECT().GetNetworkPolicyNum().Return(10).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetAppliedToGroupNum().Return(20).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetAddressGroupNum().Return(30).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetControllerConnectionStatus().Return(true).AnyTimes()

	tests := []struct {
		name              string
		nodeConfig        *config.NodeConfig
		apiPort           int
		partial           bool
		expectedAgentInfo *v1beta1.AntreaAgentInfo
	}{
		{
			name: "networkPolicyOnly-mode non-partial",
			nodeConfig: &config.NodeConfig{
				Name:       "foo",
				OVSBridge:  "br-int",
				NodeIPAddr: getIPNet("10.10.0.10"),
			},
			apiPort: 10350,
			partial: false,
			expectedAgentInfo: &v1beta1.AntreaAgentInfo{
				ObjectMeta:  v1.ObjectMeta{Name: "foo"},
				NodeRef:     corev1.ObjectReference{Kind: "Node", Name: "foo"},
				NodeSubnets: []string{},
				OVSInfo: v1beta1.OVSInfo{
					Version:    ovsVersion,
					BridgeName: "br-int",
					FlowTable:  map[string]int32{"1": 2},
				},
				NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
					NetworkPolicyNum:  10,
					AppliedToGroupNum: 20,
					AddressGroupNum:   30,
				},
				LocalPodNum: 2,
				AgentConditions: []v1beta1.AgentCondition{
					{
						Type:   v1beta1.AgentHealthy,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   v1beta1.ControllerConnectionUp,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   v1beta1.OVSDBConnectionUp,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   v1beta1.OpenflowConnectionUp,
						Status: corev1.ConditionTrue,
					},
				},
				APIPort: 10350,
				Version: "UNKNOWN",
			},
		},
		{
			name: "encap-mode non-partial",
			nodeConfig: &config.NodeConfig{
				Name:        "foo",
				OVSBridge:   "br-int",
				NodeIPAddr:  getIPNet("10.10.0.10"),
				PodIPv4CIDR: getIPNet("20.20.20.0/24"),
				PodIPv6CIDR: getIPNet("2001:ab03:cd04:55ef::/64"),
			},
			apiPort: 10350,
			partial: false,
			expectedAgentInfo: &v1beta1.AntreaAgentInfo{
				ObjectMeta:  v1.ObjectMeta{Name: "foo"},
				NodeRef:     corev1.ObjectReference{Kind: "Node", Name: "foo"},
				NodeSubnets: []string{"20.20.20.0/24", "2001:ab03:cd04:55ef::/64"},
				OVSInfo: v1beta1.OVSInfo{
					Version:    ovsVersion,
					BridgeName: "br-int",
					FlowTable:  map[string]int32{"1": 2},
				},
				NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
					NetworkPolicyNum:  10,
					AppliedToGroupNum: 20,
					AddressGroupNum:   30,
				},
				LocalPodNum: 2,
				AgentConditions: []v1beta1.AgentCondition{
					{
						Type:   v1beta1.AgentHealthy,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   v1beta1.ControllerConnectionUp,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   v1beta1.OVSDBConnectionUp,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   v1beta1.OpenflowConnectionUp,
						Status: corev1.ConditionTrue,
					},
				},
				APIPort: 10350,
				Version: "UNKNOWN",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aq := agentQuerier{
				nodeConfig:               tt.nodeConfig,
				interfaceStore:           interfaceStore,
				ofClient:                 ofClient,
				ovsBridgeClient:          ovsBridgeClient,
				networkPolicyInfoQuerier: networkPolicyInfoQuerier,
				apiPort:                  tt.apiPort,
			}
			agentInfo := &v1beta1.AntreaAgentInfo{}
			aq.GetAgentInfo(agentInfo, tt.partial)
			// Check AgentConditions separately as it contains timestamp we cannot predict.
			assert.Equal(t, len(tt.expectedAgentInfo.AgentConditions), len(agentInfo.AgentConditions))
			for i := range agentInfo.AgentConditions {
				assert.Equal(t, tt.expectedAgentInfo.AgentConditions[i].Status, agentInfo.AgentConditions[i].Status)
				assert.Equal(t, tt.expectedAgentInfo.AgentConditions[i].Type, agentInfo.AgentConditions[i].Type)
			}
			// Exclude AgentConditions before comparing the whole objects.
			tt.expectedAgentInfo.AgentConditions = nil
			agentInfo.AgentConditions = nil
			assert.Equal(t, tt.expectedAgentInfo, agentInfo)
		})
	}
}
