// Copyright 2025 Antrea Authors.
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

package connections

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	. "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

func Test_ConnStore_fillPodInfo(t *testing.T) {
	conn := GenerateConnectionFn()

	srcPod := &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "8.7.6.5",
				},
				{
					IP: "4.3.2.1",
				},
			},
			Phase: v1.PodRunning,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "srcPod",
			Namespace: "srcNamespace",
		},
	}

	dstPod := &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "10.20.30.40",
				},
				{
					IP: "50.60.70.80",
				},
			},
			Phase: v1.PodRunning,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dstPod",
			Namespace: "dstNamespace",
		},
	}

	tests := []struct {
		name              string
		conn              *connection.Connection
		hasSourcePod      bool
		hasDestinationPod bool
		expectedConn      *connection.Connection
	}{
		{
			name:         "no pod exists",
			hasSourcePod: true,
			conn:         conn(),
			expectedConn: conn(WithPodInfo("", "", "", "")),
		}, {
			name:         "src pod exists",
			hasSourcePod: true,
			conn:         conn(),
			expectedConn: conn(WithPodInfo(srcPod.Namespace, srcPod.Name, "", "")),
		}, {
			name:              "dst pod exists",
			hasDestinationPod: true,
			conn:              conn(),
			expectedConn:      conn(WithPodInfo("", "", dstPod.Namespace, dstPod.Name)),
		}, {
			name:              "both pod exists",
			hasSourcePod:      true,
			hasDestinationPod: true,
			conn:              conn(),
			expectedConn:      conn(WithPodInfo(srcPod.Namespace, srcPod.Name, dstPod.Namespace, dstPod.Name)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)

			if tt.hasSourcePod {
				mockPodStore.EXPECT().GetPodByIPAndTime(tt.conn.FlowKey.SourceAddress.String(), gomock.Any()).Return(srcPod, true)
			} else {
				mockPodStore.EXPECT().GetPodByIPAndTime(tt.conn.FlowKey.SourceAddress.String(), gomock.Any()).Return(nil, false)
			}
			if tt.hasDestinationPod {
				mockPodStore.EXPECT().GetPodByIPAndTime(tt.conn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(dstPod, true)
			} else {
				mockPodStore.EXPECT().GetPodByIPAndTime(tt.conn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(nil, false)
			}

			store := &ConnStore{
				podStore: mockPodStore,
			}
			store.fillPodInfo(tt.conn)
		})
	}
}

func Test_ConnStore_fillServiceInfo(t *testing.T) {
	conn := GenerateConnectionFn(WithServiceMark, WithRandomOriginalDestinationV4())

	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS",
			Name:      "serviceName",
		},
		Port:     "300",
		Protocol: v1.ProtocolTCP,
	}

	tests := []struct {
		name                  string
		conn                  *connection.Connection
		serviceExist          bool
		expectServicePortname bool
	}{
		{
			name:                  "no service mark",
			conn:                  GenerateConnectionFn(WithRandomOriginalDestinationV4())(),
			serviceExist:          false,
			expectServicePortname: false,
		}, {
			name:                  "fills destination service port name if service exists",
			conn:                  conn(),
			serviceExist:          true,
			expectServicePortname: true,
		}, {
			name:                  "service doesn't exist leaves service port info unfilled",
			conn:                  conn(),
			expectServicePortname: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockProxier := proxytest.NewMockProxier(ctrl)

			protocol, _ := lookupServiceProtocol(tt.conn.FlowKey.Protocol)
			serviceStr := fmt.Sprintf("%s:%d/%s", tt.conn.OriginalDestinationAddress.String(), tt.conn.OriginalDestinationPort, protocol)
			if tt.serviceExist {
				mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(svcPortName, true)
			} else if tt.conn.Mark != 0 {
				mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(k8sproxy.ServicePortName{}, false)
			}

			store := &ConnStore{
				antreaProxier: mockProxier,
			}
			store.fillServiceInfo(tt.conn)

			if tt.serviceExist {
				assert.Equal(t, tt.conn.DestinationServicePortName, svcPortName.String())
			} else {
				assert.Equal(t, tt.conn.DestinationServicePortName, "")
			}
		})
	}
}

func Test_ConnStore_fillNetworkPolicyMetadataInfo(t *testing.T) {
	var ingressOfID uint32 = 1000
	var egressOfID uint32 = 2000

	conn := GenerateConnectionFn()

	np1 := cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid1",
	}
	rule1 := agenttypes.PolicyRule{
		Direction: cpv1beta.DirectionIn,
		From:      []agenttypes.Address{},
		To:        []agenttypes.Address{},
		Service:   []cpv1beta.Service{},
		Action:    ptr.To(secv1beta1.RuleActionAllow),
		Priority:  nil,
		Name:      "rule1",
		FlowID:    uint32(0),
		TableID:   uint8(10),
		PolicyRef: &np1,
	}

	rule2 := agenttypes.PolicyRule{
		Direction: cpv1beta.DirectionIn,
		From:      []agenttypes.Address{},
		To:        []agenttypes.Address{},
		Service:   []cpv1beta.Service{},
		Action:    ptr.To(secv1beta1.RuleActionAllow),
		Priority:  nil,
		Name:      "rule2",
		FlowID:    uint32(0),
		TableID:   uint8(10),
		PolicyRef: &np1,
	}

	tests := []struct {
		name                string
		conn                *connection.Connection
		expectIngressFilled bool
		expectEgressFilled  bool
	}{
		{
			name: "no network policy used",
			conn: conn(),
		}, {
			name:                "has ingress OpenFlow id",
			conn:                conn(WithIngressOpenflowID(ingressOfID)),
			expectIngressFilled: true,
		}, {
			name:               "has egress OpenFlow id",
			conn:               conn(WithEgressOpenflowID(egressOfID)),
			expectEgressFilled: true,
		}, {
			name:                "has ingress and egress OpenFlow id",
			conn:                conn(WithIngressOpenflowID(ingressOfID), WithEgressOpenflowID(egressOfID)),
			expectIngressFilled: true,
			expectEgressFilled:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNPQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)

			if tt.expectIngressFilled {
				mockNPQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(ingressOfID).Return(&np1)
				mockNPQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
			}

			if tt.expectEgressFilled {
				mockNPQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(egressOfID).Return(&np1)
				mockNPQuerier.EXPECT().GetRuleByFlowID(egressOfID).Return(&rule2)
			}

			store := &ConnStore{
				networkPolicyQuerier:   mockNPQuerier,
				networkPolicyReadyTime: tt.conn.StartTime.Add(-10 * time.Minute),
			}

			store.fillNetworkPolicyMetadataInfo(tt.conn)

			if tt.expectIngressFilled {
				assert.Equal(t, tt.conn.IngressNetworkPolicyName, np1.Name)
				assert.Equal(t, tt.conn.IngressNetworkPolicyNamespace, np1.Namespace)
				assert.Equal(t, tt.conn.IngressNetworkPolicyUID, string(np1.UID))
				assert.Equal(t, tt.conn.IngressNetworkPolicyType, utils.PolicyTypeToUint8(np1.Type))
				assert.Equal(t, tt.conn.IngressNetworkPolicyRuleName, rule1.Name)
				assert.Equal(t, tt.conn.IngressNetworkPolicyRuleAction, registry.NetworkPolicyRuleActionAllow)
			}

			if tt.expectEgressFilled {
				assert.Equal(t, tt.conn.EgressNetworkPolicyName, np1.Name)
				assert.Equal(t, tt.conn.EgressNetworkPolicyNamespace, np1.Namespace)
				assert.Equal(t, tt.conn.EgressNetworkPolicyUID, string(np1.UID))
				assert.Equal(t, tt.conn.EgressNetworkPolicyType, utils.PolicyTypeToUint8(np1.Type))
				assert.Equal(t, tt.conn.EgressNetworkPolicyRuleName, rule2.Name)
				assert.Equal(t, tt.conn.EgressNetworkPolicyRuleAction, registry.NetworkPolicyRuleActionAllow)
			}

			if !tt.expectIngressFilled && !tt.expectEgressFilled {
				assert.Empty(t, tt.conn.EgressNetworkPolicyName)
				assert.Empty(t, tt.conn.EgressNetworkPolicyNamespace)
				assert.Empty(t, tt.conn.EgressNetworkPolicyUID)
				assert.Empty(t, tt.conn.EgressNetworkPolicyType)
				assert.Empty(t, tt.conn.EgressNetworkPolicyRuleName)
				assert.Empty(t, tt.conn.EgressNetworkPolicyRuleAction)
			}
		})
	}
}

func Test_ConnStore_fillEgressInfo(t *testing.T) {
	conn := GenerateConnectionFn(WithPodInfo("srcNS", "srcPod", "dstNS", "dstPod"), WithFlowType(utils.FlowTypeToExternal))

	egressConfig := agenttypes.EgressConfig{
		Name:       "egressName",
		UID:        types.UID("egressUID"),
		EgressIP:   RandIPv4().String(),
		EgressNode: "egressNode",
	}

	tests := []struct {
		name         string
		conn         *connection.Connection
		egressExists bool
	}{
		{
			name:         "egress doesn't exist",
			conn:         conn(),
			egressExists: false,
		}, {
			name:         "egress exist",
			conn:         conn(),
			egressExists: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			egressQuerier := queriertest.NewMockEgressQuerier(ctrl)

			if tt.egressExists {
				egressQuerier.EXPECT().GetEgress(tt.conn.SourcePodNamespace, tt.conn.SourcePodName).Return(egressConfig, nil)
			} else {
				egressQuerier.EXPECT().GetEgress(tt.conn.SourcePodNamespace, tt.conn.SourcePodName).Return(agenttypes.EgressConfig{}, errors.New("no egress available"))
			}

			store := &ConnStore{
				egressQuerier: egressQuerier,
			}
			store.fillEgressInfo(tt.conn)

			if tt.egressExists {
				assert.Equal(t, egressConfig.Name, tt.conn.EgressName)
				assert.Equal(t, egressConfig.UID, types.UID(tt.conn.EgressUID))
				assert.Equal(t, egressConfig.EgressIP, tt.conn.EgressIP)
				assert.Equal(t, egressConfig.EgressNode, tt.conn.EgressNodeName)
			} else {
				assert.Empty(t, tt.conn.EgressName)
				assert.Empty(t, tt.conn.EgressUID)
				assert.Empty(t, tt.conn.EgressIP)
				assert.Empty(t, tt.conn.EgressNodeName)
			}
		})
	}
}

func Test_ConnStore_fillFlowType(t *testing.T) {
	conn1 := GenerateConnectionFn(WithPodInfo("", "podA", "", "podB"))
	conn2 := GenerateConnectionFn(WithPodInfo("", "podA", "", ""))

	for _, tc := range []struct {
		isNetworkPolicyOnly bool
		conn                *connection.Connection
		expectedFlowType    uint8
	}{
		{true, conn1(), 1},
		{true, conn2(), 2},
		{false, conn1(), 0},
	} {
		store := &ConnStore{
			isNetworkPolicyOnly: tc.isNetworkPolicyOnly,
		}
		conn := store.fillFlowType(tc.conn)
		assert.Equal(t, tc.expectedFlowType, conn.FlowType)
	}
}
