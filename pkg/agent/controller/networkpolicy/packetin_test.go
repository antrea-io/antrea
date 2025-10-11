// Copyright 2023 Antrea Authors
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
	"net/netip"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	connectionstesting "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	flowexporterutils "antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func TestController_HandlePacketIn(t *testing.T) {
	controller, _, _ := newTestController()
	logPacketErr := fmt.Errorf("log")
	rejectRequestErr := fmt.Errorf("reject")
	storeDenyConnectionErr := fmt.Errorf("storeDenyConnection")
	controller.logPacketAction = func(in *ofctrl.PacketIn) error {
		return logPacketErr
	}
	controller.rejectRequestAction = func(in *ofctrl.PacketIn) error {
		return rejectRequestErr
	}
	controller.storeDenyConnectionAction = func(in *ofctrl.PacketIn) error {
		return storeDenyConnectionErr
	}

	logPktIn := &ofctrl.PacketIn{
		PacketIn: &openflow15.PacketIn{},
		UserData: []byte{1},
	}
	controller.HandlePacketIn(logPktIn)

	for _, tt := range []struct {
		name      string
		packetIn  *ofctrl.PacketIn
		expectErr error
	}{
		{
			name:      "EmptyPacketIn",
			packetIn:  nil,
			expectErr: fmt.Errorf("empty packetIn for Antrea Policy"),
		},
		{
			name: "MissOperationInUserdata",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP)},
			},
			expectErr: fmt.Errorf("packetIn for Antrea Policy miss the required userdata"),
		},
		{
			name: "LoggingOperation",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP), uint8(openflow.PacketInNPLoggingOperation)},
			},
			expectErr: logPacketErr,
		},
		{
			name: "RejectOperation",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP), uint8(openflow.PacketInNPRejectOperation)},
			},
			expectErr: rejectRequestErr,
		},
		{
			name: "DenyOperation",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP), uint8(openflow.PacketInNPStoreDenyOperation)},
			},
			expectErr: storeDenyConnectionErr,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.HandlePacketIn(tt.packetIn)
			assert.Equal(t, err, tt.expectErr)
		})
	}
}

// fakeRuleCache implements Reconciler and is a static cache from rule ID to PolicyRule, used for testing.
type fakeRuleCache struct {
	cache map[uint32]*types.PolicyRule
}

var _ Reconciler = &fakeRuleCache{}

func (c *fakeRuleCache) Reconcile(rule *CompletedRule) error {
	return nil
}

func (c *fakeRuleCache) BatchReconcile(rules []*CompletedRule) error {
	return nil
}

func (c *fakeRuleCache) Forget(ruleID string) error {
	return nil
}

func (c *fakeRuleCache) GetRuleByFlowID(ruleID uint32) (*types.PolicyRule, bool, error) {
	r, ok := c.cache[ruleID]
	if !ok {
		return nil, false, nil
	}
	return r, true, nil
}

func (c *fakeRuleCache) RunIDAllocatorWorker(stopCh <-chan struct{}) {}

func TestStoreDenyConnection(t *testing.T) {
	prepareMockTables()

	sourceAddr := netip.MustParseAddr("1.2.3.4")
	destinationAddr := netip.MustParseAddr("5.6.7.8")
	key := connection.Tuple{
		SourceAddress:      sourceAddr,
		DestinationAddress: destinationAddr,
	}
	policyUID := uuid.New().String()

	dropCNPDispositionData := []byte{0x11, 0x00, 0x0c, 0x11}
	dispositionMatch := generateRegMatch(openflow.APDispositionField.GetRegID(), dropCNPDispositionData)
	conjunctionData := []byte{0x11, 0x11, 0x11, 0x11}
	conjunctionMatch := generateRegMatch(openflow.APConjIDField.GetRegID(), conjunctionData)
	matchers := []openflow15.MatchField{dispositionMatch, conjunctionMatch}

	ruleCache := &fakeRuleCache{
		map[uint32]*types.PolicyRule{
			0x11111111: {
				PolicyRef: &v1beta2.NetworkPolicyReference{
					Type:      v1beta2.AntreaClusterNetworkPolicy,
					Name:      "my-policy",
					Namespace: "ns",
					UID:       k8stypes.UID(policyUID),
				},
				Name: "my-rule",
			},
		},
	}

	testCases := []struct {
		name         string
		tableID      uint8
		expectedConn *connection.Connection
	}{
		{
			name:    "ingress policy",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedConn: &connection.Connection{
				FlowKey:                        key,
				OriginalDestinationAddress:     destinationAddr,
				IngressNetworkPolicyName:       "my-policy",
				IngressNetworkPolicyNamespace:  "ns",
				IngressNetworkPolicyUID:        policyUID,
				IngressNetworkPolicyType:       flowexporterutils.PolicyTypeAntreaClusterNetworkPolicy,
				IngressNetworkPolicyRuleName:   "my-rule",
				IngressNetworkPolicyRuleAction: flowexporterutils.NetworkPolicyRuleActionDrop,
				OriginalStats:                  connection.Stats{Packets: 1},
			},
		},
		{
			name:    "egress policy",
			tableID: openflow.AntreaPolicyEgressRuleTable.GetID(),
			expectedConn: &connection.Connection{
				FlowKey:                       key,
				OriginalDestinationAddress:    destinationAddr,
				EgressNetworkPolicyName:       "my-policy",
				EgressNetworkPolicyNamespace:  "ns",
				EgressNetworkPolicyUID:        policyUID,
				EgressNetworkPolicyType:       flowexporterutils.PolicyTypeAntreaClusterNetworkPolicy,
				EgressNetworkPolicyRuleName:   "my-rule",
				EgressNetworkPolicyRuleAction: flowexporterutils.NetworkPolicyRuleActionDrop,
				OriginalStats:                 connection.Stats{Packets: 1},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			controller, _, _ := newTestController()
			mockStore := connectionstesting.NewMockDenyStore(ctrl)
			controller.denyConnStore = mockStore
			controller.podReconciler = ruleCache
			pktIn := &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: tc.tableID,
					Match: openflow15.Match{
						Fields: matchers,
					},
				},
			}
			packet := &binding.Packet{
				SourceIP:      sourceAddr.AsSlice(),
				DestinationIP: destinationAddr.AsSlice(),
			}
			mockStore.EXPECT().HasConn(key).Return(false)

			mockStore.EXPECT().SubmitDenyConn(tc.expectedConn)
			require.NoError(t, controller.storeDenyConnectionParsed(pktIn, packet))
		})
	}
}
