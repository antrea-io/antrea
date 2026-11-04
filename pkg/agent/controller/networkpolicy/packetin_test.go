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
	"time"
	"uuid"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware/go-ipfix/pkg/registry"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	"antrea.io/antrea/v2/pkg/util/channel"
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

// generateRegMatches returns the match fields for the provided register values, indexed by register
// ID. As in PacketIn messages, registers which belong to the same xreg are reported in a single
// match field.
func generateRegMatches(regData map[int][]byte) []openflow15.MatchField {
	xregData := make(map[int][]byte)
	for regID, data := range regData {
		xregID := regID / 2
		if _, ok := xregData[xregID]; !ok {
			xregData[xregID] = make([]byte, 8)
		}
		copy(xregData[xregID][4*(regID%2):], data)
	}
	var matches []openflow15.MatchField
	for xregID, data := range xregData {
		matches = append(matches, openflow15.MatchField{
			Class:   openflow15.OXM_CLASS_PACKET_REGS,
			Field:   uint8(xregID),
			HasMask: false,
			Value:   &openflow15.ByteArrayField{Data: data},
		})
	}
	return matches
}

func TestPublishDenyConnection(t *testing.T) {
	prepareMockTables()

	sourceAddr := netip.MustParseAddr("1.2.3.4")
	destinationAddr := netip.MustParseAddr("5.6.7.8")
	key := connection.Tuple{
		SourceAddress:      sourceAddr,
		DestinationAddress: destinationAddr,
	}
	policyUID := uuid.NewV4().String()

	// reg0 data with a Drop disposition, with and without APDenyRegMark set. APDenyRegMark is only set
	// by Antrea-native policy rules.
	dispositionRegID := openflow.APDispositionField.GetRegID()
	dropCNPDispositionData := []byte{0x11, 0x00, 0x0c, 0x11}
	dropK8sDispositionData := []byte{0x11, 0x00, 0x08, 0x11}
	conjIDRegID := openflow.APConjIDField.GetRegID()
	conjunctionData := []byte{0x11, 0x11, 0x11, 0x11}
	// For IPv4 Service traffic, the selected Endpoint IP (10.10.1.7 here) is loaded into reg3, which
	// is shared by EndpointIPField and APConjIDField.
	endpointIPRegID := openflow.EndpointIPField.GetRegID()
	endpointIPData := []byte{0x0a, 0x0a, 0x01, 0x07}
	// K8s NetworkPolicy default drop flows send the packet to the Agent from OutputTable, and store
	// the ID of the table which dropped it in PacketInTableField.
	tableRegID := openflow.PacketInTableField.GetRegID()
	ingressDefaultTableData := []byte{0x00, 0x00, 0x00, openflow.IngressDefaultTable.GetID()}
	egressDefaultTableData := []byte{0x00, 0x00, 0x00, openflow.EgressDefaultTable.GetID()}

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
		regData      map[int][]byte
		expectedConn *connection.Connection
	}{
		{
			name:    "ingress policy",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropCNPDispositionData, conjIDRegID: conjunctionData},
			expectedConn: &connection.Connection{
				FlowKey:                    key,
				OriginalDestinationAddress: destinationAddr,
				Disposition:                actionDrop,
				OriginalBytes:              20,
				IngressRuleID:              0x11111111,
			},
		},
		{
			name:    "egress policy",
			tableID: openflow.AntreaPolicyEgressRuleTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropCNPDispositionData, conjIDRegID: conjunctionData},
			expectedConn: &connection.Connection{
				FlowKey:                    key,
				OriginalDestinationAddress: destinationAddr,
				Disposition:                actionDrop,
				OriginalBytes:              20,
				EgressRuleID:               0x11111111,
			},
		},
		// Baseline Tier rules are installed in the same tables as the K8s NetworkPolicy default drop flows, so
		// only APDenyRegMark tells them apart.
		{
			name:    "Baseline Tier ingress policy",
			tableID: openflow.IngressDefaultTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropCNPDispositionData, conjIDRegID: conjunctionData, tableRegID: ingressDefaultTableData},
			expectedConn: &connection.Connection{
				FlowKey:                    key,
				OriginalDestinationAddress: destinationAddr,
				Disposition:                actionDrop,
				OriginalBytes:              20,
				IngressRuleID:              0x11111111,
			},
		},
		{
			name:    "Baseline Tier egress policy",
			tableID: openflow.EgressDefaultTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropCNPDispositionData, conjIDRegID: conjunctionData, tableRegID: egressDefaultTableData},
			expectedConn: &connection.Connection{
				FlowKey:                    key,
				OriginalDestinationAddress: destinationAddr,
				Disposition:                actionDrop,
				OriginalBytes:              20,
				EgressRuleID:               0x11111111,
			},
		},
		{
			name:    "K8s ingress default drop",
			tableID: openflow.OutputTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropK8sDispositionData, tableRegID: ingressDefaultTableData},
			expectedConn: &connection.Connection{
				FlowKey:                        key,
				OriginalDestinationAddress:     destinationAddr,
				Disposition:                    actionDrop,
				OriginalBytes:                  20,
				IngressNetworkPolicyType:       registry.PolicyTypeK8sNetworkPolicy,
				IngressNetworkPolicyRuleAction: registry.NetworkPolicyRuleActionDrop,
			},
		},
		{
			name:    "K8s egress default drop",
			tableID: openflow.OutputTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropK8sDispositionData, tableRegID: egressDefaultTableData},
			expectedConn: &connection.Connection{
				FlowKey:                       key,
				OriginalDestinationAddress:    destinationAddr,
				Disposition:                   actionDrop,
				OriginalBytes:                 20,
				EgressNetworkPolicyType:       registry.PolicyTypeK8sNetworkPolicy,
				EgressNetworkPolicyRuleAction: registry.NetworkPolicyRuleActionDrop,
			},
		},
		{
			name:    "K8s ingress default drop with Service Endpoint IP",
			tableID: openflow.OutputTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropK8sDispositionData, tableRegID: ingressDefaultTableData, endpointIPRegID: endpointIPData},
			expectedConn: &connection.Connection{
				FlowKey:                        key,
				OriginalDestinationAddress:     destinationAddr,
				Disposition:                    actionDrop,
				OriginalBytes:                  20,
				IngressNetworkPolicyType:       registry.PolicyTypeK8sNetworkPolicy,
				IngressNetworkPolicyRuleAction: registry.NetworkPolicyRuleActionDrop,
			},
		},
		{
			name:    "K8s egress default drop with Service Endpoint IP",
			tableID: openflow.OutputTable.GetID(),
			regData: map[int][]byte{dispositionRegID: dropK8sDispositionData, tableRegID: egressDefaultTableData, endpointIPRegID: endpointIPData},
			expectedConn: &connection.Connection{
				FlowKey:                       key,
				OriginalDestinationAddress:    destinationAddr,
				Disposition:                   actionDrop,
				OriginalBytes:                 20,
				EgressNetworkPolicyType:       registry.PolicyTypeK8sNetworkPolicy,
				EgressNetworkPolicyRuleAction: registry.NetworkPolicyRuleActionDrop,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updateReceivedCh := make(chan *connection.Connection)
			controller, _, _ := newTestController()
			connUpdateChannel := channel.NewSubscribableChannel("conn update channel", 100)
			connUpdateChannel.Subscribe(func(connInterface any) {
				conn := connInterface.(*connection.Connection)
				tc.expectedConn.StartTime = conn.StartTime
				updateReceivedCh <- conn
			})
			go connUpdateChannel.Run(t.Context().Done())

			controller.denyConnNotifier = connUpdateChannel
			controller.podReconciler = ruleCache
			pktIn := &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: tc.tableID,
					Match: openflow15.Match{
						Fields: generateRegMatches(tc.regData),
					},
				},
			}
			packet := &binding.Packet{
				SourceIP:      sourceAddr.AsSlice(),
				DestinationIP: destinationAddr.AsSlice(),
				IPLength:      20,
			}
			require.NoError(t, controller.storeDenyConnectionParsed(pktIn, packet))

			select {
			case conn := <-updateReceivedCh:
				assert.Equal(t, tc.expectedConn, conn)
			case <-time.After(time.Second):
				require.Fail(t, "connection update channel did not receive the expected packet")
			}
		})
	}
}

func TestIsK8sDefaultDeny(t *testing.T) {
	prepareMockTables()

	// reg0 holds both APDispositionField and APDenyRegMark. The K8s NetworkPolicy default drop flows only load
	// the disposition, while Antrea-native policy rules which deny a packet also load APDenyRegMark.
	dispositionRegID := openflow.APDispositionField.GetRegID()
	dropData := []byte{0x00, 0x00, 0x08, 0x00}
	dropWithDenyMarkData := []byte{0x00, 0x00, 0x0c, 0x00}
	rejectData := []byte{0x00, 0x00, 0x10, 0x00}
	allowData := []byte{0x00, 0x00, 0x00, 0x00}
	passData := []byte{0x00, 0x00, 0x18, 0x00}

	for _, tc := range []struct {
		name        string
		tableID     uint8
		disposition uint32
		regData     map[int][]byte
		expected    bool
	}{
		{
			name:        "drop in ingress default table",
			tableID:     openflow.IngressDefaultTable.GetID(),
			disposition: openflow.DispositionDrop,
			regData:     map[int][]byte{dispositionRegID: dropData},
			expected:    true,
		},
		{
			name:        "drop in egress default table",
			tableID:     openflow.EgressDefaultTable.GetID(),
			disposition: openflow.DispositionDrop,
			regData:     map[int][]byte{dispositionRegID: dropData},
			expected:    true,
		},
		{
			name:        "drop with deny mark in default table, e.g. Baseline Tier rule",
			tableID:     openflow.IngressDefaultTable.GetID(),
			disposition: openflow.DispositionDrop,
			regData:     map[int][]byte{dispositionRegID: dropWithDenyMarkData},
			expected:    false,
		},
		{
			name:        "drop without deny mark outside of default tables",
			tableID:     openflow.AntreaPolicyIngressRuleTable.GetID(),
			disposition: openflow.DispositionDrop,
			regData:     map[int][]byte{dispositionRegID: dropData},
			expected:    false,
		},
		{
			name:        "allow in default table",
			tableID:     openflow.IngressDefaultTable.GetID(),
			disposition: openflow.DispositionAllow,
			regData:     map[int][]byte{dispositionRegID: allowData},
			expected:    false,
		},
		{
			name:        "pass in default table",
			tableID:     openflow.IngressDefaultTable.GetID(),
			disposition: openflow.DispositionPass,
			regData:     map[int][]byte{dispositionRegID: passData},
			expected:    false,
		},
		{
			name:        "reject without deny mark in default table",
			tableID:     openflow.EgressDefaultTable.GetID(),
			disposition: openflow.DispositionRej,
			regData:     map[int][]byte{dispositionRegID: rejectData},
			expected:    true,
		},
		{
			name:        "no register in PacketIn",
			tableID:     openflow.IngressDefaultTable.GetID(),
			disposition: openflow.DispositionDrop,
			regData:     map[int][]byte{},
			expected:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pktIn := &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: tc.tableID,
					Match: openflow15.Match{
						Fields: generateRegMatches(tc.regData),
					},
				},
			}
			actual, err := isK8sDefaultDeny(pktIn.GetMatches(), tc.tableID, tc.disposition)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
