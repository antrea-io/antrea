// Copyright 2024 Antrea Authors
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

package gobgp

import (
	"testing"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/bgp"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestConvertGoBGPPeerToPeerStatus(t *testing.T) {
	tests := []struct {
		name     string
		peer     *gobgpapi.Peer
		expected *bgp.PeerStatus
	}{
		{
			name:     "Nil peer",
			peer:     nil,
			expected: nil,
		},
		{
			name: "Established peer",
			peer: &gobgpapi.Peer{
				Conf: &gobgpapi.PeerConf{
					NeighborAddress: "192.168.1.1",
					PeerAsn:         65001,
				},
				Transport: &gobgpapi.Transport{
					RemotePort: 179,
				},
				EbgpMultihop: &gobgpapi.EbgpMultihop{
					MultihopTtl: 1,
				},
				GracefulRestart: &gobgpapi.GracefulRestart{
					RestartTime: 120,
				},
				State: &gobgpapi.PeerState{
					SessionState: gobgpapi.PeerState_ESTABLISHED,
				},
				Timers: &gobgpapi.Timers{
					State: &gobgpapi.TimersState{
						Uptime: &timestamppb.Timestamp{Seconds: time.Now().Unix() - 3600},
					},
				},
			},
			expected: &bgp.PeerStatus{
				Address:                    "192.168.1.1",
				ASN:                        65001,
				Port:                       179,
				MultihopTTL:                1,
				GracefulRestartTimeSeconds: 120,
				SessionState:               bgp.SessionEstablished,
				UptimeSeconds:              3600,
			},
		},
		{
			name: "Idle peer",
			peer: &gobgpapi.Peer{
				Conf: &gobgpapi.PeerConf{
					NeighborAddress: "192.168.1.1",
					PeerAsn:         65001,
				},
				Transport: &gobgpapi.Transport{
					RemotePort: 179,
				},
				State: &gobgpapi.PeerState{
					SessionState: gobgpapi.PeerState_IDLE,
				},
			},

			expected: &bgp.PeerStatus{
				Address:      "192.168.1.1",
				ASN:          65001,
				Port:         179,
				SessionState: bgp.SessionIdle,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := convertGoBGPPeerToPeerStatus(tt.peer)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestConvertGoBGPDestinationToRoute(t *testing.T) {
	tests := []struct {
		name        string
		destination *gobgpapi.Destination
		expected    *bgp.Route
	}{
		{
			name:        "Nil destination",
			destination: nil,
			expected:    nil,
		},
		{
			name: "Valid destination",
			destination: &gobgpapi.Destination{
				Prefix: "192.168.1.0/24",
			},
			expected: &bgp.Route{
				Prefix: "192.168.1.0/24",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := convertGoBGPDestinationToRoute(tt.destination)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestConvertRouteTypeToGoBGPTableType(t *testing.T) {
	tableType := convertRouteTypeToGoBGPTableType(bgp.RouteAdvertised)
	assert.Equal(t, gobgpapi.TableType_ADJ_OUT, tableType)

	tableType = convertRouteTypeToGoBGPTableType(bgp.RouteReceived)
	assert.Equal(t, gobgpapi.TableType_ADJ_IN, tableType)
}

func TestConvertRouteToGoBGPPath(t *testing.T) {
	route4 := &bgp.Route{Prefix: "192.168.0.0/24"}
	path4 := convertRouteToGoBGPPath(route4)

	ipAddressPrefix4 := &gobgpapi.IPAddressPrefix{}
	assert.NoError(t, path4.GetNlri().UnmarshalTo(ipAddressPrefix4))
	assert.Equal(t, "192.168.0.0", ipAddressPrefix4.Prefix)
	assert.Equal(t, uint32(24), ipAddressPrefix4.PrefixLen)
	assert.Equal(t, gobgpapi.Family_AFI_IP, path4.GetFamily().Afi)

	route6 := &bgp.Route{Prefix: "2001:db8::/64"}
	path6 := convertRouteToGoBGPPath(route6)

	ipAddressPrefix6 := &gobgpapi.IPAddressPrefix{}
	assert.NoError(t, path6.GetNlri().UnmarshalTo(ipAddressPrefix6))
	assert.Equal(t, "2001:db8::", ipAddressPrefix6.Prefix)
	assert.Equal(t, uint32(64), ipAddressPrefix6.PrefixLen)
	assert.Equal(t, gobgpapi.Family_AFI_IP6, path6.GetFamily().Afi)
}

func TestConvertPeerConfigToGoBGPPeer(t *testing.T) {
	peerConfig := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "192.168.0.1",
			ASN:                        65000,
			Port:                       ptr.To(int32(179)),
			MultihopTTL:                ptr.To(int32(2)),
			GracefulRestartTimeSeconds: ptr.To(int32(120)),
		},
		Password: "password",
	}

	peer, err := convertPeerConfigToGoBGPPeer(peerConfig)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.0.1", peer.GetConf().GetNeighborAddress())
	assert.Equal(t, uint32(65000), peer.GetConf().GetPeerAsn())
	assert.Equal(t, "password", peer.GetConf().GetAuthPassword())
	assert.Equal(t, uint32(179), peer.GetTransport().GetRemotePort())
	assert.Equal(t, uint32(2), peer.GetEbgpMultihop().GetMultihopTtl())
	assert.Equal(t, uint32(120), peer.GetGracefulRestart().GetRestartTime())

}

func TestConvertGoBGPSessionStateToSessionState(t *testing.T) {
	tests := []struct {
		input    gobgpapi.PeerState_SessionState
		expected bgp.SessionState
	}{
		{gobgpapi.PeerState_UNKNOWN, bgp.SessionUnknown},
		{gobgpapi.PeerState_IDLE, bgp.SessionIdle},
		{gobgpapi.PeerState_CONNECT, bgp.SessionConnect},
		{gobgpapi.PeerState_ACTIVE, bgp.SessionActive},
		{gobgpapi.PeerState_OPENSENT, bgp.SessionOpenSent},
		{gobgpapi.PeerState_OPENCONFIRM, bgp.SessionOpenConfirm},
		{gobgpapi.PeerState_ESTABLISHED, bgp.SessionEstablished},
		{gobgpapi.PeerState_SessionState(999), bgp.SessionUnknown},
	}

	for _, test := range tests {
		output := convertGoBGPSessionStateToSessionState(test.input)
		assert.Equal(t, test.expected, output)
	}
}
