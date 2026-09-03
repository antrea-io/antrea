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

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
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
					SessionState: gobgpapi.PeerState_SESSION_STATE_ESTABLISHED,
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
					SessionState: gobgpapi.PeerState_SESSION_STATE_IDLE,
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

func TestConvertRouteTypeToGoBGPTableType(t *testing.T) {
	tableType := convertRouteTypeToGoBGPTableType(bgp.RouteAdvertised)
	assert.Equal(t, gobgpapi.TableType_TABLE_TYPE_ADJ_OUT, tableType)

	tableType = convertRouteTypeToGoBGPTableType(bgp.RouteReceived)
	assert.Equal(t, gobgpapi.TableType_TABLE_TYPE_ADJ_IN, tableType)
}

func TestConvertRouteToNativePath(t *testing.T) {
	route4 := &bgp.Route{Prefix: "192.168.0.0/24"}
	path4, err := convertRouteToNativePath(route4)
	require.NoError(t, err)

	assert.Equal(t, "192.168.0.0/24", path4.Nlri.String())
	assert.Equal(t, uint16(gobgpapi.Family_AFI_IP), path4.Family.Afi())

	route6 := &bgp.Route{Prefix: "2001:db8::/64"}
	path6, err := convertRouteToNativePath(route6)
	require.NoError(t, err)

	assert.Equal(t, "2001:db8::/64", path6.Nlri.String())
	assert.Equal(t, uint16(gobgpapi.Family_AFI_IP6), path6.Family.Afi())

	_, err = convertRouteToNativePath(&bgp.Route{Prefix: "invalid"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid route prefix")
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
	assert.True(t, peer.GetGracefulRestart().GetEnabled())
	// No timer is configured, so the BGP process is left to apply its own defaults.
	assert.Nil(t, peer.GetTimers())
}

func TestConvertPeerConfigToGoBGPPeerTimers(t *testing.T) {
	tests := []struct {
		name           string
		peer           *v1alpha1.BGPPeer
		expectedTimers *gobgpapi.TimersConfig
	}{
		{
			name: "no timer configured",
			peer: &v1alpha1.BGPPeer{Address: "192.168.0.1", ASN: 65000},
		},
		{
			name: "all timers configured",
			peer: &v1alpha1.BGPPeer{
				Address:                       "192.168.0.1",
				ASN:                           65000,
				HoldTimeSeconds:               ptr.To(int32(30)),
				KeepaliveIntervalSeconds:      ptr.To(int32(10)),
				ConnectRetrySeconds:           ptr.To(int32(15)),
				IdleHoldTimeAfterResetSeconds: ptr.To(int32(20)),
			},
			expectedTimers: &gobgpapi.TimersConfig{
				HoldTime:               30,
				KeepaliveInterval:      10,
				ConnectRetry:           15,
				IdleHoldTimeAfterReset: 20,
			},
		},
		{
			name: "only the hold time configured",
			peer: &v1alpha1.BGPPeer{
				Address:         "192.168.0.1",
				ASN:             65000,
				HoldTimeSeconds: ptr.To(int32(30)),
			},
			// The keepalive interval is left unset so that the BGP process derives it from the hold time.
			expectedTimers: &gobgpapi.TimersConfig{HoldTime: 30},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer, err := convertPeerConfigToGoBGPPeer(bgp.PeerConfig{BGPPeer: tt.peer})
			require.NoError(t, err)
			if tt.expectedTimers == nil {
				assert.Nil(t, peer.GetTimers())
				return
			}
			require.NotNil(t, peer.GetTimers())
			assert.Equal(t, tt.expectedTimers.GetHoldTime(), peer.GetTimers().GetConfig().GetHoldTime())
			assert.Equal(t, tt.expectedTimers.GetKeepaliveInterval(), peer.GetTimers().GetConfig().GetKeepaliveInterval())
			assert.Equal(t, tt.expectedTimers.GetConnectRetry(), peer.GetTimers().GetConfig().GetConnectRetry())
			assert.Equal(t, tt.expectedTimers.GetIdleHoldTimeAfterReset(), peer.GetTimers().GetConfig().GetIdleHoldTimeAfterReset())
		})
	}
}

func TestConvertPeerConfigToGoBGPPeerGracefulRestart(t *testing.T) {
	tests := []struct {
		name                string
		peer                *v1alpha1.BGPPeer
		expectedEnabled     bool
		expectedRestartTime uint32
	}{
		{
			name:                "enabled by default",
			peer:                &v1alpha1.BGPPeer{Address: "192.168.0.1", ASN: 65000, GracefulRestartTimeSeconds: ptr.To(int32(120))},
			expectedEnabled:     true,
			expectedRestartTime: 120,
		},
		{
			name:                "explicitly enabled",
			peer:                &v1alpha1.BGPPeer{Address: "192.168.0.1", ASN: 65000, GracefulRestartEnabled: ptr.To(true), GracefulRestartTimeSeconds: ptr.To(int32(180))},
			expectedEnabled:     true,
			expectedRestartTime: 180,
		},
		{
			name: "disabled, so the restart time is ignored",
			peer: &v1alpha1.BGPPeer{Address: "192.168.0.1", ASN: 65000, GracefulRestartEnabled: ptr.To(false), GracefulRestartTimeSeconds: ptr.To(int32(120))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer, err := convertPeerConfigToGoBGPPeer(bgp.PeerConfig{BGPPeer: tt.peer})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedEnabled, peer.GetGracefulRestart().GetEnabled())
			assert.Equal(t, tt.expectedRestartTime, peer.GetGracefulRestart().GetRestartTime())
		})
	}
}

func TestConvertGoBGPSessionStateToSessionState(t *testing.T) {
	tests := []struct {
		input    gobgpapi.PeerState_SessionState
		expected bgp.SessionState
	}{
		{gobgpapi.PeerState_SESSION_STATE_UNSPECIFIED, bgp.SessionUnknown},
		{gobgpapi.PeerState_SESSION_STATE_IDLE, bgp.SessionIdle},
		{gobgpapi.PeerState_SESSION_STATE_CONNECT, bgp.SessionConnect},
		{gobgpapi.PeerState_SESSION_STATE_ACTIVE, bgp.SessionActive},
		{gobgpapi.PeerState_SESSION_STATE_OPENSENT, bgp.SessionOpenSent},
		{gobgpapi.PeerState_SESSION_STATE_OPENCONFIRM, bgp.SessionOpenConfirm},
		{gobgpapi.PeerState_SESSION_STATE_ESTABLISHED, bgp.SessionEstablished},
		{gobgpapi.PeerState_SessionState(999), bgp.SessionUnknown},
	}

	for _, test := range tests {
		output := convertGoBGPSessionStateToSessionState(test.input)
		assert.Equal(t, test.expected, output)
	}
}
