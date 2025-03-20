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

package bgp

import (
	"context"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

// Interface defines the methods for managing a BGP (Border Gateway Protocol) process.
// Currently, only the goBGP implementation is available.
// More implementations might be added later.
type Interface interface {
	// Start starts the BGP process.
	Start(ctx context.Context) error

	// Stop terminates the BGP process.
	Stop(ctx context.Context) error

	// AddPeer adds a new BGP peer.
	AddPeer(ctx context.Context, peerConf PeerConfig) error

	// UpdatePeer updates an existing BGP peer.
	UpdatePeer(ctx context.Context, peerConf PeerConfig) error

	// RemovePeer removes a specified BGP peer.
	RemovePeer(ctx context.Context, peerConf PeerConfig) error

	// GetPeers retrieves the current status of all BGP peers.
	GetPeers(ctx context.Context) ([]PeerStatus, error)

	// AdvertiseRoutes announces the specified routes to all BGP peers.
	AdvertiseRoutes(ctx context.Context, routes []Route) error

	// WithdrawRoutes withdraws the specified routes from all BGP peers.
	WithdrawRoutes(ctx context.Context, routes []Route) error

	// GetRoutes retrieves the advertised / received routes to / from the given peer.
	GetRoutes(ctx context.Context, routeType RouteType, peerAddress string) ([]Route, error)
}

type Confederation struct {
	Identifier uint32
	Peers      []uint32
}

// GlobalConfig contains the global configuration to start a BGP server. More attributes might be added later.
type GlobalConfig struct {
	ASN           uint32
	RouterID      string
	ListenPort    int32
	Confederation *Confederation
}

type SessionState string

const (
	// SessionUnknown indicates an unknown BGP session state.
	SessionUnknown SessionState = "Unknown"
	// The following are the states of the BGP Finite State Machine.
	// For more details see https://datatracker.ietf.org/doc/html/rfc4271#section-8.2.2.
	SessionIdle        SessionState = "Idle"
	SessionConnect     SessionState = "Connect"
	SessionActive      SessionState = "Active"
	SessionOpenSent    SessionState = "OpenSent"
	SessionOpenConfirm SessionState = "OpenConfirm"
	SessionEstablished SessionState = "Established"
)

type RouteType int

const (
	RouteAdvertised RouteType = iota
	RouteReceived
)

// PeerConfig contains the configuration for a BGP peer. More attributes might be added later.
type PeerConfig struct {
	*v1alpha1.BGPPeer
	// Password is used to authenticate the BGP session with a BGP peer. This field holds the authentication password
	// required to establish a secure BGP connection. If the peer requires password-based authentication, this value
	// must be set to the appropriate password. Leaving this field empty will disable password authentication.
	Password string
}

// PeerStatus contains the status information for a BGP peer. More attributes related to status might be added later.
type PeerStatus struct {
	Address                    string
	Port                       int32
	ASN                        int32
	MultihopTTL                int32
	GracefulRestartTimeSeconds int32
	SessionState               SessionState
	UptimeSeconds              int
}

// Route represents a BGP route. Currently only prefix (e.g., "192.168.0.0/24") is needed. More attributes might be
// added later.
type Route struct {
	Prefix string
}
