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
	"context"
	"fmt"
	"net/netip"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/bgp"
)

const (
	ipv4AllZero = "0.0.0.0"
	ipv6AllZero = "::"
)

type Server struct {
	server       *server.BgpServer
	globalConfig *gobgpapi.Global
}

func NewGoBGPServer(globalConfig *bgp.GlobalConfig) *Server {
	s := &Server{
		server: server.NewBgpServer(server.LoggerOption(newGoBGPLogger())),
		globalConfig: &gobgpapi.Global{
			Asn:        globalConfig.ASN,
			RouterId:   globalConfig.RouterID,
			ListenPort: globalConfig.ListenPort,
		},
	}
	if globalConfig.Confederation != nil {
		s.globalConfig.Confederation = &gobgpapi.Confederation{
			Enabled:      true,
			Identifier:   globalConfig.Confederation.Identifier,
			MemberAsList: globalConfig.Confederation.Peers,
		}
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	go s.server.Serve()
	if err := s.server.StartBgp(ctx, &gobgpapi.StartBgpRequest{Global: s.globalConfig}); err != nil {
		return err
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if err := s.server.StopBgp(ctx, &gobgpapi.StopBgpRequest{}); err != nil {
		return err
	}
	return nil
}

func (s *Server) AddPeer(ctx context.Context, peerConf bgp.PeerConfig) error {
	peer, err := convertPeerConfigToGoBGPPeer(peerConf)
	if err != nil {
		return err
	}
	request := &gobgpapi.AddPeerRequest{Peer: peer}
	if err := s.server.AddPeer(ctx, request); err != nil {
		return err
	}
	return nil
}

func (s *Server) UpdatePeer(ctx context.Context, peerConf bgp.PeerConfig) error {
	peer, err := convertPeerConfigToGoBGPPeer(peerConf)
	if err != nil {
		return err
	}
	request := &gobgpapi.UpdatePeerRequest{Peer: peer}
	if _, err := s.server.UpdatePeer(ctx, request); err != nil {
		return err
	}
	return nil
}

func (s *Server) RemovePeer(ctx context.Context, peerConf bgp.PeerConfig) error {
	request := &gobgpapi.DeletePeerRequest{Address: peerConf.Address}
	if err := s.server.DeletePeer(ctx, request); err != nil {
		return err
	}
	return nil
}

func (s *Server) GetPeers(ctx context.Context) ([]bgp.PeerStatus, error) {
	var peerStatuses []bgp.PeerStatus
	fn := func(peer *gobgpapi.Peer) {
		peerStatus := convertGoBGPPeerToPeerStatus(peer)
		if peerStatus != nil {
			peerStatuses = append(peerStatuses, *peerStatus)
		}
	}
	request := &gobgpapi.ListPeerRequest{EnableAdvertised: true}
	if err := s.server.ListPeer(ctx, request, fn); err != nil {
		return peerStatuses, err
	}
	return peerStatuses, nil
}

func (s *Server) AdvertiseRoutes(ctx context.Context, routes []bgp.Route) error {
	for i := range routes {
		request := &gobgpapi.AddPathRequest{Path: convertRouteToGoBGPPath(&routes[i])}
		if _, err := s.server.AddPath(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) WithdrawRoutes(ctx context.Context, routes []bgp.Route) error {
	for i := range routes {
		request := &gobgpapi.DeletePathRequest{Path: convertRouteToGoBGPPath(&routes[i])}
		if err := s.server.DeletePath(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) GetRoutes(ctx context.Context, routeType bgp.RouteType, peerAddress string) ([]bgp.Route, error) {
	if !isValidIPString(peerAddress) {
		return nil, fmt.Errorf("invalid peer address: %s", peerAddress)
	}
	var routes []bgp.Route
	fn := func(destination *gobgpapi.Destination) {
		route := convertGoBGPDestinationToRoute(destination)
		if route != nil {
			routes = append(routes, *route)
		}
	}
	request := &gobgpapi.ListPathRequest{
		TableType: convertRouteTypeToGoBGPTableType(routeType),
		Family:    &gobgpapi.Family{Afi: convertToGoBGPFamilyAfi(net.IsIPv6String(peerAddress)), Safi: gobgpapi.Family_SAFI_UNICAST},
		Name:      peerAddress,
	}
	if err := s.server.ListPath(ctx, request, fn); err != nil {
		return nil, err
	}
	return routes, nil
}

func convertGoBGPPeerToPeerStatus(peer *gobgpapi.Peer) *bgp.PeerStatus {
	if peer == nil {
		return nil
	}
	peerStatus := &bgp.PeerStatus{}
	// According to the gobgp code, all pointer fields in `peer *gobgpapi.Peer` used below should be set and non-nil
	// when peers are listed. It's safe and harmless to keep the nil checks.
	if transport := peer.GetTransport(); transport != nil {
		peerStatus.Port = int32(transport.GetRemotePort())
	}
	if conf := peer.GetConf(); conf != nil {
		peerStatus.Address = conf.GetNeighborAddress()
		peerStatus.ASN = int32(conf.GetPeerAsn())
	}
	if ebgpMultiHop := peer.GetEbgpMultihop(); ebgpMultiHop != nil {
		peerStatus.MultihopTTL = int32(ebgpMultiHop.GetMultihopTtl())
	}
	if gracefulRestart := peer.GetGracefulRestart(); gracefulRestart != nil {
		peerStatus.GracefulRestartTimeSeconds = int32(gracefulRestart.GetRestartTime())
	}
	if state := peer.GetState(); state != nil {
		peerStatus.SessionState = convertGoBGPSessionStateToSessionState(state.GetSessionState())
		if peerStatus.SessionState == bgp.SessionEstablished {
			if timers := peer.GetTimers(); timers != nil {
				if timerState := timers.GetState(); timerState != nil {
					peerStatus.UptimeSeconds = int(time.Since(timerState.GetUptime().AsTime()).Seconds())
				}
			}
		}
	}
	return peerStatus
}

func convertGoBGPDestinationToRoute(destination *gobgpapi.Destination) *bgp.Route {
	if destination == nil {
		return nil
	}
	route := &bgp.Route{Prefix: destination.GetPrefix()}
	return route
}

func convertRouteTypeToGoBGPTableType(routeType bgp.RouteType) gobgpapi.TableType {
	if routeType == bgp.RouteAdvertised {
		return gobgpapi.TableType_ADJ_OUT
	}
	return gobgpapi.TableType_ADJ_IN
}

func convertRouteToGoBGPPath(route *bgp.Route) *gobgpapi.Path {
	isIPv6 := net.IsIPv6CIDRString(route.Prefix)
	goBGPIPFamily := convertToGoBGPFamilyAfi(isIPv6)
	prefix, _ := netip.ParsePrefix(route.Prefix)
	nlri, _ := anypb.New(&gobgpapi.IPAddressPrefix{
		Prefix:    prefix.Addr().String(),
		PrefixLen: uint32(prefix.Bits()),
	})

	var attrs []*anypb.Any
	a1, _ := anypb.New(&gobgpapi.OriginAttribute{
		Origin: 0,
	})
	var a2 *anypb.Any
	if isIPv6 {
		a2, _ = anypb.New(&gobgpapi.MpReachNLRIAttribute{
			Family:   &gobgpapi.Family{Afi: goBGPIPFamily, Safi: gobgpapi.Family_SAFI_UNICAST},
			NextHops: []string{ipv6AllZero},
			Nlris:    []*anypb.Any{nlri},
		})
	} else {
		a2, _ = anypb.New(&gobgpapi.NextHopAttribute{
			NextHop: ipv4AllZero,
		})
	}
	attrs = append(attrs, a1, a2)

	return &gobgpapi.Path{
		Family: &gobgpapi.Family{Afi: goBGPIPFamily, Safi: gobgpapi.Family_SAFI_UNICAST},
		Nlri:   nlri,
		Pattrs: attrs,
	}
}

func convertToGoBGPFamilyAfi(isIPv6 bool) gobgpapi.Family_Afi {
	if isIPv6 {
		return gobgpapi.Family_AFI_IP6
	}
	return gobgpapi.Family_AFI_IP
}

func convertPeerConfigToGoBGPPeer(peerConfig bgp.PeerConfig) (*gobgpapi.Peer, error) {
	// The following fields are required and are validated when the corresponding BGPPolicy is created.
	// Nonetheless, it is both safe and prudent to check them here as an additional safeguard.
	if !isValidIPString(peerConfig.Address) {
		return nil, fmt.Errorf("invalid peer address: %s", peerConfig.Address)
	}
	if peerConfig.ASN == 0 {
		return nil, fmt.Errorf("invalid peer ASN: %d", peerConfig.ASN)
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: peerConfig.Address,
			PeerAsn:         uint32(peerConfig.ASN),
			AuthPassword:    peerConfig.Password,
		},
		AfiSafis: []*gobgpapi.AfiSafi{
			{
				Config: &gobgpapi.AfiSafiConfig{
					Family: &gobgpapi.Family{
						Afi:  convertToGoBGPFamilyAfi(net.IsIPv6String(peerConfig.Address)),
						Safi: gobgpapi.Family_SAFI_UNICAST,
					},
					Enabled: true,
				},
				MpGracefulRestart: &gobgpapi.MpGracefulRestart{
					Config: &gobgpapi.MpGracefulRestartConfig{
						Enabled: true,
					},
				},
			},
		},
	}
	// The following pointer fields are set to default values when the corresponding BGPPolicy is created, so they
	// should not be nil. However, it is safe and harmless to include nil checks.
	if peerConfig.Port != nil {
		peer.Transport = &gobgpapi.Transport{
			RemotePort: uint32(*peerConfig.Port),
		}
	}
	if peerConfig.MultihopTTL != nil {
		peer.EbgpMultihop = &gobgpapi.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: uint32(*peerConfig.MultihopTTL),
		}
	}
	if peerConfig.GracefulRestartTimeSeconds != nil {
		peer.GracefulRestart = &gobgpapi.GracefulRestart{
			Enabled:     true,
			RestartTime: uint32(*peerConfig.GracefulRestartTimeSeconds),
		}
	}
	return peer, nil
}

func convertGoBGPSessionStateToSessionState(s gobgpapi.PeerState_SessionState) bgp.SessionState {
	switch s {
	case gobgpapi.PeerState_UNKNOWN:
		return bgp.SessionUnknown
	case gobgpapi.PeerState_IDLE:
		return bgp.SessionIdle
	case gobgpapi.PeerState_CONNECT:
		return bgp.SessionConnect
	case gobgpapi.PeerState_ACTIVE:
		return bgp.SessionActive
	case gobgpapi.PeerState_OPENSENT:
		return bgp.SessionOpenSent
	case gobgpapi.PeerState_OPENCONFIRM:
		return bgp.SessionOpenConfirm
	case gobgpapi.PeerState_ESTABLISHED:
		return bgp.SessionEstablished
	default:
		return bgp.SessionUnknown
	}
}

func isValidIPString(ip string) bool {
	return net.IsIPv6String(ip) || net.IsIPv4String(ip)
}
