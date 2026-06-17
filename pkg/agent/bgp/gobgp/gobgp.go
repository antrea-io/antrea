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

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
	"k8s.io/utils/net"

	"antrea.io/antrea/v2/pkg/agent/bgp"
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
	logger, levelVar := newGoBGPLogger(globalConfig.RouterID)
	s := &Server{
		server: server.NewBgpServer(server.LoggerOption(logger, levelVar)),
		globalConfig: &gobgpapi.Global{
			Asn:             globalConfig.ASN,
			RouterId:        globalConfig.RouterID,
			ListenPort:      globalConfig.ListenPort,
			ListenAddresses: globalConfig.ListenAddresses,
		},
	}
	if globalConfig.Confederation != nil {
		s.globalConfig.Confederation = &gobgpapi.Confederation{
			Enabled:      true,
			Identifier:   globalConfig.Confederation.Identifier,
			MemberAsList: globalConfig.Confederation.MemberASNs,
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
		if err := ctx.Err(); err != nil {
			return err
		}
		path, err := convertRouteToNativePath(&routes[i])
		if err != nil {
			return err
		}
		request := apiutil.AddPathRequest{
			Paths: []*apiutil.Path{path},
		}
		if _, err := s.server.AddPath(request); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) WithdrawRoutes(ctx context.Context, routes []bgp.Route) error {
	for i := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		path, err := convertRouteToNativePath(&routes[i])
		if err != nil {
			return err
		}
		request := apiutil.DeletePathRequest{
			Paths: []*apiutil.Path{path},
		}
		if err := s.server.DeletePath(request); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) GetRoutes(ctx context.Context, routeType bgp.RouteType, peerAddress string) ([]bgp.Route, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isValidIPString(peerAddress) {
		return nil, fmt.Errorf("invalid peer address: %s", peerAddress)
	}
	var routes []bgp.Route
	fn := func(prefix gobgp.NLRI, _ []*apiutil.Path) {
		routes = append(routes, bgp.Route{Prefix: prefix.String()})
	}
	request := apiutil.ListPathRequest{
		TableType: convertRouteTypeToGoBGPTableType(routeType),
		Family:    gobgp.NewFamily(uint16(convertToGoBGPFamilyAfi(net.IsIPv6String(peerAddress))), uint8(gobgpapi.Family_SAFI_UNICAST)),
		Name:      peerAddress,
	}
	if err := s.server.ListPath(request, fn); err != nil {
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

func convertRouteTypeToGoBGPTableType(routeType bgp.RouteType) gobgpapi.TableType {
	if routeType == bgp.RouteAdvertised {
		return gobgpapi.TableType_TABLE_TYPE_ADJ_OUT
	}
	return gobgpapi.TableType_TABLE_TYPE_ADJ_IN
}

func convertRouteToNativePath(route *bgp.Route) (*apiutil.Path, error) {
	isIPv6 := net.IsIPv6CIDRString(route.Prefix)
	prefix, err := netip.ParsePrefix(route.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid route prefix %q: %w", route.Prefix, err)
	}
	nlri, err := gobgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create NLRI for prefix %q: %w", route.Prefix, err)
	}

	attrs := []gobgp.PathAttributeInterface{
		gobgp.NewPathAttributeOrigin(0),
	}
	family := gobgp.NewFamily(uint16(convertToGoBGPFamilyAfi(isIPv6)), uint8(gobgpapi.Family_SAFI_UNICAST))
	if isIPv6 {
		mpreach, err := gobgp.NewPathAttributeMpReachNLRI(family, []gobgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(ipv6AllZero))
		if err != nil {
			return nil, fmt.Errorf("failed to create MP_REACH_NLRI attribute for prefix %q: %w", route.Prefix, err)
		}
		attrs = append(attrs, mpreach)
	} else {
		nh, err := gobgp.NewPathAttributeNextHop(netip.MustParseAddr(ipv4AllZero))
		if err != nil {
			return nil, fmt.Errorf("failed to create NEXT_HOP attribute for prefix %q: %w", route.Prefix, err)
		}
		attrs = append(attrs, nh)
	}

	return &apiutil.Path{
		Family: family,
		Nlri:   nlri,
		Attrs:  attrs,
	}, nil
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
		Transport: &gobgpapi.Transport{
			LocalAddress: peerConfig.LocalAddress,
		},
	}
	if peerConfig.ConnectionMode == bgp.ConnectionModePassive {
		peer.Transport.PassiveMode = true
	}
	// The following pointer fields are set to default values when the corresponding BGPPolicy is created, so they
	// should not be nil. However, it is safe and harmless to include nil checks.
	if peerConfig.Port != nil {
		peer.Transport.RemotePort = uint32(*peerConfig.Port)
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
	case gobgpapi.PeerState_SESSION_STATE_UNSPECIFIED:
		return bgp.SessionUnknown
	case gobgpapi.PeerState_SESSION_STATE_IDLE:
		return bgp.SessionIdle
	case gobgpapi.PeerState_SESSION_STATE_CONNECT:
		return bgp.SessionConnect
	case gobgpapi.PeerState_SESSION_STATE_ACTIVE:
		return bgp.SessionActive
	case gobgpapi.PeerState_SESSION_STATE_OPENSENT:
		return bgp.SessionOpenSent
	case gobgpapi.PeerState_SESSION_STATE_OPENCONFIRM:
		return bgp.SessionOpenConfirm
	case gobgpapi.PeerState_SESSION_STATE_ESTABLISHED:
		return bgp.SessionEstablished
	default:
		return bgp.SessionUnknown
	}
}

func isValidIPString(ip string) bool {
	return net.IsIPv6String(ip) || net.IsIPv4String(ip)
}
