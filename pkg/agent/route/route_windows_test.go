//go:build windows
// +build windows

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

package route

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/config"
	servicecidrtesting "antrea.io/antrea/pkg/agent/servicecidr/testing"
	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/agent/util/winnet"
	winnettesting "antrea.io/antrea/pkg/agent/util/winnet/testing"
	"antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	externalIPv4Addr1           = "1.1.1.1"
	externalIPv4Addr2           = "1.1.1.2"
	externalIPv4Addr1WithPrefix = externalIPv4Addr1 + "/32"
	externalIPv4Addr2WithPrefix = externalIPv4Addr2 + "/32"

	ipv4Route1 = generateRoute(ip.MustParseCIDR(externalIPv4Addr1WithPrefix), config.VirtualServiceIPv4, 10, winnet.MetricHigh)
	ipv4Route2 = generateRoute(ip.MustParseCIDR(externalIPv4Addr2WithPrefix), config.VirtualServiceIPv4, 10, winnet.MetricHigh)

	nodePort                    = uint16(30000)
	protocol                    = openflow.ProtocolTCP
	nodePortNetNatStaticMapping = &winnet.NetNatStaticMapping{
		Name:         antreaNatNodePort,
		ExternalIP:   net.ParseIP("0.0.0.0"),
		ExternalPort: nodePort,
		InternalIP:   config.VirtualNodePortDNATIPv4,
		InternalPort: nodePort,
		Protocol:     protocol,
	}
)

func TestSyncRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)

	nodeRoute1 := &winnet.Route{DestinationSubnet: ip.MustParseCIDR("192.168.1.0/24"), GatewayAddress: net.ParseIP("1.1.1.1")}
	nodeRoute2 := &winnet.Route{DestinationSubnet: ip.MustParseCIDR("192.168.2.0/24"), GatewayAddress: net.ParseIP("1.1.1.2")}
	serviceRoute1 := &winnet.Route{DestinationSubnet: ip.MustParseCIDR("169.254.0.253/32"), LinkIndex: 10}
	serviceRoute2 := &winnet.Route{DestinationSubnet: ip.MustParseCIDR("169.254.0.252/32"), GatewayAddress: net.ParseIP("169.254.0.253")}
	mockWinnet.EXPECT().ReplaceNetRoute(nodeRoute1)
	mockWinnet.EXPECT().ReplaceNetRoute(nodeRoute2)
	mockWinnet.EXPECT().ReplaceNetRoute(serviceRoute1)
	mockWinnet.EXPECT().ReplaceNetRoute(serviceRoute2)
	mockWinnet.EXPECT().ReplaceNetRoute(&winnet.Route{
		LinkIndex:         10,
		DestinationSubnet: ip.MustParseCIDR("192.168.0.0/24"),
		GatewayAddress:    net.IPv4zero,
		RouteMetric:       winnet.MetricDefault,
	})

	c := &Client{
		winnet:   mockWinnet,
		proxyAll: true,
		nodeConfig: &config.NodeConfig{
			GatewayConfig: &config.GatewayConfig{LinkIndex: 10, IPv4: net.ParseIP("192.168.0.1")},
			PodIPv4CIDR:   ip.MustParseCIDR("192.168.0.0/24"),
		},
	}
	c.nodeRoutes.Store("192.168.1.0/24", nodeRoute1)
	c.nodeRoutes.Store("192.168.2.0/24", nodeRoute2)
	c.serviceRoutes.Store("169.254.0.253/32", serviceRoute1)
	c.serviceRoutes.Store("169.254.0.252/32", serviceRoute2)

	assert.NoError(t, c.syncRoute())
}

func TestInitServiceIPRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	mockServiceCIDRProvider := servicecidrtesting.NewMockInterface(ctrl)
	c := &Client{
		winnet: mockWinnet,
		networkConfig: &config.NetworkConfig{
			TrafficEncapMode: config.TrafficEncapModeEncap,
			IPv4Enabled:      true,
		},
		nodeConfig: &config.NodeConfig{
			GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0", LinkIndex: 10},
		},
		serviceCIDRProvider: mockServiceCIDRProvider,
	}
	mockWinnet.EXPECT().ReplaceNetRoute(generateRoute(virtualServiceIPv4Net, net.IPv4zero, 10, winnet.MetricHigh))
	mockWinnet.EXPECT().ReplaceNetRoute(generateRoute(virtualNodePortDNATIPv4Net, config.VirtualServiceIPv4, 10, winnet.MetricHigh))
	mockWinnet.EXPECT().ReplaceNetNeighbor(generateNeigh(config.VirtualServiceIPv4, 10))
	mockServiceCIDRProvider.EXPECT().AddEventHandler(gomock.Any())
	assert.NoError(t, c.initServiceIPRoutes())
}

func TestReconcile(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	c := &Client{
		winnet:        mockWinnet,
		proxyAll:      true,
		networkConfig: &config.NetworkConfig{},
		nodeConfig: &config.NodeConfig{
			PodIPv4CIDR:   ip.MustParseCIDR("192.168.10.0/24"),
			GatewayConfig: &config.GatewayConfig{LinkIndex: 10},
		},
	}

	mockWinnet.EXPECT().RouteListFiltered(antreasyscall.AF_INET, &winnet.Route{LinkIndex: 10}, winnet.RT_FILTER_IF).Return([]winnet.Route{
		{DestinationSubnet: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 10},  // local podCIDR, should not be deleted.
		{DestinationSubnet: ip.MustParseCIDR("192.168.1.0/24"), LinkIndex: 10},   // existing podCIDR, should not be deleted.
		{DestinationSubnet: ip.MustParseCIDR("169.254.0.253/32"), LinkIndex: 10}, // service route, should not be deleted.
		{DestinationSubnet: ip.MustParseCIDR("192.168.11.0/24"), LinkIndex: 10},  // non-existing podCIDR, should be deleted.
	}, nil)

	podCIDRs := []string{"192.168.0.0/24", "192.168.1.0/24"}
	mockWinnet.EXPECT().RemoveNetRoute(&winnet.Route{DestinationSubnet: ip.MustParseCIDR("192.168.11.0/24"), LinkIndex: 10})
	assert.NoError(t, c.Reconcile(podCIDRs))
}

func TestAddRoutes(t *testing.T) {
	ipv4, nodeTransPortIPv4Addr, _ := net.ParseCIDR("172.16.10.2/24")
	nodeTransPortIPv4Addr.IP = ipv4

	tests := []struct {
		name                 string
		networkConfig        *config.NetworkConfig
		nodeConfig           *config.NodeConfig
		podCIDR              *net.IPNet
		nodeName             string
		nodeIP               net.IP
		nodeGwIP             net.IP
		expectedNetUtilCalls func(mockWinnet *winnettesting.MockInterfaceMockRecorder)
	}{
		{
			name: "encap IPv4",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("1.1.1.1"),
					LinkIndex: 10,
				},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:  ip.MustParseCIDR("192.168.10.0/24"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("1.1.1.10"),
			nodeGwIP: net.ParseIP("192.168.10.1"),
			expectedNetUtilCalls: func(mockWinnet *winnettesting.MockInterfaceMockRecorder) {
				mockWinnet.ReplaceNetRoute(&winnet.Route{
					GatewayAddress:    net.ParseIP("192.168.10.1"),
					DestinationSubnet: ip.MustParseCIDR("192.168.10.0/24"),
					LinkIndex:         10,
					RouteMetric:       winnet.MetricDefault,
				})
			},
		},
		{
			name: "noencap IPv4, direct routing",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("192.168.1.1"),
					LinkIndex: 10,
				},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:  ip.MustParseCIDR("192.168.10.0/24"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("172.16.10.3"), // In the same subnet as local Node IP.
			nodeGwIP: net.ParseIP("192.168.10.1"),
			expectedNetUtilCalls: func(mockWinnet *winnettesting.MockInterfaceMockRecorder) {
				mockWinnet.ReplaceNetRoute(&winnet.Route{
					GatewayAddress:    net.ParseIP("172.16.10.3"),
					DestinationSubnet: ip.MustParseCIDR("192.168.10.0/24"),
					RouteMetric:       winnet.MetricDefault,
				})
			},
		},
		{
			name: "noencap IPv4, no direct routing",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("192.168.1.1"),
					LinkIndex: 10,
				},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:              ip.MustParseCIDR("192.168.10.0/24"),
			nodeName:             "node0",
			nodeIP:               net.ParseIP("172.16.11.3"), // In different subnet from local Node IP.
			nodeGwIP:             net.ParseIP("192.168.10.1"),
			expectedNetUtilCalls: func(mockWinnet *winnettesting.MockInterfaceMockRecorder) {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			netutil := winnettesting.NewMockInterface(ctrl)
			c := &Client{
				winnet:        netutil,
				networkConfig: tt.networkConfig,
				nodeConfig:    tt.nodeConfig,
			}
			tt.expectedNetUtilCalls(netutil.EXPECT())
			assert.NoError(t, c.AddRoutes(tt.podCIDR, tt.nodeName, tt.nodeIP, tt.nodeGwIP))
		})
	}
}

func TestDeleteRoutes(t *testing.T) {
	existingNodeRoutes := map[string]*winnet.Route{
		"192.168.10.0/24": {GatewayAddress: net.ParseIP("172.16.10.3"), DestinationSubnet: ip.MustParseCIDR("192.168.10.0/24")},
		"192.168.11.0/24": {GatewayAddress: net.ParseIP("172.16.10.4"), DestinationSubnet: ip.MustParseCIDR("192.168.11.0/24")},
	}
	podCIDR := ip.MustParseCIDR("192.168.10.0/24")
	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	c := &Client{
		winnet:     mockWinnet,
		nodeRoutes: sync.Map{},
	}
	for podCIDRStr, nodeRoute := range existingNodeRoutes {
		c.nodeRoutes.Store(podCIDRStr, nodeRoute)
	}
	mockWinnet.EXPECT().RemoveNetRoute(&winnet.Route{GatewayAddress: net.ParseIP("172.16.10.3"), DestinationSubnet: ip.MustParseCIDR("192.168.10.0/24")})
	assert.NoError(t, c.DeleteRoutes(podCIDR))
}

func TestAddNodePortConf(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	c := &Client{
		winnet: mockWinnet,
	}
	mockWinnet.EXPECT().ReplaceNetNatStaticMapping(nodePortNetNatStaticMapping)
	assert.NoError(t, c.AddNodePortConfigs(nil, nodePort, protocol))
}

func TestDeleteNodePortConf(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	c := &Client{
		winnet: mockWinnet,
	}
	c.netNatStaticMappings.Store(fmt.Sprintf("%d-%s", nodePort, protocol), nodePortNetNatStaticMapping)
	mockWinnet.EXPECT().RemoveNetNatStaticMapping(nodePortNetNatStaticMapping)
	assert.NoError(t, c.DeleteNodePortConfigs(nil, nodePort, protocol))
}

func TestAddServiceCIDRRoute(t *testing.T) {
	nodeConfig := &config.NodeConfig{GatewayConfig: &config.GatewayConfig{LinkIndex: 10}}
	tests := []struct {
		name                 string
		curServiceIPv4CIDR   *net.IPNet
		newServiceIPv4CIDR   *net.IPNet
		expectedNetUtilCalls func(mockWinnet *winnettesting.MockInterfaceMockRecorder)
	}{
		{
			name:               "Add route for Service IPv4 CIDR",
			curServiceIPv4CIDR: nil,
			newServiceIPv4CIDR: ip.MustParseCIDR("10.96.0.1/32"),
			expectedNetUtilCalls: func(mockWinnet *winnettesting.MockInterfaceMockRecorder) {
				mockWinnet.ReplaceNetRoute(&winnet.Route{
					DestinationSubnet: &net.IPNet{IP: net.ParseIP("10.96.0.1").To4(), Mask: net.CIDRMask(32, 32)},
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
				mockWinnet.RouteListFiltered(antreasyscall.AF_INET, &winnet.Route{LinkIndex: 10}, winnet.RT_FILTER_IF).Return([]winnet.Route{
					{
						DestinationSubnet: ip.MustParseCIDR("10.96.0.0/24"),
						GatewayAddress:    config.VirtualServiceIPv4,
						RouteMetric:       winnet.MetricHigh,
						LinkIndex:         10,
					},
				}, nil)
				mockWinnet.RemoveNetRoute(&winnet.Route{
					DestinationSubnet: ip.MustParseCIDR("10.96.0.0/24"),
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
			},
		},
		{
			name:               "Add route for Service IPv4 CIDR and clean up stale routes",
			curServiceIPv4CIDR: nil,
			newServiceIPv4CIDR: ip.MustParseCIDR("10.96.0.0/28"),
			expectedNetUtilCalls: func(mockWinnet *winnettesting.MockInterfaceMockRecorder) {
				mockWinnet.ReplaceNetRoute(&winnet.Route{
					DestinationSubnet: &net.IPNet{IP: net.ParseIP("10.96.0.0").To4(), Mask: net.CIDRMask(28, 32)},
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
				mockWinnet.RouteListFiltered(antreasyscall.AF_INET, &winnet.Route{LinkIndex: 10}, winnet.RT_FILTER_IF).Return([]winnet.Route{
					{
						DestinationSubnet: ip.MustParseCIDR("10.96.0.0/24"),
						GatewayAddress:    config.VirtualServiceIPv4,
						RouteMetric:       winnet.MetricHigh,
						LinkIndex:         10,
					},
					{
						DestinationSubnet: ip.MustParseCIDR("10.96.0.0/30"),
						GatewayAddress:    config.VirtualServiceIPv4,
						RouteMetric:       winnet.MetricHigh,
						LinkIndex:         10,
					},
				}, nil)
				mockWinnet.RemoveNetRoute(&winnet.Route{
					DestinationSubnet: ip.MustParseCIDR("10.96.0.0/24"),
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
				mockWinnet.RemoveNetRoute(&winnet.Route{
					DestinationSubnet: ip.MustParseCIDR("10.96.0.0/30"),
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
			},
		},
		{
			name:               "Update route for Service IPv4 CIDR",
			curServiceIPv4CIDR: ip.MustParseCIDR("10.96.0.1/32"),
			newServiceIPv4CIDR: ip.MustParseCIDR("10.96.0.0/28"),
			expectedNetUtilCalls: func(mockWinnet *winnettesting.MockInterfaceMockRecorder) {
				mockWinnet.ReplaceNetRoute(&winnet.Route{
					DestinationSubnet: &net.IPNet{IP: net.ParseIP("10.96.0.0").To4(), Mask: net.CIDRMask(28, 32)},
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
				mockWinnet.RemoveNetRoute(&winnet.Route{
					DestinationSubnet: &net.IPNet{IP: net.ParseIP("10.96.0.1").To4(), Mask: net.CIDRMask(32, 32)},
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockWinnet := winnettesting.NewMockInterface(ctrl)
			c := &Client{
				winnet:     mockWinnet,
				nodeConfig: nodeConfig,
			}
			tt.expectedNetUtilCalls(mockWinnet.EXPECT())

			if tt.curServiceIPv4CIDR != nil {
				c.serviceRoutes.Store(serviceIPv4CIDRKey, &winnet.Route{
					DestinationSubnet: &net.IPNet{IP: net.ParseIP("10.96.0.1").To4(), Mask: net.CIDRMask(32, 32)},
					GatewayAddress:    config.VirtualServiceIPv4,
					RouteMetric:       winnet.MetricHigh,
					LinkIndex:         10,
				})
			}

			assert.NoError(t, c.addServiceCIDRRoute(tt.newServiceIPv4CIDR))
		})
	}
}

func TestAddExternalIPConfigs(t *testing.T) {
	svcToExternalIPs := map[string][]string{
		"svc1": {externalIPv4Addr1},
		"svc2": {externalIPv4Addr2},
		"svc3": {externalIPv4Addr1, externalIPv4Addr2},
	}
	expectedServiceExternalIPReferences := map[string]sets.Set[string]{
		externalIPv4Addr1: sets.New[string]("svc1", "svc3"),
		externalIPv4Addr2: sets.New[string]("svc2", "svc3"),
	}

	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	c := &Client{
		winnet:                      mockWinnet,
		serviceExternalIPReferences: make(map[string]sets.Set[string]),
		nodeConfig: &config.NodeConfig{
			GatewayConfig: &config.GatewayConfig{
				LinkIndex: 10,
			},
		},
	}
	mockWinnet.EXPECT().ReplaceNetRoute(ipv4Route1)
	mockWinnet.EXPECT().ReplaceNetRoute(ipv4Route2)

	for svcInfo, externalIPs := range svcToExternalIPs {
		for _, externalIP := range externalIPs {
			assert.NoError(t, c.AddExternalIPConfigs(svcInfo, net.ParseIP(externalIP)))
		}
	}
	assert.Equal(t, expectedServiceExternalIPReferences, c.serviceExternalIPReferences)
}

func TestDeleteExternalIPConfigs(t *testing.T) {
	svcToExternalIPs := map[string][]string{
		"svc1": {externalIPv4Addr1},
		"svc2": {externalIPv4Addr2},
		"svc3": {externalIPv4Addr1, externalIPv4Addr2},
	}

	ctrl := gomock.NewController(t)
	mockWinnet := winnettesting.NewMockInterface(ctrl)
	c := &Client{
		winnet: mockWinnet,
		serviceExternalIPReferences: map[string]sets.Set[string]{
			externalIPv4Addr1: sets.New[string]("svc1", "svc3"),
			externalIPv4Addr2: sets.New[string]("svc2", "svc3"),
		},
	}
	for ipStr, route := range map[string]*winnet.Route{externalIPv4Addr1: ipv4Route1, externalIPv4Addr2: ipv4Route2} {
		c.serviceRoutes.Store(ipStr, route)
	}

	mockWinnet.EXPECT().RemoveNetRoute(ipv4Route1)
	mockWinnet.EXPECT().RemoveNetRoute(ipv4Route2)
	for svcInfo, externalIPs := range svcToExternalIPs {
		for _, externalIP := range externalIPs {
			assert.NoError(t, c.DeleteExternalIPConfigs(svcInfo, net.ParseIP(externalIP)))
		}
	}
	assert.Equal(t, make(map[string]sets.Set[string]), c.serviceExternalIPReferences)
}
