// Copyright 2019 Antrea Authors
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

package openflow

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	ovsoftest "antrea.io/antrea/pkg/ovs/openflow/testing"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	utilip "antrea.io/antrea/pkg/util/ip"
)

const bridgeName = "dummy-br"

var (
	bridgeMgmtAddr = binding.GetMgmtAddress(ovsconfig.DefaultOVSRunDir, bridgeName)
	gwMAC, _       = net.ParseMAC("AA:BB:CC:DD:EE:EE")
	gwIP, ipNet, _ = net.ParseCIDR("10.0.1.1/24")
	_, nodeIP, _   = net.ParseCIDR("192.168.77.100/24")
	gwIPv6, _, _   = net.ParseCIDR("f00d::b00:0:0:0/80")
	gatewayConfig  = &config.GatewayConfig{
		IPv4: gwIP,
		IPv6: gwIPv6,
		MAC:  gwMAC,
	}
	nodeConfig = &config.NodeConfig{
		GatewayConfig:   gatewayConfig,
		WireGuardConfig: &config.WireGuardConfig{},
		PodIPv4CIDR:     ipNet,
		NodeIPv4Addr:    nodeIP,
		Type:            config.K8sNode,
	}
	networkConfig = &config.NetworkConfig{IPv4Enabled: true}
	egressConfig  = &config.EgressConfig{}
	serviceConfig = &config.ServiceConfig{}
)

func installNodeFlows(ofClient Client, cacheKey string) (int, error) {
	hostName := cacheKey
	peerNodeIP := net.ParseIP("192.168.1.1")
	peerConfigs := map[*net.IPNet]net.IP{
		ipNet: gwIP,
	}
	err := ofClient.InstallNodeFlows(hostName, peerConfigs, &utilip.DualStackIPs{IPv4: peerNodeIP}, 0, nil)
	client := ofClient.(*client)
	fCacheI, ok := client.featurePodConnectivity.nodeCachedFlows.Load(hostName)
	if ok {
		return len(fCacheI.(flowCache)), err
	}
	return 0, err
}

func installPodFlows(ofClient Client, cacheKey string) (int, error) {
	containerID := cacheKey
	podMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
	podIP := net.ParseIP("10.0.0.2")
	ofPort := uint32(10)
	err := ofClient.InstallPodFlows(containerID, []net.IP{podIP}, podMAC, ofPort, 0)
	client := ofClient.(*client)
	fCacheI, ok := client.featurePodConnectivity.podCachedFlows.Load(containerID)
	if ok {
		return len(fCacheI.(flowCache)), err
	}
	return 0, err
}

// TestIdempotentFlowInstallation checks that InstallNodeFlows and InstallPodFlows are idempotent.
func TestIdempotentFlowInstallation(t *testing.T) {
	testCases := []struct {
		name      string
		cacheKey  string
		numFlows  int
		installFn func(ofClient Client, cacheKey string) (int, error)
	}{
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 5, installPodFlows},
	}

	// Check the flows are installed only once even though InstallNodeFlows/InstallPodFlows is called multiple times.
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := oftest.NewMockOFEntryOperations(ctrl)
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, false, false, false, false, false, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m
			client.nodeConfig = nodeConfig
			client.networkConfig = networkConfig
			client.egressConfig = egressConfig
			client.serviceConfig = serviceConfig
			client.ipProtocols = []binding.Protocol{binding.ProtocolIP}
			client.generatePipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			// Installing the flows should succeed, and all the flows should be added into the cache.
			numCached1, err := tc.installFn(ofClient, tc.cacheKey)
			require.Nil(t, err, "Error when installing Node flows")
			assert.Equal(t, tc.numFlows, numCached1)

			// Installing the same flows again must not return an error and should not
			// add additional flows to the cache.
			numCached2, err := tc.installFn(ofClient, tc.cacheKey)
			require.Nil(t, err, "Error when installing Node flows again")

			assert.Equal(t, numCached1, numCached2)
		})
	}

	// Check the flows could be installed successfully with retry, and all the flows are added into the flow cache only once.
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := oftest.NewMockOFEntryOperations(ctrl)
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, false, false, false, false, false, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m
			client.nodeConfig = nodeConfig
			client.networkConfig = networkConfig
			client.egressConfig = egressConfig
			client.serviceConfig = serviceConfig
			client.ipProtocols = []binding.Protocol{binding.ProtocolIP}
			client.generatePipelines()

			errorCall := m.EXPECT().AddAll(gomock.Any()).Return(errors.New("Bundle error")).Times(1)
			m.EXPECT().AddAll(gomock.Any()).Return(nil).After(errorCall)

			// Installing the flows failed at the first time, and no flow cache is created.
			numCached1, err := tc.installFn(ofClient, tc.cacheKey)
			require.NotNil(t, err, "Installing flows in bundle is expected to fail")
			assert.Equal(t, 0, numCached1)

			// Installing the same flows successfully at the second time, and add flows to the cache.
			numCached2, err := tc.installFn(ofClient, tc.cacheKey)
			require.Nil(t, err, "Error when installing Node flows again")

			assert.Equal(t, tc.numFlows, numCached2)
		})
	}
}

// TestFlowInstallationFailed checks that no flows are installed into the flow cache if InstallNodeFlows and InstallPodFlows fail.
func TestFlowInstallationFailed(t *testing.T) {
	testCases := []struct {
		name        string
		cacheKey    string
		numAddCalls int
		installFn   func(ofClient Client, cacheKey string) (int, error)
	}{
		{"NodeFlows", "host", 2, installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 5, installPodFlows},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := oftest.NewMockOFEntryOperations(ctrl)
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, false, false, false, false, false, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m
			client.nodeConfig = nodeConfig
			client.networkConfig = networkConfig
			client.egressConfig = egressConfig
			client.serviceConfig = serviceConfig
			client.ipProtocols = []binding.Protocol{binding.ProtocolIP}
			client.generatePipelines()

			// We generate an error for AddAll call.
			m.EXPECT().AddAll(gomock.Any()).Return(errors.New("Bundle error"))

			var err error
			var numCached int

			numCached, err = tc.installFn(ofClient, tc.cacheKey)
			require.NotNil(t, err, "Installing flows is expected to fail")
			assert.Equal(t, 0, numCached)
		})
	}
}

// TestConcurrentFlowInstallation checks that flow installation for a given flow category (e.g. Node
// flows) and for different cache keys (e.g. different Node hostnames) can happen concurrently.
func TestConcurrentFlowInstallation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cacheKeyFormat string
		fn             func(ofClient Client, cacheKey string) (int, error)
	}{
		{"NodeFlows", "host-%d", installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-ddd%d", installPodFlows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := oftest.NewMockOFEntryOperations(ctrl)
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, false, false, false, false, false, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m
			client.nodeConfig = nodeConfig
			client.networkConfig = networkConfig
			client.egressConfig = egressConfig
			client.serviceConfig = serviceConfig
			client.ipProtocols = []binding.Protocol{binding.ProtocolIP}
			client.generatePipelines()

			var concurrentCalls atomic.Value // set to true if we observe concurrent calls
			timeoutCh := make(chan struct{})
			rendezvousCh := make(chan struct{})
			m.EXPECT().AddAll(gomock.Any()).DoAndReturn(func(args ...interface{}) error {
				select {
				case <-timeoutCh:
				case <-rendezvousCh:
					concurrentCalls.Store(true)
				case rendezvousCh <- struct{}{}:
				}
				return nil
			}).AnyTimes()

			var wg sync.WaitGroup
			done := make(chan struct{})

			for i := 0; i < 2; i++ {
				wg.Add(1)
				cacheKey := fmt.Sprintf(tc.cacheKeyFormat, i)
				go func() {
					defer wg.Done()
					_, _ = tc.fn(ofClient, cacheKey) // in mock we trust
				}()
			}
			go func() {
				defer close(done)
				wg.Wait()
			}()

			select {
			case <-time.After(time.Second):
				close(timeoutCh)
				t.Fatal("timeoutCh, maybe there are some deadlocks")
			case <-done:
				assert.True(t, concurrentCalls.Load().(bool))
			}
		})
	}

}

func Test_client_InstallTraceflowFlows(t *testing.T) {
	type fields struct {
	}
	type args struct {
		dataplaneTag uint8
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantErr     bool
		prepareFunc func(*gomock.Controller) *client
	}{
		{
			name:        "traceflow flow",
			fields:      fields{},
			args:        args{dataplaneTag: 1},
			wantErr:     false,
			prepareFunc: prepareTraceflowFlow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			c := tt.prepareFunc(ctrl)
			if err := c.InstallTraceflowFlows(tt.args.dataplaneTag, false, false, false, nil, 0, 300); (err != nil) != tt.wantErr {
				t.Errorf("InstallTraceflowFlows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_client_SendTraceflowPacket(t *testing.T) {
	type args struct {
		dataplaneTag uint8
		binding.Packet
		inPort  uint32
		outPort int32
	}
	srcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	dstMAC, _ := net.ParseMAC("11:22:33:44:55:77")
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "IPv4 ICMP",
			args: args{
				Packet: binding.Packet{
					SourceMAC:      srcMAC,
					DestinationMAC: dstMAC,
					SourceIP:       net.ParseIP("1.2.3.4"),
					DestinationIP:  net.ParseIP("1.2.3.5"),
					IPProto:        1,
					TTL:            64,
				},
			},
		},
		{
			name: "IPv4 TCP",
			args: args{
				Packet: binding.Packet{
					SourceMAC:      srcMAC,
					DestinationMAC: dstMAC,
					SourceIP:       net.ParseIP("1.2.3.4"),
					DestinationIP:  net.ParseIP("1.2.3.5"),
					IPProto:        6,
					TTL:            64,
				},
			},
		},
		{
			name: "IPv4 UDP",
			args: args{
				Packet: binding.Packet{
					SourceMAC:      srcMAC,
					DestinationMAC: dstMAC,
					SourceIP:       net.ParseIP("1.2.3.4"),
					DestinationIP:  net.ParseIP("1.2.3.5"),
					IPProto:        17,
					TTL:            64,
				},
			},
		},
		{
			name: "IPv6 ICMPv6",
			args: args{
				Packet: binding.Packet{
					SourceMAC:      srcMAC,
					DestinationMAC: dstMAC,
					SourceIP:       net.ParseIP("1111::4444"),
					DestinationIP:  net.ParseIP("1111::5555"),
					IPProto:        58,
					TTL:            64,
				},
				outPort: -1,
			},
		},
		{
			name: "IPv6 TCP",
			args: args{
				Packet: binding.Packet{
					SourceMAC:      srcMAC,
					DestinationMAC: dstMAC,
					SourceIP:       net.ParseIP("1111::4444"),
					DestinationIP:  net.ParseIP("1111::5555"),
					IPProto:        6,
					TTL:            64,
				},
			},
		},
		{
			name: "IPv6 UDP",
			args: args{
				Packet: binding.Packet{
					SourceMAC:      srcMAC,
					DestinationMAC: dstMAC,
					SourceIP:       net.ParseIP("1111::4444"),
					DestinationIP:  net.ParseIP("1111::5555"),
					IPProto:        17,
					TTL:            64,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			c := prepareSendTraceflowPacket(ctrl, !tt.wantErr)
			if err := c.SendTraceflowPacket(tt.args.dataplaneTag, &tt.args.Packet, tt.args.inPort, tt.args.outPort); (err != nil) != tt.wantErr {
				t.Errorf("SendTraceflowPacket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func prepareTraceflowFlow(ctrl *gomock.Controller) *client {
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, true, false, false, false, false, false)
	c := ofClient.(*client)
	c.cookieAllocator = cookie.NewAllocator(0)
	c.nodeConfig = nodeConfig
	m := oftest.NewMockOFEntryOperations(ctrl)
	c.ofEntryOperations = m
	c.nodeConfig = nodeConfig
	c.networkConfig = networkConfig
	c.egressConfig = egressConfig
	c.serviceConfig = serviceConfig
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
	c.generatePipelines()

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
	c.bridge = ovsoftest.NewMockBridge(ctrl)

	mFlow := ovsoftest.NewMockFlow(ctrl)
	ctx := &conjMatchFlowContext{dropFlow: mFlow}
	mFlow.EXPECT().FlowProtocol().Return(binding.Protocol("ip"))
	mFlow.EXPECT().CopyToBuilder(priorityNormal+2, false).Return(EgressDefaultTable.ofTable.BuildFlow(priorityNormal + 2)).Times(1)
	c.featureNetworkPolicy.globalConjMatchFlowCache["mockContext"] = ctx
	c.featureNetworkPolicy.policyCache.Add(&policyRuleConjunction{metricFlows: []binding.Flow{c.featureNetworkPolicy.denyRuleMetricFlow(123, false)}})
	return c
}

func prepareSendTraceflowPacket(ctrl *gomock.Controller, success bool) *client {
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, true, false, false, false, false, false)
	c := ofClient.(*client)
	c.nodeConfig = nodeConfig
	m := ovsoftest.NewMockBridge(ctrl)
	c.bridge = m
	bridge := binding.OFBridge{}
	m.EXPECT().BuildPacketOut().Return(bridge.BuildPacketOut()).Times(1)
	if success {
		m.EXPECT().SendPacketOut(gomock.Any()).Times(1)
	}
	return c
}

func Test_client_setBasePacketOutBuilder(t *testing.T) {
	type args struct {
		srcMAC  string
		dstMAC  string
		srcIP   string
		dstIP   string
		inPort  uint32
		outPort uint32
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "err invalidSrcMAC",
			args: args{
				srcMAC: "invalidMAC",
				dstMAC: "11:22:33:44:55:66",
			},
			wantErr: true,
		},
		{
			name: "err invalidDstMAC",
			args: args{
				srcMAC: "11:22:33:44:55:66",
				dstMAC: "invalidMAC",
			},
			wantErr: true,
		},
		{
			name: "err invalidSrcIP",
			args: args{
				srcMAC: "11:22:33:44:55:66",
				dstMAC: "11:22:33:44:55:77",
				srcIP:  "invalidIP",
				dstIP:  "1.2.3.4",
			},
			wantErr: true,
		},
		{
			name: "err invalidDstIP",
			args: args{
				srcMAC: "11:22:33:44:55:66",
				dstMAC: "11:22:33:44:55:77",
				srcIP:  "1.2.3.4",
				dstIP:  "invalidIP",
			},
			wantErr: true,
		},
		{
			name: "err IPVersionMismatch",
			args: args{
				srcMAC: "11:22:33:44:55:66",
				dstMAC: "11:22:33:44:55:77",
				srcIP:  "1.2.3.4",
				dstIP:  "1111::5555",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			c := prepareSetBasePacketOutBuilder(ctrl, !tt.wantErr)
			_, err := setBasePacketOutBuilder(c.bridge.BuildPacketOut(), tt.args.srcMAC, tt.args.dstMAC, tt.args.srcIP, tt.args.dstIP, tt.args.inPort, tt.args.outPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("setBasePacketOutBuilder() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func prepareSetBasePacketOutBuilder(ctrl *gomock.Controller, success bool) *client {
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, true, true, false, false, false, false, false)
	c := ofClient.(*client)
	m := ovsoftest.NewMockBridge(ctrl)
	c.bridge = m
	bridge := binding.OFBridge{}
	m.EXPECT().BuildPacketOut().Return(bridge.BuildPacketOut()).Times(1)
	if success {
		m.EXPECT().SendPacketOut(gomock.Any()).Times(1)
	}
	return c
}
