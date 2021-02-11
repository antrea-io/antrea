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

	"github.com/contiv/ofnet/ofctrl"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	ofconfig "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	ovsoftest "github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const bridgeName = "dummy-br"

var bridgeMgmtAddr = ofconfig.GetMgmtAddress(ovsconfig.DefaultOVSRunDir, bridgeName)

func installNodeFlows(ofClient Client, cacheKey string) (int, error) {
	hostName := cacheKey
	gwIP, ipNet, _ := net.ParseCIDR("10.0.1.1/24")
	peerNodeIP := net.ParseIP("192.168.1.1")
	peerConfig := map[*net.IPNet]net.IP{
		ipNet: gwIP,
	}
	err := ofClient.InstallNodeFlows(hostName, peerConfig, peerNodeIP, 0)
	client := ofClient.(*client)
	fCacheI, ok := client.nodeFlowCache.Load(hostName)
	if ok {
		return len(fCacheI.(flowCache)), err
	} else {
		return 0, err
	}
}

func installPodFlows(ofClient Client, cacheKey string) (int, error) {
	containerID := cacheKey
	podMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
	podIP := net.ParseIP("10.0.0.2")
	ofPort := uint32(10)
	err := ofClient.InstallPodFlows(containerID, []net.IP{podIP}, podMAC, ofPort)
	client := ofClient.(*client)
	fCacheI, ok := client.podFlowCache.Load(containerID)
	if ok {
		return len(fCacheI.(flowCache)), err
	} else {
		return 0, err
	}
}

// TestIdempotentFlowInstallation checks that InstallNodeFlows and InstallPodFlows are idempotent.
func TestIdempotentFlowInstallation(t *testing.T) {
	testCases := []struct {
		name      string
		cacheKey  string
		numFlows  int
		installFn func(ofClient Client, cacheKey string) (int, error)
	}{
		{"NodeFlows", "host", 2, installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 5, installPodFlows},
	}

	// Check the flows are installed only once even though InstallNodeFlows/InstallPodFlows is called multiple times.
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := oftest.NewMockOFEntryOperations(ctrl)
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, true, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m

			gwMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
			gatewayConfig := &config.GatewayConfig{MAC: gwMAC}
			client.nodeConfig = &config.NodeConfig{GatewayConfig: gatewayConfig}

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
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, true, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m

			gwMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
			gatewayConfig := &config.GatewayConfig{MAC: gwMAC}
			client.nodeConfig = &config.NodeConfig{GatewayConfig: gatewayConfig}

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
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, true, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m

			gwMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
			gatewayConfig := &config.GatewayConfig{MAC: gwMAC}
			client.nodeConfig = &config.NodeConfig{GatewayConfig: gatewayConfig}

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
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, true, false)
			client := ofClient.(*client)
			client.cookieAllocator = cookie.NewAllocator(0)
			client.ofEntryOperations = m

			gwMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
			gatewayConfig := &config.GatewayConfig{MAC: gwMAC}
			client.nodeConfig = &config.NodeConfig{GatewayConfig: gatewayConfig}

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
	type ofSwitch struct {
		ofctrl.OFSwitch
	}
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
			if err := c.InstallTraceflowFlows(tt.args.dataplaneTag); (err != nil) != tt.wantErr {
				t.Errorf("InstallTraceflowFlows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_client_SendTraceflowPacket(t *testing.T) {
	type args struct {
		dataplaneTag uint8
		srcMAC       string
		dstMAC       string
		srcIP        string
		dstIP        string
		IPProtocol   uint8
		ttl          uint8
		IPFlags      uint16
		TCPSrcPort   uint16
		TCPDstPort   uint16
		TCPFlags     uint8
		UDPSrcPort   uint16
		UDPDstPort   uint16
		ICMPType     uint8
		ICMPCode     uint8
		ICMPID       uint16
		ICMPSequence uint16
		inPort       uint32
		outPort      int32
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "err noSrcMAC",
			args:    args{},
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
			name: "err noIP",
			args: args{
				srcMAC: "11:22:33:44:55:66",
				dstMAC: "11:22:33:44:55:77",
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
		{
			name: "IPv4 ICMP",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "11:22:33:44:55:77",
				srcIP:      "1.2.3.4",
				dstIP:      "1.2.3.5",
				ttl:        64,
				IPProtocol: 1,
			},
			wantErr: false,
		},
		{
			name: "IPv4 ICMP invalid",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "",
				srcIP:      "1.2.3.4",
				dstIP:      "1.2.3.5",
				ttl:        64,
				IPProtocol: 58,
				outPort:    -1,
			},
			wantErr: true,
		},
		{
			name: "IPv4 ICMP",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "",
				srcIP:      "1.2.3.4",
				dstIP:      "1.2.3.5",
				ttl:        64,
				IPProtocol: 1,
				outPort:    -1,
			},
			wantErr: false,
		},
		{
			name: "IPv4 TCP",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "11:22:33:44:55:77",
				srcIP:      "1.2.3.4",
				dstIP:      "1.2.3.5",
				IPProtocol: 6,
			},
			wantErr: false,
		},
		{
			name: "IPv4 UDP",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "11:22:33:44:55:77",
				srcIP:      "1.2.3.4",
				dstIP:      "1.2.3.5",
				IPProtocol: 17,
			},
			wantErr: false,
		},
		{
			name: "IPv6 ICMP invalid",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "",
				srcIP:      "1111::4444",
				dstIP:      "1111::5555",
				ttl:        64,
				IPProtocol: 1,
				outPort:    -1,
			},
			wantErr: true,
		},
		{
			name: "IPv6 ICMPv6",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "",
				srcIP:      "1111::4444",
				dstIP:      "1111::5555",
				ttl:        64,
				IPProtocol: 58,
				outPort:    -1,
			},
			wantErr: false,
		},
		{
			name: "IPv6 TCP",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "11:22:33:44:55:77",
				srcIP:      "1111::4444",
				dstIP:      "1111::5555",
				IPProtocol: 6,
			},
			wantErr: false,
		},
		{
			name: "IPv6 UDP",
			args: args{
				srcMAC:     "11:22:33:44:55:66",
				dstMAC:     "11:22:33:44:55:77",
				srcIP:      "1111::4444",
				dstIP:      "1111::5555",
				IPProtocol: 17,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			c := prepareSendTraceflowPacket(ctrl, !tt.wantErr)
			if err := c.SendTraceflowPacket(tt.args.dataplaneTag, tt.args.srcMAC, tt.args.dstMAC, tt.args.srcIP, tt.args.dstIP, tt.args.IPProtocol, tt.args.ttl, tt.args.IPFlags, tt.args.TCPSrcPort, tt.args.TCPDstPort, tt.args.TCPFlags, tt.args.UDPSrcPort, tt.args.UDPDstPort, tt.args.ICMPType, tt.args.ICMPCode, tt.args.ICMPID, tt.args.ICMPSequence, tt.args.inPort, tt.args.outPort); (err != nil) != tt.wantErr {
				t.Errorf("SendTraceflowPacket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func prepareTraceflowFlow(ctrl *gomock.Controller) *client {
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, true, true)
	c := ofClient.(*client)
	c.cookieAllocator = cookie.NewAllocator(0)
	c.nodeConfig = &config.NodeConfig{}
	m := ovsoftest.NewMockBridge(ctrl)
	m.EXPECT().AddFlowsInBundle(gomock.Any(), nil, nil).Return(nil).Times(3)
	c.bridge = m

	mFlow := ovsoftest.NewMockFlow(ctrl)
	ctx := &conjMatchFlowContext{dropFlow: mFlow}
	mFlow.EXPECT().FlowProtocol().Return(ofconfig.Protocol("ip"))
	mFlow.EXPECT().CopyToBuilder(priorityNormal+2, false).Return(c.pipeline[EgressDefaultTable].BuildFlow(priorityNormal + 2)).Times(1)
	c.globalConjMatchFlowCache["mockContext"] = ctx
	c.policyCache.Add(&policyRuleConjunction{metricFlows: []ofconfig.Flow{c.dropRuleMetricFlow(123, false)}})
	return c
}

func prepareSendTraceflowPacket(ctrl *gomock.Controller, success bool) *client {
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, true, true)
	c := ofClient.(*client)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	c.nodeConfig = &config.NodeConfig{GatewayConfig: &config.GatewayConfig{MAC: mac}}
	m := ovsoftest.NewMockBridge(ctrl)
	c.bridge = m
	bridge := ofconfig.OFBridge{}
	m.EXPECT().BuildPacketOut().Return(bridge.BuildPacketOut()).Times(1)
	if success {
		m.EXPECT().SendPacketOut(gomock.Any()).Times(1)
	}
	return c
}
