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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/config"
	nodeiptest "antrea.io/antrea/pkg/agent/nodeip/testing"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	opstest "antrea.io/antrea/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	ovsoftest "antrea.io/antrea/pkg/ovs/openflow/testing"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	utilip "antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/runtime"
	"antrea.io/antrea/third_party/proxy"
)

const bridgeName = "dummy-br"

var (
	bridgeMgmtAddr = binding.GetMgmtAddress(ovsconfig.DefaultOVSRunDir, bridgeName)

	fakeGatewayMAC, _ = net.ParseMAC("0a:00:00:00:00:01")
	fakeUplinkMAC, _  = net.ParseMAC("0a:00:00:00:00:02")

	fakeGatewayIPv4, fakePodIPv4CIDR, _ = net.ParseCIDR("10.10.0.1/24")
	fakeNodeIPv4, fakeNodeIPv4Addr, _   = net.ParseCIDR("192.168.77.100/24")

	fakeGatewayIPv6, fakePodIPv6CIDR, _ = net.ParseCIDR("fec0:10:10::1/80")
	fakeNodeIPv6, fakeNodeIPv6Addr, _   = net.ParseCIDR("fec0:192:168:77::100/80")

	_, fakeServiceIPv4CIDR, _ = net.ParseCIDR("10.96.0.0/16")
	_, fakeServiceIPv6CIDR, _ = net.ParseCIDR("fec0:10:96::/64")

	_, fakeEgressExceptIPv4CIDR, _ = net.ParseCIDR("192.168.78.0/24")
	_, fakeEgressExceptIPv6CIDR, _ = net.ParseCIDR("fec0:192:168:78::/80")

	fakeL7NPTargetOFPort = uint32(10)
	fakeL7NPReturnOFPort = uint32(11)

	defaultPacketInRate = 500
)

func skipTest(tb testing.TB, skipLinux, skipWindows bool) {
	if !runtime.IsWindowsPlatform() && skipLinux {
		tb.Skipf("Skip test on Linux")
	}
	if runtime.IsWindowsPlatform() && skipWindows {
		tb.Skipf("Skip test on Windows")
	}
}

type clientOptions struct {
	enableOVSMeters            bool
	enableProxy                bool
	enableAntreaPolicy         bool
	enableEgress               bool
	enableEgressTrafficShaping bool
	proxyAll                   bool
	enableDSR                  bool
	connectUplinkToBridge      bool
	enableMulticast            bool
	enableTrafficControl       bool
	enableMulticluster         bool
	enableL7NetworkPolicy      bool
	enableL7FlowExporter       bool
	trafficEncryptionMode      config.TrafficEncryptionModeType
}

type clientOptionsFn func(*clientOptions)

func setEnableOVSMeters(v bool) clientOptionsFn {
	return func(o *clientOptions) {
		o.enableOVSMeters = v
	}
}

func enableProxyAll(o *clientOptions) {
	o.enableProxy = true
	o.proxyAll = true
}

func enableDSR(o *clientOptions) {
	o.enableProxy = true
	o.proxyAll = true
	o.enableDSR = true
}

func enableProxy(o *clientOptions) {
	o.enableProxy = true
}

func disableProxy(o *clientOptions) {
	o.enableProxy = false
	o.proxyAll = false
}

func disableEgress(o *clientOptions) {
	o.enableEgress = false
}

func enableEgressTrafficShaping(o *clientOptions) {
	// traffic shaping requires meter support
	o.enableOVSMeters = true
	o.enableEgressTrafficShaping = true
}

func setEnableEgressTrafficShaping(v bool) clientOptionsFn {
	return func(o *clientOptions) {
		if v {
			o.enableOVSMeters = true
		}
		o.enableEgressTrafficShaping = v
	}
}

func enableConnectUplinkToBridge(o *clientOptions) {
	o.connectUplinkToBridge = true
}

func enableMulticast(o *clientOptions) {
	o.enableMulticast = true
}

func disableAntreaPolicy(o *clientOptions) {
	o.enableAntreaPolicy = false
}

func enableL7NetworkPolicy(o *clientOptions) {
	o.enableL7NetworkPolicy = true
}

func enableTrafficControl(o *clientOptions) {
	o.enableTrafficControl = true
}

func enableMulticluster(o *clientOptions) {
	o.enableMulticluster = true
}

func setTrafficEncryptionMode(trafficEncryptionMode config.TrafficEncryptionModeType) clientOptionsFn {
	return func(o *clientOptions) {
		o.trafficEncryptionMode = trafficEncryptionMode
	}
}

func installNodeFlows(ofClient Client, cacheKey string) (int, error) {
	gwIP, ipNet, _ := net.ParseCIDR("10.10.0.1/24")
	hostName := cacheKey
	peerNodeIP := net.ParseIP("192.168.1.1")
	peerConfigs := map[*net.IPNet]net.IP{
		ipNet: gwIP,
	}
	err := ofClient.InstallNodeFlows(hostName, peerConfigs, &utilip.DualStackIPs{IPv4: peerNodeIP}, 0, nil)
	client := ofClient.(*client)
	fCacheI, ok := client.featurePodConnectivity.nodeCachedFlows.Load(hostName)
	if ok {
		return len(fCacheI.(flowMessageCache)), err
	}
	return 0, err
}

func installPodFlows(ofClient Client, cacheKey string) (int, error) {
	containerID := cacheKey
	podMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
	podIP := net.ParseIP("10.0.0.2")
	ofPort := uint32(10)
	err := ofClient.InstallPodFlows(containerID, []net.IP{podIP}, podMAC, ofPort, 0, nil)
	client := ofClient.(*client)
	fCacheI, ok := client.featurePodConnectivity.podCachedFlows.Load(containerID)
	if ok {
		return len(fCacheI.(flowMessageCache)), err
	}
	return 0, err
}

func installPodFlowsWithLabelID(ofClient Client, cacheKey string, labelID *uint32) (int, error) {
	containerID := cacheKey
	podMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
	podIP := net.ParseIP("10.0.0.2")
	ofPort := uint32(10)
	err := ofClient.InstallPodFlows(containerID, []net.IP{podIP}, podMAC, ofPort, 0, labelID)
	client := ofClient.(*client)
	fCacheI, ok := client.featurePodConnectivity.podCachedFlows.Load(containerID)
	if ok {
		return len(fCacheI.(flowMessageCache)), err
	}
	return 0, err
}

// TestIdempotentFlowInstallation checks that InstallNodeFlows and InstallPodFlows are idempotent.
func TestIdempotentFlowInstallation(t *testing.T) {
	labelID := uint32(1)
	testCases := []struct {
		name      string
		cacheKey  string
		labelID   *uint32
		numFlows  int
		installFn func(ofClient Client, cacheKey string, labelID *uint32) (int, error)
	}{
		{"PodFlows", "aaaa-bbbb-cccc-dddd", nil, 5, installPodFlowsWithLabelID},
		{"SNPPodFlows", "eeee-ffff-gggg-hhhh", &labelID, 5, installPodFlowsWithLabelID},
	}

	// Check the flows are installed only once even though InstallNodeFlows/InstallPodFlows is called multiple times.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			// Installing the flows should succeed, and all the flows should be added into the cache.
			numCached1, err := tc.installFn(fc, tc.cacheKey, tc.labelID)
			require.Nil(t, err, "Error when installing Node flows")
			assert.Equal(t, tc.numFlows, numCached1)

			// Installing the same flows again must not return an error and should not
			// add additional flows to the cache.
			m.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			numCached2, err := tc.installFn(fc, tc.cacheKey, tc.labelID)
			require.Nil(t, err, "Error when installing Node flows again")

			assert.Equal(t, numCached1, numCached2)
		})
	}

	// Check the flows could be installed successfully with retry, and all the flows are added into the flow cache only once.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			errorCall := m.EXPECT().AddAll(gomock.Any()).Return(errors.New("Bundle error"))
			m.EXPECT().AddAll(gomock.Any()).Return(nil).After(errorCall)

			// Installing the flows failed at the first time, and no flow cache is created.
			numCached1, err := tc.installFn(fc, tc.cacheKey, tc.labelID)
			require.NotNil(t, err, "Installing flows in bundle is expected to fail")
			assert.Equal(t, 0, numCached1)

			// Installing the same flows successfully at the second time, and add flows to the cache.
			numCached2, err := tc.installFn(fc, tc.cacheKey, tc.labelID)
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
		{"NodeFlows", "host", 1, installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 1, installPodFlows},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			// We generate an error for AddAll call.
			m.EXPECT().AddAll(gomock.Any()).Return(errors.New("Bundle error")).Times(tc.numAddCalls)

			var err error
			var numCached int

			numCached, err = tc.installFn(fc, tc.cacheKey)
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
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

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
					_, _ = tc.fn(fc, cacheKey) // in mock we trust
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

func newFakeClient(
	mockOFEntryOperations *opstest.MockOFEntryOperations,
	enableIPv4,
	enableIPv6 bool,
	nodeType config.NodeType,
	trafficEncapMode config.TrafficEncapModeType,
	options ...clientOptionsFn,
) *client {
	return newFakeClientWithBridge(mockOFEntryOperations, enableIPv4, enableIPv6, nodeType, trafficEncapMode, nil, options...)
}

func newFakeClientWithBridge(
	mockOFEntryOperations *opstest.MockOFEntryOperations,
	enableIPv4,
	enableIPv6 bool,
	nodeType config.NodeType,
	trafficEncapMode config.TrafficEncapModeType,
	bridge binding.Bridge, // use nil to use the default bridge created with binding.NewOFBridge
	options ...clientOptionsFn,
) *client {
	// default options
	o := &clientOptions{
		enableProxy:        true,
		enableAntreaPolicy: true,
		enableEgress:       true,
	}
	for _, fn := range options {
		fn(o)
	}

	client := NewClient(bridgeName,
		bridgeMgmtAddr,
		nodeiptest.NewFakeNodeIPChecker(),
		o.enableProxy,
		o.enableAntreaPolicy,
		o.enableL7NetworkPolicy,
		o.enableEgress,
		o.enableEgressTrafficShaping,
		false,
		o.proxyAll,
		o.enableDSR,
		o.connectUplinkToBridge,
		o.enableMulticast,
		o.enableTrafficControl,
		o.enableL7FlowExporter,
		o.enableMulticluster,
		NewGroupAllocator(),
		false,
		defaultPacketInRate)

	// Meters must be supported to enable Egress traffic shaping.
	// For unit tests, we can "force" client.ovsMetersAreSupported to true, even if the platform
	// running the unit tests don't actually support meters.
	client.ovsMetersAreSupported = o.enableOVSMeters

	var egressExceptCIDRs []net.IPNet
	var serviceIPv4CIDR, serviceIPv6CIDR *net.IPNet
	var nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP
	var ipProtocols []binding.Protocol
	var l7NetworkPolicyConfig *config.L7NetworkPolicyConfig

	if enableIPv4 {
		fakeNodeIPv4Addr.IP = fakeNodeIPv4
		if o.enableEgress {
			egressExceptCIDRs = append(egressExceptCIDRs, *fakeEgressExceptIPv4CIDR)
		}
		if !o.enableProxy {
			serviceIPv4CIDR = fakeServiceIPv4CIDR
		}
		if o.enableProxy && o.proxyAll {
			nodePortAddressesIPv4 = []net.IP{fakeNodeIPv4, net.ParseIP("127.0.0.1")}
		}
		ipProtocols = append(ipProtocols, binding.ProtocolIP)
	}
	if enableIPv6 {
		fakeNodeIPv6Addr.IP = fakeNodeIPv6
		if o.enableEgress {
			egressExceptCIDRs = append(egressExceptCIDRs, *fakeEgressExceptIPv6CIDR)
		}
		if !o.enableProxy {
			serviceIPv6CIDR = fakeServiceIPv6CIDR
		}
		if o.enableProxy && o.proxyAll {
			nodePortAddressesIPv6 = []net.IP{fakeNodeIPv6, net.ParseIP("::1")}
		}
		ipProtocols = append(ipProtocols, binding.ProtocolIPv6)
	}
	gatewayConfig := &config.GatewayConfig{
		IPv4:   fakeGatewayIPv4,
		IPv6:   fakeGatewayIPv6,
		MAC:    fakeGatewayMAC,
		OFPort: uint32(2),
	}
	networkConfig := &config.NetworkConfig{
		IPv4Enabled:           enableIPv4,
		IPv6Enabled:           enableIPv6,
		TrafficEncapMode:      trafficEncapMode,
		TrafficEncryptionMode: o.trafficEncryptionMode,
	}
	tunnelOFPort := uint32(0)
	if networkConfig.NeedsTunnelInterface() {
		tunnelOFPort = 1
	}
	nodeConfig := &config.NodeConfig{
		GatewayConfig:         gatewayConfig,
		TunnelOFPort:          tunnelOFPort,
		WireGuardConfig:       &config.WireGuardConfig{},
		PodIPv4CIDR:           fakePodIPv4CIDR,
		PodIPv6CIDR:           fakePodIPv6CIDR,
		NodeIPv4Addr:          fakeNodeIPv4Addr,
		NodeIPv6Addr:          fakeNodeIPv6Addr,
		NodeTransportIPv4Addr: fakeNodeIPv4Addr,
		NodeTransportIPv6Addr: fakeNodeIPv6Addr,
		Type:                  nodeType,
		HostInterfaceOFPort:   uint32(4294967294),
		UplinkNetConfig: &config.AdapterNetConfig{
			MAC:    fakeUplinkMAC,
			OFPort: uint32(4),
		},
	}
	egressConfig := &config.EgressConfig{
		ExceptCIDRs: egressExceptCIDRs,
	}
	serviceConfig := &config.ServiceConfig{
		ServiceCIDR:           serviceIPv4CIDR,
		ServiceCIDRv6:         serviceIPv6CIDR,
		NodePortAddressesIPv4: nodePortAddressesIPv4,
		NodePortAddressesIPv6: nodePortAddressesIPv6,
	}

	if o.enableL7NetworkPolicy {
		l7NetworkPolicyConfig = &config.L7NetworkPolicyConfig{
			TargetOFPort: fakeL7NPTargetOFPort,
			ReturnOFPort: fakeL7NPReturnOFPort,
		}
	}

	client.cookieAllocator = cookie.NewAllocator(1)
	client.ofEntryOperations = mockOFEntryOperations
	client.nodeConfig = nodeConfig
	client.nodeType = nodeConfig.Type
	client.networkConfig = networkConfig
	client.egressConfig = egressConfig
	client.serviceConfig = serviceConfig
	client.l7NetworkPolicyConfig = l7NetworkPolicyConfig
	client.ipProtocols = ipProtocols
	client.generatePipelines()
	client.realizePipelines()
	binding.TableNameCache = getTableNameCache()

	// This is needed even when bridge != nil for proper table initialization.
	client.bridge.(*binding.OFBridge).SetOFSwitch(ofctrl.NewSwitch(&util.MessageStream{}, GlobalVirtualMAC, client.bridge.(ofctrl.AppInterface), make(chan int), 32776))
	client.bridge.(*binding.OFBridge).Initialize()
	if bridge != nil {
		client.bridge = bridge
	}

	return client
}

func getTableNameCache() map[uint8]string {
	tableNameCache := map[uint8]string{}
	maxTableId := binding.NextTableID() - 1
	for id := uint8(0); id <= maxTableId; id++ {
		if tableName := GetFlowTableName(id); tableName != "" {
			tableNameCache[id] = tableName
		}
	}
	return tableNameCache
}

func getFlowStrings(flows interface{}) []string {
	getStrings := func(message *openflow15.FlowMod) []string {
		var strs []string
		f := binding.FlowModToString(message)
		strs = append(strs, f)
		return strs
	}
	var flowStrings []string
	switch v := flows.(type) {
	case flowMessageCache:
		for _, flow := range v {
			flowStrings = append(flowStrings, getStrings(flow)...)
		}
	case []binding.Flow:
		for _, flow := range v {
			messages, _ := flow.GetBundleMessages(binding.AddMessage)
			for _, msg := range messages {
				flowStrings = append(flowStrings, getStrings(msg.GetMessage().(*openflow15.FlowMod))...)
			}
		}
	case []*openflow15.FlowMod:
		for _, flow := range v {
			flowStrings = append(flowStrings, getStrings(flow)...)
		}
	}
	return flowStrings
}

func getGroupFromCache(groupCache binding.Group) string {
	binding.TableNameCache = getTableNameCache()

	messages, _ := groupCache.GetBundleMessages(binding.AddMessage)
	groupString := binding.GroupModToString(messages[0].GetMessage().(*openflow15.GroupMod))
	return groupString
}

func Test_client_InstallNodeFlows(t *testing.T) {
	peerGwIPv4, peerPodCIDRv4, _ := net.ParseCIDR("10.10.1.1/24")
	peerGwIPv6, peerPodCIDRv6, _ := net.ParseCIDR("fec0:10:10:1::1/80")
	peerGwMAC, _ := net.ParseMAC("00:00:10:10:01:01")
	tunnelPeerIPv4 := net.ParseIP("192.168.77.101")
	tunnelPeerIPv6 := net.ParseIP("fec0:192:168:77::101")

	testCases := []struct {
		name             string
		enableIPv4       bool
		enableIPv6       bool
		skipWindows      bool
		skipLinux        bool
		clientOptions    []clientOptionsFn
		peerConfigs      map[*net.IPNet]net.IP
		tunnelPeerIPs    *utilip.DualStackIPs
		ipsecTunOFPort   uint32
		trafficEncapMode config.TrafficEncapModeType
		expectedFlows    []string
	}{
		{
			name:             "IPv4 Encap",
			enableIPv4:       true,
			peerConfigs:      map[*net.IPNet]net.IP{peerPodCIDRv4: peerGwIPv4},
			tunnelPeerIPs:    &utilip.DualStackIPs{IPv4: tunnelPeerIPv4},
			ipsecTunOFPort:   uint32(100),
			trafficEncapMode: config.TrafficEncapModeEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPResponder, priority=200,arp,arp_tpa=10.10.1.1,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:10.10.1.1->arp_spa,IN_PORT",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=100 actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.10.1.0/24 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.77.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=192.168.77.101 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name:             "IPv6 Encap",
			enableIPv6:       true,
			skipWindows:      true,
			peerConfigs:      map[*net.IPNet]net.IP{peerPodCIDRv6: peerGwIPv6},
			tunnelPeerIPs:    &utilip.DualStackIPs{IPv6: tunnelPeerIPv6},
			ipsecTunOFPort:   uint32(100),
			trafficEncapMode: config.TrafficEncapModeEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=100 actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
				"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=fec0:192:168:77::101 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,ipv6_dst=fec0:10:10:1::/80 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:fec0:192:168:77::101->tun_ipv6_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
			},
		},
		{
			name:             "IPv4 NoEncap Linux",
			enableIPv4:       true,
			skipWindows:      true,
			clientOptions:    []clientOptionsFn{disableEgress, enableConnectUplinkToBridge},
			peerConfigs:      map[*net.IPNet]net.IP{peerPodCIDRv4: peerGwIPv4},
			tunnelPeerIPs:    &utilip.DualStackIPs{},
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPResponder, priority=200,arp,arp_tpa=10.10.1.1,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:10.10.1.1->arp_spa,IN_PORT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg4=0x0/0x100000,nw_dst=10.10.1.0/24 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg4=0x100000/0x100000,reg8=0x0/0xfff,nw_dst=10.10.1.0/24 actions=set_field:00:00:10:10:01:01->eth_dst,set_field:0x40/0xf0->reg0,goto_table:L3DecTTL",
			},
		},
		{
			name:             "IPv4 NoEncap Windows",
			enableIPv4:       true,
			skipLinux:        true,
			clientOptions:    []clientOptionsFn{disableEgress, enableConnectUplinkToBridge},
			peerConfigs:      map[*net.IPNet]net.IP{peerPodCIDRv4: peerGwIPv4},
			tunnelPeerIPs:    &utilip.DualStackIPs{},
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPResponder, priority=200,arp,arp_tpa=10.10.1.1,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:10.10.1.1->arp_spa,IN_PORT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg4=0x0/0x100000,nw_dst=10.10.1.0/24 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg4=0x100000/0x100000,reg8=0x0/0xfff,nw_dst=10.10.1.0/24 actions=set_field:00:00:10:10:01:01->eth_dst,set_field:0x40/0xf0->reg0,goto_table:L3DecTTL",
			},
		},
		{
			name:             "IPv6 NoEncap",
			enableIPv6:       true,
			skipWindows:      true,
			clientOptions:    []clientOptionsFn{disableEgress, enableConnectUplinkToBridge},
			peerConfigs:      map[*net.IPNet]net.IP{peerPodCIDRv6: peerGwIPv6},
			tunnelPeerIPs:    &utilip.DualStackIPs{},
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg4=0x0/0x100000,ipv6_dst=fec0:10:10:1::/80 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg4=0x100000/0x100000,reg8=0x0/0xfff,ipv6_dst=fec0:10:10:1::/80 actions=set_field:00:00:10:10:01:01->eth_dst,set_field:0x40/0xf0->reg0,goto_table:L3DecTTL",
			},
		},
		{
			name:             "IPv4 Encap DSR",
			enableIPv4:       true,
			clientOptions:    []clientOptionsFn{enableDSR},
			peerConfigs:      map[*net.IPNet]net.IP{peerPodCIDRv4: peerGwIPv4},
			tunnelPeerIPs:    &utilip.DualStackIPs{IPv4: tunnelPeerIPv4},
			ipsecTunOFPort:   uint32(100),
			trafficEncapMode: config.TrafficEncapModeEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPResponder, priority=200,arp,arp_tpa=10.10.1.1,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:10.10.1.1->arp_spa,IN_PORT",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=100 actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.10.1.0/24 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.77.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg3=0xa0a0100/0xffffff00,reg4=0x2000000/0x2000000 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.77.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=192.168.77.101 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			skipTest(t, tc.skipLinux, tc.skipWindows)

			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, tc.enableIPv4, tc.enableIPv6, config.K8sNode, tc.trafficEncapMode, tc.clientOptions...)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			hostname := "node1"

			assert.NoError(t, fc.InstallNodeFlows(hostname, tc.peerConfigs, tc.tunnelPeerIPs, tc.ipsecTunOFPort, peerGwMAC))
			fCacheI, ok := fc.featurePodConnectivity.nodeCachedFlows.Load(hostname)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallNodeFlows(hostname))
			_, ok = fc.featurePodConnectivity.nodeCachedFlows.Load(hostname)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallPodFlows(t *testing.T) {
	podIPv4 := net.ParseIP("10.10.0.66")
	podIPv6 := net.ParseIP("fec0:10:10::66")
	podMAC, _ := net.ParseMAC("00:00:10:10:00:66")
	podOfPort := uint32(100)
	antreaIPAMPodIPv4 := net.ParseIP("192.168.77.200")

	testCases := []struct {
		name             string
		enableIPv4       bool
		enableIPv6       bool
		clientOptions    []clientOptionsFn
		podInterfaceIPs  []net.IP
		vlanID           uint16
		trafficEncapMode config.TrafficEncapModeType
		expectedFlows    []string
	}{
		{
			name:            "IPv4",
			enableIPv4:      true,
			podInterfaceIPs: []net.IP{podIPv4},
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.66,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.66 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:            "IPv4,Multicast",
			enableIPv4:      true,
			clientOptions:   []clientOptionsFn{enableMulticast},
			podInterfaceIPs: []net.IP{podIPv4},
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.66,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.66 actions=goto_table:PipelineIPClassifier",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1050000000000, table=MulticastEgressPodMetric, priority=200,ip,nw_src=10.10.0.66 actions=goto_table:MulticastRouting",
				"cookie=0x1050000000000, table=MulticastIngressPodMetric, priority=200,ip,reg1=0x64 actions=goto_table:MulticastOutput",
			},
		},
		{
			name:            "IPv6",
			enableIPv6:      true,
			podInterfaceIPs: []net.IP{podIPv6},
			expectedFlows: []string{
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=100,dl_src=00:00:10:10:00:66,ipv6_src=fec0:10:10::66 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x200/0x200,ipv6_dst=fec0:10:10::66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:            "IPv4 and IPv6",
			enableIPv4:      true,
			enableIPv6:      true,
			podInterfaceIPs: []net.IP{podIPv4, podIPv6},
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.66,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.66 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=100,dl_src=00:00:10:10:00:66,ipv6_src=fec0:10:10::66 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x200/0x200,ipv6_dst=fec0:10:10::66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:             "IPv4,NetworkPolicyOnly",
			enableIPv4:       true,
			podInterfaceIPs:  []net.IP{podIPv4},
			trafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.66,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.66 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.10.0.66 actions=set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:             "IPv6,NetworkPolicyOnly",
			enableIPv6:       true,
			podInterfaceIPs:  []net.IP{podIPv6},
			trafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=100,dl_src=00:00:10:10:00:66,ipv6_src=fec0:10:10::66 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x200/0x200,ipv6_dst=fec0:10:10::66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,ipv6_dst=fec0:10:10::66 actions=set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:             "IPv4 and IPv6,NetworkPolicyOnly",
			enableIPv4:       true,
			enableIPv6:       true,
			podInterfaceIPs:  []net.IP{podIPv4, podIPv6},
			trafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.66,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=100,dl_src=00:00:10:10:00:66,ipv6_src=fec0:10:10::66 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.66 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x200/0x200,ipv6_dst=fec0:10:10::66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,ipv6_dst=fec0:10:10::66 actions=set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.10.0.66 actions=set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:             "IPv4,Antrea IPAM",
			enableIPv4:       true,
			clientOptions:    []clientOptionsFn{disableEgress, enableConnectUplinkToBridge},
			podInterfaceIPs:  []net.IP{antreaIPAMPodIPv4},
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=192.168.77.200,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=4,vlan_tci=0x0000/0x1000,dl_dst=00:00:10:10:00:66 actions=set_field:0x1000/0xf000->reg8,set_field:0x4/0xf->reg0,set_field:0x0/0xfff->reg8,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=4294967294,vlan_tci=0x0000/0x1000,dl_dst=00:00:10:10:00:66 actions=set_field:0x1000/0xf000->reg8,set_field:0x5/0xf->reg0,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,set_field:0x100000/0x100000->reg4,set_field:0x200/0x200->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=192.168.77.200 actions=set_field:0x1000/0xf000->reg8,set_field:0x0/0xfff->reg8,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg8=0x0/0xfff,nw_dst=192.168.77.200 actions=set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:             "IPv4,Antrea IPAM,VLAN",
			enableIPv4:       true,
			clientOptions:    []clientOptionsFn{disableEgress, enableConnectUplinkToBridge},
			podInterfaceIPs:  []net.IP{antreaIPAMPodIPv4},
			vlanID:           1,
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=192.168.77.200,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=4,dl_vlan=1,dl_dst=00:00:10:10:00:66 actions=set_field:0x1000/0xf000->reg8,set_field:0x4/0xf->reg0,set_field:0x1/0xfff->reg8,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,set_field:0x100000/0x100000->reg4,set_field:0x200/0x200->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=192.168.77.200 actions=set_field:0x1000/0xf000->reg8,set_field:0x1/0xfff->reg8,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg8=0x1/0xfff,nw_dst=192.168.77.200 actions=set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=VLAN, priority=190,reg1=0x4,in_port=100 actions=push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:Output",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, tc.enableIPv4, tc.enableIPv6, config.K8sNode, tc.trafficEncapMode, tc.clientOptions...)
			defer resetPipelines()

			expectedCalled := 1
			if fc.enableMulticast {
				expectedCalled = 2
			}
			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(expectedCalled)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(expectedCalled)

			interfaceName := "pod1"
			cacheKey := fmt.Sprintf("multicast_pod_metric_%s", interfaceName)

			assert.NoError(t, fc.InstallPodFlows(interfaceName, tc.podInterfaceIPs, podMAC, podOfPort, tc.vlanID, nil))
			fCacheI, ok := fc.featurePodConnectivity.podCachedFlows.Load(interfaceName)
			require.True(t, ok)
			flows := getFlowStrings(fCacheI)
			if fc.enableMulticast {
				fCacheI, ok = fc.featureMulticast.cachedFlows.Load(cacheKey)
				require.True(t, ok)
				flows = append(flows, getFlowStrings(fCacheI)...)
			}
			assert.ElementsMatch(t, tc.expectedFlows, flows)

			assert.NoError(t, fc.UninstallPodFlows(interfaceName))
			_, ok = fc.featurePodConnectivity.podCachedFlows.Load(interfaceName)
			require.False(t, ok)
			if fc.enableMulticast {
				_, ok = fc.featureMulticast.cachedFlows.Load(cacheKey)
				require.False(t, ok)
			}
		})
	}
}

func Test_client_UpdatePodFlows(t *testing.T) {
	podIPv4 := net.ParseIP("10.10.0.66")
	podIPv4Updated := net.ParseIP("10.10.0.88")
	podIPv6 := net.ParseIP("fec0:10:10::66")
	podIPv6Updated := net.ParseIP("fec0:10:10::88")
	podMAC, _ := net.ParseMAC("00:00:10:10:00:66")
	podOfPort := uint32(100)
	testCases := []struct {
		name                   string
		enableIPv4             bool
		enableIPv6             bool
		clientOptions          []clientOptionsFn
		podInterfaceIPs        []net.IP
		podUpdatedInterfaceIPs []net.IP
		vlanID                 uint16
		trafficEncapMode       config.TrafficEncapModeType
		expectedFlows          []string
		expectedNewFlows       []string
	}{
		{
			name:                   "IPv4",
			enableIPv4:             true,
			podInterfaceIPs:        []net.IP{podIPv4},
			podUpdatedInterfaceIPs: []net.IP{podIPv4Updated},
			expectedFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.66,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.66 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
			expectedNewFlows: []string{
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=100,arp_spa=10.10.0.88,arp_sha=00:00:10:10:00:66 actions=goto_table:ARPResponder",
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=100,dl_src=00:00:10:10:00:66,nw_src=10.10.0.88 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.88 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:                   "IPv6",
			enableIPv6:             true,
			podInterfaceIPs:        []net.IP{podIPv6},
			podUpdatedInterfaceIPs: []net.IP{podIPv6Updated},
			expectedFlows: []string{
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=100,dl_src=00:00:10:10:00:66,ipv6_src=fec0:10:10::66 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x200/0x200,ipv6_dst=fec0:10:10::66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
			expectedNewFlows: []string{
				"cookie=0x1010000000000, table=Classifier, priority=190,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=100,dl_src=00:00:10:10:00:66,ipv6_src=fec0:10:10::88 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x200/0x200,ipv6_dst=fec0:10:10::88 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=00:00:10:10:00:66 actions=set_field:0x64->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, tc.enableIPv4, tc.enableIPv6, config.K8sNode, tc.trafficEncapMode, tc.clientOptions...)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			// When only the Pod IP is updated, the flow change in Classifier and L2ForwardingCalc table should just be mod
			// messages since no flow matcher has changed. The other flows should be deleted and added as the latest ones.
			// For IPV4 case there is one additional flow delete and add for the ARPSpoofGuard table.
			numFlowDelAndAdds := 3
			if tc.enableIPv6 {
				numFlowDelAndAdds = 2
			}
			m.EXPECT().BundleOps(gomock.Len(numFlowDelAndAdds), gomock.Len(2), gomock.Len(numFlowDelAndAdds)).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			interfaceName := "pod1"
			assert.NoError(t, fc.InstallPodFlows(interfaceName, tc.podInterfaceIPs, podMAC, podOfPort, tc.vlanID, nil))
			fCacheI, ok := fc.featurePodConnectivity.podCachedFlows.Load(interfaceName)
			require.True(t, ok)
			flows := getFlowStrings(fCacheI)
			assert.ElementsMatch(t, tc.expectedFlows, flows)

			assert.NoError(t, fc.InstallPodFlows(interfaceName, tc.podUpdatedInterfaceIPs, podMAC, podOfPort, tc.vlanID, nil))
			fCacheI, ok = fc.featurePodConnectivity.podCachedFlows.Load(interfaceName)
			require.True(t, ok)
			flows = getFlowStrings(fCacheI)
			assert.ElementsMatch(t, tc.expectedNewFlows, flows)

			assert.NoError(t, fc.UninstallPodFlows(interfaceName))
			_, ok = fc.featurePodConnectivity.podCachedFlows.Load(interfaceName)
			require.False(t, ok)
		})
	}
}

func Test_client_GetPodFlowKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)

	fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap)
	defer resetPipelines()

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)

	interfaceName := "pod1"
	podInterfaceIPs := []net.IP{net.ParseIP("10.10.0.11")}
	podMAC, _ := net.ParseMAC("00:00:10:10:00:11")

	assert.NoError(t, fc.InstallPodFlows(interfaceName, podInterfaceIPs, podMAC, uint32(11), 0, nil))
	flowKeys := fc.GetPodFlowKeys(interfaceName)
	expectedFlowKeys := []string{
		"table=1,priority=200,arp,in_port=11,arp_spa=10.10.0.11,arp_sha=00:00:10:10:00:11",
		"table=3,priority=190,in_port=11",
		"table=4,priority=200,ip,in_port=11,dl_src=00:00:10:10:00:11,nw_src=10.10.0.11",
		"table=17,priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.11",
		"table=22,priority=200,dl_dst=00:00:10:10:00:11",
	}
	assert.ElementsMatch(t, expectedFlowKeys, flowKeys)
}

func Test_client_InstallServiceGroup(t *testing.T) {
	groupID := binding.GroupIDType(100)

	testCases := []struct {
		name                 string
		withSessionAffinity  bool
		endpoints            []proxy.Endpoint
		expectedGroup        string
		deleteOFEntriesError error
	}{
		{
			name: "IPv4 Endpoints",
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo("10.10.0.100", "node1", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo("10.10.0.101", "node2", "", 80, true, true, false, false, nil),
			},
			expectedGroup: "group_id=100,type=select," +
				"bucket=bucket_id:0,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xa0a0064->reg3,set_field:0x50/0xffff->reg4,resubmit:EndpointDNAT," +
				"bucket=bucket_id:1,weight:100,actions=set_field:0xa0a0065->reg3,set_field:0x50/0xffff->reg4,resubmit:EndpointDNAT",
		},
		{
			name: "IPv6 Endpoints",
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo("fec0:10:10::100", "node1", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo("fec0:10:10::101", "node2", "", 80, true, true, false, false, nil),
			},
			expectedGroup: "group_id=100,type=select," +
				"bucket=bucket_id:0,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xfec00010001000000000000000000100->xxreg3,set_field:0x50/0xffff->reg4,resubmit:EndpointDNAT," +
				"bucket=bucket_id:1,weight:100,actions=set_field:0xfec00010001000000000000000000101->xxreg3,set_field:0x50/0xffff->reg4,resubmit:EndpointDNAT",
		},
		{
			name:                "IPv4 Endpoints,SessionAffinity",
			withSessionAffinity: true,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo("10.10.0.100", "node1", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo("10.10.0.101", "node2", "", 80, true, true, false, false, nil),
			},
			expectedGroup: "group_id=100,type=select," +
				"bucket=bucket_id:0,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xa0a0064->reg3,set_field:0x50/0xffff->reg4,resubmit:ServiceLB," +
				"bucket=bucket_id:1,weight:100,actions=set_field:0xa0a0065->reg3,set_field:0x50/0xffff->reg4,resubmit:ServiceLB",
		},
		{
			name:                "IPv6 Endpoints,SessionAffinity",
			withSessionAffinity: true,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo("fec0:10:10::100", "node1", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo("fec0:10:10::101", "node2", "", 80, true, true, false, false, nil),
			},
			expectedGroup: "group_id=100,type=select," +
				"bucket=bucket_id:0,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xfec00010001000000000000000000100->xxreg3,set_field:0x50/0xffff->reg4,resubmit:ServiceLB," +
				"bucket=bucket_id:1,weight:100,actions=set_field:0xfec00010001000000000000000000101->xxreg3,set_field:0x50/0xffff->reg4,resubmit:ServiceLB",
		},
		{
			name: "delete group failed for IPv4 Endpoints",
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo("10.10.0.100", "node1", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo("10.10.0.101", "node2", "", 80, true, true, false, false, nil),
			},
			expectedGroup: "group_id=100,type=select," +
				"bucket=bucket_id:0,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xa0a0064->reg3,set_field:0x50/0xffff->reg4,resubmit:EndpointDNAT," +
				"bucket=bucket_id:1,weight:100,actions=set_field:0xa0a0065->reg3,set_field:0x50/0xffff->reg4,resubmit:EndpointDNAT",
			deleteOFEntriesError: fmt.Errorf("error when deleting Openflow entries for Service Endpoints Group 100"),
		},
		{
			name:      "No Endpoints",
			endpoints: []proxy.Endpoint{},
			expectedGroup: "group_id=100,type=select," +
				"bucket=bucket_id:0,weight:100,actions=set_field:0x4000/0x4000->reg0,resubmit:EndpointDNAT",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			m.EXPECT().AddOFEntries(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteOFEntries(gomock.Any()).Return(tc.deleteOFEntriesError).Times(1)
			assert.NoError(t, fc.InstallServiceGroup(groupID, tc.withSessionAffinity, tc.endpoints))
			gCacheI, ok := fc.featureService.groupCache.Load(groupID)
			require.True(t, ok)
			group := getGroupFromCache(gCacheI.(binding.Group))
			assert.Equal(t, tc.expectedGroup, group)

			if tc.deleteOFEntriesError == nil {
				assert.NoError(t, fc.UninstallServiceGroup(groupID))
				_, ok = fc.featureService.groupCache.Load(groupID)
				require.False(t, ok)
			} else {
				assert.Error(t, fc.UninstallServiceGroup(groupID))
				_, ok = fc.featureService.groupCache.Load(groupID)
				require.True(t, ok)
			}
		})
	}
}

func Test_client_InstallEndpointFlows(t *testing.T) {
	ep1IPv4 := "10.10.0.100"
	ep2IPv4 := "10.10.0.101"
	ep1IPv6 := "fec0:10:10::100"
	ep2IPv6 := "fec0:10:10::101"
	testCases := []struct {
		name          string
		protocol      binding.Protocol
		endpoints     []proxy.Endpoint
		expectedFlows []string
	}{
		{
			name:     "TCPv4 Endpoints",
			protocol: binding.ProtocolTCP,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo(ep1IPv4, "", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo(ep2IPv4, "", "", 80, true, true, false, false, nil),
			},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,tcp,reg3=0xa0a0064,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.100:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,tcp,reg3=0xa0a0065,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.101:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=SNATMark, priority=190,ct_state=+new+trk,ip,nw_src=10.10.0.101,nw_dst=10.10.0.101 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			},
		},
		{
			name:     "TCPv6 Endpoints",
			protocol: binding.ProtocolTCPv6,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo(ep1IPv6, "", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo(ep2IPv6, "", "", 80, true, true, false, false, nil),
			},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,tcp6,reg4=0x20050/0x7ffff,xxreg3=0xfec00010001000000000000000000100 actions=ct(commit,table=AntreaPolicyEgressRule,zone=65510,nat(dst=[fec0:10:10::100]:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,tcp6,reg4=0x20050/0x7ffff,xxreg3=0xfec00010001000000000000000000101 actions=ct(commit,table=AntreaPolicyEgressRule,zone=65510,nat(dst=[fec0:10:10::101]:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=SNATMark, priority=190,ct_state=+new+trk,ipv6,ipv6_src=fec0:10:10::101,ipv6_dst=fec0:10:10::101 actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			},
		},
		{
			name:     "UDPv4 Endpoints",
			protocol: binding.ProtocolUDP,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo(ep1IPv4, "", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo(ep2IPv4, "", "", 80, true, true, false, false, nil),
			},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,udp,reg3=0xa0a0064,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.100:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,udp,reg3=0xa0a0065,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.101:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=SNATMark, priority=190,ct_state=+new+trk,ip,nw_src=10.10.0.101,nw_dst=10.10.0.101 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			},
		},
		{
			name:     "UDPv6 Endpoints",
			protocol: binding.ProtocolUDPv6,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo(ep1IPv6, "", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo(ep2IPv6, "", "", 80, true, true, false, false, nil),
			},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,udp6,reg4=0x20050/0x7ffff,xxreg3=0xfec00010001000000000000000000100 actions=ct(commit,table=AntreaPolicyEgressRule,zone=65510,nat(dst=[fec0:10:10::100]:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,udp6,reg4=0x20050/0x7ffff,xxreg3=0xfec00010001000000000000000000101 actions=ct(commit,table=AntreaPolicyEgressRule,zone=65510,nat(dst=[fec0:10:10::101]:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=SNATMark, priority=190,ct_state=+new+trk,ipv6,ipv6_src=fec0:10:10::101,ipv6_dst=fec0:10:10::101 actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			},
		},
		{
			name:     "SCTPv4 Endpoints",
			protocol: binding.ProtocolSCTP,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo(ep1IPv4, "", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo(ep2IPv4, "", "", 80, true, true, false, false, nil),
			},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,sctp,reg3=0xa0a0064,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.100:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,sctp,reg3=0xa0a0065,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.101:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=SNATMark, priority=190,ct_state=+new+trk,ip,nw_src=10.10.0.101,nw_dst=10.10.0.101 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			},
		},
		{
			name:     "SCTPv6 Endpoints",
			protocol: binding.ProtocolSCTPv6,
			endpoints: []proxy.Endpoint{
				proxy.NewBaseEndpointInfo(ep1IPv6, "", "", 80, false, true, false, false, nil),
				proxy.NewBaseEndpointInfo(ep2IPv6, "", "", 80, true, true, false, false, nil),
			},
			expectedFlows: []string{
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,sctp6,reg4=0x20050/0x7ffff,xxreg3=0xfec00010001000000000000000000100 actions=ct(commit,table=AntreaPolicyEgressRule,zone=65510,nat(dst=[fec0:10:10::100]:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=200,sctp6,reg4=0x20050/0x7ffff,xxreg3=0xfec00010001000000000000000000101 actions=ct(commit,table=AntreaPolicyEgressRule,zone=65510,nat(dst=[fec0:10:10::101]:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1030000000000, table=SNATMark, priority=190,ct_state=+new+trk,ipv6,ipv6_src=fec0:10:10::101,ipv6_dst=fec0:10:10::101 actions=ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			assert.NoError(t, fc.InstallEndpointFlows(tc.protocol, tc.endpoints))
			var flows []string
			for _, ep := range tc.endpoints {
				endpointPort, _ := ep.Port()
				cacheKey := generateEndpointFlowCacheKey(ep.IP(), endpointPort, tc.protocol)
				fCacheI, ok := fc.featureService.cachedFlows.Load(cacheKey)
				require.True(t, ok)
				flows = append(flows, getFlowStrings(fCacheI)...)
			}
			assert.ElementsMatch(t, tc.expectedFlows, flows)

			assert.NoError(t, fc.UninstallEndpointFlows(tc.protocol, tc.endpoints))
			for _, ep := range tc.endpoints {
				endpointPort, _ := ep.Port()
				cacheKey := generateEndpointFlowCacheKey(ep.IP(), endpointPort, tc.protocol)
				_, ok := fc.featureService.cachedFlows.Load(cacheKey)
				require.False(t, ok)
			}
		})
	}
}

func Test_client_InstallServiceFlows(t *testing.T) {
	clusterGroupID := binding.GroupIDType(100)
	localGroupID := binding.GroupIDType(101)
	svcIPv4 := net.ParseIP("10.96.0.100")
	svcIPv6 := net.ParseIP("fec0:10:96::100")
	port := uint16(80)

	testCases := []struct {
		name               string
		trafficPolicyLocal bool
		protocol           binding.Protocol
		svcIP              net.IP
		affinityTimeout    uint16
		isExternal         bool
		isNodePort         bool
		isNested           bool
		isDSR              bool
		enableMulticluster bool
		expectedFlows      []string
	}{
		{
			name:     "Service ClusterIP",
			protocol: binding.ProtocolTCP,
			svcIP:    svcIPv4,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x64->reg7,group:100",
			},
		},
		{
			name:               "Service ClusterIP, local",
			protocol:           binding.ProtocolTCP,
			trafficPolicyLocal: true,
			svcIP:              svcIPv4,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x65->reg7,group:101",
			},
		},
		{
			name:     "Service ClusterIP,multicluster,nested",
			protocol: binding.ProtocolTCP,
			svcIP:    svcIPv4,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x64->reg7,set_field:0x1000000/0x1000000->reg4,group:100",
			},
			isNested:           true,
			enableMulticluster: true,
		},
		{
			name:     "Service ClusterIP,multicluster,non-nested",
			protocol: binding.ProtocolTCP,
			svcIP:    svcIPv4,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000000, table=EndpointDNAT, priority=210,tcp,reg3=0xa600064,reg4=0x1020050/0x107ffff actions=group:100",
			},
			isNested:           false,
			enableMulticluster: true,
		},
		{
			name:            "Service ClusterIP,SessionAffinity",
			protocol:        binding.ProtocolTCP,
			svcIP:           svcIPv4,
			affinityTimeout: uint16(100),
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,tcp,reg4=0x30000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x800,nw_proto=0x6,OXM_OF_TCP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service ClusterIP,IPv6,SessionAffinity",
			protocol:        binding.ProtocolTCPv6,
			svcIP:           svcIPv6,
			affinityTimeout: uint16(100),
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp6,reg4=0x10000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,tcp6,reg4=0x30000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x86dd,nw_proto=0x6,OXM_OF_TCP_DST[],NXM_NX_IPV6_DST[],NXM_NX_IPV6_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_XXREG3[]->NXM_NX_XXREG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service NodePort,SessionAffinity",
			protocol:        binding.ProtocolUDP,
			svcIP:           config.VirtualNodePortDNATIPv4,
			affinityTimeout: uint16(100),
			isExternal:      true,
			isNodePort:      true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,udp,reg4=0x90000/0xf0000,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,udp,reg4=0xb0000/0xf0000,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x800,nw_proto=0x11,OXM_OF_UDP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service NodePort,IPv6,SessionAffinity",
			protocol:        binding.ProtocolUDPv6,
			svcIP:           config.VirtualNodePortDNATIPv6,
			affinityTimeout: uint16(100),
			isExternal:      true,
			isNodePort:      true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,udp6,reg4=0x90000/0xf0000,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,udp6,reg4=0xb0000/0xf0000,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x86dd,nw_proto=0x11,OXM_OF_UDP_DST[],NXM_NX_IPV6_DST[],NXM_NX_IPV6_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_XXREG3[]->NXM_NX_XXREG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:               "Service NodePort,SessionAffinity,Short-circuiting",
			protocol:           binding.ProtocolUDP,
			svcIP:              config.VirtualNodePortDNATIPv4,
			affinityTimeout:    uint16(100),
			isExternal:         true,
			isNodePort:         true,
			trafficPolicyLocal: true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=210,udp,reg4=0x90000/0xf0000,nw_src=10.10.0.0/24,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000000, table=ServiceLB, priority=200,udp,reg4=0x90000/0xf0000,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x65->reg7,group:101",
				"cookie=0x1030000000065, table=ServiceLB, priority=190,udp,reg4=0xb0000/0xf0000,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000065,eth_type=0x800,nw_proto=0x11,OXM_OF_UDP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service LoadBalancer,SessionAffinity",
			protocol:        binding.ProtocolSCTP,
			svcIP:           svcIPv4,
			affinityTimeout: uint16(100),
			isExternal:      true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,sctp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,sctp,reg4=0x30000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x800,nw_proto=0x84,OXM_OF_SCTP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service LoadBalancer,IPv6,SessionAffinity",
			protocol:        binding.ProtocolSCTPv6,
			svcIP:           svcIPv6,
			affinityTimeout: uint16(100),
			isExternal:      true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=200,sctp6,reg4=0x10000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,sctp6,reg4=0x30000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x86dd,nw_proto=0x84,OXM_OF_SCTP_DST[],NXM_NX_IPV6_DST[],NXM_NX_IPV6_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_XXREG3[]->NXM_NX_XXREG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:               "Service LoadBalancer,SessionAffinity,Short-circuiting",
			protocol:           binding.ProtocolSCTP,
			svcIP:              svcIPv4,
			affinityTimeout:    uint16(100),
			isExternal:         true,
			trafficPolicyLocal: true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=210,sctp,reg4=0x10000/0x70000,nw_src=10.10.0.0/24,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000000, table=ServiceLB, priority=200,sctp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x65->reg7,group:101",
				"cookie=0x1030000000065, table=ServiceLB, priority=190,sctp,reg4=0x30000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000065,eth_type=0x800,nw_proto=0x84,OXM_OF_SCTP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:       "Service LoadBalancer,DSR",
			protocol:   binding.ProtocolTCP,
			svcIP:      svcIPv4,
			isExternal: true,
			isDSR:      true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=210,tcp,reg0=0x1/0xf,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x65->reg7,group:101",
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=DSRServiceMark, priority=200,tcp,reg4=0xc000000/0xe000000,nw_dst=10.96.0.100,tp_dst=80 actions=learn(table=SessionAffinity,idle_timeout=160,fin_idle_timeout=5,priority=210,delete_learned,cookie=0x1030000000064,eth_type=0x800,nw_proto=0x6,OXM_OF_TCP_SRC[],OXM_OF_TCP_DST[],NXM_OF_IP_SRC[],NXM_OF_IP_DST[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG4[25],load:NXM_NX_REG3[]->NXM_NX_REG3[]),set_field:0x2000000/0x2000000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:       "Service LoadBalancer,IPv6,DSR",
			protocol:   binding.ProtocolTCPv6,
			svcIP:      svcIPv6,
			isExternal: true,
			isDSR:      true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=210,tcp6,reg0=0x1/0xf,reg4=0x10000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x65->reg7,group:101",
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp6,reg4=0x10000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=DSRServiceMark, priority=200,tcp6,reg4=0xc000000/0xe000000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=learn(table=SessionAffinity,idle_timeout=160,fin_idle_timeout=5,priority=210,delete_learned,cookie=0x1030000000064,eth_type=0x86dd,nw_proto=0x6,OXM_OF_TCP_SRC[],OXM_OF_TCP_DST[],NXM_NX_IPV6_SRC[],NXM_NX_IPV6_DST[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG4[25],load:NXM_NX_XXREG3[]->NXM_NX_XXREG3[]),set_field:0x2000000/0x2000000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service LoadBalancer,SessionAffinity,DSR",
			protocol:        binding.ProtocolTCP,
			svcIP:           svcIPv4,
			affinityTimeout: uint16(100),
			isExternal:      true,
			isDSR:           true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=210,tcp,reg0=0x1/0xf,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x65->reg7,group:101",
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,tcp,reg4=0x30000/0x70000,nw_dst=10.96.0.100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x800,nw_proto=0x6,OXM_OF_TCP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:DSRServiceMark",
				"cookie=0x1030000000064, table=DSRServiceMark, priority=200,tcp,reg4=0xc000000/0xe000000,nw_dst=10.96.0.100,tp_dst=80 actions=learn(table=SessionAffinity,idle_timeout=160,fin_idle_timeout=5,priority=210,delete_learned,cookie=0x1030000000064,eth_type=0x800,nw_proto=0x6,OXM_OF_TCP_SRC[],OXM_OF_TCP_DST[],NXM_OF_IP_SRC[],NXM_OF_IP_DST[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG4[25],load:NXM_NX_REG3[]->NXM_NX_REG3[]),set_field:0x2000000/0x2000000->reg4,goto_table:EndpointDNAT",
			},
		},
		{
			name:            "Service LoadBalancer,IPv6,SessionAffinity,DSR",
			protocol:        binding.ProtocolTCPv6,
			svcIP:           svcIPv6,
			affinityTimeout: uint16(100),
			isExternal:      true,
			isDSR:           true,
			expectedFlows: []string{
				"cookie=0x1030000000000, table=ServiceLB, priority=210,tcp6,reg0=0x1/0xf,reg4=0x10000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x65->reg7,group:101",
				"cookie=0x1030000000000, table=ServiceLB, priority=200,tcp6,reg4=0x10000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0x64->reg7,group:100",
				"cookie=0x1030000000064, table=ServiceLB, priority=190,tcp6,reg4=0x30000/0x70000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=100,priority=200,delete_learned,cookie=0x1030000000064,eth_type=0x86dd,nw_proto=0x6,OXM_OF_TCP_DST[],NXM_NX_IPV6_DST[],NXM_NX_IPV6_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_XXREG3[]->NXM_NX_XXREG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9],load:0x1->NXM_NX_REG4[21]),set_field:0x20000/0x70000->reg4,goto_table:DSRServiceMark",
				"cookie=0x1030000000064, table=DSRServiceMark, priority=200,tcp6,reg4=0xc000000/0xe000000,ipv6_dst=fec0:10:96::100,tp_dst=80 actions=learn(table=SessionAffinity,idle_timeout=160,fin_idle_timeout=5,priority=210,delete_learned,cookie=0x1030000000064,eth_type=0x86dd,nw_proto=0x6,OXM_OF_TCP_SRC[],OXM_OF_TCP_DST[],NXM_NX_IPV6_SRC[],NXM_NX_IPV6_DST[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG4[25],load:NXM_NX_XXREG3[]->NXM_NX_XXREG3[]),set_field:0x2000000/0x2000000->reg4,goto_table:EndpointDNAT",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			var options []clientOptionsFn
			if tc.isDSR {
				options = append(options, enableDSR)
			}
			if tc.enableMulticluster {
				options = append(options, enableMulticluster)
			}
			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, options...)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			cacheKey := generateServicePortFlowCacheKey(tc.svcIP, port, tc.protocol)

			assert.NoError(t, fc.InstallServiceFlows(&types.ServiceConfig{
				ServiceIP:          tc.svcIP,
				ServicePort:        port,
				Protocol:           tc.protocol,
				TrafficPolicyLocal: tc.trafficPolicyLocal,
				LocalGroupID:       localGroupID,
				ClusterGroupID:     clusterGroupID,
				AffinityTimeout:    tc.affinityTimeout,
				IsExternal:         tc.isExternal,
				IsNodePort:         tc.isNodePort,
				IsNested:           tc.isNested,
				IsDSR:              tc.isDSR,
			}))
			fCacheI, ok := fc.featureService.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallServiceFlows(tc.svcIP, port, tc.protocol))
			_, ok = fc.featureService.cachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_GetServiceFlowKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)

	fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap)
	defer resetPipelines()

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(2)
	groupID := binding.GroupIDType(105)
	svcIP := net.ParseIP("10.96.0.224")
	svcPort := uint16(80)
	bindingProtocol := binding.ProtocolTCP
	endpoints := []proxy.Endpoint{
		proxy.NewBaseEndpointInfo("10.10.0.11", "", "", 80, false, true, false, false, nil),
		proxy.NewBaseEndpointInfo("10.10.0.12", "", "", 80, true, true, false, false, nil),
	}

	assert.NoError(t, fc.InstallServiceFlows(&types.ServiceConfig{
		ServiceIP:          svcIP,
		ServicePort:        svcPort,
		Protocol:           bindingProtocol,
		TrafficPolicyLocal: false,
		LocalGroupID:       0,
		ClusterGroupID:     groupID,
		AffinityTimeout:    100,
		IsExternal:         true,
		IsNodePort:         false,
		IsNested:           false,
		IsDSR:              false,
	}))
	assert.NoError(t, fc.InstallEndpointFlows(bindingProtocol, endpoints))
	flowKeys := fc.GetServiceFlowKeys(svcIP, svcPort, bindingProtocol, endpoints)
	expectedFlowKeys := []string{
		"table=11,priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.0.224,tp_dst=80",
		"table=11,priority=190,tcp,reg4=0x30000/0x70000,nw_dst=10.96.0.224,tp_dst=80",
		"table=12,priority=200,tcp,reg3=0xa0a000b,reg4=0x20050/0x7ffff",
		"table=12,priority=200,tcp,reg3=0xa0a000c,reg4=0x20050/0x7ffff",
		"table=20,priority=190,ct_state=+new+trk,ip,nw_src=10.10.0.12,nw_dst=10.10.0.12",
	}
	assert.ElementsMatch(t, expectedFlowKeys, flowKeys)
}

func Test_client_InstallSNATBypassServiceFlows(t *testing.T) {
	testCases := []struct {
		name             string
		serviceCIDRs     []*net.IPNet
		newServiceCIDRs  []*net.IPNet
		expectedFlows    []string
		expectedNewFlows []string
	}{
		{
			name: "IPv4",
			serviceCIDRs: []*net.IPNet{
				utilip.MustParseCIDR("10.96.0.0/24"),
			},
			newServiceCIDRs: []*net.IPNet{
				utilip.MustParseCIDR("10.96.0.0/16"),
			},
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=10.96.0.0/24 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
			expectedNewFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=10.96.0.0/16 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name: "IPv6",
			serviceCIDRs: []*net.IPNet{
				utilip.MustParseCIDR("1096::/80"),
			},
			newServiceCIDRs: []*net.IPNet{
				utilip.MustParseCIDR("1096::/64"),
			},
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=1096::/80 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
			expectedNewFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=1096::/64 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name: "dual-stack",
			serviceCIDRs: []*net.IPNet{
				utilip.MustParseCIDR("10.96.0.0/24"),
				utilip.MustParseCIDR("1096::/80"),
			},
			newServiceCIDRs: []*net.IPNet{
				utilip.MustParseCIDR("10.96.0.0/16"),
				utilip.MustParseCIDR("1096::/64"),
			},
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=10.96.0.0/24 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=1096::/80 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
			expectedNewFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=10.96.0.0/16 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=1096::/64 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			assert.NoError(t, fc.InstallSNATBypassServiceFlows(tc.serviceCIDRs))
			fCacheI, ok := fc.featureEgress.cachedFlows.Load("svc-cidrs")
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			m.EXPECT().BundleOps(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			assert.NoError(t, fc.InstallSNATBypassServiceFlows(tc.newServiceCIDRs))
			fCacheI, ok = fc.featureEgress.cachedFlows.Load("svc-cidrs")
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedNewFlows, getFlowStrings(fCacheI))
		})
	}
}

func Test_client_InstallSNATMarkFlows(t *testing.T) {
	mark := uint32(100)

	testCases := []struct {
		name                  string
		snatIP                net.IP
		trafficShapingEnabled bool
		expectedFlows         []string
	}{
		{
			name:                  "IPv4 SNAT IP",
			snatIP:                net.ParseIP("192.168.77.100"),
			trafficShapingEnabled: false,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,tun_dst=192.168.77.100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name:                  "IPv6 SNAT IP",
			snatIP:                net.ParseIP("fec0:192:168:77::100"),
			trafficShapingEnabled: false,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ipv6,tun_ipv6_dst=fec0:192:168:77::100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name:                  "IPv4 SNAT IP trafficShaping",
			snatIP:                net.ParseIP("192.168.77.100"),
			trafficShapingEnabled: true,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,tun_dst=192.168.77.100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:EgressQoS",
			},
		},
		{
			name:                  "IPv6 SNAT IP trafficShaping",
			snatIP:                net.ParseIP("fec0:192:168:77::100"),
			trafficShapingEnabled: true,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ipv6,tun_ipv6_dst=fec0:192:168:77::100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:EgressQoS",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, setEnableEgressTrafficShaping(tc.trafficShapingEnabled))
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			cacheKey := fmt.Sprintf("s%x", mark)
			assert.NoError(t, fc.InstallSNATMarkFlows(tc.snatIP, mark))
			fCacheI, ok := fc.featureEgress.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallSNATMarkFlows(mark))
			_, ok = fc.featureEgress.cachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallPodSNATFlows(t *testing.T) {
	snatIP := net.ParseIP("192.168.77.101")
	ofPort := uint32(100)

	testCases := []struct {
		name                  string
		trafficShapingEnabled bool
		snatMark              uint32
		expectedFlows         []string
	}{
		{
			name:                  "SNAT on Local",
			trafficShapingEnabled: false,
			snatMark:              uint32(100),
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,in_port=100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name:                  "SNAT on Remote",
			trafficShapingEnabled: false,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ip,in_port=100 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.77.101->tun_dst,set_field:0x10/0xf0->reg0,set_field:0x80000/0x80000->reg0,goto_table:L2ForwardingCalc",
			},
		},
		{
			name:                  "SNAT on Local trafficShaping",
			trafficShapingEnabled: true,
			snatMark:              uint32(100),
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,in_port=100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:EgressQoS",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, setEnableEgressTrafficShaping(tc.trafficShapingEnabled))
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)
			cacheKey := fmt.Sprintf("p%x", ofPort)

			assert.NoError(t, fc.InstallPodSNATFlows(ofPort, snatIP, tc.snatMark))
			fCacheI, ok := fc.featureEgress.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallPodSNATFlows(ofPort))
			_, ok = fc.featureEgress.cachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallEgressQoS(t *testing.T) {
	meterID := uint32(100)
	meterRate := uint32(100)
	meterBurst := uint32(200)
	expectedFlows := []string{"cookie=0x1040000000000, table=EgressQoS, priority=200,pkt_mark=0x64/0xff actions=meter:100,goto_table:L2ForwardingCalc"}

	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)
	bridge := ovsoftest.NewMockBridge(ctrl)
	fc := newFakeClientWithBridge(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, bridge, enableEgressTrafficShaping)
	defer resetPipelines()

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
	m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

	meter := ovsoftest.NewMockMeter(ctrl)
	meterBuilder := ovsoftest.NewMockMeterBandBuilder(ctrl)
	bridge.EXPECT().NewMeter(binding.MeterIDType(meterID), ofctrl.MeterBurst|ofctrl.MeterKbps).Return(meter).Times(1)
	meter.EXPECT().MeterBand().Return(meterBuilder).Times(1)
	meterBuilder.EXPECT().MeterType(ofctrl.MeterDrop).Return(meterBuilder).Times(1)
	meterBuilder.EXPECT().Rate(meterRate).Return(meterBuilder).Times(1)
	meterBuilder.EXPECT().Burst(meterBurst).Return(meterBuilder).Times(1)
	meterBuilder.EXPECT().Done().Return(meter).Times(1)
	meter.EXPECT().Add().Return(nil).Times(1)

	require.NoError(t, fc.InstallEgressQoS(meterID, meterRate, meterBurst))

	cacheKey := fmt.Sprintf("eq%x", meterID)
	fCacheI, ok := fc.featureEgress.cachedFlows.Load(cacheKey)
	require.True(t, ok)
	assert.ElementsMatch(t, expectedFlows, getFlowStrings(fCacheI))

	meter.EXPECT().Delete().Return(nil).Times(1)
	require.NoError(t, fc.UninstallEgressQoS(meterID))
	_, ok = fc.featureEgress.cachedFlows.Load(cacheKey)
	require.False(t, ok)
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
					IsIPv6:         true,
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
					IsIPv6:         true,
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
					IsIPv6:         true,
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
			fc := prepareSendTraceflowPacket(ctrl, !tt.wantErr)
			if err := fc.SendTraceflowPacket(tt.args.dataplaneTag, &tt.args.Packet, tt.args.inPort, tt.args.outPort); (err != nil) != tt.wantErr {
				t.Errorf("SendTraceflowPacket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func prepareTraceflowFlow(ctrl *gomock.Controller) *client {
	m := opstest.NewMockOFEntryOperations(ctrl)
	fc := newFakeClientWithBridge(m, true, false, config.K8sNode, config.TrafficEncapModeEncap, ovsoftest.NewMockBridge(ctrl))
	defer resetPipelines()

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
	_, ipCIDR, _ := net.ParseCIDR("192.168.2.30/32")
	flows, _ := EgressDefaultTable.ofTable.BuildFlow(priority100).Action().Drop().Done().GetBundleMessages(binding.AddMessage)
	flowMsg := flows[0].GetMessage().(*openflow15.FlowMod)
	ctx := &conjMatchFlowContext{
		dropFlow:              flowMsg,
		dropFlowEnableLogging: false,
		conjunctiveMatch: &conjunctiveMatch{
			tableID: 1,
			matchPairs: []matchPair{
				{
					matchKey:   MatchCTSrcIPNet,
					matchValue: *ipCIDR,
				},
			},
		}}
	fc.featureNetworkPolicy.globalConjMatchFlowCache["mockContext"] = ctx
	fc.featureNetworkPolicy.policyCache.Add(&policyRuleConjunction{metricFlows: []*openflow15.FlowMod{flowMsg}})
	return fc
}

func prepareSendTraceflowPacket(ctrl *gomock.Controller, success bool) *client {
	m := ovsoftest.NewMockBridge(ctrl)
	fc := newFakeClientWithBridge(nil, true, false, config.K8sNode, config.TrafficEncapModeEncap, m)
	defer resetPipelines()

	bridge := binding.OFBridge{}
	m.EXPECT().BuildPacketOut().Return(bridge.BuildPacketOut()).Times(1)
	if success {
		m.EXPECT().SendPacketOut(gomock.Any()).Times(1)
	}
	return fc
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
			c := prepareSetBasePacketOutBuilder(ctrl, !tt.wantErr)
			_, err := setBasePacketOutBuilder(c.bridge.BuildPacketOut(), tt.args.srcMAC, tt.args.dstMAC, tt.args.srcIP, tt.args.dstIP, tt.args.inPort, tt.args.outPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("setBasePacketOutBuilder() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func prepareSetBasePacketOutBuilder(ctrl *gomock.Controller, success bool) *client {
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, true, false, false, false, false, false, false, false, false, false, false, false, nil, false, defaultPacketInRate)
	m := ovsoftest.NewMockBridge(ctrl)
	ofClient.bridge = m
	bridge := binding.OFBridge{}
	m.EXPECT().BuildPacketOut().Return(bridge.BuildPacketOut()).Times(1)
	if success {
		m.EXPECT().SendPacketOut(gomock.Any()).Times(1)
	}
	return ofClient
}

func Test_client_SendPacketOut(t *testing.T) {
	dstIPv4 := net.ParseIP("10.10.0.66")
	dstIPv6 := net.ParseIP("fec0:10:10::66")
	testCases := []struct {
		name       string
		protocol   binding.Protocol
		isIPv6     bool
		icmpType   uint8
		icmpCode   uint8
		icmpData   []byte
		igmp       util.Message
		tcpSrcPort uint16
		tcpDstPort uint16
		tcpSeqNum  uint32
		tcpAckNum  uint32
		tcpHdrLen  uint8
		tcpFlag    uint8
		tcpWinSize uint16
		tcpData    []byte
		udpSrcPort uint16
		udpDstPort uint16
		udpData    []byte
	}{
		{
			name:       "SendTCPPacketOut IPv4",
			protocol:   binding.ProtocolTCP,
			tcpSrcPort: uint16(50000),
			tcpDstPort: uint16(80),
			tcpSeqNum:  uint32(7654321),
			tcpAckNum:  uint32(1234567),
			tcpHdrLen:  uint8(5),
			tcpFlag:    uint8(0b000100),
			tcpWinSize: uint16(123),
			tcpData:    []byte{1, 2, 3},
		},
		{
			name:       "SendTCPPacketOut IPv6",
			protocol:   binding.ProtocolTCPv6,
			isIPv6:     true,
			tcpSrcPort: uint16(50000),
			tcpDstPort: uint16(443),
			tcpSeqNum:  uint32(7654321),
			tcpAckNum:  uint32(1234567),
			tcpHdrLen:  uint8(8),
			tcpFlag:    uint8(0b000100),
			tcpWinSize: uint16(123),
			tcpData:    []byte{1, 2, 3},
		},
		{
			name:       "SendUDPPacketOut IPv4",
			protocol:   binding.ProtocolUDP,
			udpSrcPort: uint16(50000),
			udpDstPort: uint16(80),
			udpData:    []byte{0x11, 0x22},
		},
		{
			name:       "SendUDPPacketOut IPv6",
			protocol:   binding.ProtocolUDPv6,
			isIPv6:     true,
			udpSrcPort: uint16(50000),
			udpDstPort: uint16(443),
			udpData:    []byte{0x11, 0x22},
		},
		{
			name:     "SendICMPPacketOut IPv4",
			protocol: binding.ProtocolICMP,
			icmpType: uint8(3),
			icmpCode: uint8(10),
			icmpData: []byte{0x11, 0x22},
		},
		{
			name:     "SendICMPPacketOut IPv6",
			protocol: binding.ProtocolICMPv6,
			isIPv6:   true,
			icmpType: uint8(3),
			icmpCode: uint8(10),
			icmpData: []byte{0x11, 0x22},
		},
		{
			name:     "SendIGMPQueryPacketOut",
			protocol: binding.ProtocolIGMP,
			igmp: &protocol.IGMPv1or2{
				Type:            protocol.IGMPQuery,
				MaxResponseTime: 0,
				Checksum:        0,
				GroupAddress:    dstIPv4,
			},
		},
		{
			name:     "SendIGMPRemoteReportPacketOut",
			protocol: binding.ProtocolIGMP,
			igmp: &protocol.IGMPv1or2{
				Type:            protocol.IGMPQuery,
				MaxResponseTime: 0,
				Checksum:        0,
				GroupAddress:    dstIPv4,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockBridge := ovsoftest.NewMockBridge(ctrl)
			fc := newFakeClientWithBridge(nil, true, true, config.K8sNode, config.TrafficEncapModeEncap, mockBridge)
			defer resetPipelines()

			srcMAC := fc.nodeConfig.GatewayConfig.MAC
			dstMAC, _ := net.ParseMAC("00:00:10:10:00:66")
			srcIP := fc.nodeConfig.GatewayConfig.IPv4
			dstIP := dstIPv4
			if tc.isIPv6 {
				srcIP = fc.nodeConfig.GatewayConfig.IPv6
				dstIP = dstIPv6
			}

			inPort := fc.nodeConfig.GatewayConfig.OFPort
			outPort := uint32(2)
			if tc.name == "SendIGMPRemoteReportPacketOut" {
				inPort = openflow15.P_CONTROLLER
				outPort = 0
				srcIP = fc.nodeConfig.NodeIPv4Addr.IP
			}

			mockPacketOutBuilder := ovsoftest.NewMockPacketOutBuilder(ctrl)
			mockBridge.EXPECT().BuildPacketOut().Return(mockPacketOutBuilder)
			mockPacketOutBuilder.EXPECT().SetSrcMAC(srcMAC).Return(mockPacketOutBuilder)
			mockPacketOutBuilder.EXPECT().SetDstMAC(dstMAC).Return(mockPacketOutBuilder)
			mockPacketOutBuilder.EXPECT().SetSrcIP(srcIP).Return(mockPacketOutBuilder)
			mockPacketOutBuilder.EXPECT().SetDstIP(dstIP).Return(mockPacketOutBuilder)
			mockPacketOutBuilder.EXPECT().SetTTL(uint8(128)).Return(mockPacketOutBuilder)
			mockPacketOutBuilder.EXPECT().SetInport(inPort).Return(mockPacketOutBuilder)
			if outPort != 0 {
				mockPacketOutBuilder.EXPECT().SetOutport(outPort).Return(mockPacketOutBuilder)
			}
			mockPacketOutBuilder.EXPECT().Done()
			mockBridge.EXPECT().SendPacketOut(gomock.Any())
			mockPacketOutBuilder.EXPECT().SetIPProtocol(tc.protocol).Return(mockPacketOutBuilder)

			switch tc.protocol {
			case binding.ProtocolTCP, binding.ProtocolTCPv6:
				mockPacketOutBuilder.EXPECT().SetTCPSrcPort(tc.tcpSrcPort).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPDstPort(tc.tcpDstPort).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPSeqNum(tc.tcpSeqNum).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPAckNum(tc.tcpAckNum).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPHdrLen(tc.tcpHdrLen).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPFlags(tc.tcpFlag).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPWinSize(tc.tcpWinSize).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetTCPData(tc.tcpData).Return(mockPacketOutBuilder)
				assert.NoError(t, fc.SendTCPPacketOut(srcMAC.String(),
					dstMAC.String(),
					srcIP.String(),
					dstIP.String(),
					inPort,
					outPort,
					tc.isIPv6,
					tc.tcpSrcPort,
					tc.tcpDstPort,
					tc.tcpSeqNum,
					tc.tcpAckNum,
					tc.tcpHdrLen,
					tc.tcpFlag,
					tc.tcpWinSize,
					tc.tcpData,
					nil))
			case binding.ProtocolUDP, binding.ProtocolUDPv6:
				mockPacketOutBuilder.EXPECT().SetUDPSrcPort(tc.udpSrcPort).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetUDPDstPort(tc.udpDstPort).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetUDPData(tc.udpData).Return(mockPacketOutBuilder)
				assert.NoError(t, fc.SendUDPPacketOut(srcMAC.String(),
					dstMAC.String(),
					srcIP.String(),
					dstIP.String(),
					inPort,
					outPort,
					tc.isIPv6,
					tc.udpSrcPort,
					tc.udpDstPort,
					tc.udpData,
					nil))
			case binding.ProtocolICMP, binding.ProtocolICMPv6:
				mockPacketOutBuilder.EXPECT().SetICMPType(tc.icmpType).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetICMPCode(tc.icmpCode).Return(mockPacketOutBuilder)
				mockPacketOutBuilder.EXPECT().SetICMPData(tc.icmpData).Return(mockPacketOutBuilder)
				assert.NoError(t, fc.SendICMPPacketOut(srcMAC.String(),
					dstMAC.String(),
					srcIP.String(),
					dstIP.String(),
					inPort,
					outPort,
					tc.isIPv6,
					tc.icmpType,
					tc.icmpCode,
					tc.icmpData,
					nil))
			case binding.ProtocolIGMP:
				mockPacketOutBuilder.EXPECT().SetL4Packet(tc.igmp).Return(mockPacketOutBuilder)
				if tc.name == "SendIGMPQueryPacketOut" {
					assert.NoError(t, fc.SendIGMPQueryPacketOut(dstMAC, dstIP, outPort, tc.igmp))
				} else if tc.name == "SendIGMPRemoteReportPacketOut" {
					assert.NoError(t, fc.SendIGMPRemoteReportPacketOut(dstMAC, dstIP, tc.igmp))
				}
			}
		})
	}
}

func Test_client_InstallMulticastFlows(t *testing.T) {
	multicastIPv4 := net.ParseIP("224.0.0.100")
	groupID := binding.GroupIDType(101)

	testCases := []struct {
		name          string
		multicastIP   net.IP
		expectedFlows []string
	}{
		{
			name:        "IPv4 Multicast",
			multicastIP: multicastIPv4,
			expectedFlows: []string{
				"cookie=0x1050000000000, table=MulticastRouting, priority=200,ip,nw_dst=224.0.0.100 actions=group:101",
			},
		},
		//TODO: IPv6 Multicast
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, enableMulticast)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			cacheKey := fmt.Sprintf("multicast_%s", tc.multicastIP.String())
			assert.NoError(t, fc.InstallMulticastFlows(tc.multicastIP, groupID))
			fCacheI, ok := fc.featureMulticast.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallMulticastFlows(tc.multicastIP))
			_, ok = fc.featureMulticast.cachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallMulticastRemoteReportFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)

	fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap, enableMulticast)
	defer resetPipelines()

	groupID := binding.GroupIDType(102)
	expectedFlows := []string{
		"cookie=0x1050000000000, table=Classifier, priority=210,ip,in_port=1,nw_dst=224.0.0.0/4 actions=set_field:0x1/0xf->reg0,goto_table:MulticastEgressRule",
		"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,in_port=4294967293 actions=group:102",
		"cookie=0x1050000000000, table=Classifier, priority=200,in_port=4294967293 actions=goto_table:PipelineIPClassifier",
	}

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)

	cacheKey := "multicast_encap"

	assert.NoError(t, fc.InstallMulticastRemoteReportFlows(groupID))
	fCacheI, ok := fc.featureMulticast.cachedFlows.Load(cacheKey)
	require.True(t, ok)
	assert.ElementsMatch(t, expectedFlows, getFlowStrings(fCacheI))
}

func Test_client_InstallMulticasFlexibleIPAMFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	m := opstest.NewMockOFEntryOperations(ctrl)
	fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeNoEncap, enableMulticast, enableConnectUplinkToBridge, disableEgress)
	defer resetPipelines()

	expectedFlows := []string{
		"cookie=0x1050000000000, table=Classifier, priority=210,ip,in_port=4,nw_dst=224.0.0.0/4 actions=goto_table:MulticastEgressRule",
		"cookie=0x1050000000000, table=Classifier, priority=210,ip,in_port=4294967294,nw_dst=224.0.0.0/4 actions=goto_table:MulticastEgressRule",
	}

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)

	cacheKey := "multicast_flexible_ipam"

	assert.NoError(t, fc.InstallMulticastFlexibleIPAMFlows())
	fCacheI, ok := fc.featureMulticast.cachedFlows.Load(cacheKey)
	require.True(t, ok)
	assert.ElementsMatch(t, expectedFlows, getFlowStrings(fCacheI))
}

func Test_client_SendIGMPQueryPacketOut(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockBridge := ovsoftest.NewMockBridge(ctrl)
	fc := newFakeClientWithBridge(nil, true, false, config.K8sNode, config.TrafficEncapModeEncap, mockBridge)
	defer resetPipelines()

	srcMAC := fc.nodeConfig.GatewayConfig.MAC
	srcIP := fc.nodeConfig.GatewayConfig.IPv4
	inPort := fc.nodeConfig.GatewayConfig.OFPort
	dstMAC, _ := net.ParseMAC("00:00:10:10:00:66")
	dstIP := net.ParseIP("10.10.0.66")
	outPort := uint32(0)
	igmp := &protocol.IGMPv1or2{
		Type:            protocol.IGMPQuery,
		MaxResponseTime: 0,
		Checksum:        0,
		GroupAddress:    dstIP,
	}

	mockPacketOutBuilder := ovsoftest.NewMockPacketOutBuilder(ctrl)
	mockBridge.EXPECT().BuildPacketOut().Return(mockPacketOutBuilder).AnyTimes()

	mockPacketOutBuilder.EXPECT().SetSrcMAC(srcMAC).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().SetDstMAC(dstMAC).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().SetSrcIP(srcIP).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().SetDstIP(dstIP).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().SetTTL(uint8(128)).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().SetInport(inPort).Return(mockPacketOutBuilder)
	if outPort != 0 {
		mockPacketOutBuilder.EXPECT().SetOutport(outPort).Return(mockPacketOutBuilder)
	}

	mockPacketOutBuilder.EXPECT().SetIPProtocol(binding.ProtocolIGMP).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().SetL4Packet(igmp).Return(mockPacketOutBuilder)
	mockPacketOutBuilder.EXPECT().Done()

	mockBridge.EXPECT().SendPacketOut(gomock.Any())
	assert.NoError(t, fc.SendIGMPQueryPacketOut(dstMAC, dstIP, outPort, igmp))
}

func Test_client_InstallTrafficControlMarkFlows(t *testing.T) {
	tcName := "test_tc"
	sourceOFPorts := []uint32{50, 100}
	targetOFPort := uint32(200)

	testCases := []struct {
		name          string
		direction     v1alpha2.Direction
		action        v1alpha2.TrafficControlAction
		expectedFlows []string
	}{
		{
			name:      "Egress,Mirror",
			direction: v1alpha2.DirectionEgress,
			action:    v1alpha2.ActionMirror,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=50 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=100 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:      "Ingress,Mirror",
			direction: v1alpha2.DirectionIngress,
			action:    v1alpha2.ActionMirror,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x32 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x64 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:      "Both,Mirror",
			direction: v1alpha2.DirectionBoth,
			action:    v1alpha2.ActionMirror,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x32 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=50 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x64 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=100 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:      "Egress,Redirect",
			direction: v1alpha2.DirectionEgress,
			action:    v1alpha2.ActionRedirect,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=50 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=100 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:      "Ingress,Redirect",
			direction: v1alpha2.DirectionIngress,
			action:    v1alpha2.ActionRedirect,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x32 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x64 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:      "Both,Redirect",
			direction: v1alpha2.DirectionBoth,
			action:    v1alpha2.ActionRedirect,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x32 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=50 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0x64 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=100 actions=set_field:0xc8->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, enableTrafficControl)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			cacheKey := fmt.Sprintf("tc_%s", tcName)

			assert.NoError(t, fc.InstallTrafficControlMarkFlows(tcName, sourceOFPorts, targetOFPort, tc.direction, tc.action, types.TrafficControlFlowPriorityMedium))
			fCacheI, ok := fc.featurePodConnectivity.tcCachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallTrafficControlMarkFlows(tcName))
			_, ok = fc.featurePodConnectivity.tcCachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallTrafficControlReturnPortFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)

	fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, enableTrafficControl)
	defer resetPipelines()

	returnOFPort := uint32(200)
	expectedFlows := []string{
		"cookie=0x1010000000000, table=Classifier, priority=200,in_port=200 actions=set_field:0x6/0xf->reg0,goto_table:L3Forwarding",
	}

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
	m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

	cacheKey := fmt.Sprintf("tc_%d", returnOFPort)

	assert.NoError(t, fc.InstallTrafficControlReturnPortFlow(returnOFPort))
	fCacheI, ok := fc.featurePodConnectivity.tcCachedFlows.Load(cacheKey)
	require.True(t, ok)
	assert.ElementsMatch(t, expectedFlows, getFlowStrings(fCacheI))

	assert.NoError(t, fc.UninstallTrafficControlReturnPortFlow(returnOFPort))
	_, ok = fc.featurePodConnectivity.tcCachedFlows.Load(cacheKey)
	require.False(t, ok)
}

func Test_client_InstallMulticastGroup(t *testing.T) {
	groupID := binding.GroupIDType(101)
	localReceivers := []uint32{50, 100}
	remoteNodeReceivers := []net.IP{net.ParseIP("192.168.77.101"), net.ParseIP("192.168.77.102")}
	testCases := []struct {
		name                 string
		localReceivers       []uint32
		remoteNodeReceivers  []net.IP
		expectedGroup        string
		deleteOFEntriesError error
	}{
		{
			name:           "Local Receivers",
			localReceivers: localReceivers,
			expectedGroup: "group_id=101,type=all," +
				"bucket=bucket_id:0,actions=set_field:0x200000/0x600000->reg0,set_field:0x32->reg1,resubmit:MulticastIngressRule," +
				"bucket=bucket_id:1,actions=set_field:0x200000/0x600000->reg0,set_field:0x64->reg1,resubmit:MulticastIngressRule",
		},
		{
			name:                "Remote Node Receivers",
			remoteNodeReceivers: remoteNodeReceivers,
			expectedGroup: "group_id=101,type=all," +
				"bucket=bucket_id:0,actions=set_field:0x200000/0x600000->reg0,set_field:0x1->reg1,set_field:192.168.77.101->tun_dst,resubmit:MulticastOutput," +
				"bucket=bucket_id:1,actions=set_field:0x200000/0x600000->reg0,set_field:0x1->reg1,set_field:192.168.77.102->tun_dst,resubmit:MulticastOutput",
		},
		{
			name:                "Local and Remote Node Receivers",
			localReceivers:      localReceivers,
			remoteNodeReceivers: remoteNodeReceivers,
			expectedGroup: "group_id=101,type=all," +
				"bucket=bucket_id:0,actions=set_field:0x200000/0x600000->reg0,set_field:0x32->reg1,resubmit:MulticastIngressRule," +
				"bucket=bucket_id:1,actions=set_field:0x200000/0x600000->reg0,set_field:0x64->reg1,resubmit:MulticastIngressRule," +
				"bucket=bucket_id:2,actions=set_field:0x200000/0x600000->reg0,set_field:0x1->reg1,set_field:192.168.77.101->tun_dst,resubmit:MulticastOutput," +
				"bucket=bucket_id:3,actions=set_field:0x200000/0x600000->reg0,set_field:0x1->reg1,set_field:192.168.77.102->tun_dst,resubmit:MulticastOutput",
		},
		{
			name:           "DeleteOFEntries Failed",
			localReceivers: localReceivers,
			expectedGroup: "group_id=101,type=all," +
				"bucket=bucket_id:0,actions=set_field:0x200000/0x600000->reg0,set_field:0x32->reg1,resubmit:MulticastIngressRule," +
				"bucket=bucket_id:1,actions=set_field:0x200000/0x600000->reg0,set_field:0x64->reg1,resubmit:MulticastIngressRule",
			deleteOFEntriesError: fmt.Errorf("error when deleting Openflow entries for Multicast receiver Group 101"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, enableMulticast)
			defer resetPipelines()

			m.EXPECT().AddOFEntries(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteOFEntries(gomock.Any()).Return(tc.deleteOFEntriesError).Times(1)

			assert.NoError(t, fc.InstallMulticastGroup(groupID, tc.localReceivers, tc.remoteNodeReceivers))
			gCacheI, ok := fc.featureMulticast.groupCache.Load(groupID)
			require.True(t, ok)
			group := getGroupFromCache(gCacheI.(binding.Group))
			assert.Equal(t, tc.expectedGroup, group)

			if tc.deleteOFEntriesError == nil {
				assert.NoError(t, fc.UninstallMulticastGroup(groupID))
				_, ok = fc.featureMulticast.groupCache.Load(groupID)
				require.False(t, ok)
			} else {
				assert.Error(t, fc.UninstallMulticastGroup(groupID))
				_, ok = fc.featureMulticast.groupCache.Load(groupID)
				require.True(t, ok)
			}
		})
	}
}

func Test_client_InstallMulticlusterNodeFlows(t *testing.T) {
	clusterID := "test_cluster"
	_, peerServiceCIDRIPv4, _ := net.ParseCIDR("10.97.0.0/16")
	tunnelPeerIPv4 := net.ParseIP("192.168.78.101")

	testCases := []struct {
		name          string
		peerConfigs   map[*net.IPNet]net.IP
		tunnelPeerIP  net.IP
		expectedFlows []string
	}{
		{
			name:         "IPv4",
			peerConfigs:  map[*net.IPNet]net.IP{peerServiceCIDRIPv4: tunnelPeerIPv4},
			tunnelPeerIP: tunnelPeerIPv4,
			expectedFlows: []string{
				"cookie=0x1060000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.97.0.0/16 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1060000000000, table=L3Forwarding, priority=200,ct_state=+rpl+trk,ip,nw_dst=192.168.78.101 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1060000000000, table=L3Forwarding, priority=199,ip,reg0=0x2000/0x2000,nw_dst=192.168.78.101 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
			},
		},
		//TODO: IPv6
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, enableMulticluster)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			assert.NoError(t, fc.InstallMulticlusterNodeFlows(clusterID, tc.peerConfigs, tc.tunnelPeerIP, true))
			cacheKey := fmt.Sprintf("cluster_%s", clusterID)
			fCacheI, ok := fc.featureMulticluster.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallMulticlusterFlows(clusterID))
			_, ok = fc.featureMulticluster.cachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallMulticlusterGatewayFlows(t *testing.T) {
	clusterID := "test_cluster"
	_, peerServiceCIDRIPv4, _ := net.ParseCIDR("10.97.0.0/16")
	tunnelPeerIPv4 := net.ParseIP("192.168.78.101")
	localGatewayIPv4 := net.ParseIP("192.168.77.100")

	testCases := []struct {
		name           string
		peerConfigs    map[*net.IPNet]net.IP
		tunnelPeerIP   net.IP
		localGatewayIP net.IP
		expectedFlows  []string
	}{
		{
			name:           "IPv4",
			peerConfigs:    map[*net.IPNet]net.IP{peerServiceCIDRIPv4: tunnelPeerIPv4},
			tunnelPeerIP:   tunnelPeerIPv4,
			localGatewayIP: localGatewayIPv4,
			expectedFlows: []string{
				"cookie=0x1060000000000, table=UnSNAT, priority=200,ip,nw_dst=192.168.77.100 actions=ct(table=ConntrackZone,zone=65521,nat)",
				"cookie=0x1060000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.97.0.0/16 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1060000000000, table=L3Forwarding, priority=200,ct_state=+rpl+trk,ip,nw_dst=192.168.78.101 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1060000000000, table=L3Forwarding, priority=199,ip,reg0=0x2000/0x2000,nw_dst=192.168.78.101 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1060000000000, table=SNATMark, priority=210,ct_state=+new+trk,ip,nw_dst=10.97.0.0/16 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark))",
				"cookie=0x1060000000000, table=SNAT, priority=200,ct_state=+new+trk,ip,nw_dst=10.97.0.0/16 actions=ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=192.168.77.100))",
			},
		},
		//TODO: IPv6
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeEncap, enableMulticluster)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

			cacheKey := fmt.Sprintf("cluster_%s", clusterID)

			assert.NoError(t, fc.InstallMulticlusterGatewayFlows(clusterID, tc.peerConfigs, tc.tunnelPeerIP, tc.localGatewayIP, true))
			fCacheI, ok := fc.featureMulticluster.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			assert.NoError(t, fc.UninstallMulticlusterFlows(clusterID))
			_, ok = fc.featureMulticluster.cachedFlows.Load(cacheKey)
			require.False(t, ok)
		})
	}
}

func Test_client_InstallMulticlusterClassifierFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)

	fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap, enableMulticluster)
	defer resetPipelines()

	tunnelOFPort := uint32(200)
	expectedFlows := []string{
		"cookie=0x1060000000000, table=Classifier, priority=210,in_port=200,dl_dst=aa:bb:cc:dd:ee:f0 actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
		"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=aa:bb:cc:dd:ee:f0 actions=set_field:0xc8->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
		"cookie=0x1060000000000, table=Output, priority=210,reg1=0xc8,in_port=200 actions=IN_PORT",
	}

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)

	cacheKey := "multicluster-classifier"

	assert.NoError(t, fc.InstallMulticlusterClassifierFlows(tunnelOFPort, true))
	fCacheI, ok := fc.featureMulticluster.cachedFlows.Load(cacheKey)
	require.True(t, ok)
	assert.ElementsMatch(t, expectedFlows, getFlowStrings(fCacheI))
}

func Test_client_RegisterPacketInHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	bridge := ovsoftest.NewMockBridge(ctrl)
	fc := newFakeClientWithBridge(nil, true, false, config.K8sNode, config.TrafficEncapModeEncap, bridge)
	defer resetPipelines()
	bridge.EXPECT().ResumePacket(gomock.Any()).Times(1)
	fc.ResumePausePacket(nil)
}

func Test_client_ReplayFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	m := opstest.NewMockOFEntryOperations(ctrl)
	bridge := ovsoftest.NewMockBridge(ctrl)
	clientOptions := []clientOptionsFn{enableTrafficControl, enableMulticast, enableMulticluster, enableEgressTrafficShaping}
	fc := newFakeClientWithBridge(m, true, false, config.K8sNode, config.TrafficEncapModeEncap, bridge, clientOptions...)
	defer resetPipelines()

	expectedFlows := append(pipelineDefaultFlows(true /* egressTrafficShapingEnabled */, false /* externalNodeEnabled */, true /* isEncap */, true /* isIPv4 */), egressInitFlows(true)...)
	expectedFlows = append(expectedFlows, multicastInitFlows(true)...)
	expectedFlows = append(expectedFlows, networkPolicyInitFlows(true, false, false)...)
	expectedFlows = append(expectedFlows, podConnectivityInitFlows(config.TrafficEncapModeEncap, config.TrafficEncryptionModeNone, false, true, true, true)...)
	expectedFlows = append(expectedFlows, serviceInitFlows(true, true, false, false)...)

	addFlowInCache := func(cache *flowCategoryCache, cacheKey string, flows []binding.Flow) {
		fCache := flowMessageCache{}
		for _, flow := range flows {
			msg := getFlowModMessage(flow, binding.AddMessage)
			fCache[flow.MatchString()] = msg
		}
		cache.Store(cacheKey, fCache)
	}

	replayedFlows := make([]string, 0)
	// Feature Egress replays flows.
	snatIP := net.ParseIP("192.168.77.100")
	addFlowInCache(fc.featureEgress.cachedFlows, "egressFlows", []binding.Flow{fc.featureEgress.snatIPFromTunnelFlow(snatIP, uint32(100))})
	replayedFlows = append(replayedFlows,
		"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,tun_dst=192.168.77.100 actions=set_field:0x64/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:EgressQoS",
		"cookie=0x1040000000000, table=EgressQoS, priority=190 actions=goto_table:L2ForwardingCalc",
	)
	// Feature Multicast replays flows.
	podIP := net.ParseIP("10.10.0.66")
	podOfPort := uint32(100)
	addFlowInCache(fc.featureMulticast.cachedFlows, "multicastFlows", fc.featureMulticast.multicastPodMetricFlows(podIP, podOfPort))
	replayedFlows = append(replayedFlows,
		"cookie=0x1050000000000, table=MulticastEgressPodMetric, priority=200,ip,nw_src=10.10.0.66 actions=goto_table:MulticastRouting",
		"cookie=0x1050000000000, table=MulticastIngressPodMetric, priority=200,ip,reg1=0x64 actions=goto_table:MulticastOutput",
	)
	// Feature Multi-cluster replays flows.
	_, peerServiceCIDRIPv4, _ := net.ParseCIDR("10.97.0.0/16")
	tunnelPeerIP := net.ParseIP("192.168.78.101")
	localGatewayMAC, _ := net.ParseMAC("0a:00:00:00:00:01")
	addFlowInCache(fc.featureMulticluster.cachedFlows, "multiClusterFlows", fc.featureMulticluster.l3FwdFlowToRemoteGateway(localGatewayMAC, *peerServiceCIDRIPv4, tunnelPeerIP, tunnelPeerIP, true))
	replayedFlows = append(replayedFlows,
		"cookie=0x1060000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.97.0.0/16 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
		"cookie=0x1060000000000, table=L3Forwarding, priority=200,ct_state=+rpl+trk,ip,nw_dst=192.168.78.101 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
		"cookie=0x1060000000000, table=L3Forwarding, priority=199,ip,reg0=0x2000/0x2000,nw_dst=192.168.78.101 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:f0->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
	)
	// Feature Network Policy replays flows.
	fc.featureNetworkPolicy.initGroups()
	expectedGroups := []string{
		"group_id=1,type=all,bucket=bucket_id:0,actions=resubmit:EgressRule,bucket=bucket_id:1,actions=set_field:0x400000/0x600000->reg0,resubmit:Output",
		"group_id=2,type=all,bucket=bucket_id:0,actions=resubmit:EgressMetric,bucket=bucket_id:1,actions=set_field:0x400000/0x600000->reg0,resubmit:Output",
		"group_id=3,type=all,bucket=bucket_id:0,actions=resubmit:IngressRule,bucket=bucket_id:1,actions=set_field:0x400000/0x600000->reg0,resubmit:Output",
		"group_id=4,type=all,bucket=bucket_id:0,actions=resubmit:IngressMetric,bucket=bucket_id:1,actions=set_field:0x400000/0x600000->reg0,resubmit:Output",
		"group_id=5,type=all,bucket=bucket_id:0,actions=resubmit:MulticastEgressMetric,bucket=bucket_id:1,actions=set_field:0x400000/0x600000->reg0,resubmit:Output",
		"group_id=6,type=all,bucket=bucket_id:0,actions=resubmit:MulticastIngressMetric,bucket=bucket_id:1,actions=set_field:0x400000/0x600000->reg0,resubmit:Output",
	}
	ruleID := uint32(15)
	priority200 = uint16(200)
	conj := &policyRuleConjunction{
		id:          ruleID,
		actionFlows: []*openflow15.FlowMod{getFlowModMessage(fc.featureNetworkPolicy.conjunctionActionDenyFlow(ruleID, IngressRuleTable.ofTable, &priority200, DispositionDrop, true), binding.AddMessage)},
		metricFlows: []*openflow15.FlowMod{getFlowModMessage(fc.featureNetworkPolicy.denyRuleMetricFlow(ruleID, true, IngressMetricTable.GetID()), binding.AddMessage)},
	}
	assert.NoError(t, fc.featureNetworkPolicy.policyCache.Add(conj))
	mp := matchPair{matchKey: MatchDstOFPort, matchValue: int32(podOfPort)}
	context := &conjMatchFlowContext{
		flow:     getFlowModMessage(fc.featureNetworkPolicy.conjunctiveMatchFlow(IngressRuleTable.GetID(), []matchPair{mp}, &priority200, []*conjunctiveAction{{conjID: ruleID, clauseID: 2, nClause: 2}}), binding.AddMessage),
		dropFlow: getFlowModMessage(fc.featureNetworkPolicy.defaultDropFlow(IngressDefaultTable.ofTable, []matchPair{mp}, true), binding.AddMessage),
	}
	fc.featureNetworkPolicy.globalConjMatchFlowCache["npMatch"] = context
	replayedFlows = append(replayedFlows,
		"cookie=0x1020000000000, table=IngressRule, priority=200,reg1=0x64 actions=conjunction(15,2/2)",
		"cookie=0x1020000000000, table=IngressMetric, priority=200,reg0=0x400/0x400,reg3=0xf actions=drop",
	)
	replayedFlows = append(replayedFlows,
		"cookie=0x1020000000000, table=IngressRule, priority=200,conj_id=15 actions=set_field:0xf->reg3,set_field:0x400/0x400->reg0,set_field:0x800/0x1800->reg0,set_field:0x2000000/0xfe000000->reg0,set_field:0x1b/0xff->reg2,group:4",
		"cookie=0x1020000000000, table=IngressDefaultRule, priority=200,reg1=0x64 actions=set_field:0x800/0x1800->reg0,set_field:0x2000000/0xfe000000->reg0,set_field:0x400000/0x600000->reg0,set_field:0x1c/0xff->reg2,goto_table:Output",
	)

	// Feature Pod connectivity replays flows.
	podMAC, _ := net.ParseMAC("00:00:10:10:00:66")
	addFlowInCache(fc.featurePodConnectivity.podCachedFlows, "podFlows", fc.featurePodConnectivity.l3FwdFlowToPod(localGatewayMAC, []net.IP{podIP}, podMAC, false, 0))
	replayedFlows = append(replayedFlows,
		"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.66 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:00:00:10:10:00:66->eth_dst,goto_table:L3DecTTL",
	)
	_, peerPodCIDR, _ := net.ParseCIDR("10.10.1.0/24")
	addFlowInCache(fc.featurePodConnectivity.nodeCachedFlows, "nodeFlows", fc.featurePodConnectivity.l3FwdFlowsToRemoteViaTun(localGatewayMAC, *peerPodCIDR, tunnelPeerIP))
	replayedFlows = append(replayedFlows,
		"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,nw_dst=10.10.1.0/24 actions=set_field:0a:00:00:00:00:01->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.78.101->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL",
	)
	sourceOFPorts := []uint32{50, 100}
	targetOFPort := uint32(200)
	addFlowInCache(fc.featurePodConnectivity.tcCachedFlows, "tcFlows", fc.featurePodConnectivity.trafficControlMarkFlows(sourceOFPorts, targetOFPort, v1alpha2.DirectionEgress, v1alpha2.ActionMirror, priorityNormal))
	replayedFlows = append(replayedFlows,
		"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=50 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
		"cookie=0x1010000000000, table=TrafficControl, priority=200,in_port=100 actions=set_field:0xc8->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier",
	)
	// Feature Service replays flows.
	addFlowInCache(fc.featureService.cachedFlows, "endpointFlow", []binding.Flow{fc.featureService.endpointDNATFlow(podIP, uint16(80), binding.ProtocolTCP)})
	replayedFlows = append(replayedFlows,
		"cookie=0x1030000000000, table=EndpointDNAT, priority=200,tcp,reg3=0xa0a0042,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.66:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
	)

	expectedFlows = append(expectedFlows, replayedFlows...)

	bridge.EXPECT().DeleteGroupAll().Return(nil).Times(1)
	bridge.EXPECT().DeleteMeterAll().Return(nil).Times(1)

	actualGroups := make([]string, 0)
	m.EXPECT().AddOFEntries(gomock.Any()).Do(func(ofEntries []binding.OFEntry) {
		for _, entry := range ofEntries {
			switch entry.Type() {
			case binding.GroupEntry:
				groupString := getGroupFromCache(entry.(binding.Group))
				actualGroups = append(actualGroups, groupString)
			case binding.MeterEntry:

			}

		}
	}).AnyTimes()

	actualFlows := make([]string, 0)
	m.EXPECT().AddAll(gomock.Any()).Do(func(flowMessages []*openflow15.FlowMod) {
		flowStrings := getFlowStrings(flowMessages)
		actualFlows = append(actualFlows, flowStrings...)
	}).Return(nil).AnyTimes()

	// Use mock for the unit test on meter is because the current implementation in ofnet does not support
	// sending Meter modification message in a bundle message. The "Add" meter actions is dependent on a valid
	// connection to OVS, hence it may return timeout error without a mock which is possibly block the comparation
	// on the flows and groups.
	egressMeterID := uint32(1)
	egressMeterRate := uint32(100)
	egressMeterBurst := uint32(200)
	expectNewMeter := func(id, rate, burst uint32, unit ofctrl.MeterFlag, isCached bool) {
		meter := ovsoftest.NewMockMeter(ctrl)
		meterBuilder := ovsoftest.NewMockMeterBandBuilder(ctrl)
		bridge.EXPECT().NewMeter(binding.MeterIDType(id), ofctrl.MeterBurst|unit).Return(meter).Times(1)
		meter.EXPECT().MeterBand().Return(meterBuilder).Times(1)
		meterBuilder.EXPECT().MeterType(ofctrl.MeterDrop).Return(meterBuilder).Times(1)
		meterBuilder.EXPECT().Rate(rate).Return(meterBuilder).Times(1)
		meterBuilder.EXPECT().Burst(burst).Return(meterBuilder).Times(1)
		meterBuilder.EXPECT().Done().Return(meter).Times(1)
		if isCached {
			meter.EXPECT().Reset().Times(1)
		}
		meter.EXPECT().Add().Return(nil).Times(1)
	}
	// egress QOS meter:
	expectNewMeter(egressMeterID, egressMeterRate, egressMeterBurst, ofctrl.MeterKbps, true)
	egressMeter := fc.genOFMeter(binding.MeterIDType(egressMeterID), ofctrl.MeterBurst|ofctrl.MeterKbps, egressMeterRate, egressMeterBurst)
	fc.featureEgress.cachedMeter.Store(egressMeterID, egressMeter)
	// "static" PacketIn meters:
	for _, meterCfg := range []struct {
		id   binding.MeterIDType
		rate uint32
	}{
		{id: PacketInMeterIDNP, rate: uint32(defaultPacketInRate)},
		{id: PacketInMeterIDTF, rate: uint32(defaultPacketInRate)},
		{id: PacketInMeterIDDNS, rate: uint32(defaultPacketInRate)},
	} {
		expectNewMeter(uint32(meterCfg.id), meterCfg.rate, meterCfg.rate*2, ofctrl.MeterPktps, false)
	}

	fc.ReplayFlows()
	assert.ElementsMatch(t, expectedFlows, actualFlows)
	assert.ElementsMatch(t, expectedGroups, actualGroups)
}

func TestCachedFlowIsDrop(t *testing.T) {
	_, ipCIDR, _ := net.ParseCIDR("192.168.2.30/32")
	flows, err := EgressDefaultTable.ofTable.
		BuildFlow(priority100).
		MatchDstIPNet(*ipCIDR).
		Action().Drop().
		Done().
		GetBundleMessages(binding.AddMessage)
	assert.NoError(t, err)
	require.Equal(t, 1, len(flows))
	msg := flows[0].GetMessage().(*openflow15.FlowMod)
	assert.True(t, isDropFlow(msg))

	flows, err = EgressDefaultTable.ofTable.
		BuildFlow(priority100).
		MatchDstIPNet(*ipCIDR).
		Action().GotoTable(1).
		Done().
		GetBundleMessages(binding.AddMessage)
	assert.NoError(t, err)
	require.Equal(t, 1, len(flows))
	msg = flows[0].GetMessage().(*openflow15.FlowMod)
	assert.False(t, isDropFlow(msg))
}
