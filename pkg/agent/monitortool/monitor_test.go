// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitortool

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/pkg/agent/config"
	monitortesting "antrea.io/antrea/pkg/agent/monitortool/testing"
	"antrea.io/antrea/pkg/agent/util/nettest"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/ip"
)

func makeNode(nodeName string, nodeIPs []string, podCIDRs []string) *corev1.Node {
	addresses := []corev1.NodeAddress{}
	for _, ip := range nodeIPs {
		addresses = append(addresses, corev1.NodeAddress{
			Type:    corev1.NodeInternalIP,
			Address: ip,
		})
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDRs[0],
			PodCIDRs: podCIDRs,
		},
		Status: corev1.NodeStatus{
			Addresses: addresses,
		},
	}
}

var (
	nodeConfigDualStack = &config.NodeConfig{
		Name:         "node1",
		PodIPv4CIDR:  ip.MustParseCIDR("10.0.1.0/24"),
		PodIPv6CIDR:  ip.MustParseCIDR("2001:ab03:cd04:55ee:100a::/80"),
		NodeIPv4Addr: ip.MustParseCIDR("192.168.77.100/24"),
		NodeIPv6Addr: ip.MustParseCIDR("192:168:77::100/80"),
	}
	nodeConfigIPv4 = &config.NodeConfig{
		Name:         "node1",
		PodIPv4CIDR:  ip.MustParseCIDR("10.0.1.0/24"),
		NodeIPv4Addr: ip.MustParseCIDR("192.168.77.100/24"),
	}

	nlm = &crdv1alpha1.NodeLatencyMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: crdv1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: 60,
		},
	}

	node1 = makeNode("node1", []string{"192.168.77.101", "192:168:77::101"}, []string{"10.0.1.0/24", "2001:ab03:cd04:55ee:100a::/80"})
	node2 = makeNode("node2", []string{"192.168.77.102", "192:168:77::102"}, []string{"10.0.2.0/24", "2001:ab03:cd04:55ee:100b::/80"})
	node3 = makeNode("node3", []string{"192.168.77.103", "192:168:77::103"}, []string{"10.0.3.0/24", "2001:ab03:cd04:55ee:100c::/80"})
)

type testAddr struct {
	network string
	address string
}

func (a *testAddr) Network() string {
	return a.network
}
func (a *testAddr) String() string {
	return a.address
}

var (
	testAddrIPv4 = &testAddr{network: ipv4ProtocolICMPRaw, address: "0.0.0.0"}
	testAddrIPv6 = &testAddr{network: ipv6ProtocolICMPRaw, address: "::"}
)

// fakeClock is a wrapper around clocktesting.FakeClock that tracks the number
// of times NewTicker has been called, so we can write a race-free test.
type fakeClock struct {
	*clocktesting.FakeClock
	tickersAdded atomic.Int32
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{
		FakeClock: clocktesting.NewFakeClock(t),
	}
}

func (c *fakeClock) TickersAdded() int32 {
	return c.tickersAdded.Load()
}

func (c *fakeClock) NewTicker(d time.Duration) clock.Ticker {
	defer c.tickersAdded.Add(1)
	return c.FakeClock.NewTicker(d)
}

type antreaClientGetter struct {
	clientset versioned.Interface
}

func (g *antreaClientGetter) GetAntreaClient() (versioned.Interface, error) {
	return g.clientset, nil
}

type testMonitor struct {
	*NodeLatencyMonitor
	clientset          *fake.Clientset
	informerFactory    informers.SharedInformerFactory
	crdClientset       *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	ctrl               *gomock.Controller
	mockListener       *monitortesting.MockPacketListener
	clock              *fakeClock
}

func newTestMonitor(
	t *testing.T,
	nodeConfig *config.NodeConfig,
	trafficEncapMode config.TrafficEncapModeType,
	clockT time.Time,
	objects []runtime.Object,
	crdObjects []runtime.Object,
) *testMonitor {
	ctrl := gomock.NewController(t)
	clientset := fake.NewSimpleClientset(objects...)
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	crdClientset := fakeversioned.NewSimpleClientset(crdObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClientset, 0)
	nlmInformer := crdInformerFactory.Crd().V1alpha1().NodeLatencyMonitors()
	antreaClientProvider := &antreaClientGetter{fakeversioned.NewSimpleClientset(crdObjects...)}
	m := NewNodeLatencyMonitor(antreaClientProvider, nodeInformer, nlmInformer, nodeConfig, trafficEncapMode)
	fakeClock := newFakeClock(clockT)
	m.clock = fakeClock
	mockListener := monitortesting.NewMockPacketListener(ctrl)
	m.listener = mockListener

	return &testMonitor{
		NodeLatencyMonitor: m,
		clientset:          clientset,
		informerFactory:    informerFactory,
		crdClientset:       crdClientset,
		crdInformerFactory: crdInformerFactory,
		ctrl:               ctrl,
		mockListener:       mockListener,
		clock:              fakeClock,
	}
}

func TestEnableMonitor(t *testing.T) {
	ctx := context.Background()

	stopCh := make(chan struct{})
	defer close(stopCh)
	m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, time.Now(), nil, nil)
	m.crdInformerFactory.Start(stopCh)
	m.informerFactory.Start(stopCh)
	m.crdInformerFactory.WaitForCacheSync(stopCh)
	m.informerFactory.WaitForCacheSync(stopCh)
	go m.Run(stopCh)

	pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, nil)
	m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)
	pConnIPv6 := nettest.NewPacketConn(testAddrIPv6, nil, nil)
	m.mockListener.EXPECT().ListenPacket(ipv6ProtocolICMPRaw, "::").Return(pConnIPv6, nil)

	_, err := m.crdClientset.CrdV1alpha1().NodeLatencyMonitors().Create(ctx, nlm, metav1.CreateOptions{})
	require.NoError(t, err)

	require.Eventually(t, m.ctrl.Satisfied, 2*time.Second, 10*time.Millisecond)
	assert.False(t, pConnIPv4.IsClosed())
	assert.False(t, pConnIPv6.IsClosed())
}

// collectProbePackets takes as input a channel used to receive packets, and returns a function that
// can be called to collect received packets. It is useful to write assertions in tests that
// validate the list of received packets. collectProbePackets starts a goroutine in the background,
// which exists when either the input channel or the stop channel is closed.
func collectProbePackets(ch <-chan *nettest.Packet, stopCh <-chan struct{}) func([]*nettest.Packet) []*nettest.Packet {
	var m sync.Mutex
	newPackets := make([]*nettest.Packet, 0)
	go func() {
		for {
			select {
			// It may not always be convenient to close the input packet channel, so
			// stopCh can also be used as a signal to terminate the receiving goroutine.
			case <-stopCh:
				return
			case p, ok := <-ch:
				if !ok {
					return
				}
				func() {
					m.Lock()
					defer m.Unlock()
					newPackets = append(newPackets, p)
				}()
			}
		}
	}()
	return func(packets []*nettest.Packet) []*nettest.Packet {
		m.Lock()
		defer m.Unlock()
		packets = append(packets, newPackets...)
		newPackets = make([]*nettest.Packet, 0)
		return packets
	}
}

func extractIPs(packets []*nettest.Packet) []string {
	ips := make([]string, len(packets))
	for idx := range packets {
		ips[idx] = packets[idx].Addr.String()
	}
	return ips
}

func TestDisableMonitor(t *testing.T) {
	ctx := context.Background()

	stopCh := make(chan struct{})
	defer close(stopCh)
	m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, time.Now(), nil, []runtime.Object{nlm})
	m.crdInformerFactory.Start(stopCh)
	m.informerFactory.Start(stopCh)
	m.crdInformerFactory.WaitForCacheSync(stopCh)
	m.informerFactory.WaitForCacheSync(stopCh)

	pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, nil)
	m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)
	pConnIPv6 := nettest.NewPacketConn(testAddrIPv6, nil, nil)
	m.mockListener.EXPECT().ListenPacket(ipv6ProtocolICMPRaw, "::").Return(pConnIPv6, nil)

	go m.Run(stopCh)
	require.Eventually(t, m.ctrl.Satisfied, 2*time.Second, 10*time.Millisecond)

	err := m.crdClientset.CrdV1alpha1().NodeLatencyMonitors().Delete(ctx, nlm.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.True(t, pConnIPv4.IsClosed())
		assert.True(t, pConnIPv6.IsClosed())
	}, 2*time.Second, 10*time.Millisecond)
}

func TestUpdateMonitorPingInterval(t *testing.T) {
	ctx := context.Background()

	stopCh := make(chan struct{})
	defer close(stopCh)
	m := newTestMonitor(t, nodeConfigIPv4, config.TrafficEncapModeEncap, time.Now(), []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
	m.crdInformerFactory.Start(stopCh)
	m.informerFactory.Start(stopCh)
	m.crdInformerFactory.WaitForCacheSync(stopCh)
	m.informerFactory.WaitForCacheSync(stopCh)
	fakeClock := m.clock

	outCh := make(chan *nettest.Packet, 10)
	collect := collectProbePackets(outCh, stopCh)
	pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, outCh)
	m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)

	go m.Run(stopCh)

	// We wait for the first ticker to be created, which indicates that we can advance the clock
	// safely. This is not ideal, because it relies on knowledge of how the implementation
	// creates tickers.
	require.Eventually(t, func() bool {
		return fakeClock.TickersAdded() == 1
	}, 2*time.Second, 10*time.Millisecond)

	// After advancing the clock by 60s (ping interval), we should see the ICMP requests being sent.
	fakeClock.Step(60 * time.Second)
	packets := []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
	}, 2*time.Second, 10*time.Millisecond)

	// We increase the ping interval from 60s to 90s.
	newNLM := nlm.DeepCopy()
	newNLM.Spec.PingIntervalSeconds = 90
	newNLM.Generation = 1
	_, err := m.crdClientset.CrdV1alpha1().NodeLatencyMonitors().Update(ctx, newNLM, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Again, we have to wait for the second ticker to be created before we can advance the clock.
	require.Eventually(t, func() bool {
		return fakeClock.TickersAdded() == 2
	}, 2*time.Second, 10*time.Millisecond)

	// When advancing the clock by 60s (old ping iterval), we should not observe any ICMP requests.
	// We only wait for 200ms.
	fakeClock.Step(60 * time.Second)
	assert.Never(t, func() bool {
		return len(collect(nil)) > 0
	}, 200*time.Millisecond, 50*time.Millisecond)

	// After advancing the clock by an extra 30s, we should see the ICMP requests being sent.
	fakeClock.Step(30 * time.Second)
	packets = []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
	}, 2*time.Second, 10*time.Millisecond)

}

func TestSendPing(t *testing.T) {
	testCases := []struct {
		name        string
		addr        net.Addr
		targetIP    string
		requestType icmp.Type
	}{
		{
			name:        "ipv4",
			addr:        testAddrIPv4,
			targetIP:    "10.0.2.1",
			requestType: ipv4.ICMPTypeEcho,
		},
		{
			name:        "ipv6",
			addr:        testAddrIPv6,
			targetIP:    "2001:ab03:cd04:55ee:100b::1",
			requestType: ipv6.ICMPTypeEchoRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, now, nil, nil)
			const icmpSeqNum = 12
			m.icmpSeqNum.Store(icmpSeqNum)
			expectedMsg := icmp.Message{
				Type: tc.requestType,
				Code: 0,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  icmpSeqNum + 1,
					Data: []byte(now.Format(time.RFC3339Nano)),
				},
			}
			outCh := make(chan *nettest.Packet, 1)
			pConn := nettest.NewPacketConn(tc.addr, nil, outCh)
			require.NoError(t, m.sendPing(pConn, net.ParseIP(tc.targetIP)))
			expectedBytes, err := expectedMsg.Marshal(nil)
			require.NoError(t, err)
			select {
			case p := <-outCh:
				assert.Equal(t, tc.targetIP, p.Addr.String())
				assert.Equal(t, expectedBytes, p.Bytes)
			case <-time.After(1 * time.Second):
				assert.Fail(t, "ICMP message was not sent correctly")
			}
			entry, ok := m.latencyStore.getNodeIPLatencyEntry(tc.targetIP)
			assert.True(t, ok)
			assert.Equal(t, now, entry.LastSendTime)
		})
	}
}

// TestRecvPings tests that ICMP messages are handled correctly when received. We only consider the
// "normal" case here. The ICMP parsing and validation logic is tested comprehensively in
// TestHandlePing.
func TestRecvPings(t *testing.T) {
	now := time.Now()
	m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, now, nil, nil)
	inCh := make(chan *nettest.Packet, 1)
	pConn := nettest.NewPacketConn(testAddrIPv4, inCh, nil)
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		// This will block until the socket is closed.
		m.recvPings(pConn, true)
	}()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{
			ID:   int(icmpEchoID),
			Seq:  13,
			Data: []byte(now.Format(time.RFC3339Nano)),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	require.NoError(t, err)
	peerIP := "10.0.2.1"
	peerAddr := &testAddr{network: ipv4ProtocolICMPRaw, address: peerIP}
	inCh <- &nettest.Packet{
		Addr:  peerAddr,
		Bytes: msgBytes,
	}
	assert.Eventually(t, func() bool {
		_, ok := m.latencyStore.getNodeIPLatencyEntry(peerIP)
		return ok
	}, 2*time.Second, 10*time.Millisecond)

	pConn.Close()
	select {
	case <-doneCh:
		break
	case <-time.After(1 * time.Second):
		assert.Fail(t, "recvPings should return when socket is closed")
	}
}

func MustMarshal(msg *icmp.Message) []byte {
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		panic("failed to marshal ICMP message")
	}
	return msgBytes
}

func TestHandlePing(t *testing.T) {
	now := time.Now()
	payload := []byte(now.Format(time.RFC3339Nano))

	testCases := []struct {
		name     string
		msgBytes []byte
		isIPv4   bool
		isValid  bool
	}{
		{
			name: "valid IPv4",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  1,
					Data: payload,
				},
			}),
			isIPv4:  true,
			isValid: true,
		},
		{
			name: "valid IPv6",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv6.ICMPTypeEchoReply,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  1,
					Data: payload,
				},
			}),
			isIPv4:  false,
			isValid: true,
		},
		{
			name:     "invalid ICMP message",
			msgBytes: []byte("foo"), // this is too short to be a valid ICMP message
			isIPv4:   true,
			isValid:  false,
		},
		{
			name: "wrong IP family",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  1,
					Data: payload,
				},
			}),
			isIPv4:  false,
			isValid: false,
		},
		{
			name: "not an ICMP echo reply IPv4",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  1,
					Data: payload,
				},
			}),
			isIPv4:  true,
			isValid: false,
		},
		{
			name: "not an ICMP echo reply IPv6",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest,
				Code: 0,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  1,
					Data: payload,
				},
			}),
			isIPv4:  false,
			isValid: false,
		},
		{
			name: "wrong echo ID",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID) + 1,
					Seq:  1,
					Data: payload,
				},
			}),
			isIPv4:  true,
			isValid: false,
		},
		{
			name: "invalid payload",
			msgBytes: MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Body: &icmp.Echo{
					ID:   int(icmpEchoID),
					Seq:  1,
					Data: []byte("foobar"),
				},
			}),
			isIPv4:  true,
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, now, nil, nil)
			peerIP := "10.0.2.1"
			if !tc.isIPv4 {
				peerIP = "2001:ab03:cd04:55ee:100b::1"
			}
			const rtt = 1 * time.Second
			m.clock.Step(rtt)
			m.handlePing(tc.msgBytes, peerIP, tc.isIPv4)
			entry, ok := m.latencyStore.getNodeIPLatencyEntry(peerIP)
			if tc.isValid {
				require.True(t, ok)
				assert.Equal(t, m.clock.Now(), entry.LastRecvTime)
				assert.Equal(t, rtt, entry.LastMeasuredRTT)
			} else {
				assert.False(t, ok)
			}
		})
	}
}

func TestNodeAddUpdateDelete(t *testing.T) {
	ctx := context.Background()

	node := makeNode("node3", []string{"192.168.77.103", "192:168:77::103"}, []string{"10.0.3.0/24", "2001:ab03:cd04:55ee:100c::/80"})
	updatedNode := makeNode("node3", []string{"192.168.77.104", "192:168:77::104"}, []string{"10.0.4.0/24", "2001:ab03:cd04:55ee:100d::/80"})

	testCases := []struct {
		encapMode config.TrafficEncapModeType
		// before update
		expectedNodeIPs1 []string
		// after update
		expectedNodeIPs2 []string
	}{
		{
			encapMode:        config.TrafficEncapModeEncap,
			expectedNodeIPs1: []string{"10.0.3.1", "2001:ab03:cd04:55ee:100c::1"},
			expectedNodeIPs2: []string{"10.0.4.1", "2001:ab03:cd04:55ee:100d::1"},
		},
		{
			encapMode:        config.TrafficEncapModeNoEncap,
			expectedNodeIPs1: []string{"10.0.3.1", "2001:ab03:cd04:55ee:100c::1"},
			expectedNodeIPs2: []string{"10.0.4.1", "2001:ab03:cd04:55ee:100d::1"},
		},
		{
			encapMode:        config.TrafficEncapModeNetworkPolicyOnly,
			expectedNodeIPs1: []string{"192.168.77.103", "192:168:77::103"},
			expectedNodeIPs2: []string{"192.168.77.104", "192:168:77::104"},
		},
	}

	convertIPsToStrs := func(ips []net.IP) []string {
		ipStrs := make([]string, len(ips))
		for idx := range ips {
			ipStrs[idx] = ips[idx].String()
		}
		return ipStrs
	}

	for _, tc := range testCases {
		t.Run(tc.encapMode.String(), func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			// We start with node1 (the current Node) only, and it should be ignored.
			m := newTestMonitor(t, nodeConfigIPv4, tc.encapMode, time.Now(), []runtime.Object{node1}, nil)
			m.informerFactory.Start(stopCh)
			m.informerFactory.WaitForCacheSync(stopCh)
			go m.Run(stopCh)

			require.Empty(t, m.latencyStore.ListNodeIPs())

			_, err := m.clientset.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{})
			require.NoError(t, err)

			// We convert the []net.IP slice to []string before comparing the slices,
			// and not the reverse, because creating a net.IP with net.ParseIP for an
			// IPv4 address will yield a 16-byte slice which may not exactly match the
			// result of ListNodeIPs(), even though the values indeed represent the same
			// IP address.
			assert.EventuallyWithT(t, func(t *assert.CollectT) {
				assert.ElementsMatch(t, tc.expectedNodeIPs1, convertIPsToStrs(m.latencyStore.ListNodeIPs()))
			}, 2*time.Second, 10*time.Millisecond)

			_, err = m.clientset.CoreV1().Nodes().Update(ctx, updatedNode, metav1.UpdateOptions{})
			require.NoError(t, err)

			assert.EventuallyWithT(t, func(t *assert.CollectT) {
				assert.ElementsMatch(t, tc.expectedNodeIPs2, convertIPsToStrs(m.latencyStore.ListNodeIPs()))
			}, 2*time.Second, 10*time.Millisecond)

			err = m.clientset.CoreV1().Nodes().Delete(ctx, node.Name, metav1.DeleteOptions{})
			require.NoError(t, err)

			assert.EventuallyWithT(t, func(t *assert.CollectT) {
				assert.Empty(t, m.latencyStore.ListNodeIPs())
			}, 2*time.Second, 10*time.Millisecond)
		})
	}
}

func TestMonitorLoop(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, time.Now(), []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
	m.crdInformerFactory.Start(stopCh)
	m.informerFactory.Start(stopCh)
	m.crdInformerFactory.WaitForCacheSync(stopCh)
	m.informerFactory.WaitForCacheSync(stopCh)
	fakeClock := m.clock

	in4Ch := make(chan *nettest.Packet, 10)
	in6Ch := make(chan *nettest.Packet, 10)
	outCh := make(chan *nettest.Packet, 10)
	collect := collectProbePackets(outCh, stopCh)
	pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, in4Ch, outCh)
	m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)
	pConnIPv6 := nettest.NewPacketConn(testAddrIPv6, in6Ch, outCh)
	m.mockListener.EXPECT().ListenPacket(ipv6ProtocolICMPRaw, "::").Return(pConnIPv6, nil)

	go m.Run(stopCh)

	// We wait for the first ticker to be created, which indicates that we can advance the clock
	// safely. This is not ideal, because it relies on knowledge of how the implementation
	// creates tickers.
	require.Eventually(t, func() bool {
		return fakeClock.TickersAdded() == 1
	}, 2*time.Second, 10*time.Millisecond)

	require.Empty(t, m.latencyStore.getNodeIPLatencyKeys())

	// After advancing the clock by 60s (ping interval), we should see the ICMP requests being sent.
	fakeClock.Step(60 * time.Second)
	packets := []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"}, extractIPs(packets))
	}, 2*time.Second, 10*time.Millisecond)

	// The store is updated when sending the ICMP requests, as we need to store the send timestamp.
	assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"}, m.latencyStore.getNodeIPLatencyKeys())

	// Advance the clock by one more second, and send replies for all ICMP requests.
	fakeClock.Step(1 * time.Second)
	for _, packet := range packets {
		if packet.Addr.Network() == ipv4ProtocolICMPRaw {
			request, err := icmp.ParseMessage(protocolICMP, packet.Bytes)
			require.NoError(t, err)
			replyBytes := MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Body: request.Body,
			})
			in4Ch <- &nettest.Packet{
				Addr:  packet.Addr,
				Bytes: replyBytes,
			}
		} else {
			request, err := icmp.ParseMessage(protocolICMPv6, packet.Bytes)
			require.NoError(t, err)
			replyBytes := MustMarshal(&icmp.Message{
				Type: ipv6.ICMPTypeEchoReply,
				Body: request.Body,
			})
			in6Ch <- &nettest.Packet{
				Addr:  packet.Addr,
				Bytes: replyBytes,
			}
		}
	}

	// The store should eventually be updated with the correct RTT measurements.
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		for _, ip := range []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"} {
			entry, _ := m.latencyStore.getNodeIPLatencyEntry(ip)
			assert.Equal(t, 1*time.Second, entry.LastMeasuredRTT)
		}
	}, 2*time.Second, 10*time.Millisecond)

	// Delete node3 synchronously, which simplifies testing.
	m.onNodeDelete(node3)

	// After advancing the clock by another 60s (ping interval), we should see another round of
	// ICMP requests being sent, this time not including the Node that was deleted.
	// The latency store should also eventually be cleaned up to remove the stale entries for
	// that Node.
	fakeClock.Step(60 * time.Second)
	packets = []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "2001:ab03:cd04:55ee:100b::1"}, extractIPs(packets))
		nodeIPs := m.latencyStore.getNodeIPLatencyKeys()
		assert.ElementsMatch(t, []string{"10.0.2.1", "2001:ab03:cd04:55ee:100b::1"}, nodeIPs)
	}, 2*time.Second, 10*time.Millisecond)
}
