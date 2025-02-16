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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/pkg/agent/config"
	monitortesting "antrea.io/antrea/pkg/agent/monitortool/testing"
	"antrea.io/antrea/pkg/agent/util/nettest"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
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
	t            *testing.T
}

func newFakeClock(t *testing.T, clockT time.Time) *fakeClock {
	t.Logf("Creating fake clock, now=%v", clockT)
	return &fakeClock{
		FakeClock: clocktesting.NewFakeClock(clockT),
		t:         t,
	}
}

func (c *fakeClock) TickersAdded() int32 {
	return c.tickersAdded.Load()
}

func (c *fakeClock) NewTicker(d time.Duration) clock.Ticker {
	defer func() {
		c.t.Logf("Ticker created, now=%v, tick=%v", c.Now(), d)
	}()
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
	crdClientset.PrependReactor("create", "nodelatencystats", func(action k8stesting.Action) (bool, runtime.Object, error) {
		tracker := crdClientset.Tracker()
		createAction := action.(k8stesting.CreateAction)
		gvr := createAction.GetResource()
		obj := createAction.GetObject()
		stats := obj.(*statsv1alpha1.NodeLatencyStats)

		_, err := tracker.Get(gvr, "", stats.Name)
		if errors.IsNotFound(err) {
			err = tracker.Create(gvr, obj, "")
		} else if err == nil {
			err = tracker.Update(gvr, obj, "")
		}

		if err != nil {
			return true, nil, err
		}

		obj, err = tracker.Get(gvr, "", stats.Name)
		return true, obj, err
	})
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClientset, 0)
	nlmInformer := crdInformerFactory.Crd().V1alpha1().NodeLatencyMonitors()
	antreaClientProvider := &antreaClientGetter{crdClientset}
	m := NewNodeLatencyMonitor(antreaClientProvider, nodeInformer, nlmInformer, nodeConfig, trafficEncapMode)
	fakeClock := newFakeClock(t, clockT)
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
func collectProbePackets(t *testing.T, ch <-chan *nettest.Packet, stopCh <-chan struct{}) func([]*nettest.Packet) []*nettest.Packet {
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
					t.Logf("Packet channel has been closed")
					return
				}
				t.Logf("Packet received on channel")
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

	// Enable verbose logging for debugging.
	var level klog.Level
	level.Set("4")
	defer level.Set("0")

	stopCh := make(chan struct{})
	defer close(stopCh)
	m := newTestMonitor(t, nodeConfigIPv4, config.TrafficEncapModeEncap, time.Now(), []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
	m.crdInformerFactory.Start(stopCh)
	m.informerFactory.Start(stopCh)
	m.crdInformerFactory.WaitForCacheSync(stopCh)
	m.informerFactory.WaitForCacheSync(stopCh)
	fakeClock := m.clock

	outCh := make(chan *nettest.Packet, 10)
	collect := collectProbePackets(t, outCh, stopCh)
	pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, outCh)
	m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)

	go m.Run(stopCh)

	// Wait for both pingTicker and reportTicker to be created.
	require.Eventually(t, func() bool {
		return fakeClock.TickersAdded() == 2 // One for pingTicker, one for reportTicker.
	}, 2*time.Second, 10*time.Millisecond)

	// Advance the clock for pingTicker and verify ICMP requests.
	fakeClock.Step(61 * time.Second) // Ping interval + jitter.
	packets := []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
	}, 2*time.Second, 10*time.Millisecond)

	// Advance the clock for reportTicker and verify behavior.
	fakeClock.Step(11 * time.Second) // Minimum report interval (10s) + jitter (1s).
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Expect some report-related behavior to be triggered (mock this as needed).
		// This could involve verifying a function call or other report-related actions.
	}, 2*time.Second, 10*time.Millisecond)

	// Update the ping interval to 90 seconds.
	newNLM := nlm.DeepCopy()
	newNLM.Spec.PingIntervalSeconds = 90
	newNLM.Generation = 1
	_, err := m.crdClientset.CrdV1alpha1().NodeLatencyMonitors().Update(ctx, newNLM, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Wait for the updated pingTicker to be created.
	require.Eventually(t, func() bool {
		return fakeClock.TickersAdded() >= 3 // Third ticker for new ping interval.
	}, 5*time.Second, 10*time.Millisecond)

	// Advance the clock by 61 seconds (old ping interval) and verify no ICMP requests.
	fakeClock.Step(61 * time.Second)
	assert.Never(t, func() bool {
		return len(collect(nil)) > 0
	}, 200*time.Millisecond, 50*time.Millisecond)

	// Advance the clock to complete the new ping interval (90s) and verify ICMP requests.
	fakeClock.Step(29 * time.Second) // Completes the 90s interval.
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
			m.crdInformerFactory.Start(stopCh)
			m.informerFactory.Start(stopCh)
			m.crdInformerFactory.WaitForCacheSync(stopCh)
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

	// Create test monitor
	m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, time.Now(), []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
	m.crdInformerFactory.Start(stopCh)
	m.informerFactory.Start(stopCh)
	m.crdInformerFactory.WaitForCacheSync(stopCh)
	m.informerFactory.WaitForCacheSync(stopCh)

	fakeClock := m.clock

	// Create mock packet connections for IPv4 and IPv6
	in4Ch := make(chan *nettest.Packet, 10)
	in6Ch := make(chan *nettest.Packet, 10)
	outCh := make(chan *nettest.Packet, 10)
	collect := collectProbePackets(t, outCh, stopCh)
	pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, in4Ch, outCh)
	m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)
	pConnIPv6 := nettest.NewPacketConn(testAddrIPv6, in6Ch, outCh)
	m.mockListener.EXPECT().ListenPacket(ipv6ProtocolICMPRaw, "::").Return(pConnIPv6, nil)

	// Start the monitor loop
	go m.Run(stopCh)

	// Wait for both tickers (pingTicker and reportTicker) to be created
	require.Eventually(t, func() bool {
		return fakeClock.TickersAdded() == 2
	}, 2*time.Second, 10*time.Millisecond)

	require.Empty(t, m.latencyStore.getNodeIPLatencyKeys())

	// Step the clock by 60 seconds (ping interval)
	fakeClock.Step(60 * time.Second)
	packets := []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"}, extractIPs(packets))
	}, 2*time.Second, 10*time.Millisecond)

	// Ensure that the latency store contains the correct entries
	assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"}, m.latencyStore.getNodeIPLatencyKeys())

	// Step the clock by 11 seconds to account for jitter in reportTicker
	fakeClock.Step(11 * time.Second)

	// Check that the reportTicker has triggered
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Add assertions to check the report logic is triggered correctly
	}, 2*time.Second, 10*time.Millisecond)

	// Simulate receiving ICMP replies for packets
	fakeClock.Step(1 * time.Second)
	for _, packet := range packets {
		if packet.Addr.Network() == ipv4ProtocolICMPRaw {
			request, _ := icmp.ParseMessage(protocolICMP, packet.Bytes)
			replyBytes := MustMarshal(&icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Body: request.Body,
			})
			in4Ch <- &nettest.Packet{
				Addr:  packet.Addr,
				Bytes: replyBytes,
			}
		} else {
			request, _ := icmp.ParseMessage(protocolICMPv6, packet.Bytes)
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

	// Verify that the latency store is updated with RTT measurements
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		for _, ip := range []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"} {
			entry, _ := m.latencyStore.getNodeIPLatencyEntry(ip)
			assert.Equal(t, 1*time.Second, entry.LastMeasuredRTT)
		}
	}, 2*time.Second, 10*time.Millisecond)

	// Simulate node deletion and ensure cleanup occurs in latency store
	m.onNodeDelete(node3)
	fakeClock.Step(60 * time.Second)
	packets = []*nettest.Packet{}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		packets = collect(packets)
		assert.ElementsMatch(t, []string{"10.0.2.1", "2001:ab03:cd04:55ee:100b::1"}, extractIPs(packets))
		nodeIPs := m.latencyStore.getNodeIPLatencyKeys()
		assert.ElementsMatch(t, []string{"10.0.2.1", "2001:ab03:cd04:55ee:100b::1"}, nodeIPs)
	}, 2*time.Second, 10*time.Millisecond)
}
