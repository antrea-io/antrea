//go:build !windows

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
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
}

func newTestMonitor(
	t *testing.T,
	nodeConfig *config.NodeConfig,
	trafficEncapMode config.TrafficEncapModeType,
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
	}
}

func TestEnableMonitor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		stopCh := ctx.Done()
		m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, nil, nil)
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

		synctest.Wait()
		require.True(t, m.ctrl.Satisfied())
		assert.False(t, pConnIPv4.IsClosed())
		assert.False(t, pConnIPv6.IsClosed())
	})
}

// collectProbePackets takes as input a channel used to receive packets, and returns a function that
// can be called to collect received packets. It is useful to write assertions in tests that
// validate the list of received packets. collectProbePackets starts a goroutine in the background,
// which exits when either the input channel or the stop channel is closed.
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
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		stopCh := ctx.Done()
		m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, nil, []runtime.Object{nlm})
		m.crdInformerFactory.Start(stopCh)
		m.informerFactory.Start(stopCh)
		m.crdInformerFactory.WaitForCacheSync(stopCh)
		m.informerFactory.WaitForCacheSync(stopCh)

		pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, nil)
		m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)
		pConnIPv6 := nettest.NewPacketConn(testAddrIPv6, nil, nil)
		m.mockListener.EXPECT().ListenPacket(ipv6ProtocolICMPRaw, "::").Return(pConnIPv6, nil)

		go m.Run(stopCh)
		synctest.Wait()
		require.True(t, m.ctrl.Satisfied())

		require.NoError(t, m.crdClientset.CrdV1alpha1().NodeLatencyMonitors().Delete(ctx, nlm.Name, metav1.DeleteOptions{}))

		synctest.Wait()
		assert.True(t, pConnIPv4.IsClosed())
		assert.True(t, pConnIPv6.IsClosed())
	})
}

func TestUpdateMonitorPingInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		stopCh := ctx.Done()

		m := newTestMonitor(t, nodeConfigIPv4, config.TrafficEncapModeEncap, []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
		m.crdInformerFactory.Start(stopCh)
		m.informerFactory.Start(stopCh)
		m.crdInformerFactory.WaitForCacheSync(stopCh)
		m.informerFactory.WaitForCacheSync(stopCh)

		outCh := make(chan *nettest.Packet, 10)
		collect := collectProbePackets(t, outCh, stopCh)
		pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, outCh)
		m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)

		var reportCount atomic.Int32
		m.crdClientset.Fake.PrependReactor("create", "nodelatencystats", func(action k8stesting.Action) (bool, runtime.Object, error) {
			reportCount.Add(1)
			return false, nil, nil
		})

		go m.Run(stopCh)

		// After advancing the clock by 60s (ping interval), we should see the ICMP requests being sent.
		time.Sleep(60 * time.Second)
		synctest.Wait()
		packets := collect(nil)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
		assert.Equal(t, 0, int(reportCount.Load()), "Expected no report yet (jitter still pending)")

		// Advance by 1 more second (reportJitter) → total 61s: report should now occur
		time.Sleep(1 * time.Second)
		synctest.Wait()
		assert.Equal(t, 1, int(reportCount.Load()), "Expected report after jittered interval (total 61s)")

		// Clear count for next phase
		reportCount.Store(0)

		// We increase the ping interval from 60s to 90s.
		newNLM := nlm.DeepCopy()
		newNLM.Spec.PingIntervalSeconds = 90
		newNLM.Generation = 1
		_, err := m.crdClientset.CrdV1alpha1().NodeLatencyMonitors().Update(ctx, newNLM, metav1.UpdateOptions{})
		require.NoError(t, err)

		// When advancing the clock by 60s (old ping iterval), we should not observe any ICMP requests.
		time.Sleep(60 * time.Second)
		synctest.Wait()
		assert.Empty(t, collect(nil))

		// After advancing the clock by an extra 30s, we should see the ICMP requests being sent.
		time.Sleep(30 * time.Second)
		synctest.Wait()
		packets = collect(nil)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
		assert.Equal(t, 0, int(reportCount.Load()), "Expected no report yet (jitter still pending)")

		// Advance by 1 more second (reportJitter) → total 91s: report should now occur
		time.Sleep(1 * time.Second)
		synctest.Wait()
		assert.Equal(t, 1, int(reportCount.Load()), "Expected report after jittered interval (total 91s)")
	})
}

func TestPingIntervalBelowMinReportInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		stopCh := ctx.Done()
		// Create a NodeLatencyMonitor with 5s ping interval (below minReportInterval of 10s)
		nlm := &crdv1alpha1.NodeLatencyMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: crdv1alpha1.NodeLatencyMonitorSpec{
				PingIntervalSeconds: 5, // Below minReportInterval (10s)
			},
		}

		m := newTestMonitor(t, nodeConfigIPv4, config.TrafficEncapModeEncap, []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
		m.crdInformerFactory.Start(stopCh)
		m.informerFactory.Start(stopCh)
		m.crdInformerFactory.WaitForCacheSync(stopCh)
		m.informerFactory.WaitForCacheSync(stopCh)

		outCh := make(chan *nettest.Packet, 10)
		collect := collectProbePackets(t, outCh, stopCh)
		pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, nil, outCh)
		m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)

		var reportCount atomic.Int32
		m.crdClientset.Fake.PrependReactor("create", "nodelatencystats", func(action k8stesting.Action) (bool, runtime.Object, error) {
			reportCount.Add(1)
			return false, nil, nil
		})

		go m.Run(stopCh)

		// After advancing the clock by 5s (ping interval), we should see the ICMP requests being sent.
		time.Sleep(5 * time.Second)
		synctest.Wait()
		packets := collect(nil)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
		assert.Equal(t, 0, int(reportCount.Load()), "Expected no report at 5s (below minReportInterval)")

		// Advance by another 5s (total 10s, second ping cycle) - should send pings but still no report
		time.Sleep(5 * time.Second)
		synctest.Wait()
		packets = collect(nil)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1"}, extractIPs(packets))
		assert.Equal(t, 0, int(reportCount.Load()), "Expected no report yet at 10s (jitter still pending)")

		// Advance by 1 more second (reportJitter) → total 11s: report should now occur
		time.Sleep(1 * time.Second)
		synctest.Wait()
		assert.Equal(t, 1, int(reportCount.Load()), "Expected report after jittered interval (total 11s)")
	})
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
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, nil, nil)
				const icmpSeqNum = 12
				m.icmpSeqNum.Store(icmpSeqNum)
				expectedMsg := icmp.Message{
					Type: tc.requestType,
					Code: 0,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  icmpSeqNum + 1,
						Data: icmpEchoData(now),
					},
				}
				outCh := make(chan *nettest.Packet, 1)
				pConn := nettest.NewPacketConn(tc.addr, nil, outCh)
				require.NoError(t, m.sendPing(pConn, net.ParseIP(tc.targetIP)))
				expectedBytes, err := expectedMsg.Marshal(nil)
				require.NoError(t, err)
				synctest.Wait()
				select {
				case p := <-outCh:
					assert.Equal(t, tc.targetIP, p.Addr.String())
					assert.Equal(t, expectedBytes, p.Bytes)
				default:
					assert.Fail(t, "ICMP message was not sent correctly")
				}
				entry, ok := m.latencyStore.getNodeIPLatencyEntry(tc.targetIP)
				assert.True(t, ok)
				assert.Equal(t, now, entry.LastSendTime)
			})
		})
	}
}

// TestRecvPings tests that ICMP messages are handled correctly when received. We only consider the
// "normal" case here. The ICMP parsing and validation logic is tested comprehensively in
// TestHandlePing.
func TestRecvPings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, nil, nil)
		inCh := make(chan *nettest.Packet, 1)
		pConn := nettest.NewPacketConn(testAddrIPv4, inCh, nil)
		// m.recvPings will block until the socket is closed.
		go m.recvPings(pConn, true)
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Body: &icmp.Echo{
				ID:   int(icmpEchoID),
				Seq:  13,
				Data: icmpEchoData(time.Now()),
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
		synctest.Wait()
		_, ok := m.latencyStore.getNodeIPLatencyEntry(peerIP)
		assert.True(t, ok)

		pConn.Close()
	})
}

func MustMarshal(msg *icmp.Message) []byte {
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		panic("failed to marshal ICMP message")
	}
	return msgBytes
}

func TestHandlePing(t *testing.T) {
	testCases := []struct {
		name    string
		msgFn   func() []byte
		isIPv4  bool
		isValid bool
	}{
		{
			name: "valid IPv4",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  1,
						Data: icmpEchoData(time.Now()),
					},
				})
			},
			isIPv4:  true,
			isValid: true,
		},
		{
			name: "valid IPv6",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv6.ICMPTypeEchoReply,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  1,
						Data: icmpEchoData(time.Now()),
					},
				})
			},
			isIPv4:  false,
			isValid: true,
		},
		{
			name:    "invalid ICMP message",
			msgFn:   func() []byte { return []byte("foo") }, // this is too short to be a valid ICMP message
			isIPv4:  true,
			isValid: false,
		},
		{
			name: "wrong IP family",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  1,
						Data: icmpEchoData(time.Now()),
					},
				})
			},
			isIPv4:  false,
			isValid: false,
		},
		{
			name: "not an ICMP echo reply IPv4",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Code: 0,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  1,
						Data: icmpEchoData(time.Now()),
					},
				})
			},
			isIPv4:  true,
			isValid: false,
		},
		{
			name: "not an ICMP echo reply IPv6",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv6.ICMPTypeEchoRequest,
					Code: 0,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  1,
						Data: icmpEchoData(time.Now()),
					},
				})
			},
			isIPv4:  false,
			isValid: false,
		},
		{
			name: "wrong echo ID",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID) + 1,
						Seq:  1,
						Data: icmpEchoData(time.Now()),
					},
				})
			},
			isIPv4:  true,
			isValid: false,
		},
		{
			name: "invalid payload",
			msgFn: func() []byte {
				return MustMarshal(&icmp.Message{
					Type: ipv4.ICMPTypeEchoReply,
					Body: &icmp.Echo{
						ID:   int(icmpEchoID),
						Seq:  1,
						Data: []byte("foobar"),
					},
				})
			},
			isIPv4:  true,
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, nil, nil)
				peerIP := "10.0.2.1"
				if !tc.isIPv4 {
					peerIP = "2001:ab03:cd04:55ee:100b::1"
				}
				msgBytes := tc.msgFn()
				const rtt = 1 * time.Second
				time.Sleep(rtt)
				m.handlePing(msgBytes, peerIP, tc.isIPv4)
				entry, ok := m.latencyStore.getNodeIPLatencyEntry(peerIP)
				if tc.isValid {
					require.True(t, ok)
					assert.Equal(t, time.Now(), entry.LastRecvTime)
					assert.Equal(t, rtt, entry.LastMeasuredRTT)
				} else {
					assert.False(t, ok)
				}
			})
		})
	}
}

func TestNodeAddUpdateDelete(t *testing.T) {
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
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				stopCh := ctx.Done()
				// We start with node1 (the current Node) only, and it should be ignored.
				m := newTestMonitor(t, nodeConfigIPv4, tc.encapMode, []runtime.Object{node1}, nil)
				m.crdInformerFactory.Start(stopCh)
				m.informerFactory.Start(stopCh)
				m.crdInformerFactory.WaitForCacheSync(stopCh)
				m.informerFactory.WaitForCacheSync(stopCh)
				go m.Run(stopCh)

				require.Empty(t, m.latencyStore.ListNodeIPs())

				_, err := m.clientset.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{})
				require.NoError(t, err)

				synctest.Wait()
				// We convert the []net.IP slice to []string before comparing the slices,
				// and not the reverse, because creating a net.IP with net.ParseIP for an
				// IPv4 address will yield a 16-byte slice which may not exactly match the
				// result of ListNodeIPs(), even though the values indeed represent the same
				// IP address.
				assert.ElementsMatch(t, tc.expectedNodeIPs1, convertIPsToStrs(m.latencyStore.ListNodeIPs()))

				_, err = m.clientset.CoreV1().Nodes().Update(ctx, updatedNode, metav1.UpdateOptions{})
				require.NoError(t, err)

				synctest.Wait()
				assert.ElementsMatch(t, tc.expectedNodeIPs2, convertIPsToStrs(m.latencyStore.ListNodeIPs()))

				err = m.clientset.CoreV1().Nodes().Delete(ctx, node.Name, metav1.DeleteOptions{})
				require.NoError(t, err)

				synctest.Wait()
				assert.Empty(t, m.latencyStore.ListNodeIPs())
			})
		})
	}
}

func TestMonitorLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		stopCh := ctx.Done()
		m := newTestMonitor(t, nodeConfigDualStack, config.TrafficEncapModeEncap, []runtime.Object{node1, node2, node3}, []runtime.Object{nlm})
		m.crdInformerFactory.Start(stopCh)
		m.informerFactory.Start(stopCh)
		m.crdInformerFactory.WaitForCacheSync(stopCh)
		m.informerFactory.WaitForCacheSync(stopCh)

		in4Ch := make(chan *nettest.Packet, 10)
		in6Ch := make(chan *nettest.Packet, 10)
		outCh := make(chan *nettest.Packet, 10)
		collect := collectProbePackets(t, outCh, stopCh)
		pConnIPv4 := nettest.NewPacketConn(testAddrIPv4, in4Ch, outCh)
		m.mockListener.EXPECT().ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0").Return(pConnIPv4, nil)
		pConnIPv6 := nettest.NewPacketConn(testAddrIPv6, in6Ch, outCh)
		m.mockListener.EXPECT().ListenPacket(ipv6ProtocolICMPRaw, "::").Return(pConnIPv6, nil)

		var reportCount atomic.Int32
		m.crdClientset.Fake.PrependReactor("create", "nodelatencystats", func(action k8stesting.Action) (bool, runtime.Object, error) {
			reportCount.Add(1)
			return false, nil, nil
		})

		go m.Run(stopCh)
		synctest.Wait()
		require.Empty(t, m.latencyStore.getNodeIPLatencyKeys())

		// After advancing the clock by 60s (ping interval), we should see the ICMP requests being sent.
		time.Sleep(60 * time.Second)
		synctest.Wait()
		packets := collect(nil)
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"}, extractIPs(packets))
		assert.Equal(t, 0, int(reportCount.Load()), "Expected no report yet (jitter still pending)")

		// The store is updated when sending the ICMP requests, as we need to store the send timestamp.
		assert.ElementsMatch(t, []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"}, m.latencyStore.getNodeIPLatencyKeys())

		// Advance the clock by one more second, and send replies for all ICMP requests.
		time.Sleep(1 * time.Second)
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
		synctest.Wait()
		for _, ip := range []string{"10.0.2.1", "10.0.3.1", "2001:ab03:cd04:55ee:100b::1", "2001:ab03:cd04:55ee:100c::1"} {
			entry, _ := m.latencyStore.getNodeIPLatencyEntry(ip)
			assert.Equal(t, 1*time.Second, entry.LastMeasuredRTT)
		}
		assert.Equal(t, 1, int(reportCount.Load()), "Expected report after jittered interval (total 61s)")

		// Clear count for next phase
		reportCount.Store(0)
		// Delete node3
		require.NoError(t, m.clientset.CoreV1().Nodes().Delete(ctx, node3.Name, metav1.DeleteOptions{}))

		// After advancing the clock by another 60s (ping interval), we should see another round of
		// ICMP requests being sent, this time not including the Node that was deleted.
		// The latency store should also eventually be cleaned up to remove the stale entries for
		// that Node.
		time.Sleep(60 * time.Second)
		synctest.Wait()
		packets = collect(nil)
		assert.ElementsMatch(t, []string{"10.0.2.1", "2001:ab03:cd04:55ee:100b::1"}, extractIPs(packets))
		nodeIPs := m.latencyStore.getNodeIPLatencyKeys()
		assert.ElementsMatch(t, []string{"10.0.2.1", "2001:ab03:cd04:55ee:100b::1"}, nodeIPs)
		assert.Equal(t, 0, int(reportCount.Load()), "Expected no report yet (jitter still pending)")

		// Advance by 1 more second (reportJitter) → total 122s: report should now occur
		time.Sleep(1 * time.Second)
		synctest.Wait()
		assert.Equal(t, 1, int(reportCount.Load()), "Expected report after jittered interval (total 122s)")
	})
}
