// Copyright 2022 Antrea Authors.
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

package traceflow

import (
	"bytes"
	"net"
	"os"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/util"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	pod1IPv4       = "192.168.10.10"
	pod2IPv4       = "192.168.11.10"
	dstIPv4        = "192.168.99.99"
	pod1MAC, _     = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _     = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1     = uint32(1)
	ofPortPod2     = uint32(2)
	protocolICMPv6 = int32(58)

	pod1 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: pod1IPv4,
		},
	}
	pod2 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-2",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: pod2IPv4,
		},
	}
	pod3 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-3",
			Namespace: "default",
		},
	}
)

type fakeTraceflowController struct {
	*Controller
	kubeClient           kubernetes.Interface
	mockController       *gomock.Controller
	mockOFClient         *openflowtest.MockClient
	crdClient            *fakeversioned.Clientset
	crdInformerFactory   crdinformers.SharedInformerFactory
	networkPolicyQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier
	egressQuerier        *queriertest.MockEgressQuerier
}

func newFakeTraceflowController(t *testing.T, initObjects []runtime.Object, networkConfig *config.NetworkConfig, nodeConfig *config.NodeConfig) *fakeTraceflowController {
	controller := gomock.NewController(t)
	kubeClient := fake.NewSimpleClientset(&pod1, &pod2, &pod3)
	mockOFClient := openflowtest.NewMockClient(controller)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	traceflowInformer := crdInformerFactory.Crd().V1beta1().Traceflows()
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(controller)
	egressQuerier := queriertest.NewMockEgressQuerier(controller)

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, pod1IPv4, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, pod2IPv4, pod2MAC.String(), int32(ofPortPod2))

	_, serviceCIDRNet, _ := net.ParseCIDR("10.96.0.0/12")

	tfController := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		traceflowInformer:     traceflowInformer,
		traceflowLister:       traceflowInformer.Lister(),
		traceflowListerSynced: traceflowInformer.Informer().HasSynced,
		ofClient:              mockOFClient,
		networkPolicyQuerier:  npQuerier,
		egressQuerier:         egressQuerier,
		interfaceStore:        ifaceStore,
		networkConfig:         networkConfig,
		nodeConfig:            nodeConfig,
		serviceCIDR:           serviceCIDRNet,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "traceflow"),
		runningTraceflows:     make(map[int8]*traceflowState),
	}

	return &fakeTraceflowController{
		Controller:           tfController,
		kubeClient:           kubeClient,
		mockController:       controller,
		mockOFClient:         mockOFClient,
		crdClient:            crdClient,
		crdInformerFactory:   crdInformerFactory,
		networkPolicyQuerier: npQuerier,
		egressQuerier:        egressQuerier,
	}
}

func addPodInterface(ifaceStore interfacestore.InterfaceStore, podNamespace, podName, podIP, podMac string, ofPort int32) {
	containerName := k8s.NamespacedName(podNamespace, podName)
	ifIPs := []net.IP{net.ParseIP(podIP)}
	mac, _ := net.ParseMAC(podMac)
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		IPs:                      ifIPs,
		MAC:                      mac,
		InterfaceName:            util.GenerateContainerInterfaceName(podName, podNamespace, containerName),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: podName, PodNamespace: podNamespace, ContainerID: containerName},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort},
	})
}

func TestPreparePacket(t *testing.T) {
	tcs := []struct {
		name           string
		tf             *crdv1beta1.Traceflow
		intf           *interfacestore.InterfaceConfig
		receiverOnly   bool
		expectedPacket *binding.Packet
		expectedErr    string
	}{
		{
			name: "invalid destination IPv4",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						IP: "1.1.1.300",
					},
				},
			},
			expectedErr: "invalid destination IP address",
		},
		{
			name: "empty destination with no live traffic",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf2", UID: "uid2"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
				},
			},
			expectedErr: "destination is not specified",
		},
		{
			name: "receive only from a source IPv4 to destination Pod1 in live traffic traceflow",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf3", UID: "uid3"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						IP: "192.168.12.4",
					},
					Destination: crdv1beta1.Destination{
						Pod: pod1.Name,
					},
					LiveTraffic: true,
					Packet:      crdv1beta1.Packet{IPHeader: &crdv1beta1.IPHeader{}},
				},
			},
			receiverOnly: true,
			expectedPacket: &binding.Packet{
				SourceIP:       net.ParseIP("192.168.12.4"),
				DestinationMAC: pod1MAC,
			},
		},
		{
			name: "tcp packet",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf4", UID: "uid4"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1beta1.Packet{
						TransportHeader: crdv1beta1.TransportHeader{
							TCP: &crdv1beta1.TCPHeader{
								SrcPort: 80,
								DstPort: 81,
								Flags:   ptr.To[int32](11),
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				SourceIP:        net.ParseIP(pod1IPv4),
				SourceMAC:       pod1MAC,
				DestinationIP:   net.ParseIP(pod2IPv4),
				DestinationMAC:  pod2MAC,
				IPProto:         protocol.Type_TCP,
				SourcePort:      80,
				DestinationPort: 81,
				TCPFlags:        11,
				TTL:             64,
			},
		},
		{
			name: "tcp packet without flag",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf4", UID: "uid4"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1beta1.Packet{
						TransportHeader: crdv1beta1.TransportHeader{
							TCP: &crdv1beta1.TCPHeader{
								SrcPort: 80,
								DstPort: 81,
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				SourceIP:        net.ParseIP(pod1IPv4),
				SourceMAC:       pod1MAC,
				DestinationIP:   net.ParseIP(pod2IPv4),
				DestinationMAC:  pod2MAC,
				IPProto:         protocol.Type_TCP,
				SourcePort:      80,
				DestinationPort: 81,
				TCPFlags:        2,
				TTL:             64,
			},
		},
		{
			name: "udp packet",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf5", UID: "uid5"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1beta1.Packet{
						TransportHeader: crdv1beta1.TransportHeader{
							UDP: &crdv1beta1.UDPHeader{
								SrcPort: 90,
								DstPort: 100,
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				SourceIP:        net.ParseIP(pod1IPv4),
				SourceMAC:       pod1MAC,
				DestinationIP:   net.ParseIP(pod2IPv4),
				DestinationMAC:  pod2MAC,
				IPProto:         protocol.Type_UDP,
				SourcePort:      90,
				DestinationPort: 100,
				TTL:             64,
			},
		},
		{
			name: "icmp packet",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf6", UID: "uid6"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1beta1.Packet{
						TransportHeader: crdv1beta1.TransportHeader{
							ICMP: &crdv1beta1.ICMPEchoRequestHeader{
								ID:       10,
								Sequence: 20,
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				SourceIP:       net.ParseIP(pod1IPv4),
				SourceMAC:      pod1MAC,
				DestinationIP:  net.ParseIP(pod2IPv4),
				DestinationMAC: pod2MAC,
				IPProto:        protocol.Type_ICMP,
				ICMPType:       8,
				ICMPEchoID:     10,
				ICMPEchoSeq:    20,
				TTL:            64,
			},
		},
		{
			name: "source Pod without IPv4 address",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf7", UID: "uid7"},
			},
			intf:        &interfacestore.InterfaceConfig{},
			expectedErr: "source Pod does not have an IPv4 address",
		},
		{
			name: "source Pod without IPv6 address",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf8", UID: "uid8"},
				Spec: crdv1beta1.TraceflowSpec{
					Packet: crdv1beta1.Packet{
						IPv6Header: &crdv1beta1.IPv6Header{},
					},
				},
			},
			intf:        &interfacestore.InterfaceConfig{},
			expectedErr: "source Pod does not have an IPv6 address",
		},
		{
			name: "destination IP family different from packet",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf9", UID: "uid9"},
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						IP: "192.168.1.2",
					},
					LiveTraffic: true,
					Packet: crdv1beta1.Packet{
						IPv6Header: &crdv1beta1.IPv6Header{},
					},
				},
			},
			expectedErr: "destination IP does not match the IP header family",
		},
		{
			name: "source IP family different from packet for receiver only case",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf10", UID: "uid10"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						IP: "192.168.1.2",
					},
					LiveTraffic: true,
					Packet: crdv1beta1.Packet{
						IPv6Header: &crdv1beta1.IPv6Header{},
					},
				},
			},
			receiverOnly: true,
			expectedErr:  "source IP does not match the IP header family",
		},
		{
			name: "destination Pod unavailable",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf11", UID: "uid11"},
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						Pod:       "unknown pod",
						Namespace: "default",
					},
				},
			},
			expectedErr: "failed to get the destination Pod: pods \"unknown pod\"",
		},
		{
			name: "destination Pod without IPv4 address in live traffic traceflow",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf12", UID: "uid12"},
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						Pod:       pod3.Name,
						Namespace: pod3.Namespace,
					},
					LiveTraffic: true,
				},
			},
			expectedErr: "destination Pod does not have an IPv4 address",
		},
		{
			name: "destination Pod without IPv6 address in live traffic traceflow",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf13", UID: "uid13"},
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						Pod:       pod3.Name,
						Namespace: pod3.Namespace,
					},
					LiveTraffic: true,
					Packet: crdv1beta1.Packet{
						IPv6Header: &crdv1beta1.IPv6Header{},
					},
				},
			},
			expectedErr: "destination Pod does not have an IPv6 address",
		},
		{
			name: "Pod-to-IPv6 liveTraffic traceflow",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf14", UID: "uid14"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						IP: "2001:db8::68",
					},
					LiveTraffic: true,
					Packet: crdv1beta1.Packet{
						IPv6Header: &crdv1beta1.IPv6Header{
							NextHeader: &protocolICMPv6,
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				IsIPv6:        true,
				DestinationIP: net.ParseIP("2001:db8::68"),
				IPProto:       protocol.Type_IPv6ICMP,
			},
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, nil)
			podInterfaces := tfc.interfaceStore.GetContainerInterfacesByPod(pod1.Name, pod1.Namespace)
			if tt.intf != nil {
				podInterfaces[0] = tt.intf
			}

			pkt, err := tfc.preparePacket(tt.tf, podInterfaces[0], tt.receiverOnly)
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPacket, pkt)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
				assert.Nil(t, pkt)
			}
		})
	}
}

func TestErrTraceflowCRD(t *testing.T) {
	tf := &crdv1beta1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tf",
			UID:  "uid",
		},
		Spec: crdv1beta1.TraceflowSpec{
			Source: crdv1beta1.Source{
				Namespace: pod1.Namespace,
				Pod:       pod1.Name,
			},
			Destination: crdv1beta1.Destination{
				Namespace: pod2.Namespace,
				Pod:       pod2.Name,
			},
		},
		Status: crdv1beta1.TraceflowStatus{
			Phase:        crdv1beta1.Running,
			DataplaneTag: 1,
		},
	}
	expectedTf := tf
	reason := "failed"
	expectedTf.Status.Phase = crdv1beta1.Failed
	expectedTf.Status.Reason = reason

	tfc := newFakeTraceflowController(t, []runtime.Object{tf}, nil, nil)

	gotTf, err := tfc.errorTraceflowCRD(tf, reason)
	require.NoError(t, err)
	assert.Equal(t, expectedTf, gotTf)
}

func TestStartTraceflow(t *testing.T) {
	tcs := []struct {
		name           string
		tf             *crdv1beta1.Traceflow
		ofPort         uint32
		receiverOnly   bool
		packet         *binding.Packet
		expectedCalls  func(mockOFClient *openflowtest.MockClient)
		nodeConfig     *config.NodeConfig
		expectedErr    string
		expectedErrLog string
	}{
		{
			name: "Pod-to-Pod traceflow",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			ofPort: ofPortPod1,
			packet: &binding.Packet{
				SourceIP:       net.ParseIP(pod1IPv4),
				SourceMAC:      pod1MAC,
				DestinationIP:  net.ParseIP(pod2IPv4),
				DestinationMAC: pod2MAC,
				IPProto:        1,
				TTL:            64,
				ICMPType:       8,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTraceflowFlows(uint8(1), false, false, false, nil, ofPortPod1, uint16(crdv1beta1.DefaultTraceflowTimeout))
				mockOFClient.EXPECT().SendTraceflowPacket(uint8(1), &binding.Packet{
					SourceIP:       net.ParseIP(pod1IPv4),
					SourceMAC:      pod1MAC,
					DestinationIP:  net.ParseIP(pod2IPv4),
					DestinationMAC: pod2MAC,
					IPProto:        1,
					TTL:            64,
					ICMPType:       8,
				}, ofPortPod1, int32(-1))
			},
		},
		{
			name: "Pod-to-IPv4 traceflow",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf2", UID: "uid2"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						IP: dstIPv4,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			ofPort: ofPortPod1,
			packet: &binding.Packet{
				SourceIP:      net.ParseIP(pod1IPv4),
				SourceMAC:     pod1MAC,
				DestinationIP: net.ParseIP(dstIPv4),
				IPProto:       1,
				TTL:           64,
				ICMPType:      8,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTraceflowFlows(uint8(1), false, false, false, nil, ofPortPod1, uint16(crdv1beta1.DefaultTraceflowTimeout))
				mockOFClient.EXPECT().SendTraceflowPacket(uint8(1), &binding.Packet{
					SourceIP:      net.ParseIP(pod1IPv4),
					SourceMAC:     pod1MAC,
					DestinationIP: net.ParseIP(dstIPv4),
					IPProto:       1,
					TTL:           64,
					ICMPType:      8,
				}, ofPortPod1, int32(-1))
			},
		},
		{
			name: "live traceflow receive only",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf6", UID: "uid6"},
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					LiveTraffic: true,
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			ofPort: ofPortPod2,
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTraceflowFlows(uint8(1), true, false, true, &binding.Packet{DestinationMAC: pod2MAC}, ofPortPod2, uint16(crdv1beta1.DefaultTraceflowTimeout))
			},
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, tt.nodeConfig)
			if tt.expectedCalls != nil {
				tt.expectedCalls(tfc.mockOFClient)
			}

			bufWriter := bytes.NewBuffer(nil)
			klog.SetOutput(bufWriter)
			klog.LogToStderr(false)
			defer func() {
				klog.SetOutput(os.Stderr)
				klog.LogToStderr(true)
			}()

			err := tfc.startTraceflow(tt.tf)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
			if tt.expectedErrLog != "" {
				assert.Contains(t, bufWriter.String(), tt.expectedErrLog)
			}
		})
	}
}

func TestSyncTraceflow(t *testing.T) {
	tcs := []struct {
		name          string
		tf            *crdv1beta1.Traceflow
		existingState *traceflowState
		newState      *traceflowState
		expectedCalls func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name: "traceflow in running phase",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			existingState: &traceflowState{
				name: "tf1",
				uid:  "uid1",
				tag:  1,
			},
			newState: &traceflowState{
				name: "tf1",
				uid:  "uid1",
				tag:  1,
			},
		},
		{
			name: "traceflow in running phase with empty state",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			newState: &traceflowState{
				name:     "tf1",
				uid:      "uid1",
				tag:      1,
				isSender: true,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTraceflowFlows(uint8(1), false, false, false, nil, uint32(1), uint16(20))
				mockOFClient.EXPECT().SendTraceflowPacket(uint8(1), gomock.Any(), ofPortPod1, int32(-1))
			},
		},
		{
			name: "traceflow in running phase with conflict state",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Running,
					DataplaneTag: 1,
				},
			},
			existingState: &traceflowState{
				name: "tf1",
				uid:  "uid2",
				tag:  1,
			},
			newState: &traceflowState{
				name:     "tf1",
				uid:      "uid1",
				tag:      1,
				isSender: true,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallTraceflowFlows(uint8(1))
				mockOFClient.EXPECT().InstallTraceflowFlows(uint8(1), false, false, false, nil, uint32(1), uint16(20))
				mockOFClient.EXPECT().SendTraceflowPacket(uint8(1), gomock.Any(), ofPortPod1, int32(-1))
			},
		},
		{
			name: "traceflow in failed phase",
			tf: &crdv1beta1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1beta1.TraceflowSpec{
					Source: crdv1beta1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1beta1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1beta1.TraceflowStatus{
					Phase:        crdv1beta1.Failed,
					DataplaneTag: 1,
				},
			},
			existingState: &traceflowState{
				name: "tf1",
				tag:  1,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallTraceflowFlows(uint8(1))
			},
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			tfc.crdInformerFactory.Start(stopCh)
			tfc.crdInformerFactory.WaitForCacheSync(stopCh)

			if tt.existingState != nil {
				tfc.runningTraceflows[tt.tf.Status.DataplaneTag] = tt.existingState
			}

			if tt.expectedCalls != nil {
				tt.expectedCalls(tfc.mockOFClient)
			}

			err := tfc.syncTraceflow(tt.tf.Name)
			require.NoError(t, err)
			assert.Equal(t, tt.newState, tfc.runningTraceflows[tt.tf.Status.DataplaneTag])
		})
	}
}

func TestProcessTraceflowItem(t *testing.T) {
	tc := struct {
		tf           *crdv1beta1.Traceflow
		ofPort       uint32
		receiverOnly bool
		packet       *binding.Packet
		expected     bool
	}{
		tf: &crdv1beta1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
			Spec: crdv1beta1.TraceflowSpec{
				Source: crdv1beta1.Source{
					Namespace: pod1.Namespace,
					Pod:       pod1.Name,
				},
				Destination: crdv1beta1.Destination{
					Namespace: pod2.Namespace,
					Pod:       pod2.Name,
				},
			},
			Status: crdv1beta1.TraceflowStatus{
				Phase:        crdv1beta1.Running,
				DataplaneTag: 1,
			},
		},
		ofPort: ofPortPod1,
		packet: &binding.Packet{
			SourceIP:       net.ParseIP(pod1IPv4),
			SourceMAC:      pod1MAC,
			DestinationIP:  net.ParseIP(pod2IPv4),
			DestinationMAC: pod2MAC,
			IPProto:        1,
			TTL:            64,
			ICMPType:       8,
		},
		expected: true,
	}

	tfc := newFakeTraceflowController(t, []runtime.Object{tc.tf}, nil, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	tfc.crdInformerFactory.Start(stopCh)
	tfc.crdInformerFactory.WaitForCacheSync(stopCh)

	tfc.mockOFClient.EXPECT().InstallTraceflowFlows(uint8(tc.tf.Status.DataplaneTag), tc.tf.Spec.LiveTraffic, tc.tf.Spec.DroppedOnly, tc.receiverOnly, nil, tc.ofPort, uint16(crdv1beta1.DefaultTraceflowTimeout))
	tfc.mockOFClient.EXPECT().SendTraceflowPacket(uint8(tc.tf.Status.DataplaneTag), tc.packet, tc.ofPort, int32(-1))
	tfc.enqueueTraceflow(tc.tf)
	got := tfc.processTraceflowItem()
	assert.Equal(t, tc.expected, got)
}

func TestValidateTraceflow(t *testing.T) {
	tcs := []struct {
		name               string
		tf                 *crdv1beta1.Traceflow
		antreaProxyEnabled bool
		expectedErr        string
	}{
		{
			name: "AntreaProxy disabled with destination as service",
			tf: &crdv1beta1.Traceflow{
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						Service: "svcTest",
					},
				},
			},
			expectedErr: "using Service destination requires AntreaProxy enabled",
		},
		{
			name: "AntreaProxy disabled with ClusterIP destination",
			tf: &crdv1beta1.Traceflow{
				Spec: crdv1beta1.TraceflowSpec{
					Destination: crdv1beta1.Destination{
						IP: "10.96.1.1",
					},
				},
			},
			expectedErr: "using ClusterIP destination requires AntreaProxy enabled",
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, nil)
			tfc.enableAntreaProxy = tt.antreaProxyEnabled
			err := tfc.validateTraceflow(tt.tf)
			assert.ErrorContains(t, err, tt.expectedErr)
		})
	}
}
