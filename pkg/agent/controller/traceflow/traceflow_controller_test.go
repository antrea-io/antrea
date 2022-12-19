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
	"net"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	pod1IPv4   = "192.168.10.10"
	pod2IPv4   = "192.168.11.10"
	dstIPv4    = "192.168.99.99"
	pod1MAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1 = uint32(1)
	ofPortPod2 = uint32(2)

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
)

type fakeTraceflowController struct {
	*Controller
	kubeClient         kubernetes.Interface
	mockController     *gomock.Controller
	mockOFClient       *openflowtest.MockClient
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	ovsClient          *ovsconfigtest.MockOVSBridgeClient
}

func newFakeTraceflowController(t *testing.T, initObjects []runtime.Object, networkConfig *config.NetworkConfig, nodeConfig *config.NodeConfig, npQuerier querier.AgentNetworkPolicyInfoQuerier, egressQuerier querier.EgressQuerier) *fakeTraceflowController {
	controller := gomock.NewController(t)
	kubeClient := fake.NewSimpleClientset(&pod1, &pod2)
	mockOFClient := openflowtest.NewMockClient(controller)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	traceflowInformer := crdInformerFactory.Crd().V1alpha1().Traceflows()
	ovsClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, pod1IPv4, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, pod2IPv4, pod2MAC.String(), int32(ofPortPod2))

	_, serviceCIDRNet, _ := net.ParseCIDR("10.96.0.0/12")

	tfController := &Controller{
		kubeClient:            kubeClient,
		traceflowClient:       crdClient,
		traceflowInformer:     traceflowInformer,
		traceflowLister:       traceflowInformer.Lister(),
		traceflowListerSynced: traceflowInformer.Informer().HasSynced,
		ofClient:              mockOFClient,
		networkPolicyQuerier:  npQuerier,
		egressQuerier:         egressQuerier,
		ovsBridgeClient:       ovsClient,
		interfaceStore:        ifaceStore,
		networkConfig:         networkConfig,
		nodeConfig:            nodeConfig,
		serviceCIDR:           serviceCIDRNet,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "traceflow"),
		runningTraceflows:     make(map[uint8]*traceflowState),
	}
	return &fakeTraceflowController{
		Controller:         tfController,
		kubeClient:         kubeClient,
		mockController:     controller,
		mockOFClient:       mockOFClient,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		ovsClient:          ovsClient,
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
		tf             *crdv1alpha1.Traceflow
		receiverOnly   bool
		expectedPacket *binding.Packet
		expectedErr    string
	}{
		{
			name: "invalid destination ipv4",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						IP: "1.1.1.300",
					},
				},
			},
			expectedErr: "invalid destination IP address",
		},
		{
			name: "empty destination with no live traffic",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf2", UID: "uid2"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
				},
			},
			expectedErr: "destination is not specified",
		},
		{
			name: "receive only from a source ipv4 to dst pod1 in live traffic traceflow",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf3", UID: "uid3"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						IP: "192.168.12.4",
					},
					Destination: crdv1alpha1.Destination{
						Pod: pod1.Name,
					},
					LiveTraffic: true,
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
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf4", UID: "uid4"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1alpha1.Packet{
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								SrcPort: 80,
								DstPort: 81,
								Flags:   11,
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
			name: "udp packet",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf5", UID: "uid5"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1alpha1.Packet{
						TransportHeader: crdv1alpha1.TransportHeader{
							UDP: &crdv1alpha1.UDPHeader{
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
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf6", UID: "uid6"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1alpha1.Packet{
						TransportHeader: crdv1alpha1.TransportHeader{
							ICMP: &crdv1alpha1.ICMPEchoRequestHeader{
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
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, nil, nil, nil)
			defer tfc.mockController.Finish()

			podInterfaces := tfc.interfaceStore.GetContainerInterfacesByPod(pod1.Name, pod1.Namespace)

			pkt, err := tfc.preparePacket(tt.tf, podInterfaces[0], tt.receiverOnly)
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPacket, pkt)
			} else {
				require.EqualError(t, err, tt.expectedErr)
			}
		})
	}
}

func TestErrTraceflowCRD(t *testing.T) {
	tf := &crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dummy-traceflow",
			UID:  "uid",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			Source: crdv1alpha1.Source{
				Namespace: pod1.Namespace,
				Pod:       pod1.Name,
			},
			Destination: crdv1alpha1.Destination{
				Namespace: pod2.Namespace,
				Pod:       pod2.Name,
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			Phase:        crdv1alpha1.Running,
			DataplaneTag: 1,
		},
	}
	expectedTf := tf
	reason := "failed"
	expectedTf.Status.Phase = crdv1alpha1.Failed
	expectedTf.Status.Reason = reason

	tfc := newFakeTraceflowController(t, []runtime.Object{tf}, nil, nil, nil, nil)
	defer tfc.mockController.Finish()

	gotTf, err := tfc.errorTraceflowCRD(tf, reason)
	require.NoError(t, err)
	assert.Equal(t, expectedTf, gotTf)
}

func TestStartTraceflow(t *testing.T) {
	tcs := []struct {
		name         string
		tf           *crdv1alpha1.Traceflow
		ofPort       uint32
		receiverOnly bool
		packet       *binding.Packet
	}{
		{
			name: "pod-to-pod traceflow",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1alpha1.TraceflowStatus{
					Phase:        crdv1alpha1.Running,
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
		},
		{
			name: "pod-to-ipv4 traceflow",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf2", UID: "uid2"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						IP: dstIPv4,
					},
				},
				Status: crdv1alpha1.TraceflowStatus{
					Phase:        crdv1alpha1.Running,
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
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, nil, nil, nil)
			defer tfc.mockController.Finish()

			stopCh := make(chan struct{})
			defer close(stopCh)
			tfc.crdInformerFactory.Start(stopCh)
			tfc.crdInformerFactory.WaitForCacheSync(stopCh)

			tfc.mockOFClient.EXPECT().InstallTraceflowFlows(tt.tf.Status.DataplaneTag, tt.tf.Spec.LiveTraffic, tt.tf.Spec.DroppedOnly, tt.receiverOnly, nil, tt.ofPort, crdv1alpha1.DefaultTraceflowTimeout)
			tfc.mockOFClient.EXPECT().SendTraceflowPacket(tt.tf.Status.DataplaneTag, tt.packet, tt.ofPort, int32(-1))

			err := tfc.startTraceflow(tt.tf)
			require.NoError(t, err)
		})
	}
}

func TestSyncTraceflow(t *testing.T) {
	tcs := []struct {
		name          string
		tf            *crdv1alpha1.Traceflow
		tfState       *traceflowState
		expectedCalls func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name: "traceflow in running phase",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1alpha1.TraceflowStatus{
					Phase:        crdv1alpha1.Running,
					DataplaneTag: 1,
				},
			},
			tfState: &traceflowState{
				name: "tf1",
				tag:  1,
			},
		},
		{
			name: "traceflow in failed phase",
			tf: &crdv1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
				Spec: crdv1alpha1.TraceflowSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1alpha1.TraceflowStatus{
					Phase:        crdv1alpha1.Failed,
					DataplaneTag: 1,
				},
			},
			tfState: &traceflowState{
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
			tfc := newFakeTraceflowController(t, []runtime.Object{tt.tf}, nil, nil, nil, nil)
			defer tfc.mockController.Finish()
			tfc.runningTraceflows[tt.tf.Status.DataplaneTag] = tt.tfState
			stopCh := make(chan struct{})
			defer close(stopCh)
			tfc.crdInformerFactory.Start(stopCh)
			tfc.crdInformerFactory.WaitForCacheSync(stopCh)

			if tt.expectedCalls != nil {
				tt.expectedCalls(tfc.mockOFClient)
			}

			err := tfc.syncTraceflow(tt.tf.Name)
			require.NoError(t, err)
		})
	}
}

func TestProcessTraceflowItem(t *testing.T) {
	tc := struct {
		tf           *crdv1alpha1.Traceflow
		ofPort       uint32
		receiverOnly bool
		packet       *binding.Packet
		expected     bool
	}{
		tf: &crdv1alpha1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
			Spec: crdv1alpha1.TraceflowSpec{
				Source: crdv1alpha1.Source{
					Namespace: pod1.Namespace,
					Pod:       pod1.Name,
				},
				Destination: crdv1alpha1.Destination{
					Namespace: pod2.Namespace,
					Pod:       pod2.Name,
				},
			},
			Status: crdv1alpha1.TraceflowStatus{
				Phase:        crdv1alpha1.Running,
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
	tfc := newFakeTraceflowController(t, []runtime.Object{tc.tf}, nil, nil, nil, nil)
	defer tfc.mockController.Finish()

	stopCh := make(chan struct{})
	defer close(stopCh)
	tfc.crdInformerFactory.Start(stopCh)
	tfc.crdInformerFactory.WaitForCacheSync(stopCh)

	tfc.mockOFClient.EXPECT().InstallTraceflowFlows(tc.tf.Status.DataplaneTag, tc.tf.Spec.LiveTraffic, tc.tf.Spec.DroppedOnly, tc.receiverOnly, nil, tc.ofPort, crdv1alpha1.DefaultTraceflowTimeout)
	tfc.mockOFClient.EXPECT().SendTraceflowPacket(tc.tf.Status.DataplaneTag, tc.packet, tc.ofPort, int32(-1))

	tfc.enqueueTraceflow(tc.tf)

	got := tfc.processTraceflowItem()
	assert.Equal(t, tc.expected, got)
}
