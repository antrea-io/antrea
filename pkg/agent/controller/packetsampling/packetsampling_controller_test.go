// Copyright 2024 Antrea Authors.
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

package packetsampling

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/protocol"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	pod1IPv4       = "192.168.10.10"
	pod2IPv4       = "192.168.11.10"
	service1IPv4   = "10.96.0.10"
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

	service1 = v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-1",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			ClusterIP: service1IPv4,
		},
	}
)

type fakePacketSamplingController struct {
	*Controller
	kubeClient         kubernetes.Interface
	mockController     *gomock.Controller
	mockOFClient       *openflowtest.MockClient
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	informerFactory    informers.SharedInformerFactory
}

func newFakePacketSamplingController(t *testing.T, runtimeObjects []runtime.Object, initObjects []runtime.Object, networkConfig *config.NetworkConfig, nodeConfig *config.NodeConfig) *fakePacketSamplingController {
	controller := gomock.NewController(t)
	objs := []runtime.Object{
		&pod1,
		&pod2,
		&pod3,
		&service1,
	}
	objs = append(objs, generateTestSecret())
	if runtimeObjects != nil {
		objs = append(objs, runtimeObjects...)
	}
	kubeClient := fake.NewSimpleClientset(objs...)
	mockOFClient := openflowtest.NewMockClient(controller)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	packetSamplingInformer := crdInformerFactory.Crd().V1alpha1().PacketSamplings()
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)
	serviceInformer := informerFactory.Core().V1().Services()
	endpointInformer := informerFactory.Core().V1().Endpoints()

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, pod1IPv4, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, pod2IPv4, pod2MAC.String(), int32(ofPortPod2))

	_, serviceCIDRNet, _ := net.ParseCIDR("10.96.0.0/12")

	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any()).Times(1)
	psController := NewPacketSamplingController(
		kubeClient,
		crdClient,
		serviceInformer,
		endpointInformer,
		packetSamplingInformer,
		mockOFClient,
		ifaceStore,
		networkConfig,
		nodeConfig,
		serviceCIDRNet,
		true,
	)
	psController.sftpUploader = &testUploader{}

	return &fakePacketSamplingController{
		Controller:         psController,
		kubeClient:         kubeClient,
		mockController:     controller,
		mockOFClient:       mockOFClient,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		informerFactory:    informerFactory,
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

func TestErrPacketSamplingCRD(t *testing.T) {
	ps := &crdv1alpha1.PacketSampling{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ps",
			UID:  "uid",
		},
		Spec: crdv1alpha1.PacketSamplingSpec{
			Source: crdv1alpha1.Source{
				Namespace: pod1.Namespace,
				Pod:       pod1.Name,
			},
			Destination: crdv1alpha1.Destination{
				Namespace: pod2.Namespace,
				Pod:       pod2.Name,
			},
		},
		Status: crdv1alpha1.PacketSamplingStatus{
			Phase:        crdv1alpha1.PacketSamplingRunning,
			DataplaneTag: 1,
		},
	}
	expectedPS := ps
	reason := "failed"
	expectedPS.Status.Phase = crdv1alpha1.PacketSamplingFailed
	expectedPS.Status.Reason = reason

	psc := newFakePacketSamplingController(t, nil, []runtime.Object{ps}, nil, nil)

	gotPS, err := psc.errorPacketSamplingCRD(ps, reason)
	require.NoError(t, err)
	assert.Equal(t, expectedPS, gotPS)
}

func TestPreparePacket(t *testing.T) {
	pss := []struct {
		name           string
		ps             *crdv1alpha1.PacketSampling
		intf           *interfacestore.InterfaceConfig
		receiverOnly   bool
		expectedPacket *binding.Packet
		expectedErr    string
	}{
		{
			name: "invalid destination IPv4",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						IP: "1.1.1.300",
					},
				},
			},
			expectedErr: "destination IP is not valid",
		},
		{
			name: "empty destination",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps2", UID: "uid2"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
				},
			},
			expectedErr: "destination is not specified",
		},
		{
			name: "ipv4 tcp packet",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps3", UID: "uid3"},
				Spec: crdv1alpha1.PacketSamplingSpec{
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
				DestinationIP:   net.ParseIP(pod2IPv4),
				IPProto:         protocol.Type_TCP,
				SourcePort:      80,
				DestinationPort: 81,
				TCPFlags:        11,
			},
		},
		{
			name: "receiver only with source ip",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps4", UID: "uid4"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						IP: "192.168.12.4",
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{},
					},
				},
			},
			receiverOnly: true,
			expectedPacket: &binding.Packet{
				SourceIP:       net.ParseIP("192.168.12.4"),
				DestinationMAC: pod1MAC,
				IPProto:        1,
			},
		},
		{
			name: "destination Pod without IPv6 address",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps4", UID: "uid4"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Packet: crdv1alpha1.Packet{
						IPv6Header: &crdv1alpha1.IPv6Header{},
					},
				},
			},
			expectedErr: "destination Pod does not have an IPv6 address",
		},
		{
			name: "pod to ipv6 packet sampling",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps5", UID: "uid5"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						IP: "2001:db8::68",
					},
					Packet: crdv1alpha1.Packet{
						IPv6Header: &crdv1alpha1.IPv6Header{NextHeader: &protocolICMPv6},
					},
				},
			},
			expectedPacket: &binding.Packet{
				IsIPv6:        true,
				DestinationIP: net.ParseIP("2001:db8::68"),
				IPProto:       protocol.Type_IPv6ICMP,
			},
		},
		{
			name: "tcp packet without flags",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps6", UID: "uid6"},
				Spec: crdv1alpha1.PacketSamplingSpec{
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
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				DestinationIP:   net.ParseIP(pod2IPv4),
				IPProto:         protocol.Type_TCP,
				SourcePort:      80,
				DestinationPort: 81,
			},
		},
		{
			name: "udp packet",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps7", UID: "uid7"},
				Spec: crdv1alpha1.PacketSamplingSpec{
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
								SrcPort: 80,
								DstPort: 100,
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				DestinationIP:   net.ParseIP(pod2IPv4),
				IPProto:         protocol.Type_UDP,
				SourcePort:      80,
				DestinationPort: 100,
			},
		},
		{
			name: "icmp packet",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps8", UID: "uid8"},
				Spec: crdv1alpha1.PacketSamplingSpec{
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
							ICMP: &crdv1alpha1.ICMPEchoRequestHeader{},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				DestinationIP: net.ParseIP(pod2IPv4),
				IPProto:       protocol.Type_ICMP,
			},
		},
		{
			name: "destination Pod unavailable",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps11", UID: "uid11"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Destination: crdv1alpha1.Destination{
						Pod:       "unknown pod",
						Namespace: "default",
					},
				},
			},
			expectedErr: "failed to get the destination pod default/unknown pod: pods \"unknown pod\"",
		},
		{
			name: "to service packet",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps12", UID: "uid12"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Service:   service1.Name,
						Namespace: service1.Namespace,
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
				DestinationIP:   net.ParseIP(service1IPv4).To4(),
				IPProto:         protocol.Type_TCP,
				SourcePort:      80,
				DestinationPort: 81,
				TCPFlags:        11,
			},
		},
	}
	for _, ps := range pss {
		t.Run(ps.name, func(t *testing.T) {
			psc := newFakePacketSamplingController(t, nil, []runtime.Object{ps.ps}, nil, nil)
			podInterfaces := psc.interfaceStore.GetContainerInterfacesByPod(pod1.Name, pod1.Namespace)
			if ps.intf != nil {
				podInterfaces[0] = ps.intf
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			psc.crdInformerFactory.Start(stopCh)
			psc.crdInformerFactory.WaitForCacheSync(stopCh)
			psc.informerFactory.Start(stopCh)
			psc.informerFactory.WaitForCacheSync(stopCh)

			pkt, err := psc.preparePacket(ps.ps, podInterfaces[0], ps.receiverOnly)
			if ps.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, ps.expectedPacket, pkt)
			} else {
				assert.ErrorContains(t, err, ps.expectedErr)
				assert.Nil(t, pkt)
			}
		})
	}
}

func TestSyncPacketSampling(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/packetsampling/packets", 0755)
	file, err := defaultFS.Create(uidToPath(testUID))
	if err != nil {
		t.Fatal("create pcapng file error: ", err)
	}

	testWriter, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("create test pcapng writer failed: ", err)
	}

	pcs := []struct {
		name          string
		ps            *crdv1alpha1.PacketSampling
		existingState *packetSamplingState
		newState      *packetSamplingState
		expectedCalls func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name: "packetsampling in running phase",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
				},
				Status: crdv1alpha1.PacketSamplingStatus{
					Phase:        crdv1alpha1.PacketSamplingRunning,
					DataplaneTag: 1,
				},
			},
			existingState: &packetSamplingState{
				name: "ps1",
				uid:  "uid1",
				tag:  1,
			},
			newState: &packetSamplingState{
				name: "ps1",
				uid:  "uid1",
				tag:  1,
			},
		},

		{
			name: "packetsampling in failed phase",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: types.UID(testUID)},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
				},
				Status: crdv1alpha1.PacketSamplingStatus{
					Phase:        crdv1alpha1.PacketSamplingFailed,
					DataplaneTag: 1,
				},
			},
			existingState: &packetSamplingState{
				name:         "ps1",
				uid:          testUID,
				pcapngFile:   file,
				pcapngWriter: testWriter,
				tag:          1,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallPacketSamplingFlows(uint8(1))
			},
		},
	}

	for _, ps := range pcs {
		t.Run(ps.name, func(t *testing.T) {
			psc := newFakePacketSamplingController(t, nil, []runtime.Object{ps.ps}, nil, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			psc.crdInformerFactory.Start(stopCh)
			psc.crdInformerFactory.WaitForCacheSync(stopCh)

			if ps.existingState != nil {
				psc.runningPacketSamplings[ps.ps.Status.DataplaneTag] = ps.existingState
			}

			if ps.expectedCalls != nil {
				ps.expectedCalls(psc.mockOFClient)
			}

			err := psc.syncPacketSampling(ps.ps.Name)
			require.NoError(t, err)
			assert.Equal(t, ps.newState, psc.runningPacketSamplings[ps.ps.Status.DataplaneTag])
		})
	}
}

// TestPacketSamplingControllerRun was used to validate the whole run process is working. it didn't wait for
// the test ps to finished.
func TestPacketSamplingControllerRun(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/packetsampling/packets", 0755)
	ps := struct {
		name     string
		ps       *crdv1alpha1.PacketSampling
		newState *packetSamplingState
	}{
		name: "packetsampling in running phase",
		ps: &crdv1alpha1.PacketSampling{
			ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
			Spec: crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					Namespace: pod1.Namespace,
					Pod:       pod1.Name,
				},
				Destination: crdv1alpha1.Destination{
					Namespace: pod2.Namespace,
					Pod:       pod2.Name,
				},
				Type: crdv1alpha1.FirstNSampling,
				FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
					Number: 5,
				},
			},
			Status: crdv1alpha1.PacketSamplingStatus{
				Phase:        crdv1alpha1.PacketSamplingRunning,
				DataplaneTag: 1,
			},
		},
	}

	psc := newFakePacketSamplingController(t, nil, []runtime.Object{ps.ps}, nil, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	psc.crdInformerFactory.Start(stopCh)
	psc.crdInformerFactory.WaitForCacheSync(stopCh)
	psc.informerFactory.Start(stopCh)
	psc.informerFactory.WaitForCacheSync(stopCh)
	psc.mockOFClient.EXPECT().InstallPacketSamplingFlows(uint8(ps.ps.Status.DataplaneTag), false, false, &binding.Packet{DestinationIP: net.ParseIP(pod2.Status.PodIP), IPProto: protocol.Type_ICMP}, nil, ofPortPod1, uint16(crdv1alpha1.DefaultPacketSamplingTimeout))
	go psc.Run(stopCh)
	time.Sleep(300 * time.Millisecond)
}

func TestProcessPacketSamplingItem(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/packetsampling/packets", 0755)
	pc := struct {
		ps           *crdv1alpha1.PacketSampling
		ofPort       uint32
		receiverOnly bool
		packet       *binding.Packet
		expected     bool
	}{
		ps: &crdv1alpha1.PacketSampling{
			ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
			Spec: crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					Namespace: pod1.Namespace,
					Pod:       pod1.Name,
				},
				Destination: crdv1alpha1.Destination{
					Namespace: pod2.Namespace,
					Pod:       pod2.Name,
				},
				FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
					Number: 5,
				},
				Type: crdv1alpha1.FirstNSampling,
			},
			Status: crdv1alpha1.PacketSamplingStatus{
				Phase:        crdv1alpha1.PacketSamplingRunning,
				DataplaneTag: 1,
			},
		},
		ofPort: ofPortPod1,
		packet: &binding.Packet{
			DestinationIP: net.ParseIP(pod2IPv4),
			IPProto:       1,
		},
		expected: true,
	}

	psc := newFakePacketSamplingController(t, nil, []runtime.Object{pc.ps}, nil, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	psc.crdInformerFactory.Start(stopCh)
	psc.crdInformerFactory.WaitForCacheSync(stopCh)

	psc.mockOFClient.EXPECT().InstallPacketSamplingFlows(uint8(pc.ps.Status.DataplaneTag), false, pc.receiverOnly, pc.packet, nil, pc.ofPort, uint16(crdv1alpha1.DefaultPacketSamplingTimeout))
	psc.enqueuePacketSampling(pc.ps)
	got := psc.processPacketSamplingItem()
	assert.Equal(t, pc.expected, got)
}

func TestValidateTraceflow(t *testing.T) {
	pss := []struct {
		name               string
		ps                 *crdv1alpha1.PacketSampling
		antreaProxyEnabled bool
		expectedErr        string
	}{
		{
			name: "AntreaProxy disabled with destination as service",
			ps: &crdv1alpha1.PacketSampling{
				Spec: crdv1alpha1.PacketSamplingSpec{
					Destination: crdv1alpha1.Destination{
						Service: "svcTest",
					},
				},
			},
			expectedErr: "using Service destination requires AntreaProxy feature enabled",
		},
		{
			name: "AntreaProxy disabled with ClusterIP destination",
			ps: &crdv1alpha1.PacketSampling{
				Spec: crdv1alpha1.PacketSamplingSpec{
					Destination: crdv1alpha1.Destination{
						IP: "10.96.1.1",
					},
				},
			},
			expectedErr: "using ClusterIP destination requires AntreaProxy feature enabled",
		},
	}

	for _, pt := range pss {
		t.Run(pt.name, func(t *testing.T) {
			psc := newFakePacketSamplingController(t, nil, []runtime.Object{pt.ps}, nil, nil)
			psc.enableAntreaProxy = pt.antreaProxyEnabled
			err := psc.validatePacketSampling(pt.ps)
			assert.ErrorContains(t, err, pt.expectedErr)
		})
	}
}

func TestStartPacketSampling(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll(packetDirectory, 0755)
	tcs := []struct {
		name           string
		ps             *crdv1alpha1.PacketSampling
		ofPort         uint32
		receiverOnly   bool
		packet         *binding.Packet
		expectedCalls  func(mockOFClient *openflowtest.MockClient)
		nodeConfig     *config.NodeConfig
		expectedErr    string
		expectedErrLog string
	}{
		{
			name: "Pod-to-Pod PacketSampling",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod2.Namespace,
						Pod:       pod2.Name,
					},
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
				},

				Status: crdv1alpha1.PacketSamplingStatus{
					Phase:        crdv1alpha1.PacketSamplingRunning,
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
				mockOFClient.EXPECT().InstallPacketSamplingFlows(uint8(1), false, false,
					&binding.Packet{
						DestinationIP: net.ParseIP(pod2IPv4),
						IPProto:       1,
					},
					nil, ofPortPod1, crdv1alpha1.DefaultPacketSamplingTimeout)
			},
		},
		{
			name: "Pod-to-IPv4 packetsampling",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps2", UID: "uid2"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						IP: dstIPv4,
					},
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
				},
				Status: crdv1alpha1.PacketSamplingStatus{
					Phase:        crdv1alpha1.PacketSamplingRunning,
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
				mockOFClient.EXPECT().InstallPacketSamplingFlows(uint8(1), true, false, &binding.Packet{
					DestinationIP: net.ParseIP(dstIPv4),
					IPProto:       1,
				}, nil, ofPortPod1, crdv1alpha1.DefaultPacketSamplingTimeout)
			},
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakePacketSamplingController(t, nil, []runtime.Object{tt.ps}, nil, tt.nodeConfig)
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

			err := tfc.startPacketSampling(tt.ps)
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

func TestPrepareEndpointsPackets(t *testing.T) {
	pss := []struct {
		name            string
		ps              *crdv1alpha1.PacketSampling
		expectedPackets []binding.Packet
		objs            []runtime.Object
		expectedErr     string
	}{
		{
			name:        "svc-not-exist",
			expectedErr: "service \"svc1\" not found",
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps2", UID: "uid2"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod1.Namespace,
						Service:   "svc1",
					},
					Packet: crdv1alpha1.Packet{
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: 80,
							},
						},
					},
				},
			},
		},
		{
			name:        "ep-not-exist",
			expectedErr: "endpoints \"svc1\" not found",
			objs: []runtime.Object{&v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: pod1.Namespace,
					Name:      "svc1",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Name: "http",
							Port: 80,
							TargetPort: intstr.IntOrString{
								Type:   intstr.Type(intstr.Int),
								IntVal: 8080,
							},
						},
					},
				},
			}},
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps2", UID: "uid2"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod1.Namespace,
						Service:   "svc1",
					},
					Packet: crdv1alpha1.Packet{
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: 80,
							},
						},
					},
				},
			},
		},
		{
			name: "tcp-2-backends-svc",
			expectedPackets: []binding.Packet{
				{
					DestinationIP:   net.ParseIP(pod1.Status.PodIP),
					DestinationPort: 8080,
					IPProto:         protocol.Type_TCP,
				},
				{
					DestinationIP:   net.ParseIP(pod2.Status.PodIP),
					DestinationPort: 8080,
					IPProto:         protocol.Type_TCP,
				},
			},
			objs: []runtime.Object{&v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: pod1.Namespace,
					Name:      "svc1",
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Name: "http",
							Port: 80,
							TargetPort: intstr.IntOrString{
								Type:   intstr.Type(intstr.Int),
								IntVal: 8080,
							},
						},
					},
				},
			}, &v1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: pod1.Namespace,
					Name:      "svc1",
				},
				Subsets: []v1.EndpointSubset{
					{
						Addresses: []v1.EndpointAddress{
							{
								IP: pod1.Status.PodIP,
							},
							{
								IP: pod2.Status.PodIP,
							},
						},
						Ports: []v1.EndpointPort{
							{
								Name: "http",
								Port: 8080,
							},
						},
					},
				},
			}},
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: pod1.Namespace,
						Pod:       pod1.Name,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: pod1.Namespace,
						Service:   "svc1",
					},
					Packet: crdv1alpha1.Packet{
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: 80,
							},
						},
					},
				},
			},
		},
	}

	for _, ps := range pss {
		t.Run(ps.name, func(t *testing.T) {
			psc := newFakePacketSamplingController(t, ps.objs, []runtime.Object{ps.ps}, nil, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			psc.crdInformerFactory.Start(stopCh)
			psc.crdInformerFactory.WaitForCacheSync(stopCh)
			psc.informerFactory.Start(stopCh)
			psc.informerFactory.WaitForCacheSync(stopCh)

			pkts, err := psc.genEndpointMatchPackets(ps.ps)
			if ps.expectedErr == "" {
				require.NoError(t, err)
				if !reflect.DeepEqual(ps.expectedPackets, pkts) {
					t.Errorf("expected packets: %+v, got: %+v", ps.expectedPackets, pkts)
				}

			} else {
				assert.ErrorContains(t, err, ps.expectedErr)
				assert.Nil(t, pkts)
			}
		})
	}
}
