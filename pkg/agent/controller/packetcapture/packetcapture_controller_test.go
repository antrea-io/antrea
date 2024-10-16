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

package packetcapture

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"antrea.io/libOpenflow/protocol"
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
	pod1IPv4           = "192.168.10.10"
	pod2IPv4           = "192.168.11.10"
	ipv4               = "192.168.12.4"
	ipv6               = "2001:db8::68"
	service1IPv4       = "10.96.0.10"
	dstIPv4            = "192.168.99.99"
	pod1MAC, _         = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _         = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1         = uint32(1)
	ofPortPod2         = uint32(2)
	testTCPFlags       = int32(11)
	icmp6Proto         = intstr.FromInt(58)
	icmpProto          = intstr.FromString("ICMP")
	port80       int32 = 80
	port81       int32 = 81

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

	secret1 = v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fileServerAuthSecretName,
			Namespace: fileServerAuthSecretNamespace,
		},
		Data: map[string][]byte{
			"username": []byte("username"),
			"password": []byte("password"),
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

type fakePacketCaptureController struct {
	*Controller
	kubeClient         kubernetes.Interface
	mockController     *gomock.Controller
	mockOFClient       *openflowtest.MockClient
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	informerFactory    informers.SharedInformerFactory
}

func newFakePacketCaptureController(t *testing.T, runtimeObjects []runtime.Object, initObjects []runtime.Object, nodeConfig *config.NodeConfig) *fakePacketCaptureController {
	controller := gomock.NewController(t)
	objs := []runtime.Object{
		&pod1,
		&pod2,
		&pod3,
		&service1,
		&secret1,
	}
	objs = append(objs, generateTestSecret())
	if runtimeObjects != nil {
		objs = append(objs, runtimeObjects...)
	}
	kubeClient := fake.NewSimpleClientset(objs...)
	mockOFClient := openflowtest.NewMockClient(controller)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	packetCaptureInformer := crdInformerFactory.Crd().V1alpha1().PacketCaptures()
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)
	serviceInformer := informerFactory.Core().V1().Services()
	endpointInformer := informerFactory.Core().V1().Endpoints()

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, pod1IPv4, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, pod2IPv4, pod2MAC.String(), int32(ofPortPod2))

	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any()).Times(1)
	pcController := NewPacketCaptureController(
		kubeClient,
		crdClient,
		serviceInformer,
		endpointInformer,
		packetCaptureInformer,
		mockOFClient,
		ifaceStore,
		nodeConfig,
	)
	pcController.sftpUploader = &testUploader{}

	return &fakePacketCaptureController{
		Controller:         pcController,
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

func TestErrPacketCaptureCRD(t *testing.T) {
	pc := &crdv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pc",
			UID:  "uid",
		},
		Spec: crdv1alpha1.PacketCaptureSpec{
			Source: crdv1alpha1.Source{
				Pod: &crdv1alpha1.PodReference{
					Namespace: pod1.Namespace,
					Name:      pod1.Name,
				},
			},
			Destination: crdv1alpha1.Destination{
				Pod: &crdv1alpha1.PodReference{
					Namespace: pod2.Namespace,
					Name:      pod2.Name,
				},
			},
		},
		Status: crdv1alpha1.PacketCaptureStatus{
			Phase: crdv1alpha1.PacketCaptureRunning,
		},
	}
	expectedPC := pc
	reason := "failed"
	expectedPC.Status.Phase = crdv1alpha1.PacketCaptureFailed
	expectedPC.Status.Reason = reason

	pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc}, nil)

	err := pcc.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, reason, 0)
	require.NoError(t, err)
}

func TestPreparePacket(t *testing.T) {
	pcs := []struct {
		name           string
		pc             *crdv1alpha1.PacketCapture
		intf           *interfacestore.InterfaceConfig
		receiverOnly   bool
		expectedPacket *binding.Packet
		expectedErr    string
	}{
		{
			name: "empty destination",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc2", UID: "uid2"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
				},
			},
			expectedErr: "destination is not specified",
		},
		{
			name: "ipv4 tcp packet",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc3", UID: "uid3"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "TCP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								SrcPort: &port80,
								DstPort: &port81,
								Flags:   &testTCPFlags,
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
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc4", UID: "uid4"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						IP: &ipv4,
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Packet: &crdv1alpha1.Packet{
						IPFamily: v1.IPv4Protocol,
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "ICMP"},
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
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc4", UID: "uid4"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					Packet: &crdv1alpha1.Packet{
						IPFamily: v1.IPv6Protocol,
						Protocol: &icmp6Proto,
					},
				},
			},
			expectedErr: "destination Pod does not have an IPv6 address",
		},
		{
			name: "pod to ipv6 packet capture",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc5", UID: "uid5"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						IP: &ipv6,
					},
					Packet: &crdv1alpha1.Packet{
						IPFamily: v1.IPv6Protocol,
						Protocol: &icmp6Proto,
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
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc6", UID: "uid6"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "TCP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								SrcPort: &port80,
								DstPort: &port81,
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
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc7", UID: "uid7"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "UDP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							UDP: &crdv1alpha1.UDPHeader{
								SrcPort: &port80,
								DstPort: &port81,
							},
						},
					},
				},
			},
			expectedPacket: &binding.Packet{
				DestinationIP:   net.ParseIP(pod2IPv4),
				IPProto:         protocol.Type_UDP,
				SourcePort:      80,
				DestinationPort: 81,
			},
		},
		{
			name: "icmp packet",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc8", UID: "uid8"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "ICMP"},
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
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc11", UID: "uid11"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Name:      "unknown pod",
							Namespace: "default",
						},
					},
				},
			},
			expectedErr: "failed to get the destination pod default/unknown pod: pods \"unknown pod\"",
		},
		{
			name: "to service packet",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc12", UID: "uid12"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Service: &crdv1alpha1.ServiceReference{
							Name:      service1.Name,
							Namespace: service1.Namespace,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "TCP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								SrcPort: &port80,
								DstPort: &port81,
								Flags:   &testTCPFlags,
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
	for _, pc := range pcs {
		t.Run(pc.name, func(t *testing.T) {
			pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc}, nil)
			podInterfaces := pcc.interfaceStore.GetContainerInterfacesByPod(pod1.Name, pod1.Namespace)
			if pc.intf != nil {
				podInterfaces[0] = pc.intf
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			pcc.crdInformerFactory.Start(stopCh)
			pcc.crdInformerFactory.WaitForCacheSync(stopCh)
			pcc.informerFactory.Start(stopCh)
			pcc.informerFactory.WaitForCacheSync(stopCh)

			pkt, err := pcc.preparePacket(pc.pc, podInterfaces[0], pc.receiverOnly)
			if pc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, pc.expectedPacket, pkt)
			} else {
				assert.ErrorContains(t, err, pc.expectedErr)
				assert.Nil(t, pkt)
			}
		})
	}
}

func TestSyncPacketCapture(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/antrea/packetcapture/packets", 0755)
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
		pc            *crdv1alpha1.PacketCapture
		existingState *packetCaptureState
		newState      *packetCaptureState
		expectedCalls func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name: "start packetcapture",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
				},
			},
			existingState: &packetCaptureState{
				name: "pc1",
				tag:  1,
			},
			newState: &packetCaptureState{
				name: "pc1",
				tag:  1,
			},
		},

		{
			name: "packetcapture in failed phase",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: types.UID(testUID)},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
				},
				Status: crdv1alpha1.PacketCaptureStatus{
					Phase: crdv1alpha1.PacketCaptureFailed,
				},
			},
			existingState: &packetCaptureState{
				name:         "pc1",
				pcapngFile:   file,
				pcapngWriter: testWriter,
				tag:          1,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallPacketCaptureFlows(uint8(1))
			},
		},
	}

	for _, pc := range pcs {
		t.Run(pc.name, func(t *testing.T) {
			pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc}, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			pcc.crdInformerFactory.Start(stopCh)
			pcc.crdInformerFactory.WaitForCacheSync(stopCh)

			if pc.existingState != nil {
				pcc.runningPacketCaptures[pc.existingState.tag] = pc.existingState
			}

			if pc.expectedCalls != nil {
				pc.expectedCalls(pcc.mockOFClient)
			}

			err := pcc.syncPacketCapture(pc.pc.Name)
			require.NoError(t, err)
			assert.Equal(t, pc.newState, pcc.runningPacketCaptures[pc.existingState.tag])
		})
	}
}

// TestPacketCaptureControllerRun was used to validate the whole run process is working. It doesn't wait for
// the testing pc to finish.
func TestPacketCaptureControllerRun(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/antrea/packetcapture/packets", 0755)
	pc := struct {
		name     string
		pc       *crdv1alpha1.PacketCapture
		newState *packetCaptureState
	}{
		name: "start packetcapture",
		pc: &crdv1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
			Spec: crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Pod: &crdv1alpha1.PodReference{
						Namespace: pod1.Namespace,
						Name:      pod1.Name,
					},
				},
				Destination: crdv1alpha1.Destination{
					Pod: &crdv1alpha1.PodReference{
						Namespace: pod2.Namespace,
						Name:      pod2.Name,
					},
				},
				CaptureConfig: crdv1alpha1.CaptureConfig{
					FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
				},
				Packet: &crdv1alpha1.Packet{
					Protocol: &icmpProto,
				},
			},
		},
		newState: &packetCaptureState{tag: 1},
	}

	pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)
	pcc.mockOFClient.EXPECT().InstallPacketCaptureFlows(pc.newState.tag, false,
		&binding.Packet{DestinationIP: net.ParseIP(pod2.Status.PodIP), IPProto: protocol.Type_ICMP},
		nil, ofPortPod1, crdv1alpha1.DefaultPacketCaptureTimeout)
	go pcc.Run(stopCh)
	time.Sleep(300 * time.Millisecond)
}

func TestProcessPacketCaptureItem(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/antrea/packetcapture/packets", 0755)
	pc := struct {
		pc           *crdv1alpha1.PacketCapture
		ofPort       uint32
		receiverOnly bool
		packet       *binding.Packet
		expected     bool
	}{
		pc: &crdv1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
			Spec: crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Pod: &crdv1alpha1.PodReference{
						Namespace: pod1.Namespace,
						Name:      pod1.Name,
					},
				},
				Destination: crdv1alpha1.Destination{
					Pod: &crdv1alpha1.PodReference{
						Namespace: pod2.Namespace,
						Name:      pod2.Name,
					},
				},
				CaptureConfig: crdv1alpha1.CaptureConfig{
					FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
				},
				Packet: &crdv1alpha1.Packet{
					Protocol: &icmpProto,
				},
			},
		},
		ofPort: ofPortPod1,
		packet: &binding.Packet{
			DestinationIP: net.ParseIP(pod2IPv4),
			IPProto:       1,
		},
		expected: true,
	}

	pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)

	pcc.mockOFClient.EXPECT().InstallPacketCaptureFlows(uint8(1), pc.receiverOnly, pc.packet, nil, pc.ofPort, crdv1alpha1.DefaultPacketCaptureTimeout)
	pcc.enqueuePacketCapture(pc.pc)
	got := pcc.processPacketCaptureItem()
	assert.Equal(t, pc.expected, got)
}

func TestStartPacketCapture(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll(packetDirectory, 0755)
	tcs := []struct {
		name           string
		pc             *crdv1alpha1.PacketCapture
		state          *packetCaptureState
		ofPort         uint32
		receiverOnly   bool
		packet         *binding.Packet
		expectedCalls  func(mockOFClient *openflowtest.MockClient)
		nodeConfig     *config.NodeConfig
		expectedErr    string
		expectedErrLog string
	}{
		{
			name: "Pod-to-Pod PacketCapture",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
				},

				Status: crdv1alpha1.PacketCaptureStatus{
					Phase: crdv1alpha1.PacketCaptureRunning,
				},
			},
			state:  &packetCaptureState{tag: 1},
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
				mockOFClient.EXPECT().InstallPacketCaptureFlows(uint8(1), false,
					&binding.Packet{
						DestinationIP: net.ParseIP(pod2IPv4),
						IPProto:       1,
					},
					nil, ofPortPod1, crdv1alpha1.DefaultPacketCaptureTimeout)
			},
		},
		{
			name: "Pod-to-IPv4 packetcapture",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid2"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						IP: &dstIPv4,
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
				},
				Status: crdv1alpha1.PacketCaptureStatus{
					Phase: crdv1alpha1.PacketCaptureRunning,
				},
			},
			state:  &packetCaptureState{tag: 2},
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
				mockOFClient.EXPECT().InstallPacketCaptureFlows(uint8(2), false, &binding.Packet{
					DestinationIP: net.ParseIP(dstIPv4),
					IPProto:       1,
				}, nil, ofPortPod1, crdv1alpha1.DefaultPacketCaptureTimeout)
			},
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tfc := newFakePacketCaptureController(t, nil, []runtime.Object{tt.pc}, tt.nodeConfig)
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

			err := tfc.startPacketCapture(tt.pc, tt.state)
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
	pcs := []struct {
		name            string
		pc              *crdv1alpha1.PacketCapture
		expectedPackets []binding.Packet
		objs            []runtime.Object
		expectedErr     string
	}{
		{
			name:        "svc-not-exist",
			expectedErr: "service \"svc1\" not found",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid2"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Service: &crdv1alpha1.ServiceReference{
							Name:      "svc1",
							Namespace: pod1.Namespace,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "TCP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: &port80,
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
								Type:   intstr.Int,
								IntVal: 8080,
							},
						},
					},
				},
			}},
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc2", UID: "uid2"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Service: &crdv1alpha1.ServiceReference{
							Namespace: pod1.Namespace,
							Name:      "svc1",
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "TCP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: &port80,
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
								Type:   intstr.Int,
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
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod1.Namespace,
							Name:      pod1.Name,
						},
					},
					Destination: crdv1alpha1.Destination{
						Service: &crdv1alpha1.ServiceReference{
							Name:      "svc1",
							Namespace: pod1.Namespace,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &intstr.IntOrString{Type: intstr.String, StrVal: "TCP"},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: &port80,
							},
						},
					},
				},
			},
		},
	}

	for _, pc := range pcs {
		t.Run(pc.name, func(t *testing.T) {
			pcc := newFakePacketCaptureController(t, pc.objs, []runtime.Object{pc.pc}, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			pcc.crdInformerFactory.Start(stopCh)
			pcc.crdInformerFactory.WaitForCacheSync(stopCh)
			pcc.informerFactory.Start(stopCh)
			pcc.informerFactory.WaitForCacheSync(stopCh)

			pkts, err := pcc.genEndpointMatchPackets(pc.pc)
			if pc.expectedErr == "" {
				require.NoError(t, err)
				if !reflect.DeepEqual(pc.expectedPackets, pkts) {
					t.Errorf("expected packets: %+v, got: %+v", pc.expectedPackets, pkts)
				}

			} else {
				assert.ErrorContains(t, err, pc.expectedErr)
				assert.Nil(t, pkts)
			}
		})
	}
}
