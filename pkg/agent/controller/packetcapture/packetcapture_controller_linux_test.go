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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
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
	pod1MAC, _         = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _         = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1         = uint32(1)
	ofPortPod2         = uint32(2)
	testTCPFlags       = "tcp[13] & 16 != 0"
	icmp6Proto         = intstr.FromInt32(58)
	icmpProto          = intstr.FromString("ICMP")
	tcpProto           = intstr.FromString("TCP")
	udpProto           = intstr.FromInt32(17)
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

func generateTestSecret() *v1.Secret {
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "AAA",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("AAA"),
			"password": []byte("BBBCCC"),
		},
	}
}

type testUploader struct {
	url      string
	fileName string
}

func (uploader *testUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile afero.File) error {
	if url != uploader.url {
		return fmt.Errorf("expected url: %s for uploader, got: %s", uploader.url, url)
	}
	if fileName != uploader.fileName {
		return fmt.Errorf("expected filename: %s for uploader, got: %s", uploader.fileName, fileName)
	}
	return nil
}

type fakePacketCaptureController struct {
	*Controller
	kubeClient         kubernetes.Interface
	mockController     *gomock.Controller
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	informerFactory    informers.SharedInformerFactory
}

func newFakePacketCaptureController(t *testing.T, runtimeObjects []runtime.Object, initObjects []runtime.Object) *fakePacketCaptureController {
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
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	packetCaptureInformer := crdInformerFactory.Crd().V1alpha1().PacketCaptures()
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, []string{pod1IPv4, ipv6}, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, []string{pod2IPv4}, pod2MAC.String(), int32(ofPortPod2))

	pcController := NewPacketCaptureController(
		kubeClient,
		crdClient,
		packetCaptureInformer,
		ifaceStore,
		&config.NodeConfig{Name: "test-node"},
	)
	pcController.sftpUploader = &testUploader{}

	return &fakePacketCaptureController{
		Controller:         pcController,
		kubeClient:         kubeClient,
		mockController:     controller,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		informerFactory:    informerFactory,
	}
}

func addPodInterface(ifaceStore interfacestore.InterfaceStore, podNamespace, podName string, podIPs []string, podMac string, ofPort int32) {
	containerName := k8s.NamespacedName(podNamespace, podName)
	var ifIPs []net.IP
	for _, ip := range podIPs {
		ifIPs = append(ifIPs, net.ParseIP(ip))
	}
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
			CaptureConfig: crdv1alpha1.CaptureConfig{
				FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
					Number: 12,
				},
			},
			Packet: &crdv1alpha1.Packet{
				IPFamily: v1.IPv4Protocol,
				Protocol: &icmpProto,
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

	pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc})
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)

	err := pcc.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, reason, 0)
	require.NoError(t, err)
}

func TestCreateMatchPacket(t *testing.T) {
	pcs := []struct {
		name           string
		pc             *crdv1alpha1.PacketCapture
		intf           *interfacestore.InterfaceConfig
		receiverOnly   bool
		expectedPacket *binding.Packet
		expectedErr    string
	}{
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
				SourceIP:        net.ParseIP(pod1IPv4),
				DestinationIP:   net.ParseIP(pod2IPv4),
				SourcePort:      80,
				DestinationPort: 81,
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
				SourceIP:      net.ParseIP("192.168.12.4"),
				DestinationIP: net.ParseIP(pod1IPv4),
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
			expectedErr: "cannot find IP with IPv6 AddressFamily for Pod default/pod-2",
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
				SourceIP:      net.ParseIP(ipv6),
				DestinationIP: net.ParseIP("2001:db8::68"),
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
				SourceIP:        net.ParseIP(pod1IPv4),
				DestinationIP:   net.ParseIP(pod2IPv4),
				SourcePort:      80,
				DestinationPort: 81,
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
			expectedErr: "failed to get Pod default/unknown pod: pods \"unknown pod\" not found",
		},
	}
	for _, pc := range pcs {
		t.Run(pc.name, func(t *testing.T) {
			pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc})
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

			pkt, err := pcc.createMatchPacket(pc.pc)
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

func TestGenBPFFilterString(t *testing.T) {
	tt := []struct {
		name        string
		packetSpec  *crdv1alpha1.Packet
		matchPacket *binding.Packet
		expected    string
	}{
		{
			name: "tcp all args",
			packetSpec: &crdv1alpha1.Packet{
				IPFamily: v1.IPv4Protocol,
				Protocol: &tcpProto,
				TransportHeader: crdv1alpha1.TransportHeader{
					TCP: &crdv1alpha1.TCPHeader{
						Flags: &testTCPFlags,
					},
				},
			},
			matchPacket: &binding.Packet{
				SourceIP:        net.ParseIP("192.168.0.1"),
				DestinationIP:   net.ParseIP("192.168.0.2"),
				SourcePort:      80,
				DestinationPort: 81,
			},
			expected: "tcp and src host 192.168.0.1 and dst host 192.168.0.2 and src port 80 and dst port 81 and tcp[13] & 16 != 0",
		},
		{
			name: "udp no port and numeric protocol",
			packetSpec: &crdv1alpha1.Packet{
				IPFamily: v1.IPv4Protocol,
				Protocol: &udpProto,
			},
			matchPacket: &binding.Packet{
				SourceIP:      net.ParseIP("192.168.0.1"),
				DestinationIP: net.ParseIP("192.168.0.2"),
			},
			expected: "udp and src host 192.168.0.1 and dst host 192.168.0.2",
		},
		{name: "icmp with src and dest",
			packetSpec: &crdv1alpha1.Packet{
				IPFamily: v1.IPv4Protocol,
				Protocol: &icmpProto,
			},
			matchPacket: &binding.Packet{
				SourceIP:      net.ParseIP("192.168.0.1"),
				DestinationIP: net.ParseIP("192.168.0.2"),
			},
			expected: "icmp src host 192.168.0.1 and dst host 192.168.0.2",
		},
	}
	for _, pt := range tt {
		t.Run(pt.name, func(t *testing.T) {
			result := genBPFFilterStr(pt.matchPacket, pt.packetSpec)
			assert.Equal(t, pt.expected, result)
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
		newState: &packetCaptureState{},
	}

	pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc})
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)
	go pcc.Run(stopCh)
	time.Sleep(300 * time.Millisecond)
}
