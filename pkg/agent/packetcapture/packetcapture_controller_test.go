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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	pod1IPv4 = "192.168.10.10"
	pod2IPv4 = "192.168.11.10"

	ipv6       = "2001:db8::68"
	pod1MAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1 = uint32(1)
	ofPortPod2 = uint32(2)

	icmpProto    = intstr.FromString("ICMP")
	invalidProto = intstr.FromString("INVALID")

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
			Namespace: "kube-system",
		},
		Data: map[string][]byte{
			"username": []byte("username"),
			"password": []byte("password"),
		},
	}
)

func generateTestSecret() *v1.Secret {
	return &v1.Secret{
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

func genTestCR(name string, num int32) *crdv1alpha1.PacketCapture {
	result := &crdv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(fmt.Sprintf("uid-%s", name))},
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
					Number: num,
				},
			},
			Packet: &crdv1alpha1.Packet{
				Protocol: &icmpProto,
			},
			FileServer: &crdv1alpha1.PacketCaptureFileServer{
				URL: "sftp://127.0.0.1:22/aaa",
			},
		},
	}
	return result
}

type testUploader struct {
	url      string
	fileName string
}

func (uploader *testUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile io.Reader) error {
	if url != uploader.url {
		return fmt.Errorf("expected url: %s for uploader, got: %s", uploader.url, url)
	}
	if fileName != uploader.fileName {
		return fmt.Errorf("expected filename: %s for uploader, got: %s", uploader.fileName, fileName)
	}
	return nil
}

func craftTestPacket() gopacket.Packet {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	rawBytes := []byte{10, 20, 30}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		},
		&layers.IPv4{
			SrcIP: net.IP{127, 0, 0, 1},
			DstIP: net.IP{8, 8, 8, 8},
		},
		&layers.TCP{
			SrcPort: layers.TCPPort(4321),
			DstPort: layers.TCPPort(80),
		},
		gopacket.Payload(rawBytes),
	)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy)
}

type testCapture struct {
}

func (p *testCapture) Capture(ctx context.Context, device string, srcIP, dstIP net.IP, packet *crdv1alpha1.Packet) (chan gopacket.Packet, error) {
	ch := make(chan gopacket.Packet, 15)
	for i := 0; i < 15; i++ {
		ch <- craftTestPacket()
	}
	return ch, nil
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
	objs := append(runtimeObjects, &pod1, &pod2, &pod3, &secret1, generateTestSecret())
	kubeClient := fake.NewSimpleClientset(objs...)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	packetCaptureInformer := crdInformerFactory.Crd().V1alpha1().PacketCaptures()
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, []string{pod1IPv4, ipv6}, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, []string{pod2IPv4}, pod2MAC.String(), int32(ofPortPod2))

	pcController, _ := NewPacketCaptureController(
		kubeClient,
		crdClient,
		packetCaptureInformer,
		ifaceStore,
	)
	pcController.sftpUploader = &testUploader{}
	pcController.captureInterface = &testCapture{}
	t.Setenv("POD_NAME", "antrea-agent")
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

// TestPacketCaptureControllerRun was used to validate the whole run process is working. It doesn't wait for
// the testing pc to finish. on sandbox env, no good solution to open raw socket.
func TestPacketCaptureControllerRun(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/antrea/packetcapture/packets", 0755)
	pcs := []struct {
		name                  string
		pc                    *crdv1alpha1.PacketCapture
		expectConditionStatus metav1.ConditionStatus
	}{
		{
			name:                  "start packetcapture",
			expectConditionStatus: metav1.ConditionTrue,
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
							Number: 10,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &icmpProto,
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: "sftp://127.0.0.1:22/aaa",
					},
				},
			},
		},
		{
			name:                  "invalid proto",
			expectConditionStatus: metav1.ConditionFalse,
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
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 10,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &invalidProto,
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: "sftp://127.0.0.1:22/aaa",
					},
				},
			},
		},
		{
			name:                  "timeout-case",
			expectConditionStatus: metav1.ConditionFalse,
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
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 100,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &icmpProto,
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: "sftp://127.0.0.1:22/aaa",
					},
				},
			},
		},
	}

	objs := []runtime.Object{}
	for _, pc := range pcs {
		objs = append(objs, pc.pc)
	}
	pcc := newFakePacketCaptureController(t, nil, objs)
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)
	for _, item := range pcs {
		t.Run(item.name, func(t *testing.T) {
			fileName := item.pc.Name + ".pcapng"
			pcc.sftpUploader = &testUploader{fileName: fileName, url: "sftp://127.0.0.1:22/aaa"}
		})

		go pcc.Run(stopCh)
		time.Sleep(500 * time.Millisecond)
		result, err := pcc.crdClient.CrdV1alpha1().PacketCaptures().Get(context.Background(), item.pc.Name, metav1.GetOptions{})
		assert.Nil(t, err)
		for _, cond := range result.Status.Conditions {
			if cond.Type == crdv1alpha1.PacketCaptureCompleted {
				assert.Equal(t, item.expectConditionStatus, cond.Status)
			}
			if cond.Type == crdv1alpha1.PacketCaptureFileUploaded {
				assert.Equal(t, item.expectConditionStatus, cond.Status)
			}
		}

		if item.expectConditionStatus == metav1.ConditionTrue {
			assert.Equal(t, int32(10), result.Status.NumberCaptured)
			assert.Equal(t, "sftp://127.0.0.1:22/aaa/pc1.pcapng", result.Status.FilePath)
		}

		// delete cr
		err = pcc.crdClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), item.pc.Name, metav1.DeleteOptions{})
		require.NoError(t, err)

		stopCh <- struct{}{}
	}

}

func TestMergeConditions(t *testing.T) {
	tt := []struct {
		name     string
		new      []crdv1alpha1.PacketCaptureCondition
		old      []crdv1alpha1.PacketCaptureCondition
		expected []crdv1alpha1.PacketCaptureCondition
	}{

		{
			name: "use-old",
			new: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
			old: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
				},
			},
			expected: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
		},
		{
			name: "use-new",
			new: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionTrue,
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
			old: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionFalse,
				},
			},
			expected: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionTrue,
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			result := mergeConditions(item.old, item.new)
			assert.True(t, conditionSliceEqualsIgnoreLastTransitionTime(item.expected, result))
		})
	}
}

func TestUpdatePacketCaptureStatus(t *testing.T) {
	tt := []struct {
		name           string
		state          *packetCaptureState
		expectedStatus *crdv1alpha1.PacketCaptureStatus
	}{
		{
			name: "upload-error",
			state: &packetCaptureState{
				capturedPacketsNum:       15,
				targetCapturedPacketsNum: 15,
				filePath:                 "/tmp/a.pcapng",
				err:                      errors.New("failed to upload"),
			},
			expectedStatus: &crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 15,
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureCompleted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
					{
						Type:    crdv1alpha1.PacketCaptureFileUploaded,
						Status:  metav1.ConditionStatus(v1.ConditionFalse),
						Reason:  "UploadFailed",
						Message: "failed to upload",
					},
				},
			},
		},
		{
			name: "running",
			state: &packetCaptureState{
				capturedPacketsNum:       1,
				targetCapturedPacketsNum: 15,
			},
			expectedStatus: &crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 1,
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureRunning,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
					},
				},
			},
		},
	}

	objs := []runtime.Object{}
	for _, item := range tt {
		objs = append(objs, genTestCR(item.name, item.state.targetCapturedPacketsNum))
	}

	pcc := newFakePacketCaptureController(t, nil, objs)
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			err := pcc.updateStatus(context.Background(), item.name, item.state)
			require.NoError(t, err)
			result, err := pcc.crdClient.CrdV1alpha1().PacketCaptures().Get(context.TODO(), item.name, metav1.GetOptions{})
			require.NoError(t, err)
			if !packetCaptureStatusEqual(*item.expectedStatus, result.Status) {
				t.Errorf("updated status don't match: %+v %+v", *item.expectedStatus, result.Status)
			}
		})
	}

}
