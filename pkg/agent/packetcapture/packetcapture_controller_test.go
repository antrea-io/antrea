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
	"fmt"
	"io"
	"net"
	"slices"
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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/k8s"
	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

var (
	pod1IPv4 = "192.168.10.10"
	pod2IPv4 = "192.168.11.10"
	pod3IPv4 = "192.168.12.10"

	ipv6                     = "2001:db8::68"
	pod1MAC, _               = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _               = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1               = uint32(1)
	ofPortPod2               = uint32(2)
	testCaptureTimeout       = int32(1)
	testCaptureNum     int32 = 15

	icmpProto    = intstr.FromString("ICMP")
	invalidProto = intstr.FromString("INVALID")
	testFTPUrl   = "sftp://127.0.0.1:22/path"

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
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: pod3IPv4,
				},
			},
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
				URL: testFTPUrl,
			},
			Timeout: &testCaptureTimeout,
		},
	}
	return result
}

type testUploader struct {
	url      string
	fileName string
	hostKey  ssh.PublicKey
}

func (uploader *testUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile io.Reader) error {
	if url != uploader.url {
		return fmt.Errorf("expected url: %s for uploader, got: %s", uploader.url, url)
	}
	if uploader.fileName != "" && fileName != uploader.fileName {
		return fmt.Errorf("expected filename: %s, got: %s ", uploader.fileName, fileName)
	}
	if uploader.hostKey != nil {
		if config.HostKeyAlgorithms != nil && !slices.Equal(config.HostKeyAlgorithms, []string{uploader.hostKey.Type()}) {
			return fmt.Errorf("unsupported host key algorithm")
		}
		if err := config.HostKeyCallback("", nil, uploader.hostKey); err != nil {
			return fmt.Errorf("invalid host key: %w", err)
		}
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

func (p *testCapture) Capture(ctx context.Context, device string, snapLen int, srcIP, dstIP net.IP, packet *crdv1alpha1.Packet, bidirection bool) (chan gopacket.Packet, error) {
	ch := make(chan gopacket.Packet, testCaptureNum)
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
	objs := append(runtimeObjects, &pod1, &pod2, &pod3, &secret1)
	kubeClient := fake.NewSimpleClientset(objs...)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	packetCaptureInformer := crdInformerFactory.Crd().V1alpha1().PacketCaptures()
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, []string{pod1IPv4, ipv6}, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, []string{pod2IPv4}, pod2MAC.String(), int32(ofPortPod2))

	// NewPacketCaptureController dont work on windows
	pcController, err := NewPacketCaptureController(kubeClient, crdClient, packetCaptureInformer, ifaceStore)
	if err != nil {
		pcController = &Controller{
			kubeClient:            kubeClient,
			crdClient:             crdClient,
			packetCaptureInformer: packetCaptureInformer,
			packetCaptureLister:   packetCaptureInformer.Lister(),
			packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
			interfaceStore:        ifaceStore,
			captures:              make(map[string]*packetCaptureState),
		}
		packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
			AddFunc:    pcController.addPacketCapture,
			UpdateFunc: pcController.updatePacketCapture,
			DeleteFunc: pcController.deletePacketCapture,
		}, resyncPeriod)
	}

	pcController.sftpUploader = &testUploader{}
	pcController.captureInterface = &testCapture{}
	pcController.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond*50, time.Millisecond*200),
		workqueue.TypedRateLimitingQueueConfig[string]{Name: "packetcapture"},
	)

	t.Setenv("POD_NAME", "antrea-agent")
	t.Setenv("POD_NAMESPACE", "kube-system")
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

func TestMultiplePacketCaptures(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defer func() {
		defaultFS = afero.NewOsFs()
	}()
	nameFunc := func(id int) string {
		return fmt.Sprintf("pc-%d", id)
	}
	var objs []runtime.Object
	for i := 0; i < 20; i++ {
		objs = append(objs, genTestCR(nameFunc(i), testCaptureNum))
	}
	pcc := newFakePacketCaptureController(t, nil, objs)
	pcc.sftpUploader = &testUploader{url: testFTPUrl}
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)
	go pcc.Run(stopCh)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		list, _ := pcc.crdClient.CrdV1alpha1().PacketCaptures().List(context.Background(), metav1.ListOptions{})
		for _, item := range list.Items {
			var startedStatus, completeStatus, uploadStatus metav1.ConditionStatus
			for _, cond := range item.Status.Conditions {
				if cond.Type == crdv1alpha1.PacketCaptureStarted {
					startedStatus = cond.Status
				}
				if cond.Type == crdv1alpha1.PacketCaptureComplete {
					completeStatus = cond.Status
				}
				if cond.Type == crdv1alpha1.PacketCaptureFileUploaded {
					uploadStatus = cond.Status
				}
			}
			assert.Equal(c, metav1.ConditionTrue, startedStatus)
			assert.Equal(c, metav1.ConditionTrue, completeStatus)
			assert.Equal(c, metav1.ConditionTrue, uploadStatus)
		}
		pcc.mutex.Lock()
		defer pcc.mutex.Unlock()
		assert.Equal(c, 0, pcc.numRunningCaptures)
		assert.Equal(c, 20, len(pcc.captures))
	}, 5*time.Second, 50*time.Millisecond)

	for i := 0; i < 20; i++ {
		err := pcc.crdClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), nameFunc(i), metav1.DeleteOptions{})
		require.NoError(t, err)
	}
	assert.Eventually(t, func() bool {
		pcc.mutex.Lock()
		defer pcc.mutex.Unlock()
		return len(pcc.captures) == 0
	}, 2*time.Second, 20*time.Millisecond)

}

// TestPacketCaptureControllerRun was used to validate the whole run process is working.
func TestPacketCaptureControllerRun(t *testing.T) {
	pcs := []struct {
		name                 string
		pc                   *crdv1alpha1.PacketCapture
		expectStartedStatus  metav1.ConditionStatus
		expectCompleteStatus metav1.ConditionStatus
		expectUploadStatus   metav1.ConditionStatus
	}{
		{
			name:                 "pod-to-pod with file server",
			expectStartedStatus:  metav1.ConditionTrue,
			expectCompleteStatus: metav1.ConditionTrue,
			expectUploadStatus:   metav1.ConditionTrue,
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
							Number: 15,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &icmpProto,
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: "sftp://127.0.0.1:22/aaa",
					},
					Timeout: &testCaptureTimeout,
				},
			},
		},
		{
			name:                 "pod-to-pod without file server",
			expectStartedStatus:  metav1.ConditionTrue,
			expectCompleteStatus: metav1.ConditionTrue,
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
							Namespace: pod3.Namespace,
							Name:      pod3.Name,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 15,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &icmpProto,
					},
					Timeout: &testCaptureTimeout,
				},
			},
		},
		{
			name:                "invalid proto",
			expectStartedStatus: metav1.ConditionFalse,
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
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 15,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &invalidProto,
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: "sftp://127.0.0.1:22/aaa",
					},
					Timeout: &testCaptureTimeout,
				},
			},
		},
		{
			name:                 "upload failed",
			expectStartedStatus:  metav1.ConditionTrue,
			expectCompleteStatus: metav1.ConditionTrue,
			expectUploadStatus:   metav1.ConditionFalse,
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
						Pod: &crdv1alpha1.PodReference{
							Namespace: pod2.Namespace,
							Name:      pod2.Name,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 15,
						},
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &icmpProto,
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: "sftp://127.0.0.1:22/aaa-invalid",
					},
					Timeout: &testCaptureTimeout,
				},
			},
		},
	}

	objs := []runtime.Object{}
	for _, pc := range pcs {
		objs = append(objs, pc.pc)
	}
	pcc := newFakePacketCaptureController(t, nil, objs)
	pcc.sftpUploader = &testUploader{url: "sftp://127.0.0.1:22/aaa"}
	stopCh := make(chan struct{})
	defer close(stopCh)
	defer defaultFS.Remove(packetDirectory)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)
	go pcc.Run(stopCh)
	for _, item := range pcs {
		t.Run(item.name, func(t *testing.T) {
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := pcc.crdClient.CrdV1alpha1().PacketCaptures().Get(context.Background(), item.pc.Name, metav1.GetOptions{})
				require.NoError(c, err)
				var startedStatus, completeStatus, uploadStatus metav1.ConditionStatus
				for _, cond := range result.Status.Conditions {
					if cond.Type == crdv1alpha1.PacketCaptureStarted {
						startedStatus = cond.Status
					}
					if cond.Type == crdv1alpha1.PacketCaptureComplete {
						completeStatus = cond.Status
					}
					if cond.Type == crdv1alpha1.PacketCaptureFileUploaded {
						uploadStatus = cond.Status
					}
				}
				assert.Equal(c, item.expectStartedStatus, startedStatus)
				assert.Equal(c, item.expectUploadStatus, uploadStatus)
				assert.Equal(c, item.expectCompleteStatus, completeStatus)
				assert.Equal(c, item.expectUploadStatus, uploadStatus)
				if item.expectCompleteStatus == metav1.ConditionTrue {
					assert.Equal(c, testCaptureNum, result.Status.NumberCaptured)
				}
			}, 2*time.Second, 20*time.Millisecond)
		})
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
					Type:               crdv1alpha1.PacketCaptureComplete,
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
			old: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureComplete,
					LastTransitionTime: metav1.Now(),
				},
			},
			expected: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureComplete,
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
					Type:               crdv1alpha1.PacketCaptureComplete,
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
					Type:               crdv1alpha1.PacketCaptureComplete,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionFalse,
				},
			},
			expected: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureComplete,
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

func TestUploadPackets(t *testing.T) {
	ctx := context.Background()

	generateHostKey := func(t *testing.T) ssh.PublicKey {
		publicKey, _, err := sftptesting.GenerateEd25519Key()
		require.NoError(t, err)
		return publicKey
	}
	hostKey1 := generateHostKey(t)
	hostKey2 := generateHostKey(t)

	fs := afero.NewMemMapFs()

	testCases := []struct {
		name            string
		serverHostKey   ssh.PublicKey
		expectedHostKey []byte
		expectedErr     string
	}{
		{
			name:            "matching key",
			serverHostKey:   hostKey1,
			expectedHostKey: hostKey1.Marshal(),
		},
		{
			name:            "non matching key",
			serverHostKey:   hostKey2,
			expectedHostKey: hostKey1.Marshal(),
			expectedErr:     "host key mismatch",
		},
		{
			name:            "ignore host key",
			serverHostKey:   hostKey1,
			expectedHostKey: nil,
		},
		{
			name:            "invalid key format",
			serverHostKey:   hostKey1,
			expectedHostKey: []byte("abc"),
			expectedErr:     "invalid host public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pc := genTestCR("foo", testCaptureNum)
			pcc := newFakePacketCaptureController(t, nil, nil)
			pcc.sftpUploader = &testUploader{
				url:      testFTPUrl,
				fileName: pcc.generatePacketsPathForServer(pc.Name),
				hostKey:  tc.serverHostKey,
			}
			pc.Spec.FileServer.HostPublicKey = tc.expectedHostKey
			f, err := afero.TempFile(fs, "", "upload-test")
			require.NoError(t, err)
			defer f.Close()
			err = pcc.uploadPackets(ctx, pc, f)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expectedErr)
			}
		})
	}
}
