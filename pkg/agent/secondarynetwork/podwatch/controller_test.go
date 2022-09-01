// Copyright 2022 Antrea Authors
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

package podwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclientfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	ipamtesting "antrea.io/antrea/pkg/agent/secondarynetwork/ipam/testing"
	podwatchtesting "antrea.io/antrea/pkg/agent/secondarynetwork/podwatch/testing"
)

const (
	testNamespace = "nsA"
	testNode      = "test-node"

	// the ipam information is not actually used when testing, given that we
	// use a mock IPAMDelegator. But this is what the ipam information would
	// look like when using the actual IPAMDelegator implementation, which
	// invokes the whereabouts plugin.
	netAttachConfig = `{
    "cniVersion": "0.3.0",
    "type": "antrea",
    "networkType": "sriov",
    "ipam": {
        "type": "whereabouts",
        "datastore": "kubernetes",
        "kubernetes": {
            "kubeconfig": "/host/etc/cni/net.d/whereabouts.d/whereabouts.kubeconfig"
        },
        "range": "148.14.24.0/24"
    }
}`

	defaultMTU    = 1500
	sriovDeviceID = "sriov-device-id"

	podName       = "pod1"
	containerID   = "container1"
	podIP         = "1.2.3.4"
	networkName   = "net"
	interfaceName = "eth2"
)

func testNetwork(name string) *netdefv1.NetworkAttachmentDefinition {
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: netAttachConfig,
		},
	}
}

func containerNetNs(container string) string {
	return fmt.Sprintf("/var/run/netns/%s", container)
}

func testPod(name string, container string, podIP string, networks ...netdefv1.NetworkSelectionElement) (*corev1.Pod, *cnipodcache.CNIConfigInfo) {
	annotations := make(map[string]string)
	if len(networks) > 0 {
		annotation, _ := json.Marshal(networks)
		annotations[networkAttachDefAnnotationKey] = string(annotation)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   testNamespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: container,
			}},
			NodeName: testNode,
		},
	}
	if podIP != "" {
		pod.Status = corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: podIP,
			PodIPs: []corev1.PodIP{
				{IP: podIP},
			},
		}
	}
	cniConfig := &cnipodcache.CNIConfigInfo{
		PodName:        name,
		PodNameSpace:   testNamespace,
		ContainerID:    container,
		ContainerNetNS: containerNetNs(container),
		MTU:            defaultMTU,
		PodCNIDeleted:  false,
	}
	return pod, cniConfig
}

func testIPAMResult(cidr string) *current.Result {
	_, ipNet, _ := net.ParseCIDR(cidr)
	return &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: *ipNet,
			},
		},
	}
}

func init() {
	getPodContainerDeviceIDs = func(name string, namespace string) ([]string, error) {
		return []string{sriovDeviceID}, nil
	}
}

func TestPodControllerRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := fake.NewSimpleClientset()
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	podCache := cnipodcache.NewCNIPodInfoStore()
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := ipamtesting.NewMockIPAMDelegator(ctrl)
	ipamDelegator = mockIPAM
	podController := NewPodController(
		client,
		netdefclient,
		informerFactory.Core().V1().Pods().Informer(),
		testNode,
		podCache,
		interfaceConfigurator,
	)

	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		podController.Run(stopCh)
	}()

	pod, cniConfig := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	network := testNetwork(networkName)

	ipamResult := testIPAMResult("148.14.24.100/24")

	var interfaceConfigured int32
	interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
		podName,
		testNamespace,
		containerID,
		containerNetNs(containerID),
		interfaceName,
		defaultMTU,
		sriovDeviceID,
		ipamResult, // just check for pointer equality
	).Do(func(string, string, string, string, string, int, string, *current.Result) {
		atomic.AddInt32(&interfaceConfigured, 1)
	})
	mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(ipamResult, nil)

	podCache.AddCNIConfigInfo(cniConfig)
	// the NetworkAttachmentDefinition must be created before the Pod: if handleAddUpdatePod
	// runs before the NetworkAttachmentDefinition has been created, it will return an
	// error. The Pod will then be requeued, but the Poll below will timeout before the Pod has
	// a chance to be processed again. Rather than increase the timeout or change the queue's
	// minRetryDelay for tests, we ensure that the NetworkAttachmentDefinition exists by the
	// time handleAddUpdatePod runs.
	_, err := netdefclient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
	require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
	_, err = client.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
	require.NoError(t, err, "error when creating test Pod")

	// unfortunately, we cannot use the podcache being updated by the controller as a signal
	// here: the podcache is not thread-safe and is only meant to be accessed by the controller
	// event handlers (with the exception of the operations meant to be performed by the CNI server).
	assert.NoError(t, wait.Poll(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		return atomic.LoadInt32(&interfaceConfigured) > 0, nil
	}))

	mockIPAM.EXPECT().DelIPAMSubnetAddress(gomock.Any(), gomock.Any())

	require.NotNil(t, podCache.GetCNIConfigInfoByContainerID(podName, testNamespace, containerID) == nil)
	require.NoError(t, client.CoreV1().Pods(testNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{}), "error when deleting test Pod")
	assert.NoError(t, wait.Poll(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		return podCache.GetCNIConfigInfoByContainerID(podName, testNamespace, containerID) == nil, nil
	}))

	close(stopCh)
	wg.Wait()
}

func TestPodControllerAddPod(t *testing.T) {
	newPodController := func(ctrl *gomock.Controller) (*PodController, *ipamtesting.MockIPAMDelegator, *podwatchtesting.MockInterfaceConfigurator) {
		client := fake.NewSimpleClientset()
		netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
		informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
		podCache := cnipodcache.NewCNIPodInfoStore()
		interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
		mockIPAM := ipamtesting.NewMockIPAMDelegator(ctrl)
		ipamDelegator = mockIPAM
		// PodController object without event handlers
		return &PodController{
			kubeClient:            client,
			netAttachDefClient:    netdefclient,
			queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "podcontroller"),
			podInformer:           informerFactory.Core().V1().Pods().Informer(),
			nodeName:              testNode,
			podCache:              podCache,
			interfaceConfigurator: interfaceConfigurator,
		}, mockIPAM, interfaceConfigurator
	}

	pod, cniConfig := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})

	t.Run("missing network", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, _, _ := newPodController(ctrl)
		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		assert.Error(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("multiple network interfaces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, mockIPAM, interfaceConfigurator := newPodController(ctrl)

		pod, cniConfig := testPod(
			podName,
			containerID,
			podIP,
			netdefv1.NetworkSelectionElement{
				Name:             "net1",
				InterfaceRequest: "eth10",
			},
			netdefv1.NetworkSelectionElement{
				Name:             "net2",
				InterfaceRequest: "eth11",
			},
		)
		network1 := testNetwork("net1")
		network2 := testNetwork("net2")

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth10",
			defaultMTU,
			gomock.Any(),
			gomock.Any(),
		)
		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth11",
			defaultMTU,
			gomock.Any(),
			gomock.Any(),
		)

		mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
		mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.101/24"), nil)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network1, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network2, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("no network interfaces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, _, _ := newPodController(ctrl)

		pod, cniConfig := testPod(podName, containerID, podIP)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("missing podcache entry", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, _, _ := newPodController(ctrl)

		network := testNetwork(networkName)

		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("missing Status.PodIPs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, _, _ := newPodController(ctrl)

		pod, cniConfig := testPod(podName, containerID, "")
		network := testNetwork(networkName)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("different Namespace for Pod and NetworkAttachmentDefinition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, mockIPAM, interfaceConfigurator := newPodController(ctrl)

		networkNamespace := "nsB"
		network := &netdefv1.NetworkAttachmentDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: networkNamespace,
				Name:      networkName,
			},
			Spec: netdefv1.NetworkAttachmentDefinitionSpec{
				Config: netAttachConfig,
			},
		}

		pod, cniConfig := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
			Namespace:        networkNamespace,
			Name:             networkName,
			InterfaceRequest: interfaceName,
		})

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			interfaceName,
			defaultMTU,
			sriovDeviceID,
			gomock.Any(),
		)
		mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(networkNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("no interface name", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, mockIPAM, interfaceConfigurator := newPodController(ctrl)

		pod, cniConfig := testPod(
			podName,
			containerID,
			podIP,
			netdefv1.NetworkSelectionElement{
				Name:             networkName,
				InterfaceRequest: "",
			},
			netdefv1.NetworkSelectionElement{
				Name:             networkName,
				InterfaceRequest: "",
			},
		)
		network := testNetwork(networkName)

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth1",
			defaultMTU,
			gomock.Any(),
			gomock.Any(),
		)
		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth2",
			defaultMTU,
			gomock.Any(),
			gomock.Any(),
		)

		mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
		mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.101/24"), nil)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("error when creating interface", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, mockIPAM, interfaceConfigurator := newPodController(ctrl)

		network := testNetwork(networkName)

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			interfaceName,
			defaultMTU,
			gomock.Any(),
			gomock.Any(),
		).Return(fmt.Errorf("error when creating interface"))

		mockIPAM.EXPECT().GetIPAMSubnetAddress(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
		mockIPAM.EXPECT().DelIPAMSubnetAddress(gomock.Any(), gomock.Any())

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.Error(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("invalid networks annotation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		podController, _, _ := newPodController(ctrl)

		pod, cniConfig := testPod(podName, containerID, podIP)
		pod.Annotations = map[string]string{
			networkAttachDefAnnotationKey: "<invalid>",
		}
		network := testNetwork(networkName)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		// we don't expect an error here, no requeueing
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})
}
