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

//go:build !windows
// +build !windows

package podwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	current "github.com/containernetworking/cni/pkg/types/100"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclientfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	podwatchtesting "antrea.io/antrea/pkg/agent/secondarynetwork/podwatch/testing"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

const (
	testNamespace = "nsA"
	testNode      = "test-node"

	// The IPAM information is not actually used when testing, given that we
	// use a mock IPAMAllocator. But this is what the IPAM information would
	// look like when using the actual Antrea IPAM implementation.
	netAttachTemplate = `{
    "cniVersion": "{{.CNIVersion}}",
    "type": "{{.CNIType}}",
    "networkType": "{{.NetworkType}}",
    "mtu": {{.MTU}},
    "vlan": {{.VLAN}},
    "ipam": {
        "type": "{{.IPAMType}}",
        "ippools": [ "ipv4-pool-1", "ipv6-pool-1" ]
    }
}`

	defaultCNIVersion = "0.3.0"
	defaultMTU        = 1500
	sriovDeviceID     = "sriov-device-id"
	podName           = "pod1"
	containerID       = "container1"
	podIP             = "1.2.3.4"
	networkName       = "net"
	interfaceName     = "eth2"
	ovsPortUUID       = "12345678-e29b-41d4-a716-446655440000"
)

func testNetwork(name string, networkType cnipodcache.NetworkType) *netdefv1.NetworkAttachmentDefinition {
	return testNetworkExt(name, "", "", string(networkType), "", 0, 0)
}

func testNetworkExt(name, cniVersion, cniType, networkType, ipamType string, mtu int, vlan int) *netdefv1.NetworkAttachmentDefinition {
	if cniVersion == "" {
		cniVersion = defaultCNIVersion
	}
	if cniType == "" {
		cniType = "antrea"
	}
	if ipamType == "" {
		ipamType = ipam.AntreaIPAMType
	}
	data := struct {
		CNIVersion  string
		CNIType     string
		NetworkType string
		IPAMType    string
		MTU         int
		VLAN        int
	}{cniVersion, cniType, networkType, ipamType, mtu, vlan}
	tmpl := template.Must(template.New("test").Parse(netAttachTemplate))
	var b bytes.Buffer
	tmpl.Execute(&b, &data)
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: b.String(),
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
		PodNamespace:   testNamespace,
		ContainerID:    container,
		ContainerNetNS: containerNetNs(container),
		PodCNIDeleted:  false,
	}
	return pod, cniConfig
}

func testIPAMResult(cidr string) *ipam.IPAMResult {
	_, ipNet, _ := net.ParseCIDR(cidr)
	return &ipam.IPAMResult{
		Result: current.Result{
			IPs: []*current.IPConfig{
				{
					Address: *ipNet,
				},
			},
		},
	}
}

func init() {
	getPodContainerDeviceIDsFn = func(name string, namespace string) ([]string, error) {
		return []string{sriovDeviceID}, nil
	}
}

func TestPodControllerRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := fake.NewSimpleClientset()
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	podCache := cnipodcache.NewCNIPodInfoStore()
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := podwatchtesting.NewMockIPAMAllocator(ctrl)
	podController, _ := NewPodController(
		client,
		netdefclient,
		informerFactory.Core().V1().Pods().Informer(),
		testNode,
		podCache,
		nil)
	podController.interfaceConfigurator = interfaceConfigurator
	podController.ipamAllocator = mockIPAM

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
	network := testNetwork(networkName, sriovNetworkType)

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
		&ipamResult.Result,
	).Do(func(string, string, string, string, string, int, string, *current.Result) {
		atomic.AddInt32(&interfaceConfigured, 1)
	})
	mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(ipamResult, nil)

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

	mockIPAM.EXPECT().SecondaryNetworkRelease(gomock.Any())

	require.NotNil(t, podCache.GetCNIConfigInfoByContainerID(podName, testNamespace, containerID) == nil)
	require.NoError(t, client.CoreV1().Pods(testNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{}), "error when deleting test Pod")
	assert.NoError(t, wait.Poll(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		return podCache.GetCNIConfigInfoByContainerID(podName, testNamespace, containerID) == nil, nil
	}))

	close(stopCh)
	wg.Wait()
}

func TestConfigurePodSecondaryNetwork(t *testing.T) {
	element1 := netdefv1.NetworkSelectionElement{
		Name:             networkName,
		Namespace:        testNamespace,
		InterfaceRequest: interfaceName,
	}
	podOwner := &crdv1a2.PodOwner{
		Name:        podName,
		Namespace:   testNamespace,
		ContainerID: containerID,
		IFName:      interfaceName,
	}

	ctrl := gomock.NewController(t)

	tests := []struct {
		name               string
		cniVersion         string
		cniType            string
		networkType        cnipodcache.NetworkType
		ipamType           string
		mtu                int
		vlan               int
		doNotCreateNetwork bool
		interfaceCreated   bool
		expectedErr        string
		expectedCalls      func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator)
	}{
		{
			name:             "VLAN network",
			networkType:      vlanNetworkType,
			mtu:              1600,
			vlan:             101,
			interfaceCreated: true,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1600,
					uint16(101),
					gomock.Any(),
				).Return(ovsPortUUID, nil)
			},
		},
		{
			name:             "default MTU",
			networkType:      vlanNetworkType,
			vlan:             0,
			interfaceCreated: true,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					uint16(0),
					gomock.Any(),
				).Return(ovsPortUUID, nil)
			},
		},
		{
			name:             "SRIOV network",
			networkType:      sriovNetworkType,
			mtu:              1500,
			interfaceCreated: true,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
				mockIC.EXPECT().ConfigureSriovSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					sriovDeviceID,
					gomock.Any(),
				).Return(nil)
			},
		},
		{
			name:               "network not found",
			networkType:        vlanNetworkType,
			mtu:                1500,
			vlan:               100,
			doNotCreateNetwork: true,
			expectedErr:        "failed to get NetworkAttachmentDefinition:",
		},
		{
			name:        "unsupported CNI version",
			cniVersion:  "0.5.0",
			networkType: vlanNetworkType,
			mtu:         1500,
			vlan:        100,
		},
		{
			name:        "non-Antrea network",
			cniType:     "non-antrea",
			networkType: vlanNetworkType,
			mtu:         1500,
			vlan:        100,
		},
		{
			name:        "unsupported network",
			networkType: "unsupported",
		},
		{
			name:        "non-Antrea IPAM",
			networkType: vlanNetworkType,
			ipamType:    "non-antrea",
		},
		{
			name:        "negative MTU",
			networkType: sriovNetworkType,
			mtu:         -1,
		},
		{
			name:        "invalid VLAN",
			networkType: vlanNetworkType,
			vlan:        4095,
		},
		{
			name:        "negative VLAN",
			networkType: vlanNetworkType,
			vlan:        -200,
		},
		{
			name:        "IPAM failure",
			networkType: sriovNetworkType,
			mtu:         1500,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), errors.New("failure"))
			},
			expectedErr: "secondary network IPAM failed",
		},
		{
			name:        "interface failure",
			networkType: vlanNetworkType,
			mtu:         1600,
			vlan:        101,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1600,
					uint16(101),
					gomock.Any(),
				).Return("", errors.New("interface creation failure"))
				mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner).Return(nil)
			},
			expectedErr: "interface creation failure",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod, cniConfigInfo := testPod(podName, containerID, podIP, element1)
			pc, mockIPAM, interfaceConfigurator := testPodController(ctrl)
			savedCNIConfig := *cniConfigInfo

			network1 := testNetworkExt(networkName, tc.cniVersion, tc.cniType, string(tc.networkType), tc.ipamType, tc.mtu, tc.vlan)
			if !tc.doNotCreateNetwork {
				pc.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network1, metav1.CreateOptions{})
			}
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockIPAM, interfaceConfigurator)
			}
			err := pc.configurePodSecondaryNetwork(pod, []*netdefv1.NetworkSelectionElement{&element1}, cniConfigInfo)
			if tc.expectedErr == "" {
				assert.Nil(t, err)
			} else {
				assert.True(t, strings.Contains(err.Error(), tc.expectedErr))
			}

			if tc.interfaceCreated {
				info := cnipodcache.InterfaceInfo{
					NetworkType: tc.networkType,
				}
				if tc.networkType == vlanNetworkType {
					info.OVSPortUUID = ovsPortUUID
				}
				savedCNIConfig.Interfaces = map[string]*cnipodcache.InterfaceInfo{interfaceName: &info}
			}
			assert.Equal(t, &savedCNIConfig, cniConfigInfo)
		})
	}

}

func TestPodControllerAddPod(t *testing.T) {
	pod, cniConfig := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})

	t.Run("missing network", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)
		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		assert.Error(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("multiple network interfaces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodController(ctrl)

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
		savedCNIConfig := *cniConfig
		network1 := testNetwork("net1", sriovNetworkType)
		testVLAN := 100
		network2 := testNetworkExt("net2", "", "", string(vlanNetworkType), "", defaultMTU, testVLAN)

		podOwner1 := &crdv1a2.PodOwner{
			Name:        podName,
			Namespace:   testNamespace,
			ContainerID: containerID,
			IFName:      "eth10"}
		podOwner2 := &crdv1a2.PodOwner{
			Name:        podName,
			Namespace:   testNamespace,
			ContainerID: containerID,
			IFName:      "eth11"}
		networkConfig1 := types.NetworkConfig{
			CNIVersion: "0.3.0",
			Name:       "net1",
			Type:       "antrea",
			MTU:        1500,
			IPAM: &types.IPAMConfig{
				Type:    "antrea",
				IPPools: []string{"ipv4-pool-1", "ipv6-pool-1"},
			},
		}
		networkConfig2 := networkConfig1
		networkConfig2.Name = "net2"

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth10",
			interfaceDefaultMTU,
			gomock.Any(),
			gomock.Any(),
		)
		interfaceConfigurator.EXPECT().ConfigureVLANSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth11",
			defaultMTU,
			uint16(testVLAN),
			gomock.Any(),
		).Return(ovsPortUUID, nil)

		mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner1, &networkConfig1).Return(testIPAMResult("148.14.24.100/24"), nil)
		mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner2, &networkConfig2).Return(testIPAMResult("148.14.24.101/24"), nil)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network1, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network2, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))

		infos := podController.podCache.GetAllCNIConfigInfoPerPod(podName, testNamespace)
		assert.Equal(t, 1, len(infos))
		savedCNIConfig.Interfaces = map[string]*cnipodcache.InterfaceInfo{
			"eth10": {
				NetworkType: sriovNetworkType,
			},
			"eth11": {
				OVSPortUUID: ovsPortUUID,
				NetworkType: vlanNetworkType,
			},
		}
		assert.Equal(t, &savedCNIConfig, infos[0])

		mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner1).Return(nil)
		mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner2).Return(nil)
		interfaceConfigurator.EXPECT().DeleteVLANSecondaryInterface(
			containerID,
			gomock.Any(),
			ovsPortUUID).Return(nil)
		assert.NoError(t, podController.handleRemovePod(testNamespace+"/"+podName))
		infos = podController.podCache.GetAllCNIConfigInfoPerPod(podName, testNamespace)
		assert.Equal(t, 0, len(infos))
	})

	t.Run("no network interfaces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)

		pod, cniConfig := testPod(podName, containerID, podIP)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("missing podcache entry", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)

		network := testNetwork(networkName, sriovNetworkType)

		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("missing Status.PodIPs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)

		pod, cniConfig := testPod(podName, containerID, "")
		network := testNetwork(networkName, sriovNetworkType)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("different Namespace for Pod and NetworkAttachmentDefinition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodController(ctrl)

		networkNamespace := "nsB"
		network := testNetwork(networkName, sriovNetworkType)
		network.Namespace = networkNamespace

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
		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(networkNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("no interface name", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodController(ctrl)

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
		network := testNetwork(networkName, sriovNetworkType)

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

		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.101/24"), nil)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("error when creating interface", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodController(ctrl)

		network := testNetwork(networkName, sriovNetworkType)

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

		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24"), nil)
		mockIPAM.EXPECT().SecondaryNetworkRelease(gomock.Any())

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.Error(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("invalid CNI config", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)

		pod, cniConfig := testPod(
			podName,
			containerID,
			podIP,
			netdefv1.NetworkSelectionElement{
				Name: "net1",
			},
		)
		network := &netdefv1.NetworkAttachmentDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "net1",
			},
			Spec: netdefv1.NetworkAttachmentDefinitionSpec{
				// The template is not a valid CNI config spec.
				Config: netAttachTemplate,
			},
		}

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		// we don't expect an error here, no requeueing
		assert.Error(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("invalid networks annotation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)

		pod, cniConfig := testPod(podName, containerID, podIP)
		pod.Annotations = map[string]string{
			networkAttachDefAnnotationKey: "<invalid>",
		}
		network := testNetwork(networkName, sriovNetworkType)

		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		// we don't expect an error here, no requeueing
		assert.NoError(t, podController.handleAddUpdatePod(pod))
	})

	t.Run("Error when adding VF deviceID cache per Pod", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		network := testNetwork(networkName, sriovNetworkType)
		podController, _, _ := testPodController(ctrl)
		podController.podCache.AddCNIConfigInfo(cniConfig)
		_, err := podController.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")

		_, err = podController.assignUnusedSriovVFDeviceIDPerPod(podName, testNamespace, interfaceName)
		require.NoError(t, err, "error while assigning unused VfDevice ID")

		podController.deleteVFDeviceIDListPerPod(podName, testNamespace)
		require.NoError(t, err, "error deleting cache")

	})
}

func testPodController(ctrl *gomock.Controller) (*PodController, *podwatchtesting.MockIPAMAllocator, *podwatchtesting.MockInterfaceConfigurator) {
	client := fake.NewSimpleClientset()
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	podCache := cnipodcache.NewCNIPodInfoStore()
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := podwatchtesting.NewMockIPAMAllocator(ctrl)
	// PodController object without event handlers
	return &PodController{
		kubeClient:            client,
		netAttachDefClient:    netdefclient,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "podcontroller"),
		podInformer:           informerFactory.Core().V1().Pods().Informer(),
		nodeName:              testNode,
		podCache:              podCache,
		interfaceConfigurator: interfaceConfigurator,
		ipamAllocator:         mockIPAM,
	}, mockIPAM, interfaceConfigurator
}
