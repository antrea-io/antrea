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
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	cnitypes "antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/interfacestore"
	podwatchtesting "antrea.io/antrea/pkg/agent/secondarynetwork/podwatch/testing"
	"antrea.io/antrea/pkg/agent/types"
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

	netAttachNoIPAMTemplate = `{
    "cniVersion": "{{.CNIVersion}}",
    "type": "{{.CNIType}}",
    "networkType": "{{.NetworkType}}",
    "mtu": {{.MTU}},
    "vlan": {{.VLAN}}
}`

	defaultCNIVersion = "0.3.0"
	defaultMTU        = 1500
	sriovDeviceID     = "sriov-device-id"
	podName           = "pod1"
	containerID       = "container1"
	podIP             = "1.2.3.4"
	networkName       = "net"
	interfaceName     = "eth2"
)

func testNetwork(name string, networkType networkType) *netdefv1.NetworkAttachmentDefinition {
	return testNetworkExt(name, "", "", string(networkType), "", 0, 0, false)
}

func testNetworkExt(name, cniVersion, cniType, networkType, ipamType string, mtu, vlan int, noIPAM bool) *netdefv1.NetworkAttachmentDefinition {
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

	var tmpl *template.Template
	if !noIPAM {
		tmpl = template.Must(template.New("test").Parse(netAttachTemplate))
	} else {
		tmpl = template.Must(template.New("test").Parse(netAttachNoIPAMTemplate))
	}
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

func testPod(name string, container string, podIP string, networks ...netdefv1.NetworkSelectionElement) (*corev1.Pod, *podCNIInfo) {
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
	cniInfo := &podCNIInfo{
		containerID: container,
		netNS:       containerNetNs(container),
	}
	return pod, cniInfo
}

func testIPAMResult(cidr string, vlan int) *ipam.IPAMResult {
	_, ipNet, _ := net.ParseCIDR(cidr)
	return &ipam.IPAMResult{
		Result: current.Result{
			IPs: []*current.IPConfig{
				{
					Address:   *ipNet,
					Interface: current.Int(1),
				},
			},
		},
		VLANID: uint16(vlan),
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
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := podwatchtesting.NewMockIPAMAllocator(ctrl)
	podController, _ := NewPodController(
		client,
		netdefclient,
		informerFactory.Core().V1().Pods().Informer(),
		testNode,
		nil, nil)
	podController.interfaceConfigurator = interfaceConfigurator
	podController.ipamAllocator = mockIPAM
	cniCache := &podController.cniCache
	interfaceStore := podController.interfaceStore

	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		podController.Run(stopCh)
	}()

	pod, cniInfo := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	podKey := podKeyGet(pod.Name, pod.Namespace)
	network := testNetwork(networkName, sriovNetworkType)
	ipamResult := testIPAMResult("148.14.24.100/24", 0)
	podOwner := &crdv1a2.PodOwner{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		ContainerID: containerID,
		IFName:      interfaceName}
	containerConfig := interfacestore.NewContainerInterface(interfaceName, containerID,
		pod.Name, pod.Namespace, interfaceName, nil, nil, 0)

	// CNI Add event.
	event := types.PodUpdate{
		IsAdd:        true,
		PodName:      pod.Name,
		PodNamespace: pod.Namespace,
		ContainerID:  containerID,
		NetNS:        cniInfo.netNS,
	}
	podController.processCNIUpdate(event)
	cniObj, _ := cniCache.Load(podKey)
	assert.NotNil(t, cniObj)
	assert.Equal(t, cniInfo, cniObj.(*podCNIInfo))

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
		interfaceStore.AddInterface(containerConfig)
	})
	mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(ipamResult, nil)

	// The NetworkAttachmentDefinition must be created before the Pod: if handleAddUpdatePod
	// runs before the NetworkAttachmentDefinition has been created, it will return an
	// error. The Pod will then be requeued, but the Poll below will timeout before the Pod has
	// a chance to be processed again. Rather than increase the timeout or change the queue's
	// minRetryDelay for tests, we ensure that the NetworkAttachmentDefinition exists by the
	// time handleAddUpdatePod runs.
	_, err := netdefclient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(), network, metav1.CreateOptions{})
	require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
	_, err = client.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
	require.NoError(t, err, "error when creating test Pod")

	// Wait for ConfigureSriovSecondaryInterface is called.
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&interfaceConfigured) == 1
	}, 1*time.Second, 10*time.Millisecond)
	_, exists := podController.vfDeviceIDUsageMap.Load(podKey)
	assert.True(t, exists)

	podController.processCNIUpdate(event)
	interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
		podName,
		testNamespace,
		containerID,
		containerNetNs(containerID),
		interfaceName,
		defaultMTU,
		"",
		&ipamResult.Result,
	).Do(func(string, string, string, string, string, int, string, *current.Result) {
		atomic.AddInt32(&interfaceConfigured, 1)
		interfaceStore.AddInterface(containerConfig)
	})
	mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(ipamResult, nil)

	interfaceStore.DeleteInterface(containerConfig)
	// Since interface is not saved to the interface store, interface creation should be
	// triggered again.
	podController.processCNIUpdate(event)
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&interfaceConfigured) == 2
	}, 1*time.Second, 10*time.Millisecond)

	interfaceConfigurator.EXPECT().DeleteSriovSecondaryInterface(containerConfig).
		Do(func(*interfacestore.InterfaceConfig) {
			atomic.AddInt32(&interfaceConfigured, -1)
		})
	mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner)
	require.NoError(t, client.CoreV1().Pods(testNamespace).Delete(context.Background(),
		podName, metav1.DeleteOptions{}), "error when deleting test Pod")

	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&interfaceConfigured) == 1
	}, 1*time.Second, 10*time.Millisecond)
	_, exists = podController.vfDeviceIDUsageMap.Load(podKey)
	assert.False(t, exists)

	interfaceConfigurator.EXPECT().DeleteSriovSecondaryInterface(containerConfig).
		Do(func(*interfacestore.InterfaceConfig) {
			atomic.AddInt32(&interfaceConfigured, -1)
		})
	mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner)
	// CNI Del event.
	event.IsAdd = false
	// Interfac is not deleted from the interface store, so CNI Del should trigger interface
	// deletion again.
	podController.processCNIUpdate(event)
	_, exists = cniCache.Load(podKey)
	assert.False(t, exists)
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&interfaceConfigured) == 0
	}, 1*time.Second, 10*time.Millisecond)

	interfaceStore.DeleteInterface(containerConfig)
	podController.processCNIUpdate(event)

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
		networkType        networkType
		ipamType           string
		mtu                int
		vlan               int
		noIPAM             bool
		doNotCreateNetwork bool
		expectedErr        string
		expectedCalls      func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator)
	}{
		{
			name:        "VLAN network",
			networkType: vlanNetworkType,
			mtu:         1600,
			vlan:        101,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1600,
					testIPAMResult("148.14.24.100/24", 101),
				)
			},
		},
		{
			name:        "VLAN in IPPool",
			networkType: vlanNetworkType,
			vlan:        0,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				// IPAM returns the VLAN ID in the IPPool subnet.
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 101), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					testIPAMResult("148.14.24.100/24", 101),
				)
			},
		},
		{
			name:        "network VLAN overrides IPPool VLAN",
			networkType: vlanNetworkType,
			vlan:        101,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 102), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					testIPAMResult("148.14.24.100/24", 101),
				)
			},
		},
		{
			name:        "no IPAM",
			networkType: vlanNetworkType,
			noIPAM:      true,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					&ipam.IPAMResult{},
				)
			},
		},
		{
			name:        "SRIOV network",
			networkType: sriovNetworkType,
			mtu:         1500,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)
				mockIC.EXPECT().ConfigureSriovSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					sriovDeviceID,
					&testIPAMResult("148.14.24.100/24", 0).Result,
				)
			},
		},
		{
			name:               "network not found",
			networkType:        vlanNetworkType,
			mtu:                1500,
			vlan:               100,
			doNotCreateNetwork: true,
			expectedErr:        "\"net\" not found",
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
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), errors.New("failure"))
			},
			expectedErr: "secondary network IPAM failed",
		},
		{
			name:        "interface failure",
			networkType: vlanNetworkType,
			mtu:         1600,
			vlan:        101,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1600,
					testIPAMResult("148.14.24.100/24", 101),
				).Return(errors.New("interface creation failure"))
				mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner)
			},
			expectedErr: "interface creation failure",
		},
		{
			name:        "interface failure with no IPAM",
			networkType: vlanNetworkType,
			noIPAM:      true,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNs(containerID),
					interfaceName,
					1500,
					&ipam.IPAMResult{},
				).Return(errors.New("interface creation failure"))
			},
			expectedErr: "interface creation failure",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod, cniInfo := testPod(podName, containerID, podIP, element1)
			pc, mockIPAM, interfaceConfigurator := testPodControllerStart(ctrl)

			if !tc.doNotCreateNetwork {
				network1 := testNetworkExt(networkName, tc.cniVersion, tc.cniType,
					string(tc.networkType), tc.ipamType, tc.mtu, tc.vlan, tc.noIPAM)
				pc.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
					network1, metav1.CreateOptions{})
			}
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockIPAM, interfaceConfigurator)
			}
			err := pc.configurePodSecondaryNetwork(pod, []*netdefv1.NetworkSelectionElement{&element1}, cniInfo)
			if tc.expectedErr == "" {
				assert.Nil(t, err)
			} else {
				assert.True(t, strings.Contains(err.Error(), tc.expectedErr))
			}
		})
	}

}

func TestPodControllerAddPod(t *testing.T) {
	pod, _ := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	podKey := podKeyGet(podName, testNamespace)

	// Create Pod and wait for Informer cache updated.
	createPodFn := func(pc *podController, pod *corev1.Pod) {
		_, err := pc.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(),
			pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		assert.Eventually(t, func() bool {
			_, ok, err := pc.podInformer.GetIndexer().GetByKey(podKey)
			return ok == true && err == nil
		}, 1*time.Second, 10*time.Millisecond)
	}
	deletePodFn := func(pc *podController, podName string) {
		require.NoError(t, pc.kubeClient.CoreV1().Pods(testNamespace).Delete(context.Background(),
			podName, metav1.DeleteOptions{}), "error when deleting test Pod")
		assert.Eventually(t, func() bool {
			_, ok, err := pc.podInformer.GetIndexer().GetByKey(podKey)
			return !ok && err == nil
		}, 1*time.Second, 10*time.Millisecond)
	}

	t.Run("multiple network interfaces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodControllerStart(ctrl)
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
		network1 := testNetwork("net1", sriovNetworkType)
		testVLAN := 100
		network2 := testNetworkExt("net2", "", "", string(vlanNetworkType), "", defaultMTU, testVLAN, false)

		podOwner1 := &crdv1a2.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: containerID, IFName: "eth10"}
		podOwner2 := &crdv1a2.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: containerID, IFName: "eth11"}
		containerConfig1 := interfacestore.NewContainerInterface("interface1", containerID,
			pod.Name, pod.Namespace, "eth10", nil, nil, 0)
		containerConfig2 := interfacestore.NewContainerInterface("interface2", containerID,
			pod.Name, pod.Namespace, "eth11", nil, nil, 0)
		// VLAN interface should have OVSPortConfig.
		containerConfig2.OVSPortConfig = &interfacestore.OVSPortConfig{}

		staleContainerID := containerID + "-stale"
		stalePodOwner1 := &crdv1a2.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: staleContainerID, IFName: "eth1"}
		stalePodOwner2 := &crdv1a2.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: staleContainerID, IFName: "eth2"}
		staleConfig1 := interfacestore.NewContainerInterface("interface1", staleContainerID,
			pod.Name, pod.Namespace, "eth1", nil, nil, 0)
		staleConfig2 := interfacestore.NewContainerInterface("interface2", staleContainerID,
			pod.Name, pod.Namespace, "eth2", nil, nil, 0)
		staleConfig1.OVSPortConfig = &interfacestore.OVSPortConfig{}

		networkConfig1 := cnitypes.NetworkConfig{
			CNIVersion: "0.3.0",
			Name:       "net1",
			Type:       "antrea",
			MTU:        1500,
			IPAM: &cnitypes.IPAMConfig{
				Type:    "antrea",
				IPPools: []string{"ipv4-pool-1", "ipv6-pool-1"},
			},
		}
		networkConfig2 := networkConfig1
		networkConfig2.Name = "net2"

		podController.interfaceStore.AddInterface(staleConfig1)
		podController.interfaceStore.AddInterface(staleConfig2)
		// Stale interfaces in the interface store should be deleted first.
		mockIPAM.EXPECT().SecondaryNetworkRelease(stalePodOwner1)
		mockIPAM.EXPECT().SecondaryNetworkRelease(stalePodOwner2)
		interfaceConfigurator.EXPECT().DeleteVLANSecondaryInterface(staleConfig1)
		interfaceConfigurator.EXPECT().DeleteSriovSecondaryInterface(staleConfig2)

		podController.cniCache.Store(podKey, cniConfig)
		createPodFn(podController, pod)
		assert.NoError(t, podController.syncPod(podKey))
		podController.interfaceStore.DeleteInterface(staleConfig1)
		podController.interfaceStore.DeleteInterface(staleConfig2)

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth10",
			interfaceDefaultMTU,
			gomock.Any(),
			&testIPAMResult("148.14.24.100/24", 0).Result,
		)
		interfaceConfigurator.EXPECT().ConfigureVLANSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNs(containerID),
			"eth11",
			defaultMTU,
			testIPAMResult("148.14.24.101/24", 100),
		)
		mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner1, &networkConfig1).Return(testIPAMResult("148.14.24.100/24", 0), nil)
		mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner2, &networkConfig2).Return(testIPAMResult("148.14.24.101/24", 0), nil)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network1, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		_, err = podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network2, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		assert.NoError(t, podController.syncPod(podKey))

		podController.interfaceStore.AddInterface(containerConfig1)
		podController.interfaceStore.AddInterface(containerConfig2)
		mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner1)
		mockIPAM.EXPECT().SecondaryNetworkRelease(podOwner2)
		interfaceConfigurator.EXPECT().DeleteSriovSecondaryInterface(containerConfig1)
		interfaceConfigurator.EXPECT().DeleteVLANSecondaryInterface(containerConfig2)

		deletePodFn(podController, pod.Name)
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("no network interfaces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodControllerStart(ctrl)
		pod, cniConfig := testPod(podName, containerID, podIP)

		podController.cniCache.Store(podKey, cniConfig)
		createPodFn(podController, pod)
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("missing CNI cache entry", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodControllerStart(ctrl)
		network := testNetwork(networkName, sriovNetworkType)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("missing Status.PodIPs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodControllerStart(ctrl)
		pod, cniConfig := testPod(podName, containerID, "")
		network := testNetwork(networkName, sriovNetworkType)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.cniCache.Store(podKey, cniConfig)
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("different Namespace for Pod and NetworkAttachmentDefinition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodControllerStart(ctrl)
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
		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(networkNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.cniCache.Store(podKey, cniConfig)
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("no interface name", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, mockIPAM, interfaceConfigurator := testPodControllerStart(ctrl)
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

		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)
		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.101/24", 0), nil)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.cniCache.Store(podKey, cniConfig)
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("invalid CNI config", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodControllerStart(ctrl)
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

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.cniCache.Store(podKey, cniConfig)
		// We don't expect an error here, no requeueing.
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("invalid networks annotation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodControllerStart(ctrl)
		pod, cniConfig := testPod(podName, containerID, podIP)
		pod.Annotations = map[string]string{
			networkAttachDefAnnotationKey: "<invalid>",
		}
		network := testNetwork(networkName, sriovNetworkType)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.cniCache.Store(podKey, cniConfig)
		// We don't expect an error here, no requeueing.
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("updating deviceID cache per Pod", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodController(ctrl)
		_, err := podController.assignUnusedSriovVFDeviceID(podName, testNamespace, interfaceName)
		_, exists := podController.vfDeviceIDUsageMap.Load(podKey)
		assert.True(t, exists)
		require.NoError(t, err, "error while assigning unused VfDevice ID")
		podController.releaseSriovVFDeviceID(podName, testNamespace, interfaceName)
		_, exists = podController.vfDeviceIDUsageMap.Load(podKey)
		assert.True(t, exists)
		podController.deleteVFDeviceIDListPerPod(podName, testNamespace)
		_, exists = podController.vfDeviceIDUsageMap.Load(podKey)
		assert.False(t, exists)
	})
}

func testPodController(ctrl *gomock.Controller) (
	*podController, *podwatchtesting.MockIPAMAllocator,
	*podwatchtesting.MockInterfaceConfigurator) {
	client := fake.NewSimpleClientset()
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := podwatchtesting.NewMockIPAMAllocator(ctrl)

	// podController without event handlers.
	return &podController{
		kubeClient:         client,
		netAttachDefClient: netdefclient,
		queue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay),
			"podcontroller"),
		podInformer:           informerFactory.Core().V1().Pods().Informer(),
		nodeName:              testNode,
		interfaceConfigurator: interfaceConfigurator,
		ipamAllocator:         mockIPAM,
		interfaceStore:        interfacestore.NewInterfaceStore(),
	}, mockIPAM, interfaceConfigurator
}

// Create a test podController and start informerFactory.
func testPodControllerStart(ctrl *gomock.Controller) (
	*podController, *podwatchtesting.MockIPAMAllocator,
	*podwatchtesting.MockInterfaceConfigurator) {
	podController, mockIPAM, interfaceConfigurator := testPodController(ctrl)
	informerFactory := informers.NewSharedInformerFactory(podController.kubeClient, resyncPeriod)
	podController.podInformer = informerFactory.Core().V1().Pods().Informer()
	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	return podController, mockIPAM, interfaceConfigurator
}
