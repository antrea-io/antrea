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
	"github.com/google/uuid"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclientfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	cnitypes "antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	podwatchtesting "antrea.io/antrea/pkg/agent/secondarynetwork/podwatch/testing"
	"antrea.io/antrea/pkg/agent/types"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakecrd "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
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

	defaultCNIVersion  = "0.3.0"
	defaultMTU         = 1500
	sriovResourceName1 = "intel.com/intel_sriov_netdevice"
	sriovResourceName2 = "mellanox.com/mlnx_connectx5"
	sriovDeviceID11    = "sriov-device-id-11"
	sriovDeviceID12    = "sriov-device-id-12"
	sriovDeviceID21    = "sriov-device-id-21"
	podName            = "pod1"
	containerID        = "container1"
	podIP              = "1.2.3.4"
	networkName        = "net"
	interfaceName      = "eth2"
	gatewayIP          = "1.1.1.1"
)

func testNetwork(name string, networkType networkType) *netdefv1.NetworkAttachmentDefinition {
	return testNetworkExt(name, "", "", networkType, "", "", 0, 0, false)
}

func testNetworkExt(name, cniVersion, cniType string, networkType networkType, resourceName, ipamType string, mtu, vlan int, noIPAM bool) *netdefv1.NetworkAttachmentDefinition {
	if cniVersion == "" {
		cniVersion = defaultCNIVersion
	}
	if cniType == "" {
		cniType = "antrea"
	}
	if networkType == sriovNetworkType && resourceName == "" {
		resourceName = sriovResourceName1
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
	}{cniVersion, cniType, string(networkType), ipamType, mtu, vlan}

	var tmpl *template.Template
	if !noIPAM {
		tmpl = template.Must(template.New("test").Parse(netAttachTemplate))
	} else {
		tmpl = template.Must(template.New("test").Parse(netAttachNoIPAMTemplate))
	}
	var b bytes.Buffer
	tmpl.Execute(&b, &data)
	annotations := make(map[string]string)
	if resourceName != "" {
		annotations[resourceNameAnnotationKey] = resourceName
	}
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: b.String(),
		},
	}
}

func containerNetNS(container string) string {
	return fmt.Sprintf("/var/run/netns/%s", container)
}

func testPod(name string, container string, podIP string, networks ...netdefv1.NetworkSelectionElement) (*corev1.Pod, *podCNIInfo) {
	annotations := make(map[string]string)
	if len(networks) > 0 {
		annotation, _ := json.Marshal(networks)
		annotations[netdefv1.NetworkAttachmentAnnot] = string(annotation)
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
		netNS:       containerNetNS(container),
	}
	return pod, cniInfo
}

func testIPAMResultWithSRIOV(cidr string, vlan int, sriov *current.Interface) *ipam.IPAMResult {
	result := testIPAMResult(cidr, vlan)
	result.Interfaces = []*current.Interface{
		{
			Name: "eth1",
		},
		sriov,
	}
	return result
}

func testIPAMResult(cidr string, vlan int) *ipam.IPAMResult {
	ip, _, _ := net.ParseCIDR(cidr)
	mask := net.CIDRMask(32, 32)
	ipNet := net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}
	return &ipam.IPAMResult{
		Result: current.Result{
			IPs: []*current.IPConfig{
				{
					Address:   ipNet,
					Interface: current.Int(1),
				},
			},
		},
		VLANID: uint16(vlan),
	}
}

func init() {
	getPodContainerDeviceIDsFn = func(name string, namespace string) (map[string][]string, error) {
		return map[string][]string{
			sriovResourceName1: {sriovDeviceID11, sriovDeviceID12},
			sriovResourceName2: {sriovDeviceID21},
		}, nil
	}
}

func TestPodControllerRun(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-a",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{NodeName: "fakeNode"},
	}

	stalePodOwner := &crdv1beta1.PodOwner{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		ContainerID: "staleContainerID",
		IFName:      interfaceName,
	}

	pool := &crdv1beta1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: uuid.New().String()},
		Spec: crdv1beta1.IPPoolSpec{
			IPRanges: []crdv1beta1.IPRange{
				{
					Start: "10.2.2.100",
					End:   "10.2.2.110",
				},
			},
			SubnetInfo: crdv1beta1.SubnetInfo{
				Gateway:      "10.2.2.1",
				PrefixLength: 24,
			},
		},
		Status: crdv1beta1.IPPoolStatus{
			IPAddresses: []crdv1beta1.IPAddressState{
				{
					IPAddress: "10.2.2.12",
					Phase:     crdv1beta1.IPAddressPhaseAllocated,
					Owner: crdv1beta1.IPAddressOwner{
						Pod: stalePodOwner,
					},
				},
			},
		},
	}

	ctrl := gomock.NewController(t)
	client := fake.NewSimpleClientset(pod)
	crdClient := fakecrd.NewSimpleClientset(pool)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	poolInformer := crdInformerFactory.Crd().V1beta1().IPPools()
	poolLister := poolInformer.Lister()
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockOVSBridgeClient.EXPECT().GetPortList().Return(nil, nil).AnyTimes()
	primaryInterfaceStore := interfacestore.NewInterfaceStore()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := podwatchtesting.NewMockIPAMAllocator(ctrl)
	gateway := &config.GatewayConfig{Name: "", IPv4: net.ParseIP(gatewayIP)}
	nodeConfig := &config.NodeConfig{Name: "", PodIPv4CIDR: nil, GatewayConfig: gateway}
	podController, _ := NewPodController(
		client,
		netdefclient,
		informerFactory.Core().V1().Pods().Informer(),
		nil, primaryInterfaceStore, nodeConfig, mockOVSBridgeClient, poolLister)
	podController.interfaceConfigurator = interfaceConfigurator
	podController.ipamAllocator = mockIPAM
	cniCache := &podController.cniCache
	interfaceStore := podController.interfaceStore

	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	crdInformerFactory.Start(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		podController.Run(stopCh)
	}()

	mockIPAM.EXPECT().SecondaryNetworkRelease(stalePodOwner)
	pod, cniInfo := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	podKey := podKeyGet(pod.Name, pod.Namespace)
	network := testNetwork(networkName, sriovNetworkType)
	ipamResult := testIPAMResultWithSRIOV("148.14.24.100/24", 0, &current.Interface{PciID: sriovDeviceID11})
	podOwner := &crdv1beta1.PodOwner{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		ContainerID: containerID,
		IFName:      interfaceName}
	containerConfig := interfacestore.NewContainerInterface(interfaceName, containerID,
		pod.Name, pod.Namespace, interfaceName, cniInfo.netNS, nil, nil, 0)

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
		containerNetNS(containerID),
		interfaceName,
		defaultMTU,
		sriovDeviceID11,
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

	// Wait for ConfigureSriovSecondaryInterface to be called.
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
		containerNetNS(containerID),
		interfaceName,
		defaultMTU,
		sriovDeviceID11,
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
	// Interface is not deleted from the interface store, so CNI Del should trigger interface
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
	element1 := &netdefv1.NetworkSelectionElement{
		Name:             networkName,
		Namespace:        testNamespace,
		InterfaceRequest: interfaceName,
	}
	element2 := &netdefv1.NetworkSelectionElement{
		Name:             networkName,
		Namespace:        testNamespace,
		InterfaceRequest: interfaceName,
		MacRequest:       "02:42:ac:11:00:02",
	}
	element3 := &netdefv1.NetworkSelectionElement{
		Name:             networkName,
		Namespace:        testNamespace,
		InterfaceRequest: interfaceName,
		MacRequest:       "invalid-mac",
	}
	podOwner := &crdv1beta1.PodOwner{
		Name:        podName,
		Namespace:   testNamespace,
		ContainerID: containerID,
		IFName:      interfaceName,
	}

	ctrl := gomock.NewController(t)

	primaryInterface := &interfacestore.InterfaceConfig{
		InterfaceName: "fake-primary-interface-name",
		IPs:           []net.IP{net.ParseIP("192.168.1.2")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			ContainerID:  containerID,
			PodName:      podName,
			PodNamespace: testNamespace,
			IFDev:        "eth0",
		},
	}
	primaryNetworkStatus := netdefv1.NetworkStatus{
		Name:      cniserver.AntreaCNIType,
		Interface: "eth0",
		IPs:       []string{"192.168.1.2"},
		Default:   true,
		Gateway:   []string{gatewayIP},
	}

	tests := []struct {
		name                       string
		element                    *netdefv1.NetworkSelectionElement
		cniVersion                 string
		cniType                    string
		networkType                networkType
		ipamType                   string
		mtu                        int
		vlan                       int
		noIPAM                     bool
		doNotCreateNetwork         bool
		expectedNetworkStatusAnnot []netdefv1.NetworkStatus
		expectedErr                string
		expectedCalls              func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator)
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
					containerNetNS(containerID),
					interfaceName,
					1600,
					testIPAMResult("148.14.24.100/24", 101),
					nil,
				)
			},
			expectedNetworkStatusAnnot: []netdefv1.NetworkStatus{{
				Name: "net",
				IPs:  []string{"148.14.24.100"},
				DNS:  netdefv1.DNS{},
			}, primaryNetworkStatus},
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
					containerNetNS(containerID),
					interfaceName,
					1500,
					testIPAMResult("148.14.24.100/24", 101),
					nil,
				)
			},
			expectedNetworkStatusAnnot: []netdefv1.NetworkStatus{{
				Name: "net",
				IPs:  []string{"148.14.24.100"},
				DNS:  netdefv1.DNS{},
			}, primaryNetworkStatus},
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
					containerNetNS(containerID),
					interfaceName,
					1500,
					testIPAMResult("148.14.24.100/24", 101),
					nil,
				)
			},
			expectedNetworkStatusAnnot: []netdefv1.NetworkStatus{{
				Name: "net",
				IPs:  []string{"148.14.24.100"},
				DNS:  netdefv1.DNS{},
			}, primaryNetworkStatus},
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
					containerNetNS(containerID),
					interfaceName,
					1500,
					&ipam.IPAMResult{},
					nil,
				)
			},
			expectedNetworkStatusAnnot: []netdefv1.NetworkStatus{{
				Name: "net",
				DNS:  netdefv1.DNS{},
			}, primaryNetworkStatus},
		},
		{
			name:        "SRIOV network",
			networkType: sriovNetworkType,
			mtu:         1500,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResultWithSRIOV("148.14.24.100/24", 0, &current.Interface{PciID: "sriov-device-id-11"}), nil)
				mockIC.EXPECT().ConfigureSriovSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNS(containerID),
					interfaceName,
					1500,
					sriovDeviceID11,
					&testIPAMResultWithSRIOV("148.14.24.100/24", 0, &current.Interface{PciID: "sriov-device-id-11"}).Result,
				)
			},
			expectedNetworkStatusAnnot: []netdefv1.NetworkStatus{{
				Name: "net",
				IPs:  []string{"148.14.24.100"},
				DNS:  netdefv1.DNS{},
			}, primaryNetworkStatus},
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
					containerNetNS(containerID),
					interfaceName,
					1600,
					testIPAMResult("148.14.24.100/24", 101),
					nil,
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
					containerNetNS(containerID),
					interfaceName,
					1500,
					&ipam.IPAMResult{},
					nil,
				).Return(errors.New("interface creation failure"))
			},
			expectedErr: "interface creation failure",
		},
		{
			name:        "static MAC address configured",
			element:     element2,
			networkType: vlanNetworkType,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				expectedMAC, _ := net.ParseMAC("02:42:ac:11:00:02")
				mockIPAM.EXPECT().SecondaryNetworkAllocate(podOwner, gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)
				mockIC.EXPECT().ConfigureVLANSecondaryInterface(
					podName,
					testNamespace,
					containerID,
					containerNetNS(containerID),
					interfaceName,
					gomock.Any(),
					testIPAMResult("148.14.24.100/24", 0),
					expectedMAC,
				)
			},
			expectedNetworkStatusAnnot: []netdefv1.NetworkStatus{{
				Name: "net",
				IPs:  []string{"148.14.24.100"},
				DNS:  netdefv1.DNS{},
			}, primaryNetworkStatus},
		},
		{
			name:        "invalid MAC address fails",
			element:     element3,
			networkType: vlanNetworkType,
			expectedCalls: func(mockIPAM *podwatchtesting.MockIPAMAllocator, mockIC *podwatchtesting.MockInterfaceConfigurator) {
				// Expect no call to interface configurator
			},
			expectedErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			element := tc.element
			if element == nil {
				element = element1
			}

			pod, cniInfo := testPod(podName, containerID, podIP, *element)
			pc, mockIPAM, interfaceConfigurator := testPodControllerStart(ctrl)
			_, err := pc.kubeClient.CoreV1().Pods(pod.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
			require.NoError(t, err)

			pc.primaryInterfaceStore.AddInterface(primaryInterface)

			if !tc.doNotCreateNetwork {
				network1 := testNetworkExt(networkName, tc.cniVersion, tc.cniType,
					tc.networkType, "", tc.ipamType, tc.mtu, tc.vlan, tc.noIPAM)
				pc.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
					network1, metav1.CreateOptions{})
			}
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockIPAM, interfaceConfigurator)
			}
			netStatus, err := pc.configurePodSecondaryNetwork(pod, []*netdefv1.NetworkSelectionElement{element}, cniInfo)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.True(t, strings.Contains(err.Error(), tc.expectedErr))
			}
			err = pc.updatePodNetworkStatusAnnotation(netStatus, pod)
			assert.NoError(t, err)
			if tc.expectedNetworkStatusAnnot != nil {
				updatedPod, err := pc.kubeClient.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
				require.NoError(t, err)
				networkStatusAnnot, _ := netdefutils.GetNetworkStatus(updatedPod)
				assertEqualPodNetworkStatus(t, networkStatusAnnot, tc.expectedNetworkStatusAnnot)
			}
		})
	}
}

func assertEqualPodNetworkStatus(t *testing.T, actualStatus, expectedStatus []netdefv1.NetworkStatus) {
	assert.Equal(t, len(expectedStatus), len(actualStatus))
	for i := range expectedStatus {
		if expectedStatus[i].DeviceInfo != nil && actualStatus[i].DeviceInfo != nil {
			assert.Equal(t, expectedStatus[i].DeviceInfo.Pci, actualStatus[i].DeviceInfo.Pci)
			expectedStatus[i].DeviceInfo = nil
			actualStatus[i].DeviceInfo = nil
			// Remove the pointer of DeviceInfo so that we can compare the rest of the fields.
			assert.Equal(t, expectedStatus[i], actualStatus[i])
		}
	}
}

func TestConfigurePodSecondaryNetworkMultipleSriovDevices(t *testing.T) {
	ctx := context.Background()
	element1 := netdefv1.NetworkSelectionElement{
		Namespace:        testNamespace,
		Name:             "net1",
		InterfaceRequest: "eth10",
	}
	element2 := netdefv1.NetworkSelectionElement{
		Namespace:        testNamespace,
		Name:             "net2",
		InterfaceRequest: "eth11",
	}
	pod, cniInfo := testPod(podName, containerID, podIP, element1, element2)
	ctrl := gomock.NewController(t)
	pc, _, interfaceConfigurator := testPodControllerStart(ctrl)

	_, err := pc.kubeClient.CoreV1().Pods(pod.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	require.NoError(t, err)

	network1 := testNetworkExt("net1", "", "", sriovNetworkType, sriovResourceName1, "", 1500, 0, true /* noIPAM */)
	pc.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(ctx, network1, metav1.CreateOptions{})
	network2 := testNetworkExt("net2", "", "", sriovNetworkType, sriovResourceName2, "", 1500, 0, true /* noIPAM */)
	pc.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(ctx, network2, metav1.CreateOptions{})

	gomock.InOrder(
		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNS(containerID),
			element2.InterfaceRequest,
			1500,
			sriovDeviceID21,
			gomock.Any(),
		),
		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNS(containerID),
			element1.InterfaceRequest,
			1500,
			sriovDeviceID11,
			gomock.Any(),
		),
	)
	_, err = pc.configurePodSecondaryNetwork(pod, []*netdefv1.NetworkSelectionElement{&element2, &element1}, cniInfo)
	assert.NoError(t, err)

	podKey := podKeyGet(pod.Name, pod.Namespace)
	deviceCache, ok := pc.vfDeviceIDUsageMap.Load(podKey)
	require.True(t, ok)
	expectedDeviceCache := []podSriovVFDeviceIDInfo{
		{
			resourceName: sriovResourceName1,
			vfDeviceID:   sriovDeviceID11,
			ifName:       element1.InterfaceRequest,
		},
		{
			resourceName: sriovResourceName1,
			vfDeviceID:   sriovDeviceID12,
			ifName:       "",
		},
		{
			resourceName: sriovResourceName2,
			vfDeviceID:   sriovDeviceID21,
			ifName:       element2.InterfaceRequest,
		},
	}
	assert.ElementsMatch(t, expectedDeviceCache, deviceCache.([]podSriovVFDeviceIDInfo))
}

func TestPodControllerAddPod(t *testing.T) {
	pod, _ := testPod(podName, containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	podKey := podKeyGet(podName, testNamespace)

	primaryInterface := &interfacestore.InterfaceConfig{
		InterfaceName: interfaceName,
		IPs:           []net.IP{net.ParseIP("192.168.1.2")},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			ContainerID:  containerID,
			PodName:      podName,
			PodNamespace: testNamespace,
			IFDev:        "eth0",
		},
	}
	// Create Pod and wait for Informer cache updated.
	createPodFn := func(pc *PodController, pod *corev1.Pod) {
		_, err := pc.kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(),
			pod, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test Pod")
		assert.Eventually(t, func() bool {
			_, ok, err := pc.podInformer.GetIndexer().GetByKey(podKey)
			return ok == true && err == nil
		}, 1*time.Second, 10*time.Millisecond)
	}
	deletePodFn := func(pc *PodController, podName string) {
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
		network2 := testNetworkExt("net2", "", "", vlanNetworkType, "", "", defaultMTU, testVLAN, false)
		netNS := containerNetNS(containerID)

		podOwner1 := &crdv1beta1.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: containerID, IFName: "eth10"}
		podOwner2 := &crdv1beta1.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: containerID, IFName: "eth11"}
		containerConfig1 := interfacestore.NewContainerInterface("interface1", containerID,
			pod.Name, pod.Namespace, "eth10", netNS, nil, nil, 0)
		containerConfig2 := interfacestore.NewContainerInterface("interface2", containerID,
			pod.Name, pod.Namespace, "eth11", netNS, nil, nil, 0)
		// VLAN interface should have OVSPortConfig.
		containerConfig2.OVSPortConfig = &interfacestore.OVSPortConfig{}

		staleContainerID := containerID + "-stale"
		stalePodOwner1 := &crdv1beta1.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: staleContainerID, IFName: "eth1"}
		stalePodOwner2 := &crdv1beta1.PodOwner{Name: podName, Namespace: testNamespace,
			ContainerID: staleContainerID, IFName: "eth2"}
		staleConfig1 := interfacestore.NewContainerInterface("interface1", staleContainerID,
			pod.Name, pod.Namespace, "eth1", containerNetNS(staleContainerID), nil, nil, 0)
		staleConfig2 := interfacestore.NewContainerInterface("interface2", staleContainerID,
			pod.Name, pod.Namespace, "eth2", containerNetNS(staleContainerID), nil, nil, 0)
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
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
		assert.NoError(t, podController.syncPod(podKey))
		podController.interfaceStore.DeleteInterface(staleConfig1)
		podController.interfaceStore.DeleteInterface(staleConfig2)

		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			netNS,
			"eth10",
			interfaceDefaultMTU,
			gomock.Any(),
			&testIPAMResult("148.14.24.100/24", 0).Result,
		)
		interfaceConfigurator.EXPECT().ConfigureVLANSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			netNS,
			"eth11",
			defaultMTU,
			testIPAMResult("148.14.24.101/24", 100),
			nil,
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
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
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
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
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
			containerNetNS(containerID),
			interfaceName,
			defaultMTU,
			sriovDeviceID11,
			gomock.Any(),
		)
		mockIPAM.EXPECT().SecondaryNetworkAllocate(gomock.Any(), gomock.Any()).Return(testIPAMResult("148.14.24.100/24", 0), nil)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(networkNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
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
			containerNetNS(containerID),
			"eth1",
			defaultMTU,
			gomock.Any(),
			gomock.Any(),
		)
		interfaceConfigurator.EXPECT().ConfigureSriovSecondaryInterface(
			podName,
			testNamespace,
			containerID,
			containerNetNS(containerID),
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
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
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
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
		podController.cniCache.Store(podKey, cniConfig)
		// We don't expect an error here, no requeuing.
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("invalid networks annotation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _ := testPodControllerStart(ctrl)
		pod, cniConfig := testPod(podName, containerID, podIP)
		pod.Annotations = map[string]string{
			netdefv1.NetworkAttachmentAnnot: "<invalid>",
		}
		network := testNetwork(networkName, sriovNetworkType)

		_, err := podController.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
			network, metav1.CreateOptions{})
		require.NoError(t, err, "error when creating test NetworkAttachmentDefinition")
		createPodFn(podController, pod)
		podController.primaryInterfaceStore.AddInterface(primaryInterface)
		podController.cniCache.Store(podKey, cniConfig)
		// We don't expect an error here, no requeuing.
		assert.NoError(t, podController.syncPod(podKey))
	})

	t.Run("updating deviceID cache per Pod", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		podController, _, _, _ := testPodController(ctrl)
		tmpPodName := "poda"
		tmpPodNamespace := "testns"
		tmpPodKey := podKeyGet(tmpPodName, tmpPodNamespace)
		_, err := podController.assignSriovVFDeviceID(tmpPodName, tmpPodNamespace, sriovResourceName1, interfaceName)
		require.NoError(t, err, "error while assigning unused VfDevice ID")
		vfDeviceIDInfoCache, exists := podController.vfDeviceIDUsageMap.Load(tmpPodKey)
		assert.True(t, exists)
		vfDeviceIDsInfo := vfDeviceIDInfoCache.([]podSriovVFDeviceIDInfo)
		assert.Contains(t, vfDeviceIDsInfo, podSriovVFDeviceIDInfo{
			resourceName: sriovResourceName1,
			vfDeviceID:   sriovDeviceID11,
			ifName:       interfaceName,
		}, "expected interface assignment not found in cache")
		// The second call would get the assigned SR-IOV device ID directly.
		deviceID, err := podController.assignSriovVFDeviceID(tmpPodName, tmpPodNamespace, sriovResourceName1, interfaceName)
		_, exists = podController.vfDeviceIDUsageMap.Load(tmpPodKey)
		assert.True(t, exists)
		assert.Equal(t, sriovDeviceID11, deviceID, "incorrect device ID")
		require.NoError(t, err, "error while getting assigned VfDevice ID")
		podController.releaseSriovVFDeviceID(tmpPodName, tmpPodNamespace, interfaceName)
		_, exists = podController.vfDeviceIDUsageMap.Load(tmpPodKey)
		assert.True(t, exists)
		podController.deleteVFDeviceIDListPerPod(tmpPodName, tmpPodNamespace)
		_, exists = podController.vfDeviceIDUsageMap.Load(tmpPodKey)
		assert.False(t, exists)
	})
}

func testPodController(ctrl *gomock.Controller) (
	*PodController, *podwatchtesting.MockIPAMAllocator,
	*podwatchtesting.MockInterfaceConfigurator, *ovsconfigtest.MockOVSBridgeClient) {
	client := fake.NewSimpleClientset()
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	interfaceConfigurator := podwatchtesting.NewMockInterfaceConfigurator(ctrl)
	mockIPAM := podwatchtesting.NewMockIPAMAllocator(ctrl)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	gatewayIP := "1.1.1.1"
	gateway := &config.GatewayConfig{Name: "", IPv4: net.ParseIP(gatewayIP)}
	nodeConfig := &config.NodeConfig{Name: "", PodIPv4CIDR: nil, GatewayConfig: gateway}

	// PodController without event handlers.
	return &PodController{
		kubeClient:         client,
		ovsBridgeClient:    mockOVSBridgeClient,
		netAttachDefClient: netdefclient,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "podcontroller",
			},
		),
		podInformer:           informerFactory.Core().V1().Pods().Informer(),
		podLister:             informerFactory.Core().V1().Pods().Lister(),
		interfaceConfigurator: interfaceConfigurator,
		ipamAllocator:         mockIPAM,
		interfaceStore:        interfacestore.NewInterfaceStore(),
		primaryInterfaceStore: interfacestore.NewInterfaceStore(),
		nodeConfig:            nodeConfig,
	}, mockIPAM, interfaceConfigurator, mockOVSBridgeClient
}

// Create a test PodController and start informerFactory.
func testPodControllerStart(ctrl *gomock.Controller) (
	*PodController, *podwatchtesting.MockIPAMAllocator,
	*podwatchtesting.MockInterfaceConfigurator) {
	podController, mockIPAM, interfaceConfigurator, _ := testPodController(ctrl)
	informerFactory := informers.NewSharedInformerFactory(podController.kubeClient, resyncPeriod)
	podController.podInformer = informerFactory.Core().V1().Pods().Informer()
	stopCh := make(chan struct{})
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	return podController, mockIPAM, interfaceConfigurator
}

func convertExternalIDMap(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v.(string)
	}
	return out
}

func createTestInterfaces() ([]ovsconfig.OVSPortData, []*interfacestore.InterfaceConfig) {
	uuid1 := uuid.New().String()
	uuid2 := uuid.New().String()
	uuid3 := uuid.New().String()
	uuid4 := uuid.New().String()

	p1MAC, p1IP := "11:22:33:44:55:66", "192.168.1.10"
	p2MAC, p2IP := "11:22:33:44:55:77", "192.168.1.11"

	p1NetMAC, _ := net.ParseMAC(p1MAC)
	p1NetIP := net.ParseIP(p1IP)
	p2NetMAC, _ := net.ParseMAC(p2MAC)
	p2NetIP := net.ParseIP(p2IP)

	// Create InterfaceConfig objects directly.
	containerConfig1 := interfacestore.NewContainerInterface("p1", uuid1, "Pod1", "nsA", "eth0", "netns1", p1NetMAC, []net.IP{p1NetIP}, 100)
	containerConfig1.OVSPortConfig = &interfacestore.OVSPortConfig{
		OFPort: 11,
	}
	containerConfig2 := interfacestore.NewContainerInterface("p2", uuid2, "Pod2", "nsA", "eth0", "netns2", p2NetMAC, []net.IP{p2NetIP}, 100)
	containerConfig2.OVSPortConfig = &interfacestore.OVSPortConfig{
		OFPort: 12,
	}
	containerConfig3 := interfacestore.NewContainerInterface("p3", uuid3, "Pod3", "nsA", "eth0", "netns3", p2NetMAC, []net.IP{p2NetIP}, 100)
	containerConfig3.OVSPortConfig = &interfacestore.OVSPortConfig{
		OFPort: -1,
	}
	// SR-IOV interface.
	containerConfig4 := interfacestore.NewContainerInterface("p4", uuid4, "Pod4", "nsA", "eth1", "netns4", p2NetMAC, []net.IP{p2NetIP}, 0)

	ovsPort1 := ovsconfig.OVSPortData{
		UUID: uuid1, Name: "p1", OFPort: 11,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			containerConfig1))}

	ovsPort2 := ovsconfig.OVSPortData{
		UUID: uuid2, Name: "p2", OFPort: 12,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			containerConfig2))}

	ovsPort3 := ovsconfig.OVSPortData{
		UUID: uuid3, Name: "p3", OFPort: -1,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			containerConfig3))}

	ovsPort4 := ovsconfig.OVSPortData{
		UUID:   uuid4,
		Name:   "unknownIface",
		OFPort: 20,
		ExternalIDs: map[string]string{
			"unknownKey": "unknownValue"}}

	return []ovsconfig.OVSPortData{ovsPort1, ovsPort2, ovsPort3, ovsPort4}, []*interfacestore.InterfaceConfig{containerConfig1, containerConfig2, containerConfig3, containerConfig4}
}

func TestInitializeOVSSecondaryInterfaceStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	pc, _, _, mockOVSBridgeClient := testPodController(ctrl)
	ovsPorts, _ := createTestInterfaces()
	mockOVSBridgeClient.EXPECT().GetPortList().Return(ovsPorts, nil)

	err := pc.initializeOVSSecondaryInterfaceStore()
	require.NoError(t, err, "OVS ports list successfully")

	// Validate stored interfaces.
	require.Equal(t, 3, pc.interfaceStore.Len(), "Only valid interfaces should be stored")

	_, found := pc.interfaceStore.GetContainerInterface(ovsPorts[0].UUID)
	assert.True(t, found, "Interface 1 should be stored")

	_, found = pc.interfaceStore.GetContainerInterface(ovsPorts[1].UUID)
	assert.True(t, found, "Interface 2 should be stored")

	_, found = pc.interfaceStore.GetContainerInterface(ovsPorts[2].UUID)
	assert.True(t, found, "Interface 3 should be stored")

	_, found = pc.interfaceStore.GetContainerInterface(ovsPorts[3].UUID)
	assert.False(t, found, "Unknown interface type should not be stored")
}

func TestReconcileSecondaryInterfaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	pc, mockIPAM, interfaceConfigurator, _ := testPodController(ctrl)
	_, containerConfigs := createTestInterfaces()

	// Add the interfaces to primary store.
	pc.primaryInterfaceStore.AddInterface(containerConfigs[0])
	pc.primaryInterfaceStore.AddInterface(containerConfigs[2])

	// Add interfaces to controller secondaryInterfaceStore.
	pc.interfaceStore.AddInterface(containerConfigs[0])
	// Interface (container ID) is not added to the primary interface store.
	pc.interfaceStore.AddInterface(containerConfigs[1])
	// Case when OFPort == -1.
	pc.interfaceStore.AddInterface(containerConfigs[2])
	// SR-IOV interface without a primary interface.
	pc.interfaceStore.AddInterface(containerConfigs[3])

	interfaceConfigurator.EXPECT().DeleteVLANSecondaryInterface(containerConfigs[1]).Return(nil).Times(1)
	interfaceConfigurator.EXPECT().DeleteVLANSecondaryInterface(containerConfigs[2]).Return(nil).Times(1)
	interfaceConfigurator.EXPECT().DeleteSriovSecondaryInterface(containerConfigs[3]).Return(nil).Times(1)
	mockIPAM.EXPECT().SecondaryNetworkRelease(gomock.Any()).Return(nil).Times(3)

	pc.initializeCNICache()
	pc.reconcileSecondaryInterfaces()

	// Check CNI Cache.
	podCount := 0
	pc.cniCache.Range(func(key, value interface{}) bool {
		podCount++
		return true
	})
	assert.Equal(t, 2, podCount, "CNI cache should contain two Pods")

	checkPodCNIInfo := func(t *testing.T, config *interfacestore.InterfaceConfig) {
		t.Helper()
		key := fmt.Sprintf("%s/%s", config.PodNamespace, config.PodName)
		value, foundPod := pc.cniCache.Load(key)
		podCNIInfo := value.(*podCNIInfo)
		assert.True(t, foundPod, "CNI cache should contain "+key)
		assert.Equal(t, config.ContainerID, podCNIInfo.containerID)
		assert.Equal(t, config.NetNS, podCNIInfo.netNS)
	}
	checkPodCNIInfo(t, containerConfigs[0])
	checkPodCNIInfo(t, containerConfigs[2])

	// Pod2 is not added to the primary store.
	_, found := pc.cniCache.Load("nsA/Pod2")
	assert.False(t, found, "Pod should not be added to CNI cache")
}

func TestInitializeSRIOVSecondaryInterfaceStore(t *testing.T) {
	pod1, _ := testPod("Pod1", containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	pod1.Annotations[netdefv1.NetworkStatusAnnot] = `[{
    "name": "antrea",
    "interface": "eth0",
    "ips": [
        "192.0.1.18"
    ],
    "mac": "02:79:48:39:4d:12",
    "default": true,
    "dns": {},
    "gateway": [
        "192.0.1.1"
    ]
    },{
    "name": "net",
    "ips": [
        "148.14.24.100"
    ],
    "dns": {},
    "device-info": {
        "type": "pci",
        "pci": {
            "pci-address": "sriov-device-id-11"
        }
    }
}]`
	// A Pod without NetworkStatus annotations should not be added to the store.
	pod2, _ := testPod("Pod2", containerID, podIP, netdefv1.NetworkSelectionElement{
		Name:             networkName,
		InterfaceRequest: interfaceName,
	})
	// A Pod without a corresponding NetworkAttachmentDefinition should not be added to the store.
	pod3, _ := testPod("Pod3", containerID, podIP)

	client := fake.NewSimpleClientset(pod1, pod2, pod3)
	netdefclient := netdefclientfake.NewSimpleClientset().K8sCniCncfIoV1()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)

	pc := &PodController{
		kubeClient:            client,
		netAttachDefClient:    netdefclient,
		podInformer:           informerFactory.Core().V1().Pods().Informer(),
		podLister:             informerFactory.Core().V1().Pods().Lister(),
		interfaceStore:        interfacestore.NewInterfaceStore(),
		primaryInterfaceStore: interfacestore.NewInterfaceStore(),
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	primaryStore := pc.primaryInterfaceStore
	_, containerConfigs := createTestInterfaces()
	primaryStore.AddInterface(containerConfigs[0])
	primaryStore.AddInterface(containerConfigs[1])
	primaryStore.AddInterface(containerConfigs[2])

	network1 := testNetworkExt(networkName, "", "", sriovNetworkType, sriovResourceName1, "", 1500, 0, true)
	_, err := pc.netAttachDefClient.NetworkAttachmentDefinitions(testNamespace).Create(context.Background(),
		network1, metav1.CreateOptions{})
	assert.NoError(t, err, "error when creating test NetworkAttachmentDefinition")

	err = pc.initializeSRIOVSecondaryInterfaceStore()
	require.NoError(t, err, "failed to initialize SR-IOV interface store")
	require.Equal(t, 1, pc.interfaceStore.Len())
	_, ok := pc.vfDeviceIDUsageMap.Load(podKeyGet(pod1.Name, pod1.Namespace))
	require.Equal(t, true, ok)
}
