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

package trafficcontrol

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

type fakeController struct {
	*Controller
	mockController      *gomock.Controller
	mockOFClient        *openflowtest.MockClient
	mockOVSCtlClient    *ovsctltest.MockOVSCtlClient
	mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient
	crdClient           *fakeversioned.Clientset
	crdInformerFactory  crdinformers.SharedInformerFactory
	client              *fake.Clientset
	informerFactory     informers.SharedInformerFactory
	localPodInformer    cache.SharedIndexInformer
	podUpdateChannel    *channel.SubscribableChannel
}

func (c *fakeController) startInformers(stopCh chan struct{}) {
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	go c.localPodInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, c.localPodInformer.HasSynced)
	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
}

var (
	labels1 = map[string]string{"app1": "foo1"}
	labels2 = map[string]string{"app2": "foo2"}
	labels3 = map[string]string{"app3": "foo3"}

	targetPort1Name = "target-port1"
	returnPort1Name = "return-port1"
	targetPort2Name = "target-port2"
	returnPort2Name = "return-port2"
	targetPort3Name = "target-port3"

	ns1 = newNamespace("ns1", labels1)
	ns2 = newNamespace("ns2", labels2)

	targetPort1 = &v1alpha2.NetworkDevice{Name: targetPort1Name}
	returnPort1 = &v1alpha2.NetworkDevice{Name: returnPort1Name}
	targetPort2 = &v1alpha2.NetworkDevice{Name: targetPort2Name}
	returnPort2 = &v1alpha2.NetworkDevice{Name: returnPort2Name}
	targetPort3 = &v1alpha2.NetworkDevice{Name: targetPort3Name}

	pod1 = newPod("ns1", "pod1", "fakeNode", labels1)
	pod2 = newPod("ns1", "pod2", "fakeNode", labels2)
	pod3 = newPod("ns2", "pod3", "fakeNode", labels1)
	pod4 = newPod("ns2", "pod4", "fakeNode", labels2)

	pod1NN = k8s.NamespacedName("ns1", "pod1")
	pod2NN = k8s.NamespacedName("ns1", "pod2")
	pod3NN = k8s.NamespacedName("ns2", "pod3")
	pod4NN = k8s.NamespacedName("ns2", "pod4")

	pod1OFPort        = uint32(1)
	pod2OFPort        = uint32(2)
	pod3OFPort        = uint32(3)
	pod4OFPort        = uint32(4)
	targetPort1OFPort = uint32(5)
	targetPort2OFPort = uint32(7)
	returnPort2OFPort = uint32(8)
	targetPort3OFPort = uint32(9)

	podInterface1    = newPodInterface("ns1", "pod1", int32(pod1OFPort))
	podInterface2    = newPodInterface("ns1", "pod2", int32(pod2OFPort))
	podInterface3    = newPodInterface("ns2", "pod3", int32(pod3OFPort))
	podInterface4    = newPodInterface("ns2", "pod4", int32(pod4OFPort))
	targetInterface1 = newTrafficControlInterface(targetPort1Name, int32(targetPort1OFPort))
	targetInterface2 = newTrafficControlInterface(targetPort2Name, int32(targetPort2OFPort))
	returnInterface2 = newTrafficControlInterface(returnPort2Name, int32(returnPort2OFPort))
	targetInterface3 = newTrafficControlInterface(targetPort3Name, int32(targetPort3OFPort))

	tc1Name = "test-tc1"
	tc2Name = "test-tc2"
	tc3Name = "test-tc3"

	directionIngress = v1alpha2.DirectionIngress
	directionEgress  = v1alpha2.DirectionEgress
	actionMirror     = v1alpha2.ActionMirror
	actionRedirect   = v1alpha2.ActionRedirect

	externalIDs = map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTrafficControl}
)

func newFakeController(t *testing.T, objects []runtime.Object, initObjects []runtime.Object, interfaces []*interfacestore.InterfaceConfig) *fakeController {
	controller := gomock.NewController(t)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)

	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)

	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	tcInformer := crdInformerFactory.Crd().V1alpha2().TrafficControls()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	nsInformer := informerFactory.Core().V1().Namespaces()

	localPodInformer := coreinformers.NewFilteredPodInformer(
		client,
		metav1.NamespaceAll,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", "fakeNode1").String()
		},
	)

	ifaceStore := interfacestore.NewInterfaceStore()
	for _, itf := range interfaces {
		ifaceStore.AddInterface(itf)
	}

	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	tcController := NewTrafficControlController(mockOFClient, ifaceStore, mockOVSBridgeClient, mockOVSCtlClient, tcInformer, localPodInformer, nsInformer, podUpdateChannel)
	podUpdateChannel.Subscribe(tcController.processPodUpdate)

	return &fakeController{
		Controller:          tcController,
		mockController:      controller,
		mockOFClient:        mockOFClient,
		mockOVSBridgeClient: mockOVSBridgeClient,
		mockOVSCtlClient:    mockOVSCtlClient,
		crdClient:           crdClient,
		crdInformerFactory:  crdInformerFactory,
		client:              client,
		informerFactory:     informerFactory,
		localPodInformer:    localPodInformer,
		podUpdateChannel:    podUpdateChannel,
	}
}

func newPod(ns, name, nodeName string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
	}
}

func newPodInterface(podNamespace, podName string, ofPort int32) *interfacestore.InterfaceConfig {
	containerName := k8s.NamespacedName(podNamespace, podName)
	return &interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName(podName, podNamespace, containerName),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: podName, PodNamespace: podNamespace, ContainerID: containerName},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort},
	}
}

func newTrafficControlInterface(interfaceName string, ofPort int32) *interfacestore.InterfaceConfig {
	return &interfacestore.InterfaceConfig{
		Type:                     interfacestore.TrafficControlInterface,
		InterfaceName:            interfaceName,
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort, PortUUID: interfaceName},
		TunnelInterfaceConfig:    &interfacestore.TunnelInterfaceConfig{},
	}
}

func newNamespace(ns string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ns,
			Labels: labels,
		},
	}
}

func generateTrafficControl(name string,
	nsSelector,
	podSelector map[string]string,
	direction v1alpha2.Direction,
	action v1alpha2.TrafficControlAction,
	targetPort interface{},
	isTargetPortVXLAN bool,
	returnPort interface{}) *v1alpha2.TrafficControl {
	tc := &v1alpha2.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: "test-uid"},
		Spec: v1alpha2.TrafficControlSpec{
			Direction:  direction,
			Action:     action,
			ReturnPort: &v1alpha2.TrafficControlPort{},
		}}
	if nsSelector != nil {
		tc.Spec.AppliedTo.NamespaceSelector = &metav1.LabelSelector{MatchLabels: nsSelector}
	}
	if podSelector != nil {
		tc.Spec.AppliedTo.PodSelector = &metav1.LabelSelector{MatchLabels: podSelector}
	}
	switch targetPort.(type) {
	case *v1alpha2.OVSInternalPort:
		tc.Spec.TargetPort.OVSInternal = targetPort.(*v1alpha2.OVSInternalPort)
	case *v1alpha2.NetworkDevice:
		tc.Spec.TargetPort.Device = targetPort.(*v1alpha2.NetworkDevice)
	case *v1alpha2.UDPTunnel:
		if isTargetPortVXLAN {
			tc.Spec.TargetPort.VXLAN = targetPort.(*v1alpha2.UDPTunnel)
		} else {
			tc.Spec.TargetPort.GENEVE = targetPort.(*v1alpha2.UDPTunnel)
		}
	case *v1alpha2.GRETunnel:
		tc.Spec.TargetPort.GRE = targetPort.(*v1alpha2.GRETunnel)
	case *v1alpha2.ERSPANTunnel:
		tc.Spec.TargetPort.ERSPAN = targetPort.(*v1alpha2.ERSPANTunnel)
	}

	switch returnPort.(type) {
	case *v1alpha2.OVSInternalPort:
		tc.Spec.ReturnPort.OVSInternal = returnPort.(*v1alpha2.OVSInternalPort)
	case *v1alpha2.NetworkDevice:
		tc.Spec.ReturnPort.Device = returnPort.(*v1alpha2.NetworkDevice)
	default:
		tc.Spec.ReturnPort = nil
	}
	return tc
}

func generateTrafficControlState(direction v1alpha2.Direction,
	action v1alpha2.TrafficControlAction,
	targetPortName string,
	targetOFPort uint32,
	returnPortName string,
	ofPorts sets.Set[int32],
	pods sets.Set[string]) *trafficControlState {
	return &trafficControlState{
		targetPortName: targetPortName,
		targetOFPort:   targetOFPort,
		returnPortName: returnPortName,
		action:         action,
		direction:      direction,
		ofPorts:        ofPorts,
		pods:           pods,
	}
}

func waitEvents(t *testing.T, expectedEvents int, c *fakeController) {
	require.Eventually(t, func() bool {
		return c.queue.Len() == expectedEvents
	}, 5*time.Second, 10*time.Millisecond)
}

func TestTrafficControlAdd(t *testing.T) {
	destinationPort := int32(1234)
	vni := int32(1)
	greKey := int32(2222)
	remoteIP := "1.1.1.1"
	erspanDir := int32(1)
	erspanHwID := int32(1)

	networkDeviceName := "non-existing-port"
	networkDevice := &v1alpha2.NetworkDevice{Name: networkDeviceName}
	udpTunnel := &v1alpha2.UDPTunnel{RemoteIP: remoteIP, VNI: &vni, DestinationPort: &destinationPort}
	greTunnel := &v1alpha2.GRETunnel{RemoteIP: remoteIP, Key: &greKey}
	erspanTunnel := &v1alpha2.ERSPANTunnel{Version: 2, RemoteIP: remoteIP, Dir: &erspanDir, HardwareID: &erspanHwID}

	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
		podInterface3,
		podInterface4,
	}

	testcases := []struct {
		name             string
		tc               *v1alpha2.TrafficControl
		extraInterfaces  []*interfacestore.InterfaceConfig
		portToTCBindings map[string]*portToTCBinding
		expectedCalls    func(mockOFClient *openflowtest.MockClient,
			mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
			MockOVSCtlClient *ovsctltest.MockOVSCtlClient)
	}{
		{
			name: "Add TrafficControl with non-existing target port (NetworkDevice)",
			tc:   generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, networkDevice, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOVSBridgeClient.EXPECT().CreatePort(networkDeviceName, networkDeviceName, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(networkDeviceName, false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(0)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name: "Add TrafficControl with non-existing target port (VXLAN)",
			tc:   generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, udpTunnel, true, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				extraOptions := map[string]interface{}{"key": strconv.Itoa(int(vni)), "dst_port": strconv.Itoa(int(destinationPort))}

				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt(gomock.Any(), ovsconfig.TunnelType(ovsconfig.VXLANTunnel), int32(0), false, "", remoteIP, "", "", extraOptions, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(gomock.Any(), false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name: "Add TrafficControl with non-existing target port (GENEVE)",
			tc:   generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, udpTunnel, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				extraOptions := map[string]interface{}{"key": strconv.Itoa(int(vni)), "dst_port": strconv.Itoa(int(destinationPort))}

				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt(gomock.Any(), ovsconfig.TunnelType(ovsconfig.GeneveTunnel), int32(0), false, "", remoteIP, "", "", extraOptions, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(gomock.Any(), false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name: "Add TrafficControl with non-existing target port (GRE)",
			tc:   generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, greTunnel, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				extraOptions := map[string]interface{}{"key": strconv.Itoa(int(greKey))}

				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt(gomock.Any(), ovsconfig.TunnelType(ovsconfig.GRETunnel), int32(0), false, "", remoteIP, "", "", extraOptions, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(gomock.Any(), false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name: "Add TrafficControl with non-existing target port (ERSPAN)",
			tc:   generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, erspanTunnel, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				extraOptions := map[string]interface{}{"erspan_ver": "2", "erspan_dir": strconv.Itoa(int(erspanDir)), "erspan_hwid": strconv.Itoa(int(erspanHwID))}

				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt(gomock.Any(), ovsconfig.TunnelType(ovsconfig.ERSPANTunnel), int32(0), false, "", remoteIP, "", "", extraOptions, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(gomock.Any(), false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:            "Add TrafficControl with existing target port and return port",
			tc:              generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionRedirect, targetPort2, false, returnPort2),
			extraInterfaces: []*interfacestore.InterfaceConfig{targetInterface2, returnInterface2},
			portToTCBindings: map[string]*portToTCBinding{
				targetPort2Name: {targetInterface2, sets.New[string](tc2Name)},
				returnPort2Name: {returnInterface2, sets.New[string](tc2Name)},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), targetPort2OFPort, directionIngress, actionRedirect, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:            "Add TrafficControl with only Pod selector",
			tc:              generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort1, false, nil),
			extraInterfaces: []*interfacestore.InterfaceConfig{targetInterface1},
			portToTCBindings: map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc2Name)},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:            "Add TrafficControl with only Namespace selector",
			extraInterfaces: []*interfacestore.InterfaceConfig{targetInterface1},
			portToTCBindings: map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc2Name)},
			},
			tc: generateTrafficControl(tc1Name, labels1, nil, directionIngress, actionMirror, targetPort1, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod2OFPort}), targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:            "Add TrafficControl with Pod selector and Namespace selector",
			extraInterfaces: []*interfacestore.InterfaceConfig{targetInterface1},
			portToTCBindings: map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc2Name)},
			},
			tc: generateTrafficControl(tc1Name, labels1, labels2, directionIngress, actionRedirect, targetPort1, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, []uint32{pod2OFPort}, targetPort1OFPort, directionIngress, actionRedirect, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:            "Add TrafficControl with nil Pod selector and nil Namespace selector",
			extraInterfaces: []*interfacestore.InterfaceConfig{targetInterface1},
			portToTCBindings: map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc2Name)},
			},
			tc: generateTrafficControl(tc1Name, nil, nil, directionIngress, actionRedirect, targetPort1, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionRedirect, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:            "Add TrafficControl with empty Pod selector and empty Namespace selector",
			extraInterfaces: []*interfacestore.InterfaceConfig{targetInterface1},
			portToTCBindings: map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc2Name)},
			},
			tc: generateTrafficControl(tc1Name, map[string]string{}, map[string]string{}, directionIngress, actionRedirect, targetPort1, false, nil),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, []uint32{pod1OFPort, pod2OFPort, pod3OFPort, pod4OFPort}, targetPort1OFPort, directionIngress, actionRedirect, types.TrafficControlFlowPriorityMedium)
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			c := newFakeController(t, []runtime.Object{ns1, ns2, pod1, pod2, pod3, pod4}, []runtime.Object{tt.tc}, append(interfaces, tt.extraInterfaces...))

			if tt.portToTCBindings != nil {
				c.portToTCBindings = tt.portToTCBindings
			}

			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			tt.expectedCalls(c.mockOFClient, c.mockOVSBridgeClient, c.mockOVSCtlClient)
			assert.NoError(t, c.syncTrafficControl(tt.tc.Name))
		})
	}
}

func TestTrafficControlUpdate(t *testing.T) {
	tc1 := generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort1, false, nil)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
		podInterface3,
		podInterface4,
		targetInterface1,
	}

	testcases := []struct {
		name                  string
		updatedTrafficControl *v1alpha2.TrafficControl
		expectedState         *trafficControlState
		expectedCalls         func(mockOFClient *openflowtest.MockClient,
			mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
			MockOVSCtlClient *ovsctltest.MockOVSCtlClient)
	}{
		{
			name:                  "Update TrafficControl target port (NetworkDevice)",
			updatedTrafficControl: generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort2, false, nil),
			expectedState:         generateTrafficControlState(directionIngress, actionMirror, targetPort2Name, 0, "", sets.New[int32](int32(pod1OFPort), int32(pod3OFPort)), sets.New[string](pod1NN, pod3NN)),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOVSBridgeClient.EXPECT().DeletePort(gomock.Any())
				mockOVSBridgeClient.EXPECT().CreatePort(targetPort2Name, targetPort2Name, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(targetPort2Name, false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                  "Update TrafficControl action",
			updatedTrafficControl: generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionRedirect, targetPort1, false, returnPort1),
			expectedState:         generateTrafficControlState(directionIngress, actionRedirect, targetPort1Name, targetPort1OFPort, returnPort1Name, sets.New[int32](int32(pod1OFPort), int32(pod3OFPort)), sets.New[string](pod1NN, pod3NN)),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOVSBridgeClient.EXPECT().CreatePort(returnPort1Name, returnPort1Name, externalIDs)
				mockOVSBridgeClient.EXPECT().GetOFPort(returnPort1Name, false)
				mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlReturnPortFlow(gomock.Any())
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), targetPort1OFPort, directionIngress, actionRedirect, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                  "Update TrafficControl direction",
			updatedTrafficControl: generateTrafficControl(tc1Name, nil, labels1, directionEgress, actionMirror, targetPort1, false, nil),
			expectedState:         generateTrafficControlState(directionEgress, actionMirror, targetPort1Name, targetPort1OFPort, "", sets.New[int32](int32(pod1OFPort), int32(pod3OFPort)), sets.New[string](pod1NN, pod3NN)),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), targetPort1OFPort, directionEgress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                  "Update TrafficControl Pod selector",
			updatedTrafficControl: generateTrafficControl(tc1Name, nil, labels2, directionIngress, actionMirror, targetPort1, false, nil),
			expectedState:         generateTrafficControlState(directionIngress, actionMirror, targetPort1Name, targetPort1OFPort, "", sets.New[int32](int32(pod2OFPort), int32(pod4OFPort)), sets.New[string](pod2NN, pod4NN)),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod2OFPort, pod4OFPort}), targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                  "Update TrafficControl Namespace selector",
			updatedTrafficControl: generateTrafficControl(tc1Name, labels2, labels1, directionIngress, actionMirror, targetPort1, false, nil),
			expectedState:         generateTrafficControlState(directionIngress, actionMirror, targetPort1Name, targetPort1OFPort, "", sets.New[int32](int32(pod3OFPort)), sets.New[string](pod3NN)),
			expectedCalls: func(mockOFClient *openflowtest.MockClient,
				mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient,
				mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, []uint32{pod3OFPort}, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, []runtime.Object{ns1, ns2, pod1, pod2, pod3, pod4}, []runtime.Object{tc1}, interfaces)

			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			// Fake the status after TrafficControl tc1 is added.
			c.portToTCBindings = map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc1Name)},
			}
			c.tcStates = map[string]*trafficControlState{
				tc1Name: {
					targetPortName: targetPort1Name,
					targetOFPort:   targetPort1OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](int32(pod1OFPort), int32(pod3OFPort)),
					pods:           sets.New[string](pod1NN, pod3NN),
				},
			}
			c.podToTCBindings = map[string]*podToTCBinding{
				pod1NN: {effectiveTC: tc1Name, alternativeTCs: sets.New[string]()},
				pod3NN: {effectiveTC: tc1Name, alternativeTCs: sets.New[string]()},
			}

			// Ignore the TrafficControl ADD events for TrafficControl tc1.
			waitEvents(t, 1, c)
			item, _ := c.queue.Get()
			c.queue.Done(item)

			tt.updatedTrafficControl.Generation += 1
			_, err := c.crdClient.CrdV1alpha2().TrafficControls().Update(context.TODO(), tt.updatedTrafficControl, metav1.UpdateOptions{})
			require.NoError(t, err)

			// Functions are expected to be called after updating TrafficControl tc1.
			tt.expectedCalls(c.mockOFClient, c.mockOVSBridgeClient, c.mockOVSCtlClient)

			waitEvents(t, 1, c)
			require.NoError(t, c.syncTrafficControl(tc1Name))
			require.Equal(t, tt.expectedState, c.tcStates[tc1Name])
		})
	}
}

func TestSharedTargetPort(t *testing.T) {
	tc1 := generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort1, false, nil)
	tc2 := generateTrafficControl(tc2Name, nil, labels2, directionIngress, actionMirror, targetPort1, false, nil)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
		podInterface3,
		podInterface4,
	}

	c := newFakeController(t, []runtime.Object{pod1, pod2, pod3, pod4}, []runtime.Object{tc1, tc2}, interfaces)

	stopCh := make(chan struct{})
	defer close(stopCh)

	c.startInformers(stopCh)

	// Target port is expected to be crated if it doesn't exist.
	c.mockOVSBridgeClient.EXPECT().CreatePort(targetPort1Name, targetPort1Name, externalIDs)
	c.mockOVSBridgeClient.EXPECT().GetOFPort(targetPort1Name, false).Times(1)
	c.mockOVSCtlClient.EXPECT().SetPortNoFlood(gomock.Any())
	// Mark flows for TrafficControl tc1 and tc2 are expected to be installed.
	c.mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, gomock.InAnyOrder([]uint32{pod1OFPort, pod3OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
	c.mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc2Name, gomock.InAnyOrder([]uint32{pod2OFPort, pod4OFPort}), gomock.Any(), directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)

	// Process the TrafficControl ADD events for TrafficControl tc1 and tc2.
	waitEvents(t, 2, c)
	for i := 0; i < 2; i++ {
		item, _ := c.queue.Get()
		require.NoError(t, c.syncTrafficControl(item.(string)))
		c.queue.Done(item)
	}

	// If TrafficControl tc1 is deleted, then TrafficControl tc2 is deleted, the created target port is expected to be
	// deleted after delete all TrafficControls using the target port.
	s1 := c.mockOFClient.EXPECT().UninstallTrafficControlMarkFlows(tc1Name)
	s2 := c.mockOFClient.EXPECT().UninstallTrafficControlMarkFlows(tc2Name)
	s3 := c.mockOVSBridgeClient.EXPECT().DeletePort(gomock.Any())
	gomock.InOrder(s1, s2, s3)

	// Delete TrafficControl tc1.
	require.NoError(t, c.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc1Name, metav1.DeleteOptions{}))
	// Process the TrafficControl DELETE event.
	waitEvents(t, 1, c)
	item, _ := c.queue.Get()
	require.Equal(t, tc1Name, item)
	require.NoError(t, c.syncTrafficControl(item.(string)))
	c.queue.Done(item)

	// Delete TrafficControl tc2.
	require.NoError(t, c.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc2Name, metav1.DeleteOptions{}))
	// Process the TrafficControl DELETE event.
	waitEvents(t, 1, c)
	item, _ = c.queue.Get()
	require.Equal(t, tc2Name, item)
	require.NoError(t, c.syncTrafficControl(item.(string)))
	c.queue.Done(item)
}

func TestPodUpdateFromCNIServer(t *testing.T) {
	tc1 := generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort1, false, nil)

	c := newFakeController(t, nil, []runtime.Object{tc1}, []*interfacestore.InterfaceConfig{targetInterface1})

	stopCh := make(chan struct{})
	defer close(stopCh)

	c.startInformers(stopCh)
	go c.podUpdateChannel.Run(stopCh)

	// Fake the status after TrafficControl tc1 is added.
	c.portToTCBindings = map[string]*portToTCBinding{
		targetPort1Name: {targetInterface1, sets.New[string](tc1Name)},
	}
	c.tcStates = map[string]*trafficControlState{
		tc1Name: {
			targetPortName: targetPort1Name,
			targetOFPort:   targetPort1OFPort,
			action:         actionMirror,
			direction:      directionIngress,
			ofPorts:        sets.New[int32](),
			pods:           sets.New[string](),
		},
	}

	// Ignore the TrafficControl ADD event for TrafficControl tc1.
	item, _ := c.queue.Get()
	c.queue.Done(item)

	// Create a test Pod applying to the TrafficControl tc1.
	_, err := c.client.CoreV1().Pods("ns1").Create(context.TODO(), pod1, metav1.CreateOptions{})
	require.NoError(t, err)

	// Process the TrafficControl event triggered by adding the test Pod. Note that, the interface of the Pod is not ready,
	// and corresponding mark flows will not be installed.
	waitEvents(t, 1, c)
	item, _ = c.queue.Get()
	require.Equal(t, tc1Name, item)
	require.NoError(t, c.syncTrafficControl(item.(string)))
	c.queue.Done(item)

	// After syncing, verify the state of TrafficControl tc1.
	expectedState := generateTrafficControlState(directionIngress, actionMirror, targetPort1Name, targetPort1OFPort, "", sets.New[int32](), sets.New[string](pod1NN))
	require.Equal(t, expectedState, c.tcStates[tc1Name])

	// Mark flows are expected to be installed after the interface of the Pod is ready.
	c.mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, []uint32{pod1OFPort}, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)

	// Add the interface information of the test Pod to interface store to mock the interface of the Pod is ready, then
	// add an update event to podUpdateChannel to trigger a TrafficControl event.
	c.interfaceStore.AddInterface(podInterface1)
	ev := types.PodUpdate{PodName: "pod1", PodNamespace: "ns1"}
	c.podUpdateChannel.Notify(ev)

	// Process the TrafficControl event triggered by Pod update event from CNI server.
	waitEvents(t, 1, c)
	item, _ = c.queue.Get()
	require.Equal(t, tc1Name, item)
	require.NoError(t, c.syncTrafficControl(item.(string)))
	c.queue.Done(item)

	// After syncing, verify the state of TrafficControl tc1.
	expectedState = generateTrafficControlState(directionIngress, actionMirror, targetPort1Name, targetPort1OFPort, "", sets.New[int32](int32(pod1OFPort)), sets.New[string](pod1NN))
	require.Equal(t, expectedState, c.tcStates[tc1Name])
}

func TestPodLabelsUpdate(t *testing.T) {
	tc1 := generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort1, false, nil)
	tc2 := generateTrafficControl(tc2Name, nil, labels2, directionIngress, actionMirror, targetPort2, false, nil)
	tc3 := generateTrafficControl(tc3Name, nil, labels3, directionIngress, actionMirror, targetPort3, false, nil)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		targetInterface1,
		targetInterface2,
		targetInterface3,
	}
	labels12 := map[string]string{"app1": "foo1", "app2": "foo2"}
	labels13 := map[string]string{"app1": "foo1", "app3": "foo3"}
	labels23 := map[string]string{"app2": "foo2", "app3": "foo3"}
	testPod := newPod("ns1", "pod1", "fakeNode", labels12)
	testPodNN := k8s.NamespacedName("ns1", "pod1")

	testcases := []struct {
		name                                  string
		updatedPod                            *v1.Pod
		eventsTriggeredByPodLabelsUpdate      int
		eventsTriggeredByPodLabelsUpdateOrder []interface{}
		eventsTriggeredByPodEffectiveTCUpdate int
		expectedPodBinding                    *podToTCBinding
		expectedCalls                         func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name:                             "Update Pod labels to match none TrafficControl",
			updatedPod:                       newPod("ns1", "pod1", "fakeNode", nil),
			eventsTriggeredByPodLabelsUpdate: 2,
			expectedPodBinding:               nil,
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                             "Update Pod labels to match matching only TrafficControl tc1",
			updatedPod:                       newPod("ns1", "pod1", "fakeNode", labels1),
			eventsTriggeredByPodLabelsUpdate: 1,
			expectedPodBinding:               &podToTCBinding{effectiveTC: tc1Name, alternativeTCs: sets.New[string]()},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
			},
		},
		{
			name:                                  "SUpdate Pod labels to match only TrafficControl tc2",
			updatedPod:                            newPod("ns1", "pod1", "fakeNode", labels2),
			eventsTriggeredByPodLabelsUpdate:      1,
			eventsTriggeredByPodEffectiveTCUpdate: 1,
			expectedPodBinding:                    &podToTCBinding{effectiveTC: tc2Name, alternativeTCs: sets.New[string]()},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc2Name, []uint32{pod1OFPort}, targetPort2OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                                  "Update Pod labels to match TrafficControl tc2 (effective), tc3 (alternative)",
			updatedPod:                            newPod("ns1", "pod1", "fakeNode", labels23),
			eventsTriggeredByPodLabelsUpdate:      2,
			eventsTriggeredByPodLabelsUpdateOrder: []interface{}{tc1Name, tc3Name},
			eventsTriggeredByPodEffectiveTCUpdate: 1,
			expectedPodBinding:                    &podToTCBinding{effectiveTC: tc2Name, alternativeTCs: sets.New[string](tc3Name)},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc2Name, []uint32{pod1OFPort}, targetPort2OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                             "Update Pod labels to match TrafficControl tc1 (effective), tc3 (alternative)",
			updatedPod:                       newPod("ns1", "pod1", "fakeNode", labels13),
			eventsTriggeredByPodLabelsUpdate: 2,
			expectedPodBinding:               &podToTCBinding{effectiveTC: tc1Name, alternativeTCs: sets.New[string](tc3Name)},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, []runtime.Object{testPod}, []runtime.Object{tc1, tc2, tc3}, interfaces)

			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			// Fake the status after TrafficControl tc1, tc2 and tc3 is added. TrafficControl tc1 is the effective
			// TrafficControl of the Pod, and tc2 is the alternative TrafficControl of the Pod.
			c.portToTCBindings = map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc1Name)},
				targetPort2Name: {targetInterface2, sets.New[string](tc2Name)},
				targetPort3Name: {targetInterface3, sets.New[string](tc3Name)},
			}
			c.tcStates = map[string]*trafficControlState{
				tc1Name: {
					targetPortName: targetPort1Name,
					targetOFPort:   targetPort1OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](int32(pod1OFPort)),
					pods:           sets.New[string](pod1NN),
				},
				tc2Name: {
					targetPortName: targetPort2Name,
					targetOFPort:   targetPort2OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](),
					pods:           sets.New[string](pod1NN),
				},
				tc3Name: {
					targetPortName: targetPort3Name,
					targetOFPort:   targetPort3OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](),
					pods:           sets.New[string](),
				},
			}
			c.podToTCBindings = map[string]*podToTCBinding{
				pod1NN: {effectiveTC: tc1Name, alternativeTCs: sets.New[string](tc2Name)},
			}

			// Ignore the TrafficControl ADD events for TrafficControl tc1, tc2 and tc3.
			waitEvents(t, 3, c)
			for i := 0; i < 3; i++ {
				item, _ := c.queue.Get()
				c.queue.Done(item)
			}

			// Functions are expected to be called after updating the labels of the Pod.
			tt.expectedCalls(c.mockOFClient)

			// Update the labels of the Pod.
			_, err := c.client.CoreV1().Pods("ns1").Update(context.TODO(), tt.updatedPod, metav1.UpdateOptions{})
			require.NoError(t, err)

			// Updating the labels of the Pod will trigger events for all affected TrafficControls, but the order of the
			// events is random. To make sure the test work as expected (TrafficControl tc2 is promoted to the effective
			// TrafficControl of the Pod), we need to rearrange the order of events.
			if len(tt.eventsTriggeredByPodLabelsUpdateOrder) != 0 {
				waitEvents(t, tt.eventsTriggeredByPodLabelsUpdate, c)
				var events []interface{}
				for i := 0; i < tt.eventsTriggeredByPodLabelsUpdate; i++ {
					item, _ := c.queue.Get()
					events = append(events, item)
					c.queue.Done(item)
				}
				require.ElementsMatch(t, tt.eventsTriggeredByPodLabelsUpdateOrder, events)
				for _, event := range tt.eventsTriggeredByPodLabelsUpdateOrder {
					c.queue.Add(event)
				}
			}

			// Process the events of TrafficControls triggered by updating the labels of the Pod.
			waitEvents(t, tt.eventsTriggeredByPodLabelsUpdate, c)
			for i := 0; i < tt.eventsTriggeredByPodLabelsUpdate; i++ {
				item, _ := c.queue.Get()
				require.NoError(t, c.syncTrafficControl(item.(string)))
				c.queue.Done(item)
			}

			// Event can be also triggered by updating the effective TrafficControl of a Pod.
			if tt.eventsTriggeredByPodEffectiveTCUpdate > 0 {
				waitEvents(t, tt.eventsTriggeredByPodEffectiveTCUpdate, c)
				for i := 0; i < tt.eventsTriggeredByPodEffectiveTCUpdate; i++ {
					item, _ := c.queue.Get()
					require.NoError(t, c.syncTrafficControl(item.(string)))
					c.queue.Done(item)
				}
			}

			// check the binding information of the Pod.
			require.Equal(t, tt.expectedPodBinding, c.podToTCBindings[testPodNN])
		})
	}
}

func TestNamespaceLabelsUpdate(t *testing.T) {
	tc1 := generateTrafficControl(tc1Name, labels1, nil, directionIngress, actionMirror, targetPort1, false, nil)
	tc2 := generateTrafficControl(tc2Name, labels2, nil, directionIngress, actionMirror, targetPort2, false, nil)
	tc3 := generateTrafficControl(tc3Name, labels3, nil, directionIngress, actionMirror, targetPort3, false, nil)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		targetInterface1,
		targetInterface2,
		targetInterface3,
	}
	labels12 := map[string]string{"app1": "foo1", "app2": "foo2"}
	labels13 := map[string]string{"app1": "foo1", "app3": "foo3"}
	labels23 := map[string]string{"app2": "foo2", "app3": "foo3"}
	testPod := newPod("ns1", "pod1", "fakeNode", map[string]string{})
	testNS := newNamespace("ns1", labels12)
	testPodNN := k8s.NamespacedName("ns1", "pod1")

	testcases := []struct {
		name                                  string
		updatedNS                             *v1.Namespace
		eventsTriggeredByNSLabelsUpdate       int
		eventsTriggeredByNSLabelsUpdateOrder  []interface{}
		eventsTriggeredByPodEffectiveTCUpdate int
		expectedPodBinding                    *podToTCBinding
		expectedCalls                         func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name:                            "Update Namespace labels to match none TrafficControl",
			updatedNS:                       newNamespace("ns1", nil),
			eventsTriggeredByNSLabelsUpdate: 2,
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                            "Update Pod labels to match only TrafficControl tc1",
			updatedNS:                       newNamespace("ns1", labels1),
			eventsTriggeredByNSLabelsUpdate: 1,
			expectedPodBinding:              &podToTCBinding{effectiveTC: tc1Name, alternativeTCs: sets.New[string]()},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
			},
		},
		{
			name:                                  "Update Pod labels to match only TrafficControl tc2",
			updatedNS:                             newNamespace("ns1", labels2),
			eventsTriggeredByNSLabelsUpdate:       1,
			eventsTriggeredByPodEffectiveTCUpdate: 1,
			expectedPodBinding:                    &podToTCBinding{effectiveTC: tc2Name, alternativeTCs: sets.New[string]()},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc2Name, []uint32{pod1OFPort}, targetPort2OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                                  "Update Pod labels to match TrafficControl tc2 (effective), tc3 (alternative)",
			updatedNS:                             newNamespace("ns1", labels23),
			eventsTriggeredByNSLabelsUpdate:       2,
			eventsTriggeredByNSLabelsUpdateOrder:  []interface{}{tc1Name, tc3Name},
			eventsTriggeredByPodEffectiveTCUpdate: 1,
			expectedPodBinding:                    &podToTCBinding{effectiveTC: tc2Name, alternativeTCs: sets.New[string](tc3Name)},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, nil, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc2Name, []uint32{pod1OFPort}, targetPort2OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
			},
		},
		{
			name:                            "Update Pod labels to match TrafficControl tc1 (effective), tc3 (alternative)",
			updatedNS:                       newNamespace("ns1", labels13),
			eventsTriggeredByNSLabelsUpdate: 2,
			expectedPodBinding:              &podToTCBinding{effectiveTC: tc1Name, alternativeTCs: sets.New[string](tc3Name)},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, []runtime.Object{testNS, testPod}, []runtime.Object{tc1, tc2, tc3}, interfaces)

			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			// Fake the status after TrafficControl tc1, tc2 and tc3 is added. TrafficControl tc1 is the effective
			// TrafficControl of the Pod, and tc2 is the alternative TrafficControl of the Pod.
			c.portToTCBindings = map[string]*portToTCBinding{
				targetPort1Name: {targetInterface1, sets.New[string](tc1Name)},
				targetPort2Name: {targetInterface2, sets.New[string](tc2Name)},
				targetPort3Name: {targetInterface3, sets.New[string](tc3Name)},
			}
			c.tcStates = map[string]*trafficControlState{
				tc1Name: {
					targetPortName: targetPort1Name,
					targetOFPort:   targetPort1OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](int32(pod1OFPort)),
					pods:           sets.New[string](pod1NN),
				},
				tc2Name: {
					targetPortName: targetPort2Name,
					targetOFPort:   targetPort2OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](),
					pods:           sets.New[string](pod1NN),
				},
				tc3Name: {
					targetPortName: targetPort3Name,
					targetOFPort:   targetPort3OFPort,
					action:         actionMirror,
					direction:      directionIngress,
					ofPorts:        sets.New[int32](),
					pods:           sets.New[string](),
				},
			}
			c.podToTCBindings = map[string]*podToTCBinding{
				pod1NN: {effectiveTC: tc1Name, alternativeTCs: sets.New[string](tc2Name)},
			}

			// Ignore the TrafficControl ADD events for TrafficControl tc1, tc2 and tc3.
			waitEvents(t, 3, c)
			for i := 0; i < 3; i++ {
				item, _ := c.queue.Get()
				c.queue.Done(item)
			}

			// Functions are expected to be called after updating the labels of the Namespace.
			tt.expectedCalls(c.mockOFClient)

			// Update the labels of the Namespace.
			_, err := c.client.CoreV1().Namespaces().Update(context.TODO(), tt.updatedNS, metav1.UpdateOptions{})
			require.NoError(t, err)

			// Updating the labels of the Namespace will trigger events for all affected TrafficControls, but the order of
			// the events is random. To make sure the test work as expected (TrafficControl tc2 is promoted to the effective
			// TrafficControl of the Pod in Namespace in ns1), we need to rearrange the order of events.
			if len(tt.eventsTriggeredByNSLabelsUpdateOrder) != 0 {
				waitEvents(t, tt.eventsTriggeredByNSLabelsUpdate, c)
				var events []interface{}
				for i := 0; i < tt.eventsTriggeredByNSLabelsUpdate; i++ {
					item, _ := c.queue.Get()
					events = append(events, item)
					c.queue.Done(item)
				}
				require.ElementsMatch(t, tt.eventsTriggeredByNSLabelsUpdateOrder, events)
				for _, event := range tt.eventsTriggeredByNSLabelsUpdateOrder {
					c.queue.Add(event)
				}
			}

			// Process the events of TrafficControls triggered by updating the labels of the Namespace.
			waitEvents(t, tt.eventsTriggeredByNSLabelsUpdate, c)
			for i := 0; i < tt.eventsTriggeredByNSLabelsUpdate; i++ {
				item, _ := c.queue.Get()
				require.NoError(t, c.syncTrafficControl(item.(string)))
				c.queue.Done(item)
			}

			// Event can be also triggered by updating the effective TrafficControl of a Pod.
			if tt.eventsTriggeredByPodEffectiveTCUpdate > 0 {
				waitEvents(t, tt.eventsTriggeredByPodEffectiveTCUpdate, c)
				for i := 0; i < tt.eventsTriggeredByPodEffectiveTCUpdate; i++ {
					item, _ := c.queue.Get()
					require.NoError(t, c.syncTrafficControl(item.(string)))
					c.queue.Done(item)
				}
			}

			// check the binding information of the Pod.
			require.Equal(t, tt.expectedPodBinding, c.podToTCBindings[testPodNN])
		})
	}
}

func TestPodDelete(t *testing.T) {
	tc1 := generateTrafficControl(tc1Name, nil, labels1, directionIngress, actionMirror, targetPort1, false, nil)
	tc2 := generateTrafficControl(tc2Name, nil, labels1, directionIngress, actionMirror, targetPort2, false, nil)
	tc3 := generateTrafficControl(tc3Name, nil, labels1, directionIngress, actionMirror, targetPort3, false, nil)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface3,
		targetInterface1,
		targetInterface2,
		targetInterface3,
	}

	c := newFakeController(t, []runtime.Object{pod1, pod3}, []runtime.Object{tc1, tc2, tc3}, interfaces)

	stopCh := make(chan struct{})
	defer close(stopCh)

	c.startInformers(stopCh)

	// Fake the status after TrafficControl tc1, tc2 and tc3 is added. TrafficControl tc1 is the effective
	// TrafficControl of the Pod, and tc2, tc3 is the alternative TrafficControl of the Pods.
	c.portToTCBindings = map[string]*portToTCBinding{
		targetPort1Name: {targetInterface1, sets.New[string](tc1Name)},
		targetPort2Name: {targetInterface2, sets.New[string](tc2Name)},
		targetPort3Name: {targetInterface3, sets.New[string](tc3Name)},
	}
	c.tcStates = map[string]*trafficControlState{
		tc1Name: {
			targetPortName: targetPort1Name,
			targetOFPort:   targetPort1OFPort,
			action:         actionMirror,
			direction:      directionIngress,
			ofPorts:        sets.New[int32](int32(pod1OFPort), int32(pod3OFPort)),
			pods:           sets.New[string](pod1NN, pod3NN),
		},
		tc2Name: {
			targetPortName: targetPort2Name,
			targetOFPort:   targetPort2OFPort,
			action:         actionMirror,
			direction:      directionIngress,
			ofPorts:        sets.New[int32](),
			pods:           sets.New[string](pod1NN, pod3NN),
		},
		tc3Name: {
			targetPortName: targetPort3Name,
			targetOFPort:   targetPort3OFPort,
			action:         actionMirror,
			direction:      directionIngress,
			ofPorts:        sets.New[int32](),
			pods:           sets.New[string](pod1NN, pod3NN),
		},
	}
	c.podToTCBindings = map[string]*podToTCBinding{
		pod1NN: {effectiveTC: tc1Name, alternativeTCs: sets.New[string](tc2Name, tc3Name)},
		pod3NN: {effectiveTC: tc1Name, alternativeTCs: sets.New[string](tc2Name, tc3Name)},
	}

	// Ignore the TrafficControl ADD events for TrafficControl tc1, tc2 and tc3.
	waitEvents(t, 3, c)
	for i := 0; i < 3; i++ {
		item, _ := c.queue.Get()
		c.queue.Done(item)
	}

	c.mockOFClient.EXPECT().InstallTrafficControlMarkFlows(tc1Name, []uint32{pod3OFPort}, targetPort1OFPort, directionIngress, actionMirror, types.TrafficControlFlowPriorityMedium)
	expectedPod3Binding := &podToTCBinding{
		effectiveTC:    tc1Name,
		alternativeTCs: sets.New[string](tc2Name, tc3Name),
	}

	// Delete Pod pod1.
	require.NoError(t, c.client.CoreV1().Pods(pod1.Namespace).Delete(context.TODO(), pod1.Name, metav1.DeleteOptions{}))

	// Process the TrafficControl events triggered by deleting Pod pod1.
	waitEvents(t, 3, c)
	for i := 0; i < 3; i++ {
		item, _ := c.queue.Get()
		require.NoError(t, c.syncTrafficControl(item.(string)))
		c.queue.Done(item)
	}

	// Check the binding information of Pod pod1, pod3 and TrafficControl.
	_, exists := c.podToTCBindings[pod1NN]
	require.Equal(t, false, exists)
	require.Equal(t, expectedPod3Binding, c.podToTCBindings[pod3NN])
}

func int32Ptr(i int32) *int32 {
	j := i
	return &j
}

func TestGenTunnelPortName(t *testing.T) {
	testcases := []struct {
		name         string
		ports        []*v1alpha2.TrafficControlPort
		expectedName string
	}{
		{
			name: "VXLAN",
			ports: []*v1alpha2.TrafficControlPort{
				{
					VXLAN: &v1alpha2.UDPTunnel{
						RemoteIP: "1.1.1.1",
					},
				},
				{
					VXLAN: &v1alpha2.UDPTunnel{
						RemoteIP:        "1.1.1.1",
						DestinationPort: int32Ptr(4789),
					},
				},
				{
					VXLAN: &v1alpha2.UDPTunnel{
						RemoteIP: "1.1.1.1",
						VNI:      int32Ptr(0),
					},
				},
				{
					VXLAN: &v1alpha2.UDPTunnel{
						RemoteIP:        "1.1.1.1",
						DestinationPort: int32Ptr(4789),
						VNI:             int32Ptr(0),
					},
				},
			},
			expectedName: "vxlan-cb3ab8",
		},
		{
			name: "GENEVE",
			ports: []*v1alpha2.TrafficControlPort{
				{
					GENEVE: &v1alpha2.UDPTunnel{
						RemoteIP: "1.1.1.1",
					},
				},
				{
					GENEVE: &v1alpha2.UDPTunnel{
						RemoteIP:        "1.1.1.1",
						DestinationPort: int32Ptr(6081),
					},
				},
				{
					GENEVE: &v1alpha2.UDPTunnel{
						RemoteIP: "1.1.1.1",
						VNI:      int32Ptr(0),
					},
				},
				{
					GENEVE: &v1alpha2.UDPTunnel{
						RemoteIP:        "1.1.1.1",
						DestinationPort: int32Ptr(6081),
						VNI:             int32Ptr(0),
					},
				},
			},
			expectedName: "geneve-e17764",
		},
		{
			name: "GRE",
			ports: []*v1alpha2.TrafficControlPort{
				{
					GRE: &v1alpha2.GRETunnel{
						RemoteIP: "1.1.1.1",
					},
				},
				{
					GRE: &v1alpha2.GRETunnel{
						RemoteIP: "1.1.1.1",
						Key:      int32Ptr(0),
					},
				},
			},
			expectedName: "gre-b2d3bd",
		},
		{
			name: "ERSPAN",
			ports: []*v1alpha2.TrafficControlPort{
				{
					ERSPAN: &v1alpha2.ERSPANTunnel{
						RemoteIP: "1.1.1.1",
						Version:  1,
					},
				},
				{
					ERSPAN: &v1alpha2.ERSPANTunnel{
						RemoteIP: "1.1.1.1",
						Version:  1,
					},
				},
				{
					ERSPAN: &v1alpha2.ERSPANTunnel{
						RemoteIP:  "1.1.1.1",
						Version:   1,
						SessionID: int32Ptr(0),
					},
				},
				{
					ERSPAN: &v1alpha2.ERSPANTunnel{
						RemoteIP:   "1.1.1.1",
						Version:    1,
						SessionID:  int32Ptr(0),
						Index:      int32Ptr(0),
						Dir:        int32Ptr(0),
						HardwareID: int32Ptr(0),
					},
				},
			},
			expectedName: "erspan-9de667",
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			for _, port := range tt.ports {
				var gotName string
				switch {
				case port.VXLAN != nil:
					gotName = genVXLANPortName(port.VXLAN)
				case port.GENEVE != nil:
					gotName = genGENEVEPortName(port.GENEVE)
				case port.GRE != nil:
					gotName = genGREPortName(port.GRE)
				case port.ERSPAN != nil:
					gotName = genERSPANPortName(port.ERSPAN)
				}
				assert.Equal(t, tt.expectedName, gotName)
			}
		})
	}
}
