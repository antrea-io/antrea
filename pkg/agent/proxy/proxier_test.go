// Copyright 2020 Antrea Authors
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

package proxy

import (
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/metrics/testutil"

	"antrea.io/antrea/pkg/agent/openflow"
	ofmock "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/proxy/metrics"
	"antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/route"
	routemock "antrea.io/antrea/pkg/agent/route/testing"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

var (
	svcIPv4          = net.ParseIP("10.20.30.41")
	svcIPv6          = net.ParseIP("2001::10:20:30:41")
	ep1IPv4          = net.ParseIP("10.180.0.1")
	ep1IPv6          = net.ParseIP("2001::10:180:0:1")
	ep2IPv4          = net.ParseIP("10.180.0.2")
	ep2IPv6          = net.ParseIP("2001::10:180:0:2")
	loadBalancerIPv4 = net.ParseIP("169.254.169.1")
	loadBalancerIPv6 = net.ParseIP("fec0::169:254:169:1")
	svcNodePortIPv4  = net.ParseIP("192.168.77.100")
	svcNodePortIPv6  = net.ParseIP("2001::192:168:77:100")
	hostname         = "localhost"

	nodePortAddressesIPv4 = []net.IP{svcNodePortIPv4}
	nodePortAddressesIPv6 = []net.IP{svcNodePortIPv6}
)

func makeNamespaceName(namespace, name string) apimachinerytypes.NamespacedName {
	return apimachinerytypes.NamespacedName{Namespace: namespace, Name: name}
}

func makeServiceMap(proxier *proxier, allServices ...*corev1.Service) {
	for i := range allServices {
		proxier.serviceChanges.OnServiceUpdate(nil, allServices[i])
	}
	proxier.serviceChanges.OnServiceSynced()
}

func makeTestService(namespace, name string, svcFunc func(*corev1.Service)) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{},
		},
		Spec:   corev1.ServiceSpec{},
		Status: corev1.ServiceStatus{},
	}
	svcFunc(svc)
	return svc
}

func makeEndpointsMap(proxier *proxier, allEndpoints ...*corev1.Endpoints) {
	for i := range allEndpoints {
		proxier.endpointsChanges.OnEndpointUpdate(nil, allEndpoints[i])
	}
	proxier.endpointsChanges.OnEndpointsSynced()
}

func makeTestEndpoints(namespace, name string, eptFunc func(*corev1.Endpoints)) *corev1.Endpoints {
	ept := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	eptFunc(ept)
	return ept
}

type proxyOptions struct {
	proxyAllEnabled      bool
	proxyLoadBalancerIPs bool
}

type proxyOptionsFn func(*proxyOptions)

func withProxyAll(o *proxyOptions) {
	o.proxyAllEnabled = true
}

func withoutProxyLoadBalancerIPs(o *proxyOptions) {
	o.proxyLoadBalancerIPs = false
}

func NewFakeProxier(routeClient route.Interface, ofClient openflow.Client, nodePortAddresses []net.IP, groupIDAllocator openflow.GroupAllocator, isIPv6 bool, options ...proxyOptionsFn) *proxier {
	hostname := "localhost"
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)

	ipFamily := corev1.IPv4Protocol
	if isIPv6 {
		ipFamily = corev1.IPv6Protocol
	}

	o := &proxyOptions{
		proxyAllEnabled:      false,
		proxyLoadBalancerIPs: true,
	}

	for _, fn := range options {
		fn(o)
	}

	p := &proxier{
		endpointsChanges:         newEndpointsChangesTracker(hostname, false, isIPv6),
		serviceChanges:           newServiceChangesTracker(recorder, ipFamily, []string{"kube-system/kube-dns", "192.168.1.2"}),
		serviceMap:               k8sproxy.ServiceMap{},
		serviceInstalledMap:      k8sproxy.ServiceMap{},
		endpointsInstalledMap:    types.EndpointsMap{},
		endpointReferenceCounter: map[string]int{},
		endpointsMap:             types.EndpointsMap{},
		groupCounter:             types.NewGroupCounter(groupIDAllocator, make(chan string, 100)),
		ofClient:                 ofClient,
		routeClient:              routeClient,
		serviceStringMap:         map[string]k8sproxy.ServicePortName{},
		isIPv6:                   isIPv6,
		nodePortAddresses:        nodePortAddresses,
		proxyAll:                 o.proxyAllEnabled,
		proxyLoadBalancerIPs:     o.proxyLoadBalancerIPs,
		numLocalEndpoints:        map[apimachinerytypes.NamespacedName]int{},
	}
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, 2)
	return p
}

func testClusterIP(t *testing.T, svcIP net.IP, ep1IP, ep2IP net.IP, isIPv6, nodeLocalInternal bool, extraSvcs []*corev1.Service, extraEps []*corev1.Endpoints) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6, withProxyAll)

	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	if nodeLocalInternal {
		internalTrafficPolicy = corev1.ServiceInternalTrafficPolicyLocal
	}

	allServices := append(extraSvcs,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
			svc.Spec.InternalTrafficPolicy = &internalTrafficPolicy
		}))
	makeServiceMap(fp, allServices...)

	remoteEndpoint := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP: ep1IP.String(),
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}},
	}
	localEndpoint := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP:       ep2IP.String(),
			NodeName: &hostname,
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}},
	}
	epFunc := func(ept *corev1.Endpoints) { ept.Subsets = []corev1.EndpointSubset{localEndpoint, remoteEndpoint} }
	allEps := append(extraEps, makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, epFunc))
	makeEndpointsMap(fp, allEps...)

	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), "", "", svcPort, true, true, false, false, nil)}
	expectedAllEps := expectedLocalEps
	if !nodeLocalInternal {
		expectedAllEps = append(expectedAllEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, false, false, nil))
	}

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalInternal)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	fp.syncProxyRules()
}

func testLoadBalancer(t *testing.T, nodePortAddresses []net.IP, svcIP, ep1IP, ep2IP, loadBalancerIP net.IP, isIPv6, nodeLocalInternal, nodeLocalExternal, proxyLoadBalancerIPs bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	options := []proxyOptionsFn{withProxyAll}
	if !proxyLoadBalancerIPs {
		options = append(options, withoutProxyLoadBalancerIPs)
	}
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, options...)

	svcPort := 80
	svcNodePort := 30008
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	externalTrafficPolicy := corev1.ServiceExternalTrafficPolicyTypeCluster
	if nodeLocalExternal {
		externalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	if nodeLocalInternal {
		internalTrafficPolicy = corev1.ServiceInternalTrafficPolicyLocal
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.LoadBalancerIP = loadBalancerIP.String()
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			ingress := []corev1.LoadBalancerIngress{{IP: loadBalancerIP.String()}}
			svc.Status.LoadBalancer.Ingress = ingress
			svc.Spec.Ports = []corev1.ServicePort{{
				NodePort: int32(svcNodePort),
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
			svc.Spec.ExternalTrafficPolicy = externalTrafficPolicy
			svc.Spec.InternalTrafficPolicy = &internalTrafficPolicy
		}),
	)

	remoteEndpoint := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP: ep1IP.String(),
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}},
	}
	localEndpoint := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP:       ep2IP.String(),
			NodeName: &hostname,
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}},
	}

	epFunc := func(ept *corev1.Endpoints) { ept.Subsets = []corev1.EndpointSubset{localEndpoint, remoteEndpoint} }
	eps := []*corev1.Endpoints{makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, epFunc)}
	makeEndpointsMap(fp, eps...)

	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), "", "", svcPort, true, true, false, false, nil)}
	expectedAllEps := expectedLocalEps
	if !(nodeLocalInternal && nodeLocalExternal) {
		expectedAllEps = append(expectedAllEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, false, false, nil))
	}

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	if nodeLocalInternal != nodeLocalExternal {
		var clusterIPEps, nodePortEps []k8sproxy.Endpoint
		if nodeLocalInternal {
			clusterIPEps = expectedLocalEps
			nodePortEps = expectedAllEps
		} else {
			clusterIPEps = expectedAllEps
			nodePortEps = expectedLocalEps
		}
		groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalInternal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(clusterIPEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)
		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalExternal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(nodePortEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, gomock.Any(), uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)
		if proxyLoadBalancerIPs {
			mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeLoadBalancer).Times(1)
		}
	} else {
		nodeLocalVal := nodeLocalInternal && nodeLocalExternal
		groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalVal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(expectedAllEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, gomock.Any(), uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)
		if proxyLoadBalancerIPs {
			mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeLoadBalancer).Times(1)
		}
		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, !nodeLocalVal)
		mockOFClient.EXPECT().UninstallGroup(groupID).Times(1)
	}
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	if proxyLoadBalancerIPs {
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}
	mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

	fp.syncProxyRules()
}

func testNodePort(t *testing.T, nodePortAddresses []net.IP, svcIP, ep1IP, ep2IP net.IP, isIPv6, nodeLocalInternal, nodeLocalExternal bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	svcPort := 80
	svcNodePort := 31000
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	externalTrafficPolicy := corev1.ServiceExternalTrafficPolicyTypeCluster
	if nodeLocalExternal {
		externalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	if nodeLocalInternal {
		internalTrafficPolicy = corev1.ServiceInternalTrafficPolicyLocal
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.Type = corev1.ServiceTypeNodePort
			svc.Spec.Ports = []corev1.ServicePort{{
				NodePort: int32(svcNodePort),
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
			svc.Spec.ExternalTrafficPolicy = externalTrafficPolicy
			svc.Spec.InternalTrafficPolicy = &internalTrafficPolicy
		}),
	)

	remoteEndpoint := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP: ep1IP.String(),
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}},
	}
	localEndpoint := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP:       ep2IP.String(),
			NodeName: &hostname,
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}},
	}

	var eps []*corev1.Endpoints
	epFunc := func(ept *corev1.Endpoints) {
		if nodeLocalInternal && nodeLocalExternal {
			ept.Subsets = []corev1.EndpointSubset{localEndpoint}
		} else {
			ept.Subsets = []corev1.EndpointSubset{localEndpoint, remoteEndpoint}
		}
	}
	eps = append(eps, makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, epFunc))
	makeEndpointsMap(fp, eps...)

	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), "", "", svcPort, true, true, false, false, nil)}
	expectedAllEps := expectedLocalEps
	if !(nodeLocalInternal && nodeLocalExternal) {
		expectedAllEps = append(expectedAllEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, false, false, nil))
	}

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	if nodeLocalInternal != nodeLocalExternal {
		var clusterIPEps, nodePortEps []k8sproxy.Endpoint
		if nodeLocalInternal {
			clusterIPEps = expectedLocalEps
			nodePortEps = expectedAllEps
		} else {
			clusterIPEps = expectedAllEps
			nodePortEps = expectedLocalEps
		}
		groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalInternal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(clusterIPEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)

		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalExternal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(nodePortEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, gomock.Any(), uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)
	} else {
		nodeLocalVal := nodeLocalInternal && nodeLocalExternal
		groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalVal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.InAnyOrder(expectedAllEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, gomock.Any(), uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)

		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, !nodeLocalVal)
		mockOFClient.EXPECT().UninstallGroup(groupID).Times(1)
	}
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddNodePort(gomock.Any(), uint16(svcNodePort), bindingProtocol).Times(1)

	fp.syncProxyRules()
}

func TestCluster(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
			testClusterIP(t, svcIPv4, ep1IPv4, ep2IPv4, false, false, []*corev1.Service{}, []*corev1.Endpoints{})
		})
		t.Run("InternalTrafficPolicy Local", func(t *testing.T) {
			testClusterIP(t, svcIPv4, ep1IPv4, ep2IPv4, false, true, []*corev1.Service{}, []*corev1.Endpoints{})
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
			testClusterIP(t, svcIPv6, ep1IPv6, ep2IPv6, true, false, []*corev1.Service{}, []*corev1.Endpoints{})
		})
		t.Run("InternalTrafficPolicy Local", func(t *testing.T) {
			testClusterIP(t, svcIPv6, ep1IPv6, ep2IPv6, true, true, []*corev1.Service{}, []*corev1.Endpoints{})
		})
	})
}

func TestLoadBalancer(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, false, true)
		})
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, true, true)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, true, false, true)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, true, true, true)
		})
		t.Run("No External IPs", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, nil, loadBalancerIPv4, false, false, false, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, false, true)
		})
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, true, true)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, true, false, true)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, true, true, true)
		})
		t.Run("No External IPs", func(t *testing.T) {
			testLoadBalancer(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, nil, loadBalancerIPv6, true, false, false, false)
		})
	})
}

func TestNodePort(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, false, false, false)
		})
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, false, false, true)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, false, true, false)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv4, svcIPv4, ep1IPv4, ep2IPv4, false, true, true)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, true, false, false)
		})
		t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, true, false, true)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, true, true, false)
		})
		t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
			testNodePort(t, nodePortAddressesIPv6, svcIPv6, ep1IPv6, ep2IPv6, true, true, true)
		})
	})
}

func TestClusterSkipServices(t *testing.T) {
	svc1Port := 53
	svc1PortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("kube-system", "kube-dns"),
		Port:           "53",
		Protocol:       corev1.ProtocolTCP,
	}
	svc2Port := 88
	svc2PortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("kube-system", "test"),
		Port:           "88",
		Protocol:       corev1.ProtocolTCP,
	}
	svc1 := makeTestService(svc1PortName.Namespace, svc1PortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = "10.96.10.12"
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svc1PortName.Port,
			Port:     int32(svc1Port),
			Protocol: corev1.ProtocolTCP,
		}}
	})
	svc2 := makeTestService(svc2PortName.Namespace, svc2PortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = "192.168.1.2"
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svc2PortName.Port,
			Port:     int32(svc2Port),
			Protocol: corev1.ProtocolTCP,
		}}
	})
	svcs := []*corev1.Service{svc1, svc2}

	ep1 := makeTestEndpoints(svc1PortName.Namespace, svc1PortName.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: "172.16.1.2",
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svc1PortName.Port,
				Port:     int32(svc1Port),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})
	ep2 := makeTestEndpoints(svc2PortName.Namespace, svc2PortName.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: "172.16.1.3",
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svc2PortName.Port,
				Port:     int32(svc2Port),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})
	eps := []*corev1.Endpoints{ep1, ep2}
	testClusterIP(t, svcIPv4, ep1IPv4, ep2IPv4, false, false, svcs, eps)
}

func TestDualStackService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	ipv4GGroupAllocator := openflow.NewGroupAllocator(false)
	ipv6GGroupAllocator := openflow.NewGroupAllocator(true)
	fpv4 := NewFakeProxier(mockRouteClient, mockOFClient, nil, ipv4GGroupAllocator, false)
	fpv6 := NewFakeProxier(mockRouteClient, mockOFClient, nil, ipv6GGroupAllocator, true)
	metaProxier := k8sproxy.NewMetaProxier(fpv4, fpv6)

	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	svcIPv4 := net.ParseIP("10.20.30.41")
	svcIPv6 := net.ParseIP("10:20::41")

	s := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = svcIPv4.String()
		svc.Spec.ClusterIPs = []string{svcIPv4.String(), svcIPv6.String()}
		svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}}
	})

	epv4 := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: "10.180.30.41",
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})

	epv6 := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: "10:180::1",
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})

	metaProxier.OnServiceUpdate(nil, s)
	metaProxier.OnServiceSynced()
	metaProxier.OnEndpointsUpdate(nil, epv4)
	metaProxier.OnEndpointsUpdate(nil, epv6)
	metaProxier.OnEndpointsSynced()

	groupIDv4 := fpv4.groupCounter.AllocateIfNotExist(svcPortName, false)
	groupIDv6 := fpv6.groupCounter.AllocateIfNotExist(svcPortName, false)

	mockOFClient.EXPECT().InstallServiceGroup(groupIDv4, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDv4, svcIPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)

	mockOFClient.EXPECT().InstallServiceGroup(groupIDv6, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCPv6, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDv6, svcIPv6, uint16(svcPort), binding.ProtocolTCPv6, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)

	fpv4.syncProxyRules()
	fpv6.syncProxyRules()
}

func testClusterIPRemoval(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6, withProxyAll)

	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           fmt.Sprint(svcPort),
		Protocol:       corev1.ProtocolTCP,
	}
	service := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = svcIP.String()
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}}
	})
	makeServiceMap(fp, service)

	epFunc := func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: epIP.String(),
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	}

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}
	ep := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, epFunc)
	makeEndpointsMap(fp, ep)
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	mockOFClient.EXPECT().UninstallGroup(gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(service, nil)
	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemovalIPv4(t *testing.T) {
	testClusterIPRemoval(t, net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), false)
}

func TestClusterIPRemovalIPv6(t *testing.T) {
	testClusterIPRemoval(t, net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), true)
}

func testClusterIPNoEndpoint(t *testing.T, svcIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPort := 80
	svcNodePort := 3001
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
		}),
	)
	makeEndpointsMap(fp)
	fp.syncProxyRules()
}

func TestClusterIPNoEndpointIPv4(t *testing.T) {
	testClusterIPNoEndpoint(t, net.ParseIP("10.20.30.41"), false)
}

func TestClusterIPNoEndpointIPv6(t *testing.T) {
	testClusterIPNoEndpoint(t, net.ParseIP("10:20::41"), true)
}

func testClusterIPRemoveSamePortEndpoint(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	svcPortNameUDP := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1-udp"),
		Port:           "80",
		Protocol:       corev1.ProtocolUDP,
	}
	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
		}),
		makeTestService(svcPortName.Namespace, svcPortNameUDP.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolUDP,
			}}
		}),
	)

	ep := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: epIP.String(),
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})
	epUDP := makeTestEndpoints(svcPortName.Namespace, svcPortNameUDP.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: epIP.String(),
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolUDP,
			}},
		}}
	})
	protocolTCP := binding.ProtocolTCP
	protocolUDP := binding.ProtocolUDP
	if isIPv6 {
		protocolTCP = binding.ProtocolTCPv6
		protocolUDP = binding.ProtocolUDPv6
	}
	makeEndpointsMap(fp, ep, epUDP)

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	groupIDUDP := fp.groupCounter.AllocateIfNotExist(svcPortNameUDP, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDUDP, false, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallEndpointFlows(protocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(protocolUDP, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), protocolTCP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDUDP, svcIP, uint16(svcPort), protocolUDP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(protocolUDP, gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.endpointsChanges.OnEndpointUpdate(epUDP, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemoveSamePortEndpointIPv4(t *testing.T) {
	testClusterIPRemoveSamePortEndpoint(t, net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), false)
}

func TestClusterIPRemoveSamePortEndpointIPv6(t *testing.T) {
	testClusterIPRemoveSamePortEndpoint(t, net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), true)
}

func testClusterIPRemoveEndpoints(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
		}),
	)

	ep := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: epIP.String(),
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})
	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}
	makeEndpointsMap(fp, ep)
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemoveEndpointsIPv4(t *testing.T) {
	testClusterIPRemoveEndpoints(t, net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), false)
}

func TestClusterIPRemoveEndpointsIPv6(t *testing.T) {
	testClusterIPRemoveEndpoints(t, net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), true)
}

func testSessionAffinity(t *testing.T, svcExternalIPs net.IP, svcIP net.IP, epIP net.IP, affinitySeconds int32, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPort := 80
	svcNodePort := 3001
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.Type = corev1.ServiceTypeNodePort
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.ExternalIPs = []string{svcExternalIPs.String()}
			svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svc.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{
					TimeoutSeconds: &affinitySeconds,
				},
			}
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
		}),
	)
	makeEndpointsMap(fp,
		makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
			ept.Subsets = []corev1.EndpointSubset{{
				Addresses: []corev1.EndpointAddress{{
					IP: epIP.String(),
				}},
				Ports: []corev1.EndpointPort{{
					Name:     svcPortName.Port,
					Port:     int32(svcPort),
					Protocol: corev1.ProtocolTCP,
				}},
			}}
		}),
	)
	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, true, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	var expectedAffinity uint16
	if affinitySeconds > math.MaxUint16 {
		expectedAffinity = math.MaxUint16
	} else {
		expectedAffinity = uint16(affinitySeconds)
	}
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, expectedAffinity, false, corev1.ServiceTypeClusterIP).Times(1)

	fp.syncProxyRules()
}

func TestSessionAffinityIPv4(t *testing.T) {
	affinitySeconds := corev1.DefaultClientIPServiceAffinitySeconds
	testSessionAffinity(t, net.ParseIP("50.60.70.81"), net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), affinitySeconds, false)
}

func TestSessionAffinityIPv6(t *testing.T) {
	affinitySeconds := corev1.DefaultClientIPServiceAffinitySeconds
	testSessionAffinity(t, net.ParseIP("5060:70::81"), net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), affinitySeconds, true)
}

func TestSessionAffinityOverflow(t *testing.T) {
	// Ensure that the SessionAffinity timeout is truncated to the max supported value, instead
	// of wrapping around.
	affinitySeconds := int32(math.MaxUint16 + 10)
	testSessionAffinity(t, net.ParseIP("50.60.70.81"), net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), affinitySeconds, false)
}

func testSessionAffinityNoEndpoint(t *testing.T, svcExternalIPs net.IP, svcIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPort := 80
	svcNodePort := 3001
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	timeoutSeconds := corev1.DefaultClientIPServiceAffinitySeconds

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.Type = corev1.ServiceTypeNodePort
			svc.Spec.ClusterIP = svcIP.String()
			svc.Spec.ExternalIPs = []string{svcExternalIPs.String()}
			svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svc.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{
					TimeoutSeconds: &timeoutSeconds,
				},
			}
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
				NodePort: int32(svcNodePort),
			}}
		}),
	)
	makeEndpointsMap(fp)
	fp.syncProxyRules()
}

func TestSessionAffinityNoEndpointIPv4(t *testing.T) {
	testSessionAffinityNoEndpoint(t, net.ParseIP("50.60.70.81"), net.ParseIP("10.20.30.41"), false)
}

func TestSessionAffinityIPv6NoEndpoint(t *testing.T) {
	testSessionAffinityNoEndpoint(t, net.ParseIP("5060:70::81"), net.ParseIP("10:20::41"), true)
}

func testPortChange(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPort1 := 80
	svcPort2 := 8080
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	service := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = svcIP.String()
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:       svcPortName.Port,
			Port:       int32(svcPort1),
			TargetPort: intstr.FromInt(80),
			Protocol:   corev1.ProtocolTCP,
		}}
	})
	makeServiceMap(fp, service)

	epFunc := func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: epIP.String(),
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(80),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	}

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}
	ep := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, epFunc)
	makeEndpointsMap(fp, ep)
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort1), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort1), bindingProtocol)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort2), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP)

	fp.syncProxyRules()

	serviceNew := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = svcIP.String()
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort2),
			Protocol: corev1.ProtocolTCP,
		}}
	})

	fp.serviceChanges.OnServiceUpdate(service, serviceNew)
	fp.syncProxyRules()
}

func TestPortChangeIPv4(t *testing.T) {
	testPortChange(t, net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), false)
}

func TestPortChangeIPv6(t *testing.T) {
	testPortChange(t, net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), true)
}

func TestServicesWithSameEndpoints(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	groupAllocator := openflow.NewGroupAllocator(false)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, false)
	epIP := net.ParseIP("10.50.60.71")
	svcIP1 := net.ParseIP("10.180.30.41")
	svcIP2 := net.ParseIP("10.180.30.42")
	svcPort := 80
	svcPortName1 := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	svcPortName2 := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc2"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	svcMapFactory := func(svcPortName k8sproxy.ServicePortName, svcIP string) *corev1.Service {
		svc := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
		})
		makeServiceMap(fp, svc)
		return svc
	}

	svc1 := svcMapFactory(svcPortName1, svcIP1.String())
	svc2 := svcMapFactory(svcPortName2, svcIP2.String())

	epMapFactory := func(svcPortName k8sproxy.ServicePortName, epIP string) *corev1.Endpoints {
		ep := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
			ept.Subsets = []corev1.EndpointSubset{{
				Addresses: []corev1.EndpointAddress{{
					IP: epIP,
				}},
				Ports: []corev1.EndpointPort{{
					Name:     svcPortName.Port,
					Port:     int32(svcPort),
					Protocol: corev1.ProtocolTCP,
				}},
			}}
		})
		makeEndpointsMap(fp, ep)
		return ep
	}

	ep1 := epMapFactory(svcPortName1, epIP.String())
	ep2 := epMapFactory(svcPortName2, epIP.String())

	groupID1 := fp.groupCounter.AllocateIfNotExist(svcPortName1, false)
	groupID2 := fp.groupCounter.AllocateIfNotExist(svcPortName2, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID1, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID2, false, gomock.Any()).Times(1)
	bindingProtocol := binding.ProtocolTCP
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID1, svcIP1, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID2, svcIP2, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP1, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP2, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallGroup(groupID1).Times(1)
	mockOFClient.EXPECT().UninstallGroup(groupID2).Times(1)
	// Since these two Services reference to the same Endpoint, there should only be one operation.
	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)

	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc1, nil)
	fp.endpointsChanges.OnEndpointUpdate(ep1, nil)
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc2, nil)
	fp.endpointsChanges.OnEndpointUpdate(ep2, nil)
	fp.syncProxyRules()
}

func TestMetrics(t *testing.T) {
	metrics.Register()

	for _, tc := range []struct {
		name                string
		svcIP, ep1IP, ep2IP net.IP
		isIPv6              bool
	}{
		{"IPv4", svcIPv4, ep1IPv4, ep2IPv4, false},
		{"IPv6", svcIPv6, ep1IPv6, ep2IPv6, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpointsUpdateTotalMetric := metrics.EndpointsUpdatesTotal.CounterMetric
			servicesUpdateTotalMetric := metrics.ServicesUpdatesTotal.CounterMetric
			endpointsInstallMetric := metrics.EndpointsInstalledTotal.GaugeMetric
			servicesInstallMetric := metrics.ServicesInstalledTotal.GaugeMetric
			if tc.isIPv6 {
				endpointsUpdateTotalMetric = metrics.EndpointsUpdatesTotalV6.CounterMetric
				servicesUpdateTotalMetric = metrics.ServicesUpdatesTotalV6.CounterMetric
				endpointsInstallMetric = metrics.EndpointsInstalledTotalV6.GaugeMetric
				servicesInstallMetric = metrics.ServicesInstalledTotalV6.GaugeMetric
			}
			testClusterIP(t, tc.svcIP, tc.ep1IP, tc.ep2IP, tc.isIPv6, false, []*corev1.Service{}, []*corev1.Endpoints{})
			v, err := testutil.GetCounterMetricValue(endpointsUpdateTotalMetric)
			assert.NoError(t, err)
			assert.Equal(t, 0, int(v))
			v, err = testutil.GetCounterMetricValue(servicesUpdateTotalMetric)
			assert.Equal(t, 0, int(v))
			assert.NoError(t, err)
			v, err = testutil.GetGaugeMetricValue(servicesInstallMetric)
			assert.Equal(t, 1, int(v))
			assert.NoError(t, err)
			v, err = testutil.GetGaugeMetricValue(endpointsInstallMetric)
			assert.Equal(t, 2, int(v))
			assert.NoError(t, err)

			testClusterIPRemoval(t, tc.svcIP, tc.ep1IP, tc.isIPv6)

			v, err = testutil.GetCounterMetricValue(endpointsUpdateTotalMetric)
			assert.NoError(t, err)
			assert.Equal(t, 0, int(v))
			v, err = testutil.GetCounterMetricValue(servicesUpdateTotalMetric)
			assert.Equal(t, 0, int(v))
			assert.NoError(t, err)
			v, err = testutil.GetGaugeMetricValue(servicesInstallMetric)
			assert.Equal(t, 0, int(v))
			assert.NoError(t, err)
			v, err = testutil.GetGaugeMetricValue(endpointsInstallMetric)
			assert.Equal(t, 0, int(v))
			assert.NoError(t, err)
		})
	}
}
