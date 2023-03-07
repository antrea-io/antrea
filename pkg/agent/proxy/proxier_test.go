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
	"math"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"

	agentconfig "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	ofmock "antrea.io/antrea/pkg/agent/openflow/testing"
	openflowtypes "antrea.io/antrea/pkg/agent/openflow/types"
	"antrea.io/antrea/pkg/agent/proxy/metrics"
	"antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/route"
	routemock "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/servicecidr"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

var (
	svc1IPv4              = net.ParseIP("10.20.30.41")
	svc2IPv4              = net.ParseIP("10.20.30.42")
	svc1IPv6              = net.ParseIP("2001::10:20:30:41")
	svc2IPv6              = net.ParseIP("2001::10:20:30:42")
	ep1IPv4               = net.ParseIP("10.180.0.1")
	ep1IPv6               = net.ParseIP("2001::10:180:0:1")
	ep2IPv4               = net.ParseIP("10.180.0.2")
	ep2IPv6               = net.ParseIP("2001::10:180:0:2")
	loadBalancerIPv4      = net.ParseIP("169.254.169.1")
	loadBalancerIPv6      = net.ParseIP("fec0::169:254:169:1")
	svcNodePortIPv4       = net.ParseIP("192.168.77.100")
	svcNodePortIPv6       = net.ParseIP("2001::192:168:77:100")
	nodePortAddressesIPv4 = []net.IP{svcNodePortIPv4}
	nodePortAddressesIPv6 = []net.IP{svcNodePortIPv6}
	svcPort               = 80
	svcNodePort           = 30008
	svcPortName           = makeSvcPortName("ns", "svc", strconv.Itoa(svcPort), corev1.ProtocolTCP)

	hostname = "localhostName"

	skippedServiceNN = "kube-system/kube-dns"
	skippedClusterIP = "192.168.1.2"
)

func makeSvcPortName(namespace, name, port string, protocol corev1.Protocol) k8sproxy.ServicePortName {
	return k8sproxy.ServicePortName{
		NamespacedName: apimachinerytypes.NamespacedName{Namespace: namespace, Name: name},
		Port:           port,
		Protocol:       protocol,
	}
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

func makeEndpointSliceMap(proxier *proxier, allEndpoints ...*discovery.EndpointSlice) {
	for i := range allEndpoints {
		proxier.endpointsChanges.OnEndpointSliceUpdate(allEndpoints[i], false)
	}
	proxier.endpointsChanges.OnEndpointsSynced()
}

func makeTestEndpointSlice(namespace, name string, eps []discovery.Endpoint, ports []discovery.EndpointPort, isIPv6 bool) *discovery.EndpointSlice {
	addrType := discovery.AddressTypeIPv4
	if isIPv6 {
		addrType = discovery.AddressTypeIPv6
	}
	endpointSlice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				discovery.LabelServiceName: name,
			},
		},
	}
	endpointSlice.Endpoints = eps
	endpointSlice.Ports = ports
	endpointSlice.AddressType = addrType
	return endpointSlice
}

func makeTestClusterIPService(svcPortName *k8sproxy.ServicePortName,
	clusterIP net.IP,
	svcPort int32,
	protocol corev1.Protocol,
	affinitySeconds *int32,
	internalTrafficPolicy *corev1.ServiceInternalTrafficPolicyType) *corev1.Service {
	return makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = clusterIP.String()
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     svcPort,
			Protocol: protocol,
		}}
		if internalTrafficPolicy != nil {
			svc.Spec.InternalTrafficPolicy = internalTrafficPolicy
		}
		if affinitySeconds != nil {
			svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svc.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{
					TimeoutSeconds: affinitySeconds,
				},
			}
		}
	})
}

func makeTestNodePortService(svcPortName *k8sproxy.ServicePortName,
	clusterIP net.IP,
	svcPort,
	svcNodePort int32,
	protocol corev1.Protocol,
	affinitySeconds *int32,
	internalTrafficPolicy corev1.ServiceInternalTrafficPolicyType,
	externalTrafficPolicy corev1.ServiceExternalTrafficPolicyType) *corev1.Service {
	return makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = clusterIP.String()
		svc.Spec.Type = corev1.ServiceTypeNodePort
		svc.Spec.Ports = []corev1.ServicePort{{
			NodePort: svcNodePort,
			Name:     svcPortName.Port,
			Port:     svcPort,
			Protocol: protocol,
		}}
		svc.Spec.ExternalTrafficPolicy = externalTrafficPolicy
		svc.Spec.InternalTrafficPolicy = &internalTrafficPolicy
		if affinitySeconds != nil {
			svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svc.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{
					TimeoutSeconds: affinitySeconds,
				},
			}
		}
	})
}

func makeTestLoadBalancerService(svcPortName *k8sproxy.ServicePortName,
	clusterIP net.IP,
	loadBalancerIPs []net.IP,
	svcPort,
	svcNodePort int32,
	protocol corev1.Protocol,
	affinitySeconds *int32,
	internalTrafficPolicy *corev1.ServiceInternalTrafficPolicyType,
	externalTrafficPolicy corev1.ServiceExternalTrafficPolicyType) *corev1.Service {
	return makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = clusterIP.String()
		svc.Spec.Type = corev1.ServiceTypeLoadBalancer
		var ingress []corev1.LoadBalancerIngress
		for _, ip := range loadBalancerIPs {
			ingress = append(ingress, corev1.LoadBalancerIngress{IP: ip.String()})
		}
		svc.Status.LoadBalancer.Ingress = ingress
		svc.Spec.Ports = []corev1.ServicePort{{
			NodePort: svcNodePort,
			Name:     svcPortName.Port,
			Port:     svcPort,
			Protocol: protocol,
		}}
		svc.Spec.ExternalTrafficPolicy = externalTrafficPolicy
		if internalTrafficPolicy != nil {
			svc.Spec.InternalTrafficPolicy = internalTrafficPolicy
		}
		if affinitySeconds != nil {
			svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svc.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{
					TimeoutSeconds: affinitySeconds,
				},
			}
		}
	})
}

func makeTestEndpointSubset(svcPortName *k8sproxy.ServicePortName,
	epIP net.IP,
	port int32,
	protocol corev1.Protocol,
	isLocal bool) *corev1.EndpointSubset {
	var nodeName *string
	if isLocal {
		nodeName = &hostname
	}
	return &corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{{
			IP:       epIP.String(),
			NodeName: nodeName,
		}},
		Ports: []corev1.EndpointPort{{
			Name:     svcPortName.Port,
			Port:     port,
			Protocol: protocol,
		}},
	}
}

func makeTestEndpointSliceEndpointAndPort(svcPortName *k8sproxy.ServicePortName,
	epIP net.IP,
	port int32,
	protocol corev1.Protocol,
	isLocal bool) (*discovery.Endpoint, *discovery.EndpointPort) {
	ready := true
	var nodeName *string
	if isLocal {
		nodeName = &hostname
	}
	return &discovery.Endpoint{
			Addresses: []string{
				epIP.String(),
			},
			Conditions: discovery.EndpointConditions{
				Ready: &ready,
			},
			Hostname: nodeName,
			NodeName: nodeName,
		}, &discovery.EndpointPort{
			Name:     &svcPortName.Port,
			Port:     &port,
			Protocol: &protocol,
		}
}

func makeTestEndpoints(svcPortName *k8sproxy.ServicePortName, epSubsets []corev1.EndpointSubset) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcPortName.Name,
			Namespace: svcPortName.Namespace,
		},
		Subsets: epSubsets,
	}
}

type proxyOptions struct {
	proxyAllEnabled      bool
	proxyLoadBalancerIPs bool
	endpointSliceEnabled bool
}

type proxyOptionsFn func(*proxyOptions)

func withProxyAll(o *proxyOptions) {
	o.proxyAllEnabled = true
}

func withoutProxyLoadBalancerIPs(o *proxyOptions) {
	o.proxyLoadBalancerIPs = false
}

func withEndpointSlice(o *proxyOptions) {
	o.endpointSliceEnabled = true
}

func getMockClients(ctrl *gomock.Controller) (*ofmock.MockClient, *routemock.MockInterface) {
	mockOFClient := ofmock.NewMockClient(ctrl)
	mockRouteClient := routemock.NewMockInterface(ctrl)
	return mockOFClient, mockRouteClient
}

type fakeServiceCIDRDiscoverer struct {
	servicecidr.Interface
}

func (f fakeServiceCIDRDiscoverer) GetServiceCIDR(isIPv6 bool) (*net.IPNet, error) {
	_, serviceCIDR, _ := net.ParseCIDR("10.96.0.0/24")
	return serviceCIDR, nil
}

func (f fakeServiceCIDRDiscoverer) AddEventHandler(handler servicecidr.EventHandler) {}

func NewFakeProxier(routeClient route.Interface, ofClient openflow.Client, nodePortAddresses []net.IP, groupIDAllocator openflow.GroupAllocator, isIPv6 bool, options ...proxyOptionsFn) *proxier {
	o := &proxyOptions{
		proxyAllEnabled:      false,
		proxyLoadBalancerIPs: true,
		endpointSliceEnabled: false,
	}

	for _, fn := range options {
		fn(o)
	}

	serviceCIDRProvider := fakeServiceCIDRDiscoverer{}
	p := NewProxier(hostname,
		informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0),
		ofClient,
		isIPv6,
		routeClient,
		nodePortAddresses,
		o.proxyAllEnabled,
		[]string{skippedServiceNN, skippedClusterIP},
		o.proxyLoadBalancerIPs,
		types.NewGroupCounter(groupIDAllocator, make(chan string, 100)),
		true,
		serviceCIDRProvider)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, 2)
	if o.endpointSliceEnabled {
		p.endpointsChanges = newEndpointsChangesTracker(hostname, o.endpointSliceEnabled, isIPv6)
	}
	return p
}

func testClusterIPAdd(t *testing.T,
	svcIP net.IP,
	ep1IP net.IP,
	ep2IP net.IP,
	isIPv6 bool,
	nodeLocalInternal bool,
	extraSvcs []*corev1.Service,
	extraEps []*corev1.Endpoints,
	endpointSliceEnabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	options := []proxyOptionsFn{withProxyAll}
	if endpointSliceEnabled {
		options = append(options, withEndpointSlice)
	}
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6, options...)

	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	if nodeLocalInternal {
		internalTrafficPolicy = corev1.ServiceInternalTrafficPolicyLocal
	}
	allSvcs := append(extraSvcs, makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, &internalTrafficPolicy))
	makeServiceMap(fp, allSvcs...)

	if !endpointSliceEnabled {
		remoteEpSubset := makeTestEndpointSubset(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
		localEpSubset := makeTestEndpointSubset(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
		allEps := append(extraEps, makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*remoteEpSubset, *localEpSubset}))
		makeEndpointsMap(fp, allEps...)
	} else {
		remoteEp, remoteEpPort := makeTestEndpointSliceEndpointAndPort(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
		localEp, localEpPort := makeTestEndpointSliceEndpointAndPort(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
		endpointSlice := makeTestEndpointSlice(svcPortName.Namespace,
			svcPortName.Name,
			[]discovery.Endpoint{*remoteEp, *localEp},
			[]discovery.EndpointPort{*remoteEpPort, *localEpPort},
			isIPv6)
		makeEndpointSliceMap(fp, endpointSlice)
	}

	var nodeName string
	var serving bool
	if endpointSliceEnabled {
		nodeName = hostname
		serving = true
	}
	expectedAllEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), nodeName, "", svcPort, true, true, serving, false, nil)}
	if !nodeLocalInternal {
		expectedAllEps = append(expectedAllEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, serving, false, nil))
	}

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalInternal)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	fp.syncProxyRules()
}

func testClusterIPAddWithMCService(t *testing.T,
	svcIP net.IP,
	ep1IP net.IP,
	ep2IP net.IP) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	isIPv6 := false
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	options := []proxyOptionsFn{withProxyAll}
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6, options...)

	mcSvcPortName := makeSvcPortName("ns", "antrea-mc-svc", strconv.Itoa(svcPort), corev1.ProtocolTCP)
	allSvcs := []*corev1.Service{
		makeTestClusterIPService(&mcSvcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil),
		makeTestClusterIPService(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, nil, nil),
	}
	makeServiceMap(fp, allSvcs...)

	remoteEpSubset := makeTestEndpointSubset(&mcSvcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
	svcIPEpSubset := makeTestEndpointSubset(&mcSvcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, false)
	allEps := []*corev1.Endpoints{makeTestEndpoints(&mcSvcPortName, []corev1.EndpointSubset{*remoteEpSubset, *svcIPEpSubset})}
	makeEndpointsMap(fp, allEps...)

	expectedAllEps := []k8sproxy.Endpoint{
		k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, false, false, nil),
	}

	bindingProtocol := binding.ProtocolTCP

	groupID := fp.groupCounter.AllocateIfNotExist(mcSvcPortName, false)
	localService := &openflowtypes.ServiceGroupInfo{
		GroupID:  fp.groupCounter.AllocateIfNotExist(svcPortName, false),
		Endpoint: k8sproxy.NewBaseEndpointInfo(ep2IP.String(), "", "", svcPort, false, true, false, false, nil),
	}
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, localService, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	fp.syncProxyRules()
}

func testLoadBalancerAdd(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	ep1IP net.IP,
	ep2IP net.IP,
	loadBalancerIP net.IP,
	isIPv6 bool,
	nodeLocalInternal bool,
	nodeLocalExternal bool,
	proxyLoadBalancerIPs bool,
	endpointSliceEnabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	options := []proxyOptionsFn{withProxyAll}
	if !proxyLoadBalancerIPs {
		options = append(options, withoutProxyLoadBalancerIPs)
	}
	if endpointSliceEnabled {
		options = append(options, withEndpointSlice)
	}
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, options...)

	externalTrafficPolicy := corev1.ServiceExternalTrafficPolicyTypeCluster
	if nodeLocalExternal {
		externalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	if nodeLocalInternal {
		internalTrafficPolicy = corev1.ServiceInternalTrafficPolicyLocal
	}
	svc := makeTestLoadBalancerService(&svcPortName, svcIP,
		[]net.IP{loadBalancerIP},
		int32(svcPort),
		int32(svcNodePort),
		corev1.ProtocolTCP,
		nil,
		&internalTrafficPolicy,
		externalTrafficPolicy)
	makeServiceMap(fp, svc)

	if !endpointSliceEnabled {
		remoteEpSubset := makeTestEndpointSubset(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
		localEpSubset := makeTestEndpointSubset(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
		eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*remoteEpSubset, *localEpSubset})
		makeEndpointsMap(fp, eps)
	} else {
		remoteEp, remoteEpPort := makeTestEndpointSliceEndpointAndPort(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
		localEp, localEpPort := makeTestEndpointSliceEndpointAndPort(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
		endpointSlice := makeTestEndpointSlice(svcPortName.Namespace,
			svcPortName.Name,
			[]discovery.Endpoint{*remoteEp, *localEp},
			[]discovery.EndpointPort{*remoteEpPort, *localEpPort},
			isIPv6)
		makeEndpointSliceMap(fp, endpointSlice)
	}

	var nodeName string
	var serving bool
	if endpointSliceEnabled {
		nodeName = hostname
		serving = true
	}
	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), nodeName, "", svcPort, true, true, serving, false, nil)}
	expectedAllEps := expectedLocalEps
	if !(nodeLocalInternal && nodeLocalExternal) {
		expectedAllEps = append(expectedAllEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, serving, false, nil))
	}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
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
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(clusterIPEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)
		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalExternal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(nodePortEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)
		if proxyLoadBalancerIPs {
			mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeLoadBalancer).Times(1)
		}
	} else {
		nodeLocalVal := nodeLocalInternal && nodeLocalExternal
		groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalVal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedAllEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)
		if proxyLoadBalancerIPs {
			mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeLoadBalancer).Times(1)
		}
		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, !nodeLocalVal)
		mockOFClient.EXPECT().UninstallServiceGroup(groupID).Times(1)
	}
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	if proxyLoadBalancerIPs {
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}
	mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

	fp.syncProxyRules()
}

func testNodePortAdd(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	ep1IP net.IP,
	ep2IP net.IP,
	isIPv6 bool,
	nodeLocalInternal bool,
	nodeLocalExternal bool,
	endpointSliceEnabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	options := []proxyOptionsFn{withProxyAll}
	if endpointSliceEnabled {
		options = append(options, withEndpointSlice)
	}
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, options...)

	externalTrafficPolicy := corev1.ServiceExternalTrafficPolicyTypeCluster
	if nodeLocalExternal {
		externalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	if nodeLocalInternal {
		internalTrafficPolicy = corev1.ServiceInternalTrafficPolicyLocal
	}
	svc := makeTestNodePortService(&svcPortName, svcIP,
		int32(svcPort),
		int32(svcNodePort),
		corev1.ProtocolTCP,
		nil,
		internalTrafficPolicy,
		externalTrafficPolicy)
	makeServiceMap(fp, svc)

	if !endpointSliceEnabled {
		remoteEpSubset := makeTestEndpointSubset(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
		localEpSubset := makeTestEndpointSubset(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
		eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*remoteEpSubset, *localEpSubset})
		makeEndpointsMap(fp, eps)
	} else {
		remoteEp, remoteEpPort := makeTestEndpointSliceEndpointAndPort(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
		localEp, localEpPort := makeTestEndpointSliceEndpointAndPort(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
		endpointSlice := makeTestEndpointSlice(svcPortName.Namespace,
			svcPortName.Name,
			[]discovery.Endpoint{*remoteEp, *localEp},
			[]discovery.EndpointPort{*remoteEpPort, *localEpPort},
			isIPv6)
		makeEndpointSliceMap(fp, endpointSlice)
	}

	var nodeName string
	var serving bool
	if endpointSliceEnabled {
		nodeName = hostname
		serving = true
	}
	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), nodeName, "", svcPort, true, true, serving, false, nil)}
	expectedAllEps := expectedLocalEps
	if !(nodeLocalInternal && nodeLocalExternal) {
		expectedAllEps = append(expectedAllEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, serving, false, nil))
	}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
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
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(clusterIPEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)

		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalExternal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(nodePortEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)
	} else {
		nodeLocalVal := nodeLocalInternal && nodeLocalExternal
		groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalVal)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedAllEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeClusterIP).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), nodeLocalExternal, corev1.ServiceTypeNodePort).Times(1)

		groupID = fp.groupCounter.AllocateIfNotExist(svcPortName, !nodeLocalVal)
		mockOFClient.EXPECT().UninstallServiceGroup(groupID).Times(1)
	}
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

	fp.syncProxyRules()
}

func TestClusterIPAdd(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv4, ep1IPv4, ep2IPv4, false, false, []*corev1.Service{}, []*corev1.Endpoints{}, false)
			})
			t.Run("InternalTrafficPolicy Local", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv4, ep1IPv4, ep2IPv4, false, true, []*corev1.Service{}, []*corev1.Endpoints{}, false)
			})
		})
		t.Run("Multicluster-ClusterIP-as-Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
				testClusterIPAddWithMCService(t, svc1IPv4, ep1IPv4, net.ParseIP("10.96.0.3"))
			})
		})
		t.Run("EndpointSlice", func(t *testing.T) {
			t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv4, ep1IPv4, ep2IPv4, false, false, []*corev1.Service{}, []*corev1.Endpoints{}, true)
			})
			t.Run("InternalTrafficPolicy Local", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv4, ep1IPv4, ep2IPv4, false, true, []*corev1.Service{}, []*corev1.Endpoints{}, true)
			})
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv6, ep1IPv6, ep2IPv6, true, false, []*corev1.Service{}, []*corev1.Endpoints{}, false)
			})
			t.Run("InternalTrafficPolicy Local", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv6, ep1IPv6, ep2IPv6, true, true, []*corev1.Service{}, []*corev1.Endpoints{}, false)
			})
		})
		t.Run("EndpointSlice", func(t *testing.T) {
			t.Run("InternalTrafficPolicy Cluster", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv6, ep1IPv6, ep2IPv6, true, false, []*corev1.Service{}, []*corev1.Endpoints{}, true)
			})
			t.Run("InternalTrafficPolicy Local", func(t *testing.T) {
				testClusterIPAdd(t, svc1IPv6, ep1IPv6, ep2IPv6, true, true, []*corev1.Service{}, []*corev1.Endpoints{}, true)
			})
		})
	})
}

func TestLoadBalancerAdd(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, false, true, false)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, true, true, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, true, false, true, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, true, true, true, false)
			})
			t.Run("No External IPs", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, false, false, false)
			})
		})
		t.Run("EndpointSlice", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, false, true, true)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, true, true, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, true, false, true, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, true, true, true, true)
			})
			t.Run("No External IPs", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, loadBalancerIPv4, false, false, false, false, true)
			})
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, false, true, false)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, true, true, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, true, false, true, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, true, true, true, false)
			})
			t.Run("No External IPs", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, false, false, false)
			})
		})
		t.Run("EndpointSlice", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, false, true, true)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, true, true, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, true, false, true, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, true, true, true, true)
			})
			t.Run("No External IPs", func(t *testing.T) {
				testLoadBalancerAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, loadBalancerIPv6, true, false, false, false, true)
			})
		})
	})
}

func TestNodePortAdd(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, false, false, false)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, false, true, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, true, false, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, true, true, false)
			})
		})
		t.Run("EndpointSlice", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, false, false, true)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, false, true, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, true, false, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, ep2IPv4, false, true, true, true)
			})
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("Endpoints", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, false, false, false)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, false, true, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, true, false, false)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, true, true, false)
			})
		})
		t.Run("EndpointSlice", func(t *testing.T) {
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, false, false, true)
			})
			t.Run("InternalTrafficPolicy:Cluster ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, false, true, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Cluster", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, true, false, true)
			})
			t.Run("InternalTrafficPolicy:Local ExternalTrafficPolicy:Local", func(t *testing.T) {
				testNodePortAdd(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, ep2IPv6, true, true, true, true)
			})
		})
	})
}

func TestClusterSkipServices(t *testing.T) {
	svc1Port := 53
	svc2Port := 88
	svc1ClusterIP := net.ParseIP("10.96.10.12")
	svc2ClusterIP := net.ParseIP(skippedClusterIP)
	ep1IP := net.ParseIP("172.16.1.2")
	ep2IP := net.ParseIP("172.16.1.3")

	skippedServiceNamespace := strings.Split(skippedServiceNN, "/")[0]
	skippedServiceName := strings.Split(skippedServiceNN, "/")[1]
	svc1PortName := makeSvcPortName(skippedServiceNamespace, skippedServiceName, strconv.Itoa(svc1Port), corev1.ProtocolTCP)
	svc2PortName := makeSvcPortName("kube-system", "test", strconv.Itoa(svc2Port), corev1.ProtocolTCP)
	svc1 := makeTestClusterIPService(&svc1PortName, svc1ClusterIP, int32(svc1Port), corev1.ProtocolTCP, nil, nil)
	svc2 := makeTestClusterIPService(&svc2PortName, svc2ClusterIP, int32(svc2Port), corev1.ProtocolTCP, nil, nil)
	svcs := []*corev1.Service{svc1, svc2}

	epSubset := makeTestEndpointSubset(&svc1PortName, ep1IP, int32(svc1Port), corev1.ProtocolTCP, false)
	ep1 := makeTestEndpoints(&svc1PortName, []corev1.EndpointSubset{*epSubset})
	epSubset = makeTestEndpointSubset(&svc1PortName, ep2IP, int32(svc2Port), corev1.ProtocolTCP, false)
	ep2 := makeTestEndpoints(&svc2PortName, []corev1.EndpointSubset{*epSubset})
	eps := []*corev1.Endpoints{ep1, ep2}

	testClusterIPAdd(t, svc1IPv4, ep1IPv4, ep2IPv4, false, false, svcs, eps, false)
}

func TestDualStackService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	ipv4GroupAllocator := openflow.NewGroupAllocator(false)
	ipv6GroupAllocator := openflow.NewGroupAllocator(true)
	fpv4 := NewFakeProxier(mockRouteClient, mockOFClient, nil, ipv4GroupAllocator, false)
	fpv6 := NewFakeProxier(mockRouteClient, mockOFClient, nil, ipv6GroupAllocator, true)
	metaProxier := k8sproxy.NewMetaProxier(fpv4, fpv6)

	svc := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = svc1IPv4.String()
		svc.Spec.ClusterIPs = []string{svc1IPv4.String(), svc1IPv6.String()}
		svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}}
	})

	epSubset := makeTestEndpointSubset(&svcPortName, ep1IPv4, int32(svcPort), corev1.ProtocolTCP, false)
	epv4 := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	epSubset = makeTestEndpointSubset(&svcPortName, ep1IPv6, int32(svcPort), corev1.ProtocolTCP, false)
	epv6 := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})

	metaProxier.OnServiceUpdate(nil, svc)
	metaProxier.OnServiceSynced()
	metaProxier.OnEndpointsUpdate(nil, epv4)
	metaProxier.OnEndpointsUpdate(nil, epv6)
	metaProxier.OnEndpointsSynced()

	groupIDv4 := fpv4.groupCounter.AllocateIfNotExist(svcPortName, false)
	groupIDv6 := fpv6.groupCounter.AllocateIfNotExist(svcPortName, false)

	mockOFClient.EXPECT().InstallServiceGroup(groupIDv4, false, nil, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDv4, svc1IPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)

	mockOFClient.EXPECT().InstallServiceGroup(groupIDv6, false, nil, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCPv6, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDv6, svc1IPv6, uint16(svcPort), binding.ProtocolTCPv6, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)

	fpv4.syncProxyRules()
	fpv6.syncProxyRules()
}

func testClusterIPRemove(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6, withProxyAll)

	svc := makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	ep := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, ep)

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc, nil)
	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func testNodePortRemove(t *testing.T, nodePortAddresses []net.IP, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	svc := makeTestNodePortService(&svcPortName, svcIP,
		int32(svcPort),
		int32(svcNodePort),
		corev1.ProtocolTCP,
		nil,
		corev1.ServiceInternalTrafficPolicyCluster,
		corev1.ServiceExternalTrafficPolicyTypeLocal)
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, true)
	ep := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, ep)

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}
	expectedEp := k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, true, true, false, false, nil)
	expectedAllEps := []k8sproxy.Endpoint{expectedEp}

	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedAllEps).Times(1)
	groupIDLocal := fp.groupCounter.AllocateIfNotExist(svcPortName, true)
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDLocal, false, nil, expectedAllEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, expectedAllEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), true, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDLocal, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), true, corev1.ServiceTypeNodePort).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, expectedEp).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(gomock.Any()).Times(2)
	mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc, nil)
	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func testLoadBalancerRemove(t *testing.T, nodePortAddresses []net.IP, svcIP net.IP, epIP net.IP, loadBalancerIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	externalTrafficPolicy := corev1.ServiceExternalTrafficPolicyTypeLocal
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster

	svc := makeTestLoadBalancerService(&svcPortName, svcIP,
		[]net.IP{loadBalancerIP},
		int32(svcPort),
		int32(svcNodePort),
		corev1.ProtocolTCP,
		nil,
		&internalTrafficPolicy,
		externalTrafficPolicy)
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, true)
	ep := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, ep)

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}
	expectedEp := k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, true, true, false, false, nil)
	expectedAllEps := []k8sproxy.Endpoint{expectedEp}

	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedAllEps).Times(1)
	groupIDLocal := fp.groupCounter.AllocateIfNotExist(svcPortName, true)
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, expectedAllEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDLocal, false, nil, expectedAllEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), true, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDLocal, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), true, corev1.ServiceTypeNodePort).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDLocal, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), true, corev1.ServiceTypeLoadBalancer).Times(1)

	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)

	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, expectedEp).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(loadBalancerIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(gomock.Any()).Times(2)
	mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	mockRouteClient.EXPECT().DeleteLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc, nil)
	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemove(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testClusterIPRemove(t, svc1IPv4, ep1IPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testClusterIPRemove(t, svc1IPv6, ep1IPv6, true)
	})
}

func TestNodePortRemove(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testNodePortRemove(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testNodePortRemove(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, true)
	})
}

func TestLoadBalancerRemove(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testLoadBalancerRemove(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, loadBalancerIPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testLoadBalancerRemove(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, loadBalancerIPv6, true)
	})

}

func testClusterIPNoEndpoint(t *testing.T, svcIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svc := makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	makeServiceMap(fp, svc)
	makeEndpointsMap(fp)
	fp.syncProxyRules()
}

func TestClusterIPNoEndpoint(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testClusterIPNoEndpoint(t, svc1IPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testClusterIPNoEndpoint(t, svc1IPv6, true)
	})
}

func testClusterIPRemoveSamePortEndpoint(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svcPortNameTCP := makeSvcPortName("ns", "svc-tcp", strconv.Itoa(svcPort), corev1.ProtocolTCP)
	svcPortNameUDP := makeSvcPortName("ns", "svc-udp", strconv.Itoa(svcPort), corev1.ProtocolUDP)

	svcTCP := makeTestClusterIPService(&svcPortNameTCP, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	svcUDP := makeTestClusterIPService(&svcPortNameUDP, svcIP, int32(svcPort), corev1.ProtocolUDP, nil, nil)
	makeServiceMap(fp, svcTCP, svcUDP)

	epSubset := makeTestEndpointSubset(&svcPortNameTCP, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	epTCP := makeTestEndpoints(&svcPortNameTCP, []corev1.EndpointSubset{*epSubset})
	epSubset = makeTestEndpointSubset(&svcPortNameUDP, epIP, int32(svcPort), corev1.ProtocolUDP, false)
	epUDP := makeTestEndpoints(&svcPortNameUDP, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, epTCP, epUDP)

	protocolTCP := binding.ProtocolTCP
	protocolUDP := binding.ProtocolUDP
	if isIPv6 {
		protocolTCP = binding.ProtocolTCPv6
		protocolUDP = binding.ProtocolUDPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortNameTCP, false)
	groupIDUDP := fp.groupCounter.AllocateIfNotExist(svcPortNameUDP, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDUDP, false, nil, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallEndpointFlows(protocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(protocolUDP, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), protocolTCP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDUDP, svcIP, uint16(svcPort), protocolUDP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(protocolUDP, gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.endpointsChanges.OnEndpointUpdate(epUDP, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemoveSamePortEndpoint(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testClusterIPRemoveSamePortEndpoint(t, svc1IPv4, ep1IPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testClusterIPRemoveSamePortEndpoint(t, svc1IPv6, ep1IPv6, true)
	})
}

func testClusterIPRemoveEndpoints(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svc := makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	ep := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, ep)

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemoveEndpoints(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testClusterIPRemoveEndpoints(t, svc1IPv4, ep1IPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testClusterIPRemoveEndpoints(t, svc1IPv6, ep1IPv6, true)
	})
}

func testSessionAffinity(t *testing.T, svcIP net.IP, epIP net.IP, affinitySeconds int32, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	svc := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.Type = corev1.ServiceTypeNodePort
		svc.Spec.ClusterIP = svcIP.String()
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
	})
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	ep := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, ep)

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}
	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, true, nil, gomock.Any()).Times(1)
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

func TestSessionAffinity(t *testing.T) {
	affinitySeconds := corev1.DefaultClientIPServiceAffinitySeconds
	t.Run("IPv4", func(t *testing.T) {
		testSessionAffinity(t, svc1IPv4, ep1IPv4, affinitySeconds, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testSessionAffinity(t, svc1IPv6, ep1IPv6, affinitySeconds, true)
	})
}

func TestSessionAffinityOverflow(t *testing.T) {
	// Ensure that the SessionAffinity timeout is truncated to the max supported value, instead
	// of wrapping around.
	affinitySeconds := int32(math.MaxUint16 + 10)
	testSessionAffinity(t, svc1IPv4, ep1IPv4, affinitySeconds, false)
}

func testSessionAffinityNoEndpoint(t *testing.T, svcExternalIPs net.IP, svcIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6)

	timeoutSeconds := corev1.DefaultClientIPServiceAffinitySeconds

	svc := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
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
	})
	makeServiceMap(fp, svc)
	makeEndpointsMap(fp)
	fp.syncProxyRules()
}

func TestSessionAffinityNoEndpoint(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testSessionAffinityNoEndpoint(t, net.ParseIP("50.60.70.81"), svc1IPv4, false)
	})
	t.Run("IPv6", func(t *testing.T) {
		testSessionAffinityNoEndpoint(t, net.ParseIP("5060:70::81"), svc1IPv6, true)
	})
}

func testServiceClusterIPUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	updatedSvcIP net.IP,
	loadBalancerIP net.IP,
	epIP net.IP,
	svcType corev1.ServiceType,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var svc, updatedSvc *corev1.Service
	switch svcType {
	case corev1.ServiceTypeClusterIP:
		svc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
		updatedSvc = makeTestClusterIPService(&svcPortName, updatedSvcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	case corev1.ServiceTypeNodePort:
		svc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestNodePortService(&svcPortName, updatedSvcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
	case corev1.ServiceTypeLoadBalancer:
		svc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestLoadBalancerService(&svcPortName, updatedSvcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	}
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, eps)

	expectedEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, false, true, false, false, nil)}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	s1 := mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	s2 := mockOFClient.EXPECT().InstallServiceFlows(groupID, updatedSvcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	s2.After(s1)
	mockRouteClient.EXPECT().DeleteClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(updatedSvcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

		mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)

		mockOFClient.EXPECT().UninstallServiceFlows(loadBalancerIP, uint16(svcPort), bindingProtocol).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().DeleteLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}

	fp.syncProxyRules()
	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	fp.syncProxyRules()
}

func TestServiceClusterIPUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceClusterIPUpdate(t, nil, svc1IPv4, svc2IPv4, nil, ep1IPv4, corev1.ServiceTypeClusterIP, false)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServiceClusterIPUpdate(t, nodePortAddressesIPv4, svc1IPv4, svc2IPv4, nil, ep1IPv4, corev1.ServiceTypeNodePort, false)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceClusterIPUpdate(t, nodePortAddressesIPv4, svc1IPv4, svc2IPv4, loadBalancerIPv4, ep1IPv4, corev1.ServiceTypeLoadBalancer, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceClusterIPUpdate(t, nil, svc1IPv6, svc2IPv6, nil, ep1IPv6, corev1.ServiceTypeClusterIP, true)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServiceClusterIPUpdate(t, nodePortAddressesIPv6, svc1IPv6, svc2IPv6, nil, ep1IPv6, corev1.ServiceTypeNodePort, true)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceClusterIPUpdate(t, nodePortAddressesIPv6, svc1IPv6, svc2IPv6, loadBalancerIPv6, ep1IPv6, corev1.ServiceTypeLoadBalancer, true)
		})
	})
}

func testServicePortUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	loadBalancerIP net.IP,
	epIP net.IP,
	svcType corev1.ServiceType,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var svc, updatedSvc *corev1.Service
	switch svcType {
	case corev1.ServiceTypeClusterIP:
		svc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
		updatedSvc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort+1), corev1.ProtocolTCP, nil, nil)
	case corev1.ServiceTypeNodePort:
		svc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort+1), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
	case corev1.ServiceTypeLoadBalancer:
		svc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort+1), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	}
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, eps)

	expectedEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, false, true, false, false, nil)}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	s1 := mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	s2 := mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort+1), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	s2.After(s1)

	mockRouteClient.EXPECT().DeleteClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

		mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)

		s1 = mockOFClient.EXPECT().UninstallServiceFlows(loadBalancerIP, uint16(svcPort), bindingProtocol)
		s2 = mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort+1), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		s2.After(s1)

		mockRouteClient.EXPECT().DeleteLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}
	fp.syncProxyRules()
	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	fp.syncProxyRules()
}

func TestServicePortUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServicePortUpdate(t, nil, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeClusterIP, false)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServicePortUpdate(t, nodePortAddressesIPv4, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeNodePort, false)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServicePortUpdate(t, nodePortAddressesIPv4, svc1IPv4, loadBalancerIPv4, ep1IPv4, corev1.ServiceTypeLoadBalancer, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServicePortUpdate(t, nil, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeClusterIP, true)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServicePortUpdate(t, nodePortAddressesIPv6, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeNodePort, true)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServicePortUpdate(t, nodePortAddressesIPv6, svc1IPv6, loadBalancerIPv6, ep1IPv6, corev1.ServiceTypeLoadBalancer, true)
		})
	})
}

func testServiceNodePortUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	loadBalancerIP net.IP,
	epIP net.IP,
	svcType corev1.ServiceType,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var svc, updatedSvc *corev1.Service
	switch svcType {
	case corev1.ServiceTypeNodePort:
		svc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort+1), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
	case corev1.ServiceTypeLoadBalancer:
		svc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort+1), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	}
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, eps)

	expectedEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, false, true, false, false, nil)}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().DeleteClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

		s1 := mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol)
		mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
		s2 := mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort+1), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort+1), bindingProtocol).Times(1)
		s2.After(s1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)

		mockOFClient.EXPECT().UninstallServiceFlows(loadBalancerIP, uint16(svcPort), bindingProtocol)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().DeleteLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}

	fp.syncProxyRules()
	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	fp.syncProxyRules()
}

func TestServiceNodePortUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("NodePort", func(t *testing.T) {
			testServiceNodePortUpdate(t, nodePortAddressesIPv4, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeNodePort, false)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceNodePortUpdate(t, nodePortAddressesIPv4, svc1IPv4, loadBalancerIPv4, ep1IPv4, corev1.ServiceTypeLoadBalancer, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("NodePort", func(t *testing.T) {
			testServiceNodePortUpdate(t, nodePortAddressesIPv6, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeNodePort, true)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceNodePortUpdate(t, nodePortAddressesIPv6, svc1IPv6, loadBalancerIPv6, ep1IPv6, corev1.ServiceTypeLoadBalancer, true)
		})
	})
}

func testServiceExternalTrafficPolicyUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	loadBalancerIP net.IP,
	ep1IP net.IP,
	ep2IP net.IP,
	svcType corev1.ServiceType,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var svc, updatedSvc *corev1.Service
	switch svcType {
	case corev1.ServiceTypeNodePort:
		svc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeLocal)
	case corev1.ServiceTypeLoadBalancer:
		svc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeLocal)
	}
	makeServiceMap(fp, svc)

	remoteEpSubset := makeTestEndpointSubset(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
	localEpSubset := makeTestEndpointSubset(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*remoteEpSubset, *localEpSubset})
	makeEndpointsMap(fp, eps)

	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), "", "", svcPort, true, true, false, false, nil)}
	expectedAllEps := append(expectedLocalEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, false, false, nil))

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	groupIDLocal := fp.groupCounter.AllocateIfNotExist(svcPortName, true)

	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), true, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().DeleteClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedAllEps)).Times(1)
		mockOFClient.EXPECT().InstallServiceGroup(groupIDLocal, false, nil, expectedLocalEps).Times(1)

		s1 := mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol).Times(1)
		s2 := mockOFClient.EXPECT().InstallServiceFlows(groupIDLocal, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), true, corev1.ServiceTypeNodePort).Times(1)
		s2.After(s1)

		mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		s1 := mockOFClient.EXPECT().UninstallServiceFlows(loadBalancerIP, uint16(svcPort), bindingProtocol).Times(1)
		s2 := mockOFClient.EXPECT().InstallServiceFlows(groupIDLocal, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), true, corev1.ServiceTypeLoadBalancer).Times(1)
		s2.After(s1)

		mockRouteClient.EXPECT().DeleteLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}
	fp.syncProxyRules()
}

func TestServiceExternalTrafficPolicyUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("NodePort", func(t *testing.T) {
			testServiceExternalTrafficPolicyUpdate(t, nodePortAddressesIPv4, svc1IPv4, nil, ep1IPv4, ep2IPv4, corev1.ServiceTypeNodePort, false)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceExternalTrafficPolicyUpdate(t, nodePortAddressesIPv4, svc1IPv4, loadBalancerIPv4, ep1IPv4, ep2IPv4, corev1.ServiceTypeLoadBalancer, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("NodePort", func(t *testing.T) {
			testServiceExternalTrafficPolicyUpdate(t, nodePortAddressesIPv6, svc1IPv6, nil, ep1IPv6, ep2IPv6, corev1.ServiceTypeNodePort, true)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceExternalTrafficPolicyUpdate(t, nodePortAddressesIPv6, svc1IPv6, loadBalancerIPv6, ep1IPv6, ep2IPv6, corev1.ServiceTypeLoadBalancer, true)
		})
	})
}

func testServiceInternalTrafficPolicyUpdate(t *testing.T,
	svcIP net.IP,
	ep1IP net.IP,
	ep2IP net.IP,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, isIPv6, withProxyAll)

	internalTrafficPolicyCluster := corev1.ServiceInternalTrafficPolicyCluster
	internalTrafficPolicyLocal := corev1.ServiceInternalTrafficPolicyLocal

	svc := makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, &internalTrafficPolicyCluster)
	updatedSvc := makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, &internalTrafficPolicyLocal)
	makeServiceMap(fp, svc)

	remoteEpSubset := makeTestEndpointSubset(&svcPortName, ep1IP, int32(svcPort), corev1.ProtocolTCP, false)
	localEpSubset := makeTestEndpointSubset(&svcPortName, ep2IP, int32(svcPort), corev1.ProtocolTCP, true)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*remoteEpSubset, *localEpSubset})
	makeEndpointsMap(fp, eps)

	expectedLocalEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(ep2IP.String(), "", "", svcPort, true, true, false, false, nil)}
	expectedAllEps := append(expectedLocalEps, k8sproxy.NewBaseEndpointInfo(ep1IP.String(), "", "", svcPort, false, true, false, false, nil))

	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedAllEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	groupIDLocal := fp.groupCounter.AllocateIfNotExist(svcPortName, true)

	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedLocalEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDLocal, false, nil, expectedLocalEps).Times(1)
	fp.syncProxyRules()
}

func TestServiceInternalTrafficPolicyUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceInternalTrafficPolicyUpdate(t, svc1IPv4, ep1IPv4, ep2IPv4, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceInternalTrafficPolicyUpdate(t, svc1IPv6, ep1IPv6, ep2IPv6, true)
		})
	})
}

func testServiceIngressIPsUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	epIP net.IP,
	loadBalancerIPs []net.IP,
	updatedLoadBalancerIPs []net.IP,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var loadBalancerIPStrs, updatedLoadBalancerIPStrs []string
	for _, ip := range loadBalancerIPs {
		loadBalancerIPStrs = append(loadBalancerIPStrs, ip.String())
	}
	for _, ip := range updatedLoadBalancerIPs {
		updatedLoadBalancerIPStrs = append(updatedLoadBalancerIPStrs, ip.String())
	}

	svc := makeTestLoadBalancerService(&svcPortName, svcIP, loadBalancerIPs, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	updatedSvc := makeTestLoadBalancerService(&svcPortName, svcIP, updatedLoadBalancerIPs, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, eps)

	expectedEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, false, true, false, false, nil)}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.InAnyOrder(expectedEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, gomock.InAnyOrder(expectedEps)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
	for _, ip := range loadBalancerIPs {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, ip, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
	}
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	mockRouteClient.EXPECT().AddLoadBalancer(gomock.InAnyOrder(loadBalancerIPStrs)).Times(1)

	toDeleteLoadBalancerIPs := smallSliceDifference(loadBalancerIPStrs, updatedLoadBalancerIPStrs)
	toAddLoadBalancerIPs := smallSliceDifference(updatedLoadBalancerIPStrs, loadBalancerIPStrs)
	for _, ipStr := range toDeleteLoadBalancerIPs {
		mockOFClient.EXPECT().UninstallServiceFlows(net.ParseIP(ipStr), uint16(svcPort), bindingProtocol).Times(1)
	}
	for _, ipStr := range toAddLoadBalancerIPs {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, net.ParseIP(ipStr), uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
	}
	mockRouteClient.EXPECT().DeleteLoadBalancer(gomock.InAnyOrder(toDeleteLoadBalancerIPs)).Times(1)
	mockRouteClient.EXPECT().AddLoadBalancer(gomock.InAnyOrder(toAddLoadBalancerIPs)).Times(1)

	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	fp.syncProxyRules()
	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	fp.syncProxyRules()
}

func TestServiceIngressIPsUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("LoadBalancer", func(t *testing.T) {
			loadBalancerIPs := []net.IP{net.ParseIP("169.254.1.1"), net.ParseIP("169.254.1.2")}
			updatedLoadBalancerIPs := []net.IP{net.ParseIP("169.254.1.2"), net.ParseIP("169.254.1.3")}
			testServiceIngressIPsUpdate(t, nodePortAddressesIPv4, svc1IPv4, ep1IPv4, loadBalancerIPs, updatedLoadBalancerIPs, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("LoadBalancer", func(t *testing.T) {
			loadBalancerIPs := []net.IP{net.ParseIP("fec0::169:254:1:1"), net.ParseIP("fec0::169:254:1:2")}
			updatedLoadBalancerIPs := []net.IP{net.ParseIP("fec0::169:254:1:2"), net.ParseIP("fec0::169:254:1:3")}
			testServiceIngressIPsUpdate(t, nodePortAddressesIPv6, svc1IPv6, ep1IPv6, loadBalancerIPs, updatedLoadBalancerIPs, true)
		})
	})
}

func testServiceStickyMaxAgeSecondsUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	loadBalancerIP net.IP,
	epIP net.IP,
	svcType corev1.ServiceType,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var svc, updatedSvc *corev1.Service
	affinitySeconds := int32(10)
	updatedAffinitySeconds := int32(100)
	switch svcType {
	case corev1.ServiceTypeClusterIP:
		svc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, &affinitySeconds, nil)
		updatedSvc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, &updatedAffinitySeconds, nil)
	case corev1.ServiceTypeNodePort:
		svc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, &affinitySeconds, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, &updatedAffinitySeconds, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
	case corev1.ServiceTypeLoadBalancer:
		svc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, &affinitySeconds, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, &updatedAffinitySeconds, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	}
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, eps)

	expectedEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, false, true, false, false, nil)}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, true, nil, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(affinitySeconds), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(updatedAffinitySeconds), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(affinitySeconds), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(affinitySeconds), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}

	fp.syncProxyRules()
	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	fp.syncProxyRules()
}

func TestServiceStickyMaxAgeSecondsUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceStickyMaxAgeSecondsUpdate(t, nil, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeClusterIP, false)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServiceStickyMaxAgeSecondsUpdate(t, nodePortAddressesIPv4, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeNodePort, false)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceStickyMaxAgeSecondsUpdate(t, nodePortAddressesIPv4, svc1IPv4, loadBalancerIPv4, ep1IPv4, corev1.ServiceTypeLoadBalancer, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceStickyMaxAgeSecondsUpdate(t, nil, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeClusterIP, true)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServiceStickyMaxAgeSecondsUpdate(t, nodePortAddressesIPv6, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeNodePort, true)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceStickyMaxAgeSecondsUpdate(t, nodePortAddressesIPv6, svc1IPv6, loadBalancerIPv6, ep1IPv6, corev1.ServiceTypeLoadBalancer, true)
		})
	})
}

func testServiceSessionAffinityTypeUpdate(t *testing.T,
	nodePortAddresses []net.IP,
	svcIP net.IP,
	loadBalancerIP net.IP,
	epIP net.IP,
	svcType corev1.ServiceType,
	isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(isIPv6)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddresses, groupAllocator, isIPv6, withProxyAll)

	var svc, updatedSvc *corev1.Service
	affinitySeconds := int32(100)
	switch svcType {
	case corev1.ServiceTypeClusterIP:
		svc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, nil, nil)
		updatedSvc = makeTestClusterIPService(&svcPortName, svcIP, int32(svcPort), corev1.ProtocolTCP, &affinitySeconds, nil)
	case corev1.ServiceTypeNodePort:
		svc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestNodePortService(&svcPortName, svcIP, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, &affinitySeconds, corev1.ServiceInternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyTypeCluster)
	case corev1.ServiceTypeLoadBalancer:
		svc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, nil, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
		updatedSvc = makeTestLoadBalancerService(&svcPortName, svcIP, []net.IP{loadBalancerIP}, int32(svcPort), int32(svcNodePort), corev1.ProtocolTCP, &affinitySeconds, nil, corev1.ServiceExternalTrafficPolicyTypeCluster)
	}
	makeServiceMap(fp, svc)

	epSubset := makeTestEndpointSubset(&svcPortName, epIP, int32(svcPort), corev1.ProtocolTCP, false)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, eps)

	expectedEps := []k8sproxy.Endpoint{k8sproxy.NewBaseEndpointInfo(epIP.String(), "", "", svcPort, false, true, false, false, nil)}

	bindingProtocol := binding.ProtocolTCP
	vIP := agentconfig.VirtualNodePortDNATIPv4
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
		vIP = agentconfig.VirtualNodePortDNATIPv6
	}

	groupID := fp.groupCounter.AllocateIfNotExist(svcPortName, false)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, nil, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, expectedEps).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, true, nil, expectedEps).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(affinitySeconds), false, corev1.ServiceTypeClusterIP).Times(1)
	mockRouteClient.EXPECT().DeleteClusterIPRoute(svcIP).Times(1)
	mockRouteClient.EXPECT().AddClusterIPRoute(svcIP).Times(1)

	if svcType == corev1.ServiceTypeNodePort || svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)

		mockOFClient.EXPECT().UninstallServiceFlows(vIP, uint16(svcNodePort), bindingProtocol).Times(1)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, vIP, uint16(svcNodePort), bindingProtocol, uint16(affinitySeconds), false, corev1.ServiceTypeNodePort).Times(1)
		mockRouteClient.EXPECT().DeleteNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
		mockRouteClient.EXPECT().AddNodePort(nodePortAddresses, uint16(svcNodePort), bindingProtocol).Times(1)
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)

		mockOFClient.EXPECT().UninstallServiceFlows(loadBalancerIP, uint16(svcPort), bindingProtocol)
		mockOFClient.EXPECT().InstallServiceFlows(groupID, loadBalancerIP, uint16(svcPort), bindingProtocol, uint16(affinitySeconds), false, corev1.ServiceTypeLoadBalancer).Times(1)
		mockRouteClient.EXPECT().DeleteLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
		mockRouteClient.EXPECT().AddLoadBalancer([]string{loadBalancerIP.String()}).Times(1)
	}

	fp.syncProxyRules()
	fp.serviceChanges.OnServiceUpdate(svc, updatedSvc)
	fp.syncProxyRules()
}

func TestServiceSessionAffinityTypeUpdate(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceSessionAffinityTypeUpdate(t, nil, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeClusterIP, false)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServiceSessionAffinityTypeUpdate(t, nodePortAddressesIPv4, svc1IPv4, nil, ep1IPv4, corev1.ServiceTypeNodePort, false)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceSessionAffinityTypeUpdate(t, nodePortAddressesIPv4, svc1IPv4, loadBalancerIPv4, ep1IPv4, corev1.ServiceTypeLoadBalancer, false)
		})
	})
	t.Run("IPv6", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			testServiceSessionAffinityTypeUpdate(t, nil, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeClusterIP, true)
		})
		t.Run("NodePort", func(t *testing.T) {
			testServiceSessionAffinityTypeUpdate(t, nodePortAddressesIPv6, svc1IPv6, nil, ep1IPv6, corev1.ServiceTypeNodePort, true)
		})
		t.Run("LoadBalancer", func(t *testing.T) {
			testServiceSessionAffinityTypeUpdate(t, nodePortAddressesIPv6, svc1IPv6, loadBalancerIPv6, ep1IPv6, corev1.ServiceTypeLoadBalancer, true)
		})
	})
}

func TestServicesWithSameEndpoints(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(false)
	fp := NewFakeProxier(mockRouteClient, mockOFClient, nil, groupAllocator, false)

	svcPortName1 := makeSvcPortName("ns", "svc1", strconv.Itoa(svcPort), corev1.ProtocolTCP)
	svcPortName2 := makeSvcPortName("ns", "svc2", strconv.Itoa(svcPort), corev1.ProtocolTCP)
	svc1 := makeTestClusterIPService(&svcPortName1, svc1IPv4, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	svc2 := makeTestClusterIPService(&svcPortName2, svc2IPv4, int32(svcPort), corev1.ProtocolTCP, nil, nil)
	makeServiceMap(fp, svc1, svc2)

	epSubset := makeTestEndpointSubset(&svcPortName1, ep1IPv4, int32(svcPort), corev1.ProtocolTCP, false)
	ep1 := makeTestEndpoints(&svcPortName1, []corev1.EndpointSubset{*epSubset})
	epSubset = makeTestEndpointSubset(&svcPortName2, ep1IPv4, int32(svcPort), corev1.ProtocolTCP, false)
	ep2 := makeTestEndpoints(&svcPortName2, []corev1.EndpointSubset{*epSubset})
	makeEndpointsMap(fp, ep1, ep2)

	groupID1 := fp.groupCounter.AllocateIfNotExist(svcPortName1, false)
	groupID2 := fp.groupCounter.AllocateIfNotExist(svcPortName2, false)
	mockOFClient.EXPECT().InstallServiceGroup(groupID1, false, nil, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupID2, false, nil, gomock.Any()).Times(1)
	bindingProtocol := binding.ProtocolTCP
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID1, svc1IPv4, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID2, svc2IPv4, uint16(svcPort), bindingProtocol, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svc1IPv4, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svc2IPv4, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(groupID1).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(groupID2).Times(1)
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
	legacyregistry.Reset()
	metrics.Register()

	for _, tc := range []struct {
		name                string
		svcIP, ep1IP, ep2IP net.IP
		isIPv6              bool
	}{
		{"IPv4", svc1IPv4, ep1IPv4, ep2IPv4, false},
		{"IPv6", svc1IPv6, ep1IPv6, ep2IPv6, true},
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

			testClusterIPAdd(t, tc.svcIP, tc.ep1IP, tc.ep2IP, tc.isIPv6, false, []*corev1.Service{}, []*corev1.Endpoints{}, false)
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

			testClusterIPRemove(t, tc.svcIP, tc.ep1IP, tc.isIPv6)

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

func TestGetServiceFlowKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient, mockRouteClient := getMockClients(ctrl)
	groupAllocator := openflow.NewGroupAllocator(false)
	svc := makeTestNodePortService(&svcPortName,
		svc1IPv4,
		int32(svcPort),
		int32(svcNodePort),
		corev1.ProtocolTCP,
		nil,
		corev1.ServiceInternalTrafficPolicyLocal,
		corev1.ServiceExternalTrafficPolicyTypeCluster)
	remoteEpSubset := makeTestEndpointSubset(&svcPortName, ep1IPv4, int32(svcPort), corev1.ProtocolTCP, false)
	localEpSubset := makeTestEndpointSubset(&svcPortName, ep2IPv4, int32(svcPort), corev1.ProtocolTCP, true)
	eps := makeTestEndpoints(&svcPortName, []corev1.EndpointSubset{*remoteEpSubset, *localEpSubset})

	testCases := []struct {
		name             string
		svc              *corev1.Service
		eps              *corev1.Endpoints
		serviceInstalled bool
		expectedFound    bool
	}{
		{
			name:             "Installed Service with Endpoints",
			svc:              svc,
			eps:              eps,
			serviceInstalled: true,
			expectedFound:    true,
		},
		{
			name:             "Not installed Service without Endpoints",
			svc:              svc,
			serviceInstalled: false,
			expectedFound:    false,
		},
		{
			name:             "Not installed Service with Endpoints",
			svc:              svc,
			eps:              eps,
			serviceInstalled: false,
			expectedFound:    false,
		},
		{
			name:             "Not existing Service",
			serviceInstalled: false,
			expectedFound:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fp := NewFakeProxier(mockRouteClient, mockOFClient, nodePortAddressesIPv4, groupAllocator, false, withProxyAll)
			if tc.svc != nil {
				makeServiceMap(fp, svc)
			}
			if tc.eps != nil {
				makeEndpointsMap(fp, eps)
			}
			if tc.svc != nil && tc.eps != nil && tc.serviceInstalled {
				mockRouteClient.EXPECT().AddClusterIPRoute(svc1IPv4).Times(1)
				mockRouteClient.EXPECT().AddNodePort(nodePortAddressesIPv4, uint16(svcNodePort), binding.ProtocolTCP).Times(1)
				mockOFClient.EXPECT().InstallServiceGroup(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
				mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
				mockOFClient.EXPECT().InstallServiceFlows(gomock.Any(), gomock.Any(), uint16(svcNodePort), binding.ProtocolTCP, uint16(0), false, corev1.ServiceTypeNodePort).Times(1)
				mockOFClient.EXPECT().InstallServiceFlows(gomock.Any(), svc1IPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0), false, corev1.ServiceTypeClusterIP).Times(1)
				fp.syncProxyRules()
			}

			var expectedGroupIDs []binding.GroupIDType
			if tc.serviceInstalled {
				expectedGroupIDs = append(expectedGroupIDs, fp.groupCounter.AllocateIfNotExist(svcPortName, false))
				expectedGroupIDs = append(expectedGroupIDs, fp.groupCounter.AllocateIfNotExist(svcPortName, true))
				mockOFClient.EXPECT().GetServiceFlowKeys(svc1IPv4, uint16(svcPort), binding.ProtocolTCP, gomock.Any()).Times(1)
			}

			_, groupIDs, found := fp.GetServiceFlowKeys("svc", "ns")
			assert.ElementsMatch(t, expectedGroupIDs, groupIDs)
			assert.Equal(t, tc.expectedFound, found)
		})
	}
}
