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
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/metrics/testutil"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	ofmock "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
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

func NewFakeProxier(ofClient openflow.Client, isIPv6 bool) *proxier {
	hostname := "localhost"
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	p := &proxier{
		endpointsChanges:     newEndpointsChangesTracker(hostname),
		serviceChanges:       newServiceChangesTracker(recorder, isIPv6),
		serviceMap:           k8sproxy.ServiceMap{},
		serviceInstalledMap:  k8sproxy.ServiceMap{},
		endpointInstalledMap: map[k8sproxy.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		groupCounter:         types.NewGroupCounter(),
		ofClient:             ofClient,
		serviceStringMap:     map[string]k8sproxy.ServicePortName{},
		isIPv6:               isIPv6,
	}
	return p
}

func testClusterIP(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient, isIPv6)

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

	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	bindingProtocol := binding.ProtocolTCP
	if isIPv6 {
		bindingProtocol = binding.ProtocolTCPv6
	}
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any(), isIPv6).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0)).Times(1)

	fp.syncProxyRules()
}

func TestClusterIPv4(t *testing.T) {
	testClusterIP(t, net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), false)
}

func TestClusterIPv6(t *testing.T) {
	testClusterIP(t, net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), true)
}

func testClusterIPRemoval(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient, isIPv6)

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
	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any(), isIPv6).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0)).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort), bindingProtocol).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(bindingProtocol, gomock.Any()).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(groupID).Times(1)

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
	fp := NewFakeProxier(mockOFClient, isIPv6)

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
	fp := NewFakeProxier(mockOFClient, isIPv6)

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

	groupID, _ := fp.groupCounter.Get(svcPortName)
	groupIDUDP, _ := fp.groupCounter.Get(svcPortNameUDP)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDUDP, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(protocolTCP, gomock.Any(), isIPv6).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(protocolUDP, gomock.Any(), isIPv6).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), protocolTCP, uint16(0)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDUDP, svcIP, uint16(svcPort), protocolUDP, uint16(0)).Times(1)
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
	fp := NewFakeProxier(mockOFClient, isIPv6)

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
	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any(), isIPv6).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(0)).Times(1)
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

func testSessionAffinityNoEndpoint(t *testing.T, svcExternalIPs net.IP, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient, isIPv6)

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
			svc.Spec.Type = "NodePort"
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
	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, true, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any(), isIPv6).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), bindingProtocol, uint16(corev1.DefaultClientIPServiceAffinitySeconds)).Times(1)

	fp.syncProxyRules()
}

func TestSessionAffinityNoEndpointIPv4(t *testing.T) {
	testSessionAffinityNoEndpoint(t, net.ParseIP("50.60.70.81"), net.ParseIP("10.20.30.41"), net.ParseIP("10.180.0.1"), false)
}

func TestSessionAffinityNoEndpointIPv6(t *testing.T) {
	testSessionAffinityNoEndpoint(t, net.ParseIP("5060:70::81"), net.ParseIP("10:20::41"), net.ParseIP("10:180::1"), true)
}

func testSessionAffinity(t *testing.T, svcExternalIPs net.IP, svcIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient, isIPv6)

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
			svc.Spec.Type = "NodePort"
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

func TestSessionAffinityIPv4(t *testing.T) {
	testSessionAffinity(t, net.ParseIP("50.60.70.81"), net.ParseIP("10.20.30.41"), false)
}

func TestSessionAffinityIPv6(t *testing.T) {
	testSessionAffinity(t, net.ParseIP("5060:70::81"), net.ParseIP("10:20::41"), true)
}

func testPortChange(t *testing.T, svcIP net.IP, epIP net.IP, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient, isIPv6)

	svcPort1 := 80
	svcPort2 := 8080
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "http",
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
	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(2)
	mockOFClient.EXPECT().InstallEndpointFlows(bindingProtocol, gomock.Any(), isIPv6).Times(2)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort1), bindingProtocol, uint16(0))
	mockOFClient.EXPECT().UninstallServiceFlows(svcIP, uint16(svcPort1), bindingProtocol)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort2), bindingProtocol, uint16(0))

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

func TestMetrics(t *testing.T) {
	metrics.Register()

	for _, tc := range []struct {
		name        string
		svcIP, epIP string
		isIPv6      bool
	}{
		{"IPv4", "10.20.30.41", "10.180.0.1", false},
		{"IPv6", "fc01::1", "fe01::1", true},
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
			testClusterIP(t, net.ParseIP(tc.svcIP), net.ParseIP(tc.epIP), tc.isIPv6)
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
			assert.Equal(t, 1, int(v))
			assert.NoError(t, err)

			testClusterIPRemoval(t, net.ParseIP(tc.svcIP), net.ParseIP(tc.epIP), tc.isIPv6)

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
