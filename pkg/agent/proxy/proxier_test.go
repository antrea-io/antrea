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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	ofmock "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
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

func NewFakeProxier(ofClient openflow.Client) *proxier {
	hostname := "localhost"
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	p := &proxier{
		endpointsChanges:     newEndpointsChangesTracker(hostname),
		serviceChanges:       newServiceChangesTracker(recorder),
		serviceMap:           k8sproxy.ServiceMap{},
		serviceInstalledMap:  k8sproxy.ServiceMap{},
		endpointInstalledMap: map[k8sproxy.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		groupCounter:         types.NewGroupCounter(),
		ofClient:             ofClient,
		serviceStringMap:     map[string]k8sproxy.ServicePortName{},
	}
	return p
}

func TestClusterIP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIPv4 := net.ParseIP("10.20.30.41")
	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIPv4.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
		}),
	)

	epIP := net.ParseIP("10.180.0.1")
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
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0)).Times(1)

	fp.syncProxyRules()
}

func TestClusterIPRemoval(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIPv4 := net.ParseIP("10.20.30.41")
	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           fmt.Sprint(svcPort),
		Protocol:       corev1.ProtocolTCP,
	}
	svc := makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
		svc.Spec.ClusterIP = svcIPv4.String()
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:     svcPortName.Port,
			Port:     int32(svcPort),
			Protocol: corev1.ProtocolTCP,
		}}
	})
	makeServiceMap(fp, svc)

	epIP := net.ParseIP("10.180.0.1")
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
	ep := makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, epFunc)
	makeEndpointsMap(fp, ep)
	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0)).Times(1)
	mockOFClient.EXPECT().UninstallServiceFlows(svcIPv4, uint16(svcPort), binding.ProtocolTCP).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().UninstallServiceGroup(groupID).Times(1)

	fp.syncProxyRules()

	fp.serviceChanges.OnServiceUpdate(svc, nil)
	fp.syncProxyRules()
}

func TestClusterIPNoEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIP := "10.20.30.41"
	svcPort := 80
	svcNodePort := 3001
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}

	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIP
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

func TestClusterIPRemoveSamePortEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIPv4 := net.ParseIP("10.20.30.41")
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
			svc.Spec.ClusterIP = svcIPv4.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
		}),
		makeTestService(svcPortName.Namespace, svcPortNameUDP.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIPv4.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolUDP,
			}}
		}),
	)

	epIP := "10.180.0.1"
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
	epUDP := makeTestEndpoints(svcPortName.Namespace, svcPortNameUDP.Name, func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: epIP,
			}},
			Ports: []corev1.EndpointPort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolUDP,
			}},
		}}
	})
	makeEndpointsMap(fp, ep, epUDP)

	groupID, _ := fp.groupCounter.Get(svcPortName)
	groupIDUDP, _ := fp.groupCounter.Get(svcPortNameUDP)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceGroup(groupIDUDP, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolUDP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0)).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupIDUDP, svcIPv4, uint16(svcPort), binding.ProtocolUDP, uint16(0)).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(binding.ProtocolUDP, gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.endpointsChanges.OnEndpointUpdate(epUDP, nil)
	fp.syncProxyRules()
}

func TestClusterIPRemoveEndpoints(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIPv4 := net.ParseIP("10.20.30.41")
	svcPort := 80
	svcPortName := k8sproxy.ServicePortName{
		NamespacedName: makeNamespaceName("ns1", "svc1"),
		Port:           "80",
		Protocol:       corev1.ProtocolTCP,
	}
	makeServiceMap(fp,
		makeTestService(svcPortName.Namespace, svcPortName.Name, func(svc *corev1.Service) {
			svc.Spec.ClusterIP = svcIPv4.String()
			svc.Spec.Ports = []corev1.ServicePort{{
				Name:     svcPortName.Port,
				Port:     int32(svcPort),
				Protocol: corev1.ProtocolTCP,
			}}
		}),
	)

	epIP := "10.180.0.1"
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
	groupID, _ := fp.groupCounter.Get(svcPortName)
	mockOFClient.EXPECT().InstallServiceGroup(groupID, false, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIPv4, uint16(svcPort), binding.ProtocolTCP, uint16(0)).Times(1)
	mockOFClient.EXPECT().UninstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	fp.syncProxyRules()

	fp.endpointsChanges.OnEndpointUpdate(ep, nil)
	fp.syncProxyRules()
}

func TestSessionAffinityNoEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIP := net.ParseIP("10.20.30.41")
	svcPort := 80
	svcNodePort := 3001
	svcExternalIPs := "50.60.70.81"
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
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
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
	epIPv4 := "10.180.0.1"
	makeEndpointsMap(fp,
		makeTestEndpoints(svcPortName.Namespace, svcPortName.Name, func(ept *corev1.Endpoints) {
			ept.Subsets = []corev1.EndpointSubset{{
				Addresses: []corev1.EndpointAddress{{
					IP: epIPv4,
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
	mockOFClient.EXPECT().InstallServiceGroup(groupID, true, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallEndpointFlows(binding.ProtocolTCP, gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallServiceFlows(groupID, svcIP, uint16(svcPort), binding.ProtocolTCP, uint16(corev1.DefaultClientIPServiceAffinitySeconds)).Times(1)

	fp.syncProxyRules()
}

func TestSessionAffinity(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOFClient := ofmock.NewMockClient(ctrl)
	fp := NewFakeProxier(mockOFClient)

	svcIP := net.ParseIP("10.20.30.41")
	svcPort := 80
	svcNodePort := 3001
	svcExternalIPs := "50.60.70.81"
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
			svc.Spec.ExternalIPs = []string{svcExternalIPs}
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
