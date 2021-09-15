// Copyright 2021 Antrea Authors
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

package externalip

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/ipassigner"
	ipassignertest "antrea.io/antrea/pkg/agent/ipassigner/testing"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/types"
)

const (
	fakeNode1              = "node1"
	fakeNode2              = "node2"
	fakeNodeIP             = "1.1.1.1"
	fakeExternalIPPoolName = "pool1"
	fakeLoadBalancerIP1    = "1.2.3.4"
	fakeLoadBalancerIP2    = "1.2.3.5"
)

var (
	servicePolicyCluster = makeService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyTypeCluster, fakeExternalIPPoolName, fakeLoadBalancerIP1)
	servicePolicyLocal   = makeService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyTypeLocal, fakeExternalIPPoolName, fakeLoadBalancerIP1)
)

type fakeLocalIPDetector struct {
	localIPs sets.String
}

func (d *fakeLocalIPDetector) IsLocalIP(ip string) bool {
	return d.localIPs.Has(ip)
}

func (d *fakeLocalIPDetector) Run(stopCh <-chan struct{}) {
	<-stopCh
}

func (d *fakeLocalIPDetector) AddEventHandler(handler ipassigner.LocalIPEventHandler) {
}

func (d *fakeLocalIPDetector) HasSynced() bool {
	return true
}

var _ ipassigner.LocalIPDetector = (*fakeLocalIPDetector)(nil)

type fakeMemberlistCluster struct {
	nodes []string
}

var _ memberlist.Interface = (*fakeMemberlistCluster)(nil)

func (f *fakeMemberlistCluster) AddClusterEventHandler(h memberlist.ClusterNodeEventHandler) {

}

func (f *fakeMemberlistCluster) AliveNodes() sets.String {
	return sets.NewString(f.nodes...)
}

func (f *fakeMemberlistCluster) SelectNodeForIP(ip, externalIPPool string, fillters ...func(string) bool) (string, error) {
	var selectNode string
	for _, n := range f.nodes {
		passed := true
		for _, f := range fillters {
			if !f(n) {
				passed = false
				break
			}
		}
		if passed {
			selectNode = n
			break
		}
	}
	if selectNode == "" {
		return selectNode, fmt.Errorf("no Node available for IP %s and externalIPPool %s", ip, externalIPPool)
	}
	return selectNode, nil
}

type fakeController struct {
	*ExternalIPController
	mockController        *gomock.Controller
	clientset             *fake.Clientset
	informerFactory       informers.SharedInformerFactory
	mockIPAssigner        *ipassignertest.MockIPAssigner
	fakeMemberlistCluster *fakeMemberlistCluster
}

func newFakeController(t *testing.T, objs ...runtime.Object) *fakeController {

	controller := gomock.NewController(t)
	clientset := fake.NewSimpleClientset(objs...)
	mockIPAssigner := ipassignertest.NewMockIPAssigner(controller)
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	localIPDetector := &fakeLocalIPDetector{}
	serviceInformer := informerFactory.Core().V1().Services()
	endpointInformer := informerFactory.Core().V1().Endpoints()

	memberlistCluster := &fakeMemberlistCluster{}
	eipController := &ExternalIPController{
		nodeName:              fakeNode1,
		serviceInformer:       serviceInformer.Informer(),
		serviceListerSynced:   serviceInformer.Informer().HasSynced,
		serviceLister:         serviceInformer.Lister(),
		endpointsInformer:     endpointInformer.Informer(),
		endpointsListerSynced: endpointInformer.Informer().HasSynced,
		endpointsLister:       endpointInformer.Lister(),
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "loadbalancer"),

		loadBalancerStates: make(map[apimachinerytypes.NamespacedName]externalIPState),
		cluster:            memberlistCluster,
		ipAssigner:         mockIPAssigner,
		localIPDetector:    localIPDetector,
	}
	return &fakeController{
		ExternalIPController:  eipController,
		mockController:        controller,
		clientset:             clientset,
		informerFactory:       informerFactory,
		mockIPAssigner:        mockIPAssigner,
		fakeMemberlistCluster: memberlistCluster,
	}

}

func makeService(name, namespace string, serviceType corev1.ServiceType,
	trafficPolicy corev1.ServiceExternalTrafficPolicyType, ipPool, lbIP string) *corev1.Service {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:                  serviceType,
			ExternalTrafficPolicy: trafficPolicy,
		},
	}
	if lbIP != "" {
		service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{IP: lbIP},
		}
	}
	if ipPool != "" {
		service.Annotations = map[string]string{
			types.ServiceExternalIPPoolAnnotationKey: ipPool,
		}
	}
	return service
}

func makeEndpoints(name, namespace string, addresses, notReadyAddresses map[string]string) *corev1.Endpoints {
	var addr, notReadyAddr []corev1.EndpointAddress
	for k, v := range addresses {
		ip := k
		addr = append(addr, corev1.EndpointAddress{
			IP:       ip,
			NodeName: stringPtr(v),
		})
	}
	for k, v := range notReadyAddresses {
		ip := k
		notReadyAddr = append(notReadyAddr, corev1.EndpointAddress{
			IP:       ip,
			NodeName: stringPtr(v),
		})
	}
	service := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},

		Subsets: []corev1.EndpointSubset{
			{
				Addresses:         addr,
				NotReadyAddresses: notReadyAddr,
			},
		},
	}
	return service
}

func TestCreateService(t *testing.T) {
	tests := []struct {
		name              string
		existingEndpoints []*corev1.Endpoints
		serviceToCreate   *corev1.Service
		healthyNodes      []string
		expectedCalls     func(mockIPAssigner *ipassignertest.MockIPAssigner)
		expectedLBStates  map[apimachinerytypes.NamespacedName]externalIPState
		expectedError     bool
	}{
		{
			"new Service created and local Node selected",
			nil,
			servicePolicyCluster,
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLoadBalancerIP1)
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {
					ip:           fakeLoadBalancerIP1,
					assignedNode: fakeNode1,
				},
			},
			false,
		},

		{
			"new Service created and local Node not selected",
			nil,
			servicePolicyCluster,
			[]string{fakeNode2, fakeNode1},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {
					ip:           fakeLoadBalancerIP1,
					assignedNode: fakeNode2,
				},
			},
			false,
		},
		{
			"new Service created with ExternalTrafficPolicy=Local and local Node selected",
			[]*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
					},
					nil),
			},
			servicePolicyLocal,
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLoadBalancerIP1)
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeLoadBalancerIP1,
					assignedNode: fakeNode1,
				},
			},
			false,
		},
		{
			"new Service created with ExternalTrafficPolicy=Local and local Node not Selected",
			[]*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					nil),
			},
			servicePolicyLocal,
			[]string{fakeNode2, fakeNode1},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeLoadBalancerIP1,
					assignedNode: fakeNode2,
				},
			},
			false,
		},
		{
			"new Service created with ExternalTrafficPolicy=Local and local Node has no healthy endpoints",
			[]*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					map[string]string{
						"2.3.4.5": fakeNode1,
					}),
			},
			servicePolicyLocal,
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeLoadBalancerIP1,
					assignedNode: fakeNode2,
				},
			},
			false,
		},
		{
			"new Service created with ExternalTrafficPolicy=Local and no Nodes has healthy endpoints",
			[]*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					}),
			},
			servicePolicyLocal,
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
			},
			map[apimachinerytypes.NamespacedName]externalIPState{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for _, s := range tt.existingEndpoints {
				objs = append(objs, s)
			}
			objs = append(objs, tt.serviceToCreate)
			c := newFakeController(t, objs...)
			defer c.mockController.Finish()
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.fakeMemberlistCluster.nodes = tt.healthyNodes
			tt.expectedCalls(c.mockIPAssigner)
			err := c.syncService(keyFor(tt.serviceToCreate))
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedLBStates, c.loadBalancerStates)
		})
	}
}

func TestUpdateService(t *testing.T) {
	service1UpdatedLBIP := servicePolicyCluster.DeepCopy()
	service1UpdatedLBIP.Status.LoadBalancer.Ingress[0].IP = fakeLoadBalancerIP2

	service1ChangedType := servicePolicyCluster.DeepCopy()
	service1ChangedType.Spec.Type = corev1.ServiceTypeClusterIP

	service1LBIPRecalimed := servicePolicyCluster.DeepCopy()
	service1LBIPRecalimed.Status.LoadBalancer.Ingress = nil

	serviceChangedExternalTrafficPolicy := servicePolicyCluster.DeepCopy()
	serviceChangedExternalTrafficPolicy.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal

	tests := []struct {
		name             string
		endpoints        []*corev1.Endpoints
		serviceToUpdate  *corev1.Service
		previousLBStates map[apimachinerytypes.NamespacedName]externalIPState
		expectedLBStates map[apimachinerytypes.NamespacedName]externalIPState
		healthyNodes     []string
		expectedCalls    func(mockIPAssigner *ipassignertest.MockIPAssigner)
		expectedError    bool
	}{
		{
			"Service Updated LB IP and local Node selected",
			nil,
			service1UpdatedLBIP,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(service1UpdatedLBIP): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(service1UpdatedLBIP): {fakeLoadBalancerIP2, fakeNode1},
			},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
				mockIPAssigner.EXPECT().AssignIP(fakeLoadBalancerIP2)
			},
			false,
		},
		{
			"Service Updated LB IP and local Node not selected",
			nil,
			service1UpdatedLBIP,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(service1UpdatedLBIP): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(service1UpdatedLBIP): {fakeLoadBalancerIP2, fakeNode2},
			},
			[]string{fakeNode2, fakeNode1},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP2)
			},
			false,
		},
		{
			"Service changed type to ClusterIP",
			nil,
			service1ChangedType,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(service1UpdatedLBIP): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			false,
		},
		{
			"Service LoadBalancer IP reclaimed",
			nil,
			service1ChangedType,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(service1UpdatedLBIP): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			false,
		},
		{
			"Service changed ExternalTrafficPolicy to local",
			[]*corev1.Endpoints{
				makeEndpoints(serviceChangedExternalTrafficPolicy.Name, serviceChangedExternalTrafficPolicy.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					}, map[string]string{
						"2.3.4.5": fakeNode1,
					}),
			},
			serviceChangedExternalTrafficPolicy,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceChangedExternalTrafficPolicy): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceChangedExternalTrafficPolicy): {fakeLoadBalancerIP1, fakeNode2},
			},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			false,
		},
		{
			"local Node no longer selected",
			nil,
			servicePolicyCluster,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {fakeLoadBalancerIP1, fakeNode2},
			},
			[]string{fakeNode2, fakeNode1},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			false,
		},
		{
			"local Node no longer have healy endpoints",
			[]*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					}, map[string]string{
						"2.3.4.5": fakeNode1,
					}),
			},
			servicePolicyLocal,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeLoadBalancerIP1, fakeNode2},
			},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP1)
			},
			false,
		},
		{
			"should not migrate to other nodes if local Node still have healthy endpoints",
			[]*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					nil,
				),
			},
			servicePolicyLocal,
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeLoadBalancerIP1, fakeNode1},
			},
			map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeLoadBalancerIP1, fakeNode1},
			},
			[]string{fakeNode2, fakeNode1},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeLoadBalancerIP1)
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for _, s := range tt.endpoints {
				objs = append(objs, s)
			}
			objs = append(objs, tt.serviceToUpdate)
			c := newFakeController(t, objs...)
			c.loadBalancerStates = tt.previousLBStates
			defer c.mockController.Finish()
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.fakeMemberlistCluster.nodes = tt.healthyNodes
			tt.expectedCalls(c.mockIPAssigner)
			err := c.syncService(keyFor(tt.serviceToUpdate))
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedLBStates, c.loadBalancerStates)
		})
	}
}

func TestStaleLoadBalancerIPRemoval(t *testing.T) {
	service3 := servicePolicyCluster.DeepCopy()
	service3.Name = "svc3"
	service3.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: fakeLoadBalancerIP2},
	}
	tests := []struct {
		name             string
		existingServices []*corev1.Service
		assignedIPs      []string
		expectedCalls    func(mockIPAssigner *ipassignertest.MockIPAssigner)
	}{
		{
			"should keep assigned IPs if coressponding Services are present",
			[]*corev1.Service{servicePolicyCluster, service3},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignedIPs().DoAndReturn(
					func() interface{} {
						return sets.NewString(fakeLoadBalancerIP1, fakeLoadBalancerIP2)
					},
				)
			},
		},
		{
			"should cleanup stale assigned IPs",
			[]*corev1.Service{servicePolicyCluster},
			[]string{fakeNode1, fakeNode2},
			func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignedIPs().DoAndReturn(
					func() interface{} {
						return sets.NewString(fakeLoadBalancerIP1, fakeLoadBalancerIP2)
					},
				)
				mockIPAssigner.EXPECT().UnassignIP(fakeLoadBalancerIP2)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for _, s := range tt.existingServices {
				objs = append(objs, s)
			}
			c := newFakeController(t, objs...)
			defer c.mockController.Finish()
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			tt.expectedCalls(c.mockIPAssigner)
			c.removeStaleExternalIPs()
		})
	}
}

func keyFor(svc *corev1.Service) apimachinerytypes.NamespacedName {
	return apimachinerytypes.NamespacedName{
		Namespace: svc.Namespace,
		Name:      svc.Name,
	}
}

func stringPtr(s string) *string {
	return &s
}
