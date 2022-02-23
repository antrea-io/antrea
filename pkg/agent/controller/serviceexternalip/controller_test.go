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

package serviceexternalip

import (
	"fmt"
	"sort"
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

	ipassignertest "antrea.io/antrea/pkg/agent/ipassigner/testing"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/types"
)

const (
	fakeNode1              = "node1"
	fakeNode2              = "node2"
	fakeExternalIPPoolName = "pool1"
	fakeServiceExternalIP1 = "1.2.3.4"
	fakeServiceExternalIP2 = "1.2.3.5"
)

var (
	servicePolicyCluster = makeService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyTypeCluster, fakeExternalIPPoolName, fakeServiceExternalIP1)
	servicePolicyLocal   = makeService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, corev1.ServiceExternalTrafficPolicyTypeLocal, fakeExternalIPPoolName, fakeServiceExternalIP1)
)

type fakeMemberlistCluster struct {
	nodes  []string
	hashFn func([]string) []string
}

func fakeHashFn(invert bool) func([]string) []string {
	return func(s []string) []string {
		hashed := make([]string, len(s))
		copy(hashed, s)
		sort.Strings(hashed)
		if invert {
			i, j := 0, len(hashed)-1
			for i < j {
				hashed[i], hashed[j] = hashed[j], hashed[i]
				i++
				j--
			}
		}
		return hashed
	}
}

var _ memberlist.Interface = (*fakeMemberlistCluster)(nil)

func (f *fakeMemberlistCluster) AddClusterEventHandler(h memberlist.ClusterNodeEventHandler) {
}

func (f *fakeMemberlistCluster) AliveNodes() sets.String {
	return sets.NewString(f.nodes...)
}

func (f *fakeMemberlistCluster) SelectNodeForIP(ip, externalIPPool string, filters ...func(string) bool) (string, error) {
	var selectNode string
	for _, n := range f.hashFn(f.nodes) {
		passed := true
		for _, f := range filters {
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
	*ServiceExternalIPController
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

	serviceInformer := informerFactory.Core().V1().Services()
	endpointInformer := informerFactory.Core().V1().Endpoints()

	memberlistCluster := &fakeMemberlistCluster{
		// default fake hash function which will return the sorted string slice in ascending order.
		hashFn: fakeHashFn(false),
	}
	eipController := &ServiceExternalIPController{
		nodeName:              fakeNode1,
		serviceInformer:       serviceInformer.Informer(),
		serviceListerSynced:   serviceInformer.Informer().HasSynced,
		serviceLister:         serviceInformer.Lister(),
		endpointsInformer:     endpointInformer.Informer(),
		endpointsListerSynced: endpointInformer.Informer().HasSynced,
		endpointsLister:       endpointInformer.Lister(),
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "serviceExternalIP"),
		client:                clientset,
		externalIPStates:      make(map[apimachinerytypes.NamespacedName]externalIPState),
		cluster:               memberlistCluster,
		ipAssigner:            mockIPAssigner,
		assignedIPs:           make(map[string]sets.String),
	}
	return &fakeController{
		ServiceExternalIPController: eipController,
		mockController:              controller,
		clientset:                   clientset,
		informerFactory:             informerFactory,
		mockIPAssigner:              mockIPAssigner,
		fakeMemberlistCluster:       memberlistCluster,
	}
}

func makeService(name, namespace string, serviceType corev1.ServiceType,
	trafficPolicy corev1.ServiceExternalTrafficPolicyType, ipPool, externalIP string) *corev1.Service {
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
	if externalIP != "" {
		service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{IP: externalIP},
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
		name                     string
		previousExternalIPStates map[apimachinerytypes.NamespacedName]externalIPState
		existingEndpoints        []*corev1.Endpoints
		serviceToCreate          *corev1.Service
		healthyNodes             []string
		overrideHashFn           func([]string) []string
		expectedCalls            func(mockIPAssigner *ipassignertest.MockIPAssigner)
		expectedExternalIPStates map[apimachinerytypes.NamespacedName]externalIPState
		expectError              bool
	}{
		{
			name:                     "new Service created and local Node selected",
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			existingEndpoints:        nil,
			serviceToCreate:          servicePolicyCluster,
			healthyNodes:             []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeServiceExternalIP1)
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode1,
				},
			},
			expectError: false,
		},
		{
			name:                     "new Service created and local Node not selected",
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			existingEndpoints:        nil,
			serviceToCreate:          servicePolicyCluster,
			healthyNodes:             []string{fakeNode1, fakeNode2},
			overrideHashFn:           fakeHashFn(true),
			expectedCalls:            func(mockIPAssigner *ipassignertest.MockIPAssigner) {},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode2,
				},
			},
			expectError: false,
		},
		{
			name:                     "new Service created with ExternalTrafficPolicy=Local and local Node selected",
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			existingEndpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
					},
					nil),
			},
			serviceToCreate: servicePolicyLocal,
			healthyNodes:    []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeServiceExternalIP1)
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode1,
				},
			},
			expectError: false,
		},
		{
			name:                     "new Service created with ExternalTrafficPolicy=Local and local Node not Selected",
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			existingEndpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					map[string]string{
						"2.3.4.7": fakeNode2,
					},
				),
			},
			serviceToCreate: servicePolicyLocal,
			healthyNodes:    []string{fakeNode1, fakeNode2},
			// invert the sorted string to select other Nodes.
			overrideHashFn: fakeHashFn(true),
			expectedCalls:  func(mockIPAssigner *ipassignertest.MockIPAssigner) {},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode2,
				},
			},
			expectError: false,
		},
		{
			name:                     "new Service created with ExternalTrafficPolicy=Local and local Node has no healthy endpoints",
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			existingEndpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.6": fakeNode2,
					},
					map[string]string{
						"2.3.4.5": fakeNode1,
					}),
			},
			serviceToCreate: servicePolicyLocal,
			healthyNodes:    []string{fakeNode1, fakeNode2},
			expectedCalls:   func(mockIPAssigner *ipassignertest.MockIPAssigner) {},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode2,
				},
			},
			expectError: false,
		},
		{
			name:                     "new Service created with ExternalTrafficPolicy=Local and no Nodes has healthy endpoints",
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			existingEndpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					nil,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					}),
			},
			serviceToCreate:          servicePolicyLocal,
			healthyNodes:             []string{fakeNode1, fakeNode2},
			expectedCalls:            func(mockIPAssigner *ipassignertest.MockIPAssigner) {},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			expectError:              true,
		},
		{
			name:              "new Service created and local Node selected and IP already assigned by other Service",
			existingEndpoints: nil,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode1},
			},
			serviceToCreate: servicePolicyCluster,
			healthyNodes:    []string{fakeNode1, fakeNode2},
			expectedCalls:   func(mockIPAssigner *ipassignertest.MockIPAssigner) {},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode1,
				},
				keyFor(servicePolicyCluster): {
					ip:           fakeServiceExternalIP1,
					assignedNode: fakeNode1,
				},
			},
			expectError: false,
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
			if tt.overrideHashFn != nil {
				c.fakeMemberlistCluster.hashFn = tt.overrideHashFn
			}
			c.externalIPStates = tt.previousExternalIPStates
			for service, state := range tt.previousExternalIPStates {
				if c.assignedIPs[state.ip] == nil {
					c.assignedIPs[state.ip] = sets.NewString()
				}
				c.assignedIPs[state.ip].Insert(service.String())
			}
			tt.expectedCalls(c.mockIPAssigner)
			err := c.syncService(keyFor(tt.serviceToCreate))
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedExternalIPStates, c.externalIPStates)
		})
	}
}

func TestUpdateService(t *testing.T) {
	serviceExternalTrafficPolicyClusterUpdatedExternalIP := servicePolicyCluster.DeepCopy()
	serviceExternalTrafficPolicyClusterUpdatedExternalIP.Status.LoadBalancer.Ingress[0].IP = fakeServiceExternalIP2

	serviceExternalTrafficPolicyClusterWithSameExternalIP := servicePolicyCluster.DeepCopy()
	serviceExternalTrafficPolicyClusterWithSameExternalIP.Name = "svc-same-eip"
	serviceExternalTrafficPolicyClusterWithSameExternalIP.Status.LoadBalancer.Ingress[0].IP = fakeServiceExternalIP2

	serviceExternalTrafficLocalWithNodeSelected := servicePolicyLocal.DeepCopy()
	serviceExternalTrafficLocalWithNodeSelected.Status.LoadBalancer.Ingress[0].Hostname = fakeNode1

	serviceExternalTrafficLocalUpdatedHostname := servicePolicyLocal.DeepCopy()
	serviceExternalTrafficLocalUpdatedHostname.Status.LoadBalancer.Ingress[0].Hostname = fakeNode2

	serviceChangedType := servicePolicyCluster.DeepCopy()
	serviceChangedType.Spec.Type = corev1.ServiceTypeClusterIP

	serviceExternalIPRecalimed := servicePolicyCluster.DeepCopy()
	serviceExternalIPRecalimed.Status.LoadBalancer.Ingress = nil

	serviceChangedExternalTrafficPolicy := servicePolicyCluster.DeepCopy()
	serviceChangedExternalTrafficPolicy.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal

	tests := []struct {
		name                     string
		endpoints                []*corev1.Endpoints
		serviceToUpdate          *corev1.Service
		previousExternalIPStates map[apimachinerytypes.NamespacedName]externalIPState
		expectedExternalIPStates map[apimachinerytypes.NamespacedName]externalIPState
		healthyNodes             []string
		overrideHashFn           func([]string) []string
		expectedCalls            func(mockIPAssigner *ipassignertest.MockIPAssigner)
		expectError              bool
	}{
		{
			name:            "Service updated external IP and local Node selected",
			endpoints:       nil,
			serviceToUpdate: serviceExternalTrafficPolicyClusterUpdatedExternalIP,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP): {fakeServiceExternalIP2, fakeNode1},
			},
			healthyNodes: []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
				mockIPAssigner.EXPECT().AssignIP(fakeServiceExternalIP2)
			},
			expectError: false,
		},
		{
			name:            "Service updated external IP and local Node selected but other Service still owns the assigned IP",
			endpoints:       nil,
			serviceToUpdate: serviceExternalTrafficPolicyClusterUpdatedExternalIP,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterWithSameExternalIP): {fakeServiceExternalIP1, fakeNode1},
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP):  {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterWithSameExternalIP): {fakeServiceExternalIP1, fakeNode1},
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP):  {fakeServiceExternalIP2, fakeNode1},
			},
			healthyNodes: []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeServiceExternalIP2)
			},
			expectError: false,
		},
		{
			name:            "Service updated external IP and local Node not selected",
			endpoints:       nil,
			serviceToUpdate: serviceExternalTrafficPolicyClusterUpdatedExternalIP,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP): {fakeServiceExternalIP2, fakeNode2},
			},
			healthyNodes:   []string{fakeNode1, fakeNode2},
			overrideHashFn: fakeHashFn(true),
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name:            "Service changed type to ClusterIP",
			endpoints:       nil,
			serviceToUpdate: serviceChangedType,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			healthyNodes:             []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name:            "Service external IP reclaimed",
			endpoints:       nil,
			serviceToUpdate: serviceChangedType,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceExternalTrafficPolicyClusterUpdatedExternalIP): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			healthyNodes:             []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name: "Service changed ExternalTrafficPolicy to local and local Node have to healthy Endpoints",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(serviceChangedExternalTrafficPolicy.Name, serviceChangedExternalTrafficPolicy.Namespace,
					map[string]string{
						"2.3.4.6": fakeNode2,
					}, map[string]string{
						"2.3.4.5": fakeNode1,
					}),
			},
			serviceToUpdate: serviceChangedExternalTrafficPolicy,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceChangedExternalTrafficPolicy): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(serviceChangedExternalTrafficPolicy): {fakeServiceExternalIP1, fakeNode2},
			},
			healthyNodes: []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name:            "local Node no longer selected",
			endpoints:       nil,
			serviceToUpdate: servicePolicyCluster,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyCluster): {fakeServiceExternalIP1, fakeNode2},
			},
			healthyNodes:   []string{fakeNode1, fakeNode2},
			overrideHashFn: fakeHashFn(true),
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name: "local Node no longer have healthy endpoints",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.6": fakeNode2,
					}, map[string]string{
						"2.3.4.5": fakeNode1,
					}),
			},
			serviceToUpdate: serviceExternalTrafficLocalWithNodeSelected,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode2},
			},
			healthyNodes: []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name: "should not migrate to other Nodes if selected Node still have healthy endpoints",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					nil,
				),
			},
			overrideHashFn:  fakeHashFn(true),
			serviceToUpdate: serviceExternalTrafficLocalWithNodeSelected,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode1},
			},
			healthyNodes:  []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {},
			expectError:   false,
		},
		{
			name: "other Node could promote itself as the new owner",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					nil,
				),
			},
			serviceToUpdate: serviceExternalTrafficLocalUpdatedHostname,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode1},
			},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode2},
			},
			healthyNodes: []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().UnassignIP(fakeServiceExternalIP1)
			},
			expectError: false,
		},
		{
			name: "agent restarts and should not select new Node if current selected Node still healthy and have healthy endpoints",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					nil,
				),
			},
			overrideHashFn:           fakeHashFn(true),
			serviceToUpdate:          serviceExternalTrafficLocalWithNodeSelected,
			previousExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{},
			expectedExternalIPStates: map[apimachinerytypes.NamespacedName]externalIPState{
				keyFor(servicePolicyLocal): {fakeServiceExternalIP1, fakeNode1},
			},
			healthyNodes: []string{fakeNode1, fakeNode2},
			expectedCalls: func(mockIPAssigner *ipassignertest.MockIPAssigner) {
				mockIPAssigner.EXPECT().AssignIP(fakeServiceExternalIP1)
			},
			expectError: false,
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
			c.externalIPStates = tt.previousExternalIPStates
			defer c.mockController.Finish()
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.fakeMemberlistCluster.nodes = tt.healthyNodes
			if tt.overrideHashFn != nil {
				c.fakeMemberlistCluster.hashFn = tt.overrideHashFn
			}
			for service, state := range tt.previousExternalIPStates {
				if c.assignedIPs[state.ip] == nil {
					c.assignedIPs[state.ip] = sets.NewString()
				}
				c.assignedIPs[state.ip].Insert(service.String())
			}
			tt.expectedCalls(c.mockIPAssigner)
			err := c.syncService(keyFor(tt.serviceToUpdate))
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedExternalIPStates, c.externalIPStates)
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

func TestServiceExternalIPController_nodesHasHealthyServiceEndpoint(t *testing.T) {
	tests := []struct {
		name                 string
		endpoints            []*corev1.Endpoints
		serviceToTest        *corev1.Service
		expectedHealthyNodes sets.String
	}{
		{
			name: "all Endpoints are healthy",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.6": fakeNode2,
					},
					nil,
				),
			},
			serviceToTest:        servicePolicyLocal.DeepCopy(),
			expectedHealthyNodes: sets.NewString(fakeNode1, fakeNode2),
		},
		{
			name: "one Node does not have any healthy Endpoints",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.5": fakeNode1,
					},
					map[string]string{
						"2.3.4.6": fakeNode2,
					},
				),
			},
			serviceToTest:        servicePolicyLocal.DeepCopy(),
			expectedHealthyNodes: sets.NewString(fakeNode1),
		},
		{
			name: "Node have both healthy Endpoints and unhealthy Endpoints",
			endpoints: []*corev1.Endpoints{
				makeEndpoints(servicePolicyLocal.Name, servicePolicyLocal.Namespace,
					map[string]string{
						"2.3.4.6": fakeNode1,
						"2.3.4.8": fakeNode2,
					},
					map[string]string{
						"2.3.4.5": fakeNode1,
						"2.3.4.7": fakeNode2,
					},
				),
			},
			serviceToTest:        servicePolicyLocal.DeepCopy(),
			expectedHealthyNodes: sets.NewString(fakeNode1, fakeNode2),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for _, s := range tt.endpoints {
				objs = append(objs, s)
			}
			c := newFakeController(t, objs...)
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			got, err := c.nodesHasHealthyServiceEndpoint(tt.serviceToTest)
			assert.NoError(t, err)
			assert.True(t, tt.expectedHealthyNodes.Equal(got), "Expected healthy Nodes %v, got %v", tt.expectedHealthyNodes, got)
		})
	}
}
