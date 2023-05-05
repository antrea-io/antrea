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
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	antreaagenttypes "antrea.io/antrea/pkg/agent/types"
	antreacrds "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/controller/externalippool"
)

type loadBalancerController struct {
	*ServiceExternalIPController
	crdClient           versioned.Interface
	client              kubernetes.Interface
	informerFactory     informers.SharedInformerFactory
	crdInformerFactory  crdinformers.SharedInformerFactory
	externalIPAllocator *externalippool.ExternalIPPoolController
}

func newExternalIPPool(name, cidr, start, end string) *antreacrds.ExternalIPPool {
	pool := &antreacrds.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if len(cidr) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, antreacrds.IPRange{CIDR: cidr})
	}
	if len(start) > 0 && len(end) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, antreacrds.IPRange{Start: start, End: end})
	}
	return pool
}

func newService(name, namespace string, serviceType corev1.ServiceType, externalIP, ipPool string) *corev1.Service {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:           serviceType,
			LoadBalancerIP: externalIP,
		},
	}
	if ipPool != "" {
		service.Annotations = map[string]string{
			antreaagenttypes.ServiceExternalIPPoolAnnotationKey: ipPool,
		}
	}
	return service
}

func newController(objects, crdObjects []runtime.Object) *loadBalancerController {
	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	externalIPPoolController := externalippool.NewExternalIPPoolController(crdClient, crdInformerFactory.Crd().V1beta1().ExternalIPPools())
	controller := NewServiceExternalIPController(client, informerFactory.Core().V1().Services(), externalIPPoolController)
	return &loadBalancerController{
		ServiceExternalIPController: controller,
		informerFactory:             informerFactory,
		crdInformerFactory:          crdInformerFactory,
		crdClient:                   crdClient,
		client:                      client,
		externalIPAllocator:         externalIPPoolController,
	}
}

func mutateSvc(svc *corev1.Service, mutator func(_ *corev1.Service)) *corev1.Service {
	mutator(svc)
	return svc
}

func TestAddService(t *testing.T) {
	tests := []struct {
		name               string
		externalIPPool     []*antreacrds.ExternalIPPool
		existingServices   []*corev1.Service
		service            *corev1.Service
		expectedExternalIP string
	}{
		{
			name: "Service with valid ExternalIPPool annotation",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			service:            newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip1"),
			expectedExternalIP: "1.2.3.4",
		},
		{
			name: "Service with valid ExternalIPPool annotation and multiple ExternalIPPool present",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
				newExternalIPPool("eip2", "", "1.2.4.4", "1.2.4.5"),
			},
			service:            newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip2"),
			expectedExternalIP: "1.2.4.4",
		},
		{
			name: "Service with requested IP",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			service:            newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"),
			expectedExternalIP: "1.2.3.5",
		},
		{
			name: "Service with requested IP that is occupied",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			existingServices: []*corev1.Service{
				mutateSvc(newService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"), func(svc *corev1.Service) {
					svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.2.3.5"}}
				}),
			},
			service:            newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"),
			expectedExternalIP: "",
		},
		{
			name: "Service with requested IP that is occupied and sharable",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			existingServices: []*corev1.Service{
				mutateSvc(newService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"), func(svc *corev1.Service) {
					svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.2.3.5"}}
					svc.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
				}),
			},
			service: mutateSvc(newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"), func(svc *corev1.Service) {
				svc.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
			}),
			expectedExternalIP: "1.2.3.5",
		},
		{
			name: "Service with exclusively requested IP that is occupied and sharable",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			existingServices: []*corev1.Service{
				mutateSvc(newService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"), func(svc *corev1.Service) {
					svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.2.3.5"}}
					svc.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
				}),
			},
			service:            newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"),
			expectedExternalIP: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeObjects []runtime.Object
			for _, svc := range tt.existingServices {
				fakeObjects = append(fakeObjects, svc)
			}
			var fakeCRDObjects []runtime.Object
			for _, eip := range tt.externalIPPool {
				fakeCRDObjects = append(fakeCRDObjects, eip)
			}
			controller := newController(fakeObjects, fakeCRDObjects)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
			go controller.Run(stopCh)
			_, err := controller.client.CoreV1().Services(tt.service.Namespace).Create(context.TODO(), tt.service, metav1.CreateOptions{})
			require.NoError(t, err)
			var svcUpdated *corev1.Service
			var externalIP string
			assert.Eventually(t, func() bool {
				var err error
				svcUpdated, err = controller.client.CoreV1().Services(tt.service.Namespace).Get(context.TODO(), tt.service.Name, metav1.GetOptions{})
				require.NoError(t, err)
				externalIP = getServiceExternalIP(svcUpdated)
				return externalIP == tt.expectedExternalIP
			}, 500*time.Millisecond, 100*time.Millisecond)
			ipPool := svcUpdated.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey]
			assert.NotEmpty(t, ipPool)
			assert.True(t, controller.externalIPAllocator.IPPoolExists(ipPool))
			if externalIP != "" {
				assert.True(t, controller.externalIPAllocator.IPPoolHasIP(ipPool, net.ParseIP(externalIP)))
			}
		})
	}
}

func TestRestart(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	// svc1 and svc2 allow shared IP, request 1.1.1.1, and already get it assigned.
	// They should continue using 1.1.1.1.
	svc1 := newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.1", "eip1")
	svc1.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
	svc1.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.1.1.1"}}
	svc2 := newService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.1", "eip1")
	svc2.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
	svc2.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.1.1.1"}}
	// svc3 allows shared IP and requests 1.1.1.1.
	// It should get the IP assigned.
	svc3 := newService("svc3", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.1", "eip1")
	svc3.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
	// svc4 doesn't allow shared IP and requests 1.1.1.1.
	// It shouldn't get the IP assigned.
	svc4 := newService("svc4", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.1", "eip1")

	// svc5 allows shared IP, requests 1.1.1.2, and already gets it assigned.
	// It should continue using 1.1.1.2.
	svc5 := newService("svc5", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.2", "eip1")
	svc5.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
	svc5.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.1.1.2"}}
	// svc6 doesn't allow shared IP, requests 1.1.1.2, and already gets it assigned.
	// It should continue using 1.1.1.2.
	svc6 := newService("svc6", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.2", "eip1")
	svc6.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.1.1.2"}}
	// svc7 allows shared IP, requests 1.1.1.2.
	// It shouldn't get the IP assigned.
	svc7 := newService("svc7", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.2", "eip1")
	svc7.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
	// svc8 doesn't allow shared IP, requests 1.1.1.2.
	// It shouldn't get the IP assigned.
	svc8 := newService("svc8", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.2", "eip1")

	// svc9 requests 1.1.1.10 and got 1.1.1.9 assigned before.
	// It should get the requested IP assigned.
	svc9 := newService("svc9", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.1.10", "eip1")
	svc9.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.1.1.9"}}

	// svc10 doesn't request a particular IP.
	// It should get the next available IP: 1.1.1.3.
	svc10 := newService("svc10", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip1")

	// svc11 requests 1.1.2.2 from another pool.
	// It should get the requested ip assigned.
	svc11 := newService("svc11", "ns1", corev1.ServiceTypeLoadBalancer, "1.1.2.2", "eip2")

	eip1 := newExternalIPPool("eip1", "", "1.1.1.1", "1.1.1.10")
	eip2 := newExternalIPPool("eip2", "", "1.1.2.1", "1.1.2.10")

	fakeObjects := []runtime.Object{svc1, svc2, svc3, svc4, svc5, svc6, svc7, svc8, svc9, svc10, svc11}
	fakeCRDObjects := []runtime.Object{eip1, eip2}
	controller := newController(fakeObjects, fakeCRDObjects)
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)

	go controller.externalIPAllocator.Run(stopCh)
	go controller.Run(stopCh)

	checkForServiceExternalIP(t, controller, svc1.Name, svc1.Namespace, "1.1.1.1")
	checkForServiceExternalIP(t, controller, svc2.Name, svc2.Namespace, "1.1.1.1")
	checkForServiceExternalIP(t, controller, svc3.Name, svc3.Namespace, "1.1.1.1")
	checkForServiceExternalIP(t, controller, svc4.Name, svc4.Namespace, "")
	checkForServiceExternalIP(t, controller, svc5.Name, svc5.Namespace, "1.1.1.2")
	checkForServiceExternalIP(t, controller, svc6.Name, svc6.Namespace, "1.1.1.2")
	checkForServiceExternalIP(t, controller, svc7.Name, svc7.Namespace, "")
	checkForServiceExternalIP(t, controller, svc8.Name, svc8.Namespace, "")
	checkForServiceExternalIP(t, controller, svc9.Name, svc9.Namespace, "1.1.1.10")
	checkForServiceExternalIP(t, controller, svc10.Name, svc10.Namespace, "1.1.1.3")
	checkForServiceExternalIP(t, controller, svc11.Name, svc11.Namespace, "1.1.2.2")
	checkExternalIPPoolUsed(t, controller, "eip1", 4)
	checkExternalIPPoolUsed(t, controller, "eip2", 1)
}

func TestSyncService(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	var fakeObjects []runtime.Object
	var fakeCRDObjects []runtime.Object
	controller := newController(fakeObjects, fakeCRDObjects)
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
	go controller.externalIPAllocator.Run(stopCh)
	go controller.Run(stopCh)

	require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))

	var err error

	service := newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip1")
	_, err = controller.client.CoreV1().Services(service.Namespace).Create(context.TODO(), service, metav1.CreateOptions{})
	require.NoError(t, err)

	updateService := func(svc *corev1.Service, mutator func(svc *corev1.Service)) {
		svc, err := controller.client.CoreV1().Services(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})
		require.NoError(t, err)
		toUpdate := svc.DeepCopy()
		toUpdate = mutateSvc(toUpdate, mutator)
		_, err = controller.client.CoreV1().Services(toUpdate.Namespace).Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
		require.NoError(t, err)
	}

	eip1 := newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5")

	t.Run("IP pool eip1 created", func(t *testing.T) {
		_, err = controller.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), eip1, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("IP pool eip1 deleted", func(t *testing.T) {
		err = controller.crdClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), eip1.Name, metav1.DeleteOptions{})
		assert.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
	})

	t.Run("IP pool eip1 re-created", func(t *testing.T) {
		// Re-create ExternalIPPool.
		_, err = controller.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), eip1, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	// svc2 doesn't allow shared IP while svc3 allows it.
	service2 := newService("svc2", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.4", "eip1")
	service3 := mutateSvc(newService("svc3", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.4", "eip1"), func(svc *corev1.Service) {
		svc.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
	})
	t.Run("svc2 and svc3 requesting the same IP", func(t *testing.T) {
		_, err = controller.client.CoreV1().Services(service2.Namespace).Create(context.TODO(), service2, metav1.CreateOptions{})
		require.NoError(t, err)
		_, err = controller.client.CoreV1().Services(service3.Namespace).Create(context.TODO(), service3, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkForServiceExternalIP(t, controller, service2.Name, service2.Namespace, "")
		checkForServiceExternalIP(t, controller, service3.Name, service3.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("svc1 allowing shared IP", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey] = "true"
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkForServiceExternalIP(t, controller, service2.Name, service2.Namespace, "")
		checkForServiceExternalIP(t, controller, service3.Name, service3.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("Service changes ExternalIPPool annotation to eip2", func(t *testing.T) {
		// Change ExternalIPPool annotation.
		updateService(service, func(svc *corev1.Service) {
			svc.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip2"
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkForServiceExternalIP(t, controller, service2.Name, service2.Namespace, "")
		checkForServiceExternalIP(t, controller, service3.Name, service3.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("svc3 deleted", func(t *testing.T) {
		err = controller.client.CoreV1().Services(service3.Namespace).Delete(context.TODO(), service3.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkForServiceExternalIP(t, controller, service2.Name, service2.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("svc2 deleted", func(t *testing.T) {
		err = controller.client.CoreV1().Services(service2.Namespace).Delete(context.TODO(), service2.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
	})

	eip2 := newExternalIPPool("eip2", "", "1.2.4.4", "1.2.4.5")

	t.Run("IP pool eip2 created", func(t *testing.T) {
		// Create second ExternalIPPool.
		_, err = controller.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), eip2, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.4.4")
		checkExternalIPPoolUsed(t, controller, "eip2", 1)
	})

	t.Run("specify another IP from IP pool eip2", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Spec.LoadBalancerIP = "1.2.4.5"
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.4.5")
		checkExternalIPPoolUsed(t, controller, "eip2", 1)
	})

	t.Run("specify an IP from IP pool eip1 without changing annotation", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Spec.LoadBalancerIP = "1.2.3.5"
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("change annotation to use IP pool eip1", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip1"
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.5")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Specify non-existent IP of IP pool eip1", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Spec.LoadBalancerIP = "1.2.3.6"
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
	})

	t.Run("Specify empty IP", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Spec.LoadBalancerIP = ""
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Change Service type", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Spec.Type = corev1.ServiceTypeClusterIP
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Change Service type back", func(t *testing.T) {
		updateService(service, func(svc *corev1.Service) {
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
		})
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Delete service", func(t *testing.T) {
		err = controller.client.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})
}

func checkForServiceExternalIP(t *testing.T, controller *loadBalancerController, name, namespace, expectedExternalIP string) {
	t.Helper()
	assert.Eventually(t, func() bool {
		serviceUpdated, err := controller.client.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		require.NoError(t, err)
		externalIP := getServiceExternalIP(serviceUpdated)
		return externalIP == expectedExternalIP
	}, 500*time.Millisecond, 100*time.Millisecond)
}

func checkExternalIPPoolUsed(t *testing.T, controller *loadBalancerController, poolName string, used int) {
	t.Helper()
	exists := controller.externalIPAllocator.IPPoolExists(poolName)
	require.True(t, exists)
	assert.Eventually(t, func() bool {
		eip, err := controller.crdClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
		require.NoError(t, err)
		t.Logf("current status %#v", eip.Status)
		return eip.Status.Usage.Used == used
	}, 500*time.Millisecond, 100*time.Millisecond)
}
