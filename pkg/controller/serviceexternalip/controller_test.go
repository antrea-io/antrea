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
	antreacrds "antrea.io/antrea/pkg/apis/crd/v1alpha2"
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
	externalIPPoolController := externalippool.NewExternalIPPoolController(crdClient, crdInformerFactory.Crd().V1alpha2().ExternalIPPools())
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

func TestAddService(t *testing.T) {
	tests := []struct {
		name               string
		externalIPPool     []*antreacrds.ExternalIPPool
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
			name: "Service with user specified external IP",
			externalIPPool: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			service:            newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"),
			expectedExternalIP: "1.2.3.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeObjects []runtime.Object
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
			assert.True(t, controller.externalIPAllocator.IPPoolHasIP(ipPool, net.ParseIP(externalIP)))
		})
	}
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

	var service *corev1.Service
	var err error

	service = newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip1")
	_, err = controller.client.CoreV1().Services(service.Namespace).Create(context.TODO(), service, metav1.CreateOptions{})
	require.NoError(t, err)

	eip1 := newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5")

	t.Run("IP pool eip1 created", func(t *testing.T) {
		_, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eip1, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("IP pool eip1 deleted", func(t *testing.T) {
		err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), eip1.Name, metav1.DeleteOptions{})
		assert.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
	})

	t.Run("IP pool eip1 re-created", func(t *testing.T) {
		// Re-create ExternalIPPool.
		_, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eip1, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
	})

	t.Run("Service changes ExternalIPPool annotation to eip2", func(t *testing.T) {
		// Change ExternalIPPool annotation.
		service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip2"
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
	})

	eip2 := newExternalIPPool("eip2", "", "1.2.4.4", "1.2.4.5")

	t.Run("IP pool eip2 created", func(t *testing.T) {
		// Create second ExternalIPPool.
		_, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eip2, metav1.CreateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.4.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 1)
	})

	t.Run("specify another IP from IP pool eip2", func(t *testing.T) {
		service.Spec.LoadBalancerIP = "1.2.4.5"
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.4.5")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 1)
	})

	t.Run("specify an IP from IP pool eip1 without changing annotation", func(t *testing.T) {
		service.Spec.LoadBalancerIP = "1.2.3.4"
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("change annotation to use IP pool eip1", func(t *testing.T) {
		service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip1"
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		require.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")
		checkExternalIPPoolUsed(t, controller, "eip1", 1)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Specify non-existent IP of IP pool eip1", func(t *testing.T) {
		service.Spec.LoadBalancerIP = "1.2.3.6"
		service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip1"
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		assert.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Change Service type", func(t *testing.T) {
		// Change Service type.
		service.Spec.LoadBalancerIP = ""
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		assert.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "1.2.3.4")

		service.Spec.Type = corev1.ServiceTypeClusterIP
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		assert.NoError(t, err)
		checkForServiceExternalIP(t, controller, service.Name, service.Namespace, "")
		checkExternalIPPoolUsed(t, controller, "eip1", 0)
		checkExternalIPPoolUsed(t, controller, "eip2", 0)
	})

	t.Run("Change Service type back", func(t *testing.T) {
		service.Spec.Type = corev1.ServiceTypeLoadBalancer
		_, err = controller.client.CoreV1().Services(service.Namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
		require.NoError(t, err)
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
	assert.Eventually(t, func() bool {
		serviceUpdated, err := controller.client.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		require.NoError(t, err)
		externalIP := getServiceExternalIP(serviceUpdated)
		return externalIP == expectedExternalIP
	}, 500*time.Millisecond, 100*time.Millisecond)
}

func checkExternalIPPoolUsed(t *testing.T, controller *loadBalancerController, poolName string, used int) {
	exists := controller.externalIPAllocator.IPPoolExists(poolName)
	require.True(t, exists)
	assert.Eventually(t, func() bool {
		eip, err := controller.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
		require.NoError(t, err)
		t.Logf("current status %#v", eip.Status)
		return eip.Status.Usage.Used == used
	}, 500*time.Millisecond, 100*time.Millisecond)
}
