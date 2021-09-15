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
	*ExternalIPController
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

func newService(name, namespace string, serviceType corev1.ServiceType, lbIP, ipPool string) *corev1.Service {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:           serviceType,
			LoadBalancerIP: lbIP,
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
	controller := NewExternalIPController(client, informerFactory.Core().V1().Services(), externalIPPoolController)
	return &loadBalancerController{
		ExternalIPController: controller,
		informerFactory:      informerFactory,
		crdInformerFactory:   crdInformerFactory,
		crdClient:            crdClient,
		client:               client,
		externalIPAllocator:  externalIPPoolController,
	}
}

func TestAddService(t *testing.T) {
	tests := []struct {
		name                   string
		externalIPPool         []*antreacrds.ExternalIPPool
		service                *corev1.Service
		expectedLoadBalancerIP string
	}{
		{
			"Service with valid ExternalIPPool annotation",
			[]*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip1"),
			"1.2.3.4",
		},
		{
			"Service with valid ExternalIPPool annotation and multiple ExternalIPPool present",
			[]*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
				newExternalIPPool("eip2", "", "1.2.4.4", "1.2.4.5"),
			},
			newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip2"),
			"1.2.4.4",
		},
		{
			"Service with empty ExternalIPPool annotation",
			[]*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "", "eip1"),
			"1.2.3.4",
		},
		{
			"Service with user specified LoadBalancer IP",
			[]*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5"),
			},
			newService("svc1", "ns1", corev1.ServiceTypeLoadBalancer, "1.2.3.5", "eip1"),
			"1.2.3.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
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
			_, err := controller.client.CoreV1().Services(tt.service.Namespace).Create(ctx, tt.service, metav1.CreateOptions{})
			require.NoError(t, err)
			var svcUpdated *corev1.Service
			var lbIP string
			assert.Eventually(t, func() bool {
				var err error
				svcUpdated, err = controller.client.CoreV1().Services(tt.service.Namespace).Get(ctx, tt.service.Name, metav1.GetOptions{})
				require.NoError(t, err)
				lbIP = getServiceExternalIP(svcUpdated)
				return lbIP == tt.expectedLoadBalancerIP
			}, 500*time.Millisecond, 100*time.Millisecond)
			ipPool := svcUpdated.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey]
			assert.NotEmpty(t, ipPool)
			assert.True(t, controller.externalIPAllocator.IPPoolExists(ipPool))
			assert.True(t, controller.externalIPAllocator.IPPoolHasIP(ipPool, net.ParseIP(lbIP)))
		})
	}
}

func TestSyncService(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	_, err = controller.client.CoreV1().Services(service.Namespace).Create(ctx, service, metav1.CreateOptions{})
	assert.NoError(t, err)

	// Create ExternalIPPool
	eip1 := newExternalIPPool("eip1", "", "1.2.3.4", "1.2.3.5")
	_, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(ctx, eip1, metav1.CreateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.3.4")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 1)

	// Delete ExternalIPPool
	err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Delete(ctx, eip1.Name, metav1.DeleteOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "")

	// Re-create ExternalIPPool
	_, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(ctx, eip1, metav1.CreateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.3.4")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 1)

	// Change ExternalIPPool annotation
	service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip2"
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 0)

	// Create second ExternalIPPool
	eip2 := newExternalIPPool("eip2", "", "1.2.4.4", "1.2.4.5")
	_, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(ctx, eip2, metav1.CreateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.4.4")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 0)
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 1)

	// Specify IP from ExternalIPPool
	service.Spec.LoadBalancerIP = "1.2.4.5"
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.4.5")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 0)
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 1)

	// Specify IP from ExternalIPPool with mismatched ExternalIPPool annotation
	service.Spec.LoadBalancerIP = "1.2.4.4"
	service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip1"
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.4.4")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 0)
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 1)

	// Specify non-existent IP of ExternalIPPool
	service.Spec.LoadBalancerIP = "1.2.4.6"
	service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = "eip2"
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 0)
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 0)

	// Change Service type
	service.Spec.LoadBalancerIP = ""
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.4.4")

	service.Spec.Type = corev1.ServiceTypeClusterIP
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "")
	checkExternalIPPoolUsed(t, controller, ctx, "eip1", 0)
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 0)

	// Change Service type back to LoadBalancer
	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	_, err = controller.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkForLBIP(t, controller, ctx, service.Name, service.Namespace, "1.2.4.4")
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 1)

	// Delete Service
	err = controller.client.CoreV1().Services(service.Namespace).Delete(ctx, service.Name, metav1.DeleteOptions{})
	assert.NoError(t, err)
	checkExternalIPPoolUsed(t, controller, ctx, "eip2", 0)

}

func checkForLBIP(t *testing.T, controller *loadBalancerController, ctx context.Context, name, namespace, expectedLBIP string) {
	assert.Eventually(t, func() bool {
		serviceUpdated, err := controller.client.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		require.NoError(t, err)
		lbIP := getServiceExternalIP(serviceUpdated)
		return lbIP == expectedLBIP
	}, 500*time.Millisecond, 100*time.Millisecond)
}

func checkExternalIPPoolUsed(t *testing.T, controller *loadBalancerController, ctx context.Context, poolName string, used int) {
	exists := controller.externalIPAllocator.IPPoolExists(poolName)
	require.True(t, exists)
	assert.Eventually(t, func() bool {
		eip, err := controller.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
		require.NoError(t, err)
		t.Logf("current status %#v", eip.Status)
		return eip.Status.Usage.Used == used
	}, 500*time.Millisecond, 100*time.Millisecond)
}
