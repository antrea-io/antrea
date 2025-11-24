// Copyright 2024 Antrea Authors
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

package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
)

const (
	testNamespace   = "kube-system"
	testServiceName = "antrea"
	testServicePort = 443
	testTargetPort  = 10349
	testEndpointIP1 = "172.18.0.3"
	testEndpointIP2 = "172.18.0.4"
)

func getTestObjects() (*corev1.Service, *discoveryv1.EndpointSlice) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testServiceName,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app":       "antrea",
				"component": "antrea=controller",
			},
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.96.0.1",
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(testTargetPort),
				},
			},
		},
	}
	endpointSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testServiceName + "-7vzhx",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: testServiceName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{testEndpointIP1},
				Conditions: discoveryv1.EndpointConditions{
					Ready: ptr.To(true),
				},
			},
		},
		Ports: []discoveryv1.EndpointPort{
			{
				Name:     ptr.To("https"),
				Port:     ptr.To(int32(testTargetPort)),
				Protocol: ptr.To(corev1.ProtocolTCP),
			},
		},
	}
	return svc, endpointSlice
}

func getEndpointURL(ip string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(ip, fmt.Sprint(testTargetPort)),
	}
}

func runTestEndpointResolver(ctx context.Context, t *testing.T, objects ...runtime.Object) (*fake.Clientset, *EndpointResolver) {
	k8sClient := fake.NewSimpleClientset(objects...)
	resolver := NewEndpointResolver(k8sClient, testNamespace, testServiceName, testServicePort)
	go resolver.Run(ctx)
	// Wait for informers to sync to avoid race condition between List and Watch with the fake clientset.
	// Note that we cannot call resolver.informerFactory.WaitForCacheSync instead, as that only
	// waits until *started* informers' caches have been synced, and at this point
	// resolver.informerFactory.Start may not have been called yet.
	// We also check the return value of cache.WaitForCacheSync even though it should only be
	// true if the context was cancelled. which should not happen in our test cases.
	require.True(t, cache.WaitForCacheSync(ctx.Done(), resolver.serviceListerSynced, resolver.endpointSliceInformerSynced))
	return k8sClient, resolver
}

func TestEndpointResolver(t *testing.T) {
	t.Run("add Service and EndpointSlice", func(t *testing.T) {
		ctx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		k8sClient, resolver := runTestEndpointResolver(ctx, t)
		require.Nil(t, resolver.CurrentEndpointURL())
		svc, endpointSlice := getTestObjects()
		k8sClient.CoreV1().Services(testNamespace).Create(ctx, svc, metav1.CreateOptions{})
		k8sClient.DiscoveryV1().EndpointSlices(testNamespace).Create(ctx, endpointSlice, metav1.CreateOptions{})
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Equal(t, getEndpointURL(testEndpointIP1), resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("update Endpoint address", func(t *testing.T) {
		ctx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		svc, endpointSlice := getTestObjects()
		k8sClient, resolver := runTestEndpointResolver(ctx, t, svc, endpointSlice)
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Equal(t, getEndpointURL(testEndpointIP1), resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
		endpointSlice.Endpoints[0].Addresses[0] = testEndpointIP2
		k8sClient.DiscoveryV1().EndpointSlices(testNamespace).Update(ctx, endpointSlice, metav1.UpdateOptions{})
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Equal(t, getEndpointURL(testEndpointIP2), resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("remove Endpoint address", func(t *testing.T) {
		ctx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		svc, endpointSlice := getTestObjects()
		k8sClient, resolver := runTestEndpointResolver(ctx, t, svc, endpointSlice)
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Equal(t, getEndpointURL(testEndpointIP1), resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
		endpointSlice.Endpoints = nil
		k8sClient.DiscoveryV1().EndpointSlices(testNamespace).Update(ctx, endpointSlice, metav1.UpdateOptions{})
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Nil(t, resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("delete Service", func(t *testing.T) {
		ctx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		svc, endpointSlice := getTestObjects()
		k8sClient, resolver := runTestEndpointResolver(ctx, t, svc, endpointSlice)
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Equal(t, getEndpointURL(testEndpointIP1), resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
		k8sClient.CoreV1().Services(testNamespace).Delete(ctx, testServiceName, metav1.DeleteOptions{})
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			assert.Nil(t, resolver.CurrentEndpointURL())
		}, 2*time.Second, 50*time.Millisecond)
	})
}
