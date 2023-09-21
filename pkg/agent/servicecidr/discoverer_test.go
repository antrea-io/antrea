// Copyright 2023 Antrea Authors
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

package servicecidr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/util/ip"
)

func makeService(namespace, name string, clusterIP string, protocol corev1.Protocol) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			ClusterIPs: []string{clusterIP},
			ClusterIP:  clusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:     "80",
					Port:     int32(80),
					Protocol: protocol,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
	return svc
}

func TestServiceCIDRProvider(t *testing.T) {
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	svcInformer := informerFactory.Core().V1().Services()
	serviceCIDRProvider := NewServiceCIDRDiscoverer(svcInformer)
	serviceCIDRChan := make(chan []*net.IPNet)
	serviceCIDRProvider.AddEventHandler(func(serviceCIDRs []*net.IPNet) {
		{
			serviceCIDRChan <- serviceCIDRs
		}
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	go serviceCIDRProvider.Run(stopCh)

	check := func(expectedServiceCIDRs []*net.IPNet, expectedEvent []*net.IPNet) {
		if expectedEvent != nil {
			select {
			case event := <-serviceCIDRChan:
				assert.Equal(t, expectedEvent, event)
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for expected Service CIDR")
			}
		} else {
			select {
			case <-serviceCIDRChan:
				t.Fatal("Received unexpected event")
			case <-time.After(100 * time.Millisecond):
			}
		}
		serviceCIDRs, err := serviceCIDRProvider.GetServiceCIDRs()
		if expectedServiceCIDRs != nil {
			assert.NoError(t, err)
			assert.Equal(t, expectedServiceCIDRs, serviceCIDRs)
		} else {
			assert.ErrorContains(t, err, "Service CIDR discoverer is not initialized yet")
		}
	}

	check(nil, nil)

	svc := makeService("ns1", "svc0", "None", corev1.ProtocolTCP)
	_, err := client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check(nil, nil)

	svc = makeService("ns1", "svc1", "10.10.0.1", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.1/32")}, []*net.IPNet{ip.MustParseCIDR("10.10.0.1/32")})

	svc = makeService("ns1", "svc2", "10.10.0.2", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/30")}, []*net.IPNet{ip.MustParseCIDR("10.10.0.0/30")})

	svc = makeService("ns1", "svc5", "10.10.0.5", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29")}, []*net.IPNet{ip.MustParseCIDR("10.10.0.0/29")})

	svc = makeService("ns1", "svc4", "10.10.0.4", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29")}, nil)

	err = client.CoreV1().Services("ns1").Delete(context.TODO(), "svc4", metav1.DeleteOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29")}, nil)

	svc = makeService("ns1", "svc60", "None", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29")}, nil)

	svc = makeService("ns1", "svc61", "10::1", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29"), ip.MustParseCIDR("10::1/128")}, []*net.IPNet{ip.MustParseCIDR("10::1/128")})

	svc = makeService("ns1", "svc62", "10::2", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29"), ip.MustParseCIDR("10::/126")}, []*net.IPNet{ip.MustParseCIDR("10::/126")})

	svc = makeService("ns1", "svc65", "10::5", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29"), ip.MustParseCIDR("10::/125")}, []*net.IPNet{ip.MustParseCIDR("10::/125")})

	svc = makeService("ns1", "svc64", "10::4", corev1.ProtocolTCP)
	_, err = client.CoreV1().Services("ns1").Create(context.TODO(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29"), ip.MustParseCIDR("10::/125")}, nil)

	err = client.CoreV1().Services("ns1").Delete(context.TODO(), "svc64", metav1.DeleteOptions{})
	assert.NoError(t, err)
	check([]*net.IPNet{ip.MustParseCIDR("10.10.0.0/29"), ip.MustParseCIDR("10::/125")}, nil)
}
