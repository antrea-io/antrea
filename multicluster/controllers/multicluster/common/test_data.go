/*
Copyright 2021 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	k8smcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcsv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

var (
	LocalClusterID  = "cluster-a"
	LeaderNamespace = "default"

	SvcPort80 = corev1.ServicePort{
		Name:     "http",
		Protocol: corev1.ProtocolTCP,
		Port:     80,
	}
	SvcPort8080 = corev1.ServicePort{
		Name:     "http",
		Protocol: corev1.ProtocolTCP,
		Port:     8080,
	}
	SvcNginxSpec = corev1.ServiceSpec{
		ClusterIP:  "192.168.2.3",
		ClusterIPs: []string{"192.168.2.3"},
		Ports: []corev1.ServicePort{
			SvcPort80,
		},
		Type: corev1.ServiceTypeClusterIP,
	}
	SvcNginx = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Spec: SvcNginxSpec,
	}
	addr1 = corev1.EndpointAddress{
		IP:       "192.168.17.11",
		Hostname: "pod1",
	}
	addr2 = corev1.EndpointAddress{
		IP:       "192.168.17.12",
		Hostname: "pod1",
	}
	EPPorts80 = []corev1.EndpointPort{
		{
			Name:     "http",
			Port:     80,
			Protocol: corev1.ProtocolTCP,
		},
	}
	EPNginxSubset = []corev1.EndpointSubset{
		{
			Addresses: []corev1.EndpointAddress{
				addr1,
			},
			Ports: EPPorts80,
		},
	}
	EPNginxSubset2 = []corev1.EndpointSubset{
		{
			Addresses: []corev1.EndpointAddress{
				addr2,
			},
			Ports: EPPorts80,
		},
	}
	EPNginx = &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Subsets: EPNginxSubset,
	}

	TestCtx    = context.Background()
	TestScheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(mcsv1alpha1.AddToScheme(TestScheme))
	utilruntime.Must(mcsv1alpha2.AddToScheme(TestScheme))
	utilruntime.Must(k8smcsapi.AddToScheme(TestScheme))
	utilruntime.Must(k8sscheme.AddToScheme(TestScheme))
	utilruntime.Must(crdv1beta1.AddToScheme(TestScheme))
}
