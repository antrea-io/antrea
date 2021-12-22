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

package multicluster

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	k8smcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var (
	svcPort80 = corev1.ServicePort{
		Name:     "http",
		Protocol: corev1.ProtocolTCP,
		Port:     80,
	}
	svcPort8080 = corev1.ServicePort{
		Name:     "http",
		Protocol: corev1.ProtocolTCP,
		Port:     8080,
	}
	svcNginxSpec = corev1.ServiceSpec{
		ClusterIP:  "192.168.2.3",
		ClusterIPs: []string{"192.168.2.3"},
		Ports: []corev1.ServicePort{
			svcPort80,
		},
		Type: corev1.ServiceTypeClusterIP,
	}
	svcNginx = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Spec: svcNginxSpec,
	}
	addr1 = corev1.EndpointAddress{
		IP:       "192.168.17.11",
		Hostname: "pod1",
	}
	addr2 = corev1.EndpointAddress{
		IP:       "192.168.17.12",
		Hostname: "pod1",
	}
	epPorts80 = []corev1.EndpointPort{
		{
			Name:     "http",
			Port:     80,
			Protocol: corev1.ProtocolTCP,
		},
	}
	epPorts8080 = []corev1.EndpointPort{
		{
			Name:     "http",
			Port:     8080,
			Protocol: corev1.ProtocolTCP,
		},
	}
	epNginxSubset = []corev1.EndpointSubset{
		{
			Addresses: []corev1.EndpointAddress{
				addr1,
			},
			Ports: epPorts80,
		},
	}
	epNginxSubset2 = []corev1.EndpointSubset{
		{
			Addresses: []corev1.EndpointAddress{
				addr2,
			},
			Ports: epPorts80,
		},
	}
	epNginx = &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Subsets: epNginxSubset,
	}
	req = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "nginx",
	}}

	ctx    = context.Background()
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(mcsv1alpha1.AddToScheme(scheme))
	utilruntime.Must(k8smcsapi.AddToScheme(scheme))
	utilruntime.Must(k8sscheme.AddToScheme(scheme))
}
