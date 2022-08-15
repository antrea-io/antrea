// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type ExternalNodeSpecBuilder struct {
	spec      crdv1alpha1.ExternalNodeSpec
	name      string
	namespace string
	labels    map[string]string
}

func (t *ExternalNodeSpecBuilder) SetName(namespace string, name string) *ExternalNodeSpecBuilder {
	t.namespace = namespace
	t.name = name
	return t
}

func (t *ExternalNodeSpecBuilder) AddInterface(name string, ips []string) *ExternalNodeSpecBuilder {
	t.spec.Interfaces = append(t.spec.Interfaces, crdv1alpha1.NetworkInterface{
		Name: name,
		IPs:  ips,
	})
	return t
}

func (t *ExternalNodeSpecBuilder) AddLabels(labels map[string]string) *ExternalNodeSpecBuilder {
	if t.labels == nil {
		t.labels = make(map[string]string)
	}
	for k, v := range labels {
		t.labels[k] = v
	}
	return t
}

func (t *ExternalNodeSpecBuilder) Get() *crdv1alpha1.ExternalNode {
	return &crdv1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.name,
			Namespace: t.namespace,
			Labels:    t.labels,
		},
		Spec: t.spec,
	}
}
