package utils

import (
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ExternalNodeSpecBuilder struct {
	Spec      crdv1alpha1.ExternalNodeSpec
	Name      string
	Namespace string
}

func (t *ExternalNodeSpecBuilder) SetName(namespace string, name string) *ExternalNodeSpecBuilder {
	t.Namespace = namespace
	t.Name = name
	return t
}

func (t *ExternalNodeSpecBuilder) Get() *crdv1alpha1.ExternalNode {
	return &crdv1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
		},
		Spec: t.Spec,
	}
}
