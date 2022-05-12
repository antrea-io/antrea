package utils

import (
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ExternalEntitySpecSpecBuilder struct {
	Spec      crdv1alpha2.ExternalEntitySpec
	Name      string
	Namespace string
}

func (t *ExternalEntitySpecSpecBuilder) SetName(namespace string, name string) *ExternalEntitySpecSpecBuilder {
	t.Namespace = namespace
	t.Name = name
	return t
}

func (t *ExternalEntitySpecSpecBuilder) Get() *crdv1alpha2.ExternalEntity {
	return &crdv1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
		},
		Spec: t.Spec,
	}
}
