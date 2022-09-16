/*
Copyright 2022 Antrea Authors.

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

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=labelidentities,scope=Cluster

// +kubebuilder:printcolumn:name="Label",type=string,JSONPath=`.spec.label`,description="Normalized string of a label identity"
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.spec.id`,description="ID allocated for the label identity by the leader cluster"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// LabelIdentity is an imported label identity from the ClusterSet.
// For each unique label identity, a LabelIdentity will be created in the member cluster.
type LabelIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec LabelIdentitySpec `json:"spec,omitempty"`
}

type LabelIdentitySpec struct {
	// Label is the normalized string of a label identity.
	// The format of normalized label identity is `ns:(?P<nslabels>(.)*)&pod:(?P<podlabels>(.)*)`
	// E.g., `ns:kubernetes.io/metadata.name=kube-system&pod:app=db`
	Label string `json:"label,omitempty"`
	// ID is the ID allocated for the label identity by the leader cluster.
	ID uint32 `json:"id,omitempty"`
}

// +kubebuilder:object:root=true

// LabelIdentityList contains a list of LabelIdentity.
type LabelIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LabelIdentity `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&LabelIdentity{},
		&LabelIdentityList{},
	)
}
