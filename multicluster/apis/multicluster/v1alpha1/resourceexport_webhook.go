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

package v1alpha1

import (
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
)

func (r *ResourceExport) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-multicluster-crd-antrea-io-v1alpha1-resourceexport,mutating=true,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=create;update,versions=v1alpha1,name=mresourceexport.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ResourceExport{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ResourceExport) Default() {
	klog.InfoS("default", "name", r.Name)
	if r.Spec.ClusterNetworkPolicy == nil {
		// Only mutate ResourceExport created for ClusterNetworkPolicy resources
		return
	}
	if len(r.Labels) == 0 {
		r.Labels = map[string]string{}
	}
	if nameLabelVal, exists := r.Labels[constants.SourceName]; !exists || nameLabelVal != r.Spec.Name {
		r.Labels[constants.SourceName] = r.Spec.Name
	}
	if namespaceLabelVal, exists := r.Labels[constants.SourceNamespace]; !exists || namespaceLabelVal != "" {
		r.Labels[constants.SourceNamespace] = ""
	}
	if kindLabelVal, exists := r.Labels[constants.SourceKind]; !exists || kindLabelVal != constants.AntreaClusterNetworkPolicyKind {
		r.Labels[constants.SourceKind] = constants.AntreaClusterNetworkPolicyKind
	}
	if r.DeletionTimestamp.IsZero() && !stringExistsInSlice(r.Finalizers, constants.ResourceExportFinalizer) {
		r.Finalizers = append(r.Finalizers, constants.ResourceExportFinalizer)
	}
}

func stringExistsInSlice(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
