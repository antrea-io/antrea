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
	"slices"

	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

<<<<<<< HEAD
	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
=======
	"antrea.io/antrea/multicluster/apis/multicluster/constants"
>>>>>>> origin/main
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
	// Add domain qualified finalizer for ResourceExports to avoid Kubernetes from reporting errors:
	//  "prefer a domain-qualified finalizer name to avoid accidental conflicts with other finalizer writers"
	// https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#finalizers
	// Note for ResourceExports created before Antrea v2.2, LegacyResourceExportFinalizer may still be present
	// and needs to be removed before a ResourceExport is deleted.
	if r.DeletionTimestamp.IsZero() && !slices.Contains(r.Finalizers, constants.ResourceExportFinalizer) {
		r.Finalizers = append(r.Finalizers, constants.ResourceExportFinalizer)
	}
}
