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
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// log is for logging in this package.
var resourceexportlog = logf.Log.WithName("resourceexport-resource")

func (r *ResourceExport) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-multicluster-crd-antrea-io-v1alpha1-resourceexport,mutating=true,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=create;update,versions=v1alpha1,name=mresourceexport.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ResourceExport{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ResourceExport) Default() {
	resourceexportlog.Info("default", "name", r.Name)
	if r.Spec.ClusterNetworkPolicy == nil {
		// Only mutate ResourceExport created for ClusterNetworkPolicy resources
		return
	}
	if len(r.Labels) == 0 {
		r.Labels = map[string]string{}
	}
	if nameLabelVal, exists := r.Labels[common.SourceName]; !exists || nameLabelVal != r.Spec.Name {
		r.Labels[common.SourceName] = r.Spec.Name
	}
	if namespaceLabelVal, exists := r.Labels[common.SourceNamespace]; !exists || namespaceLabelVal != "" {
		r.Labels[common.SourceNamespace] = ""
	}
	// TODO: put sourceClusterID for leader cluster?
	if kindLabelVal, exists := r.Labels[common.SourceKind]; !exists || kindLabelVal != common.AntreaClusterNetworkPolicyKind {
		r.Labels[common.SourceKind] = common.AntreaClusterNetworkPolicyKind
	}
	if r.DeletionTimestamp.IsZero() && !common.StringExistsInSlice(r.Finalizers, common.ResourceExportFinalizer) {
		r.Finalizers = []string{common.ResourceExportFinalizer}
	}
}

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-resourceexport,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=create;update,versions=v1alpha1,name=vresourceexport.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ResourceExport{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ResourceExport) ValidateCreate() error {
	resourceexportlog.Info("validate create", "name", r.Name)
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ResourceExport) ValidateUpdate(old runtime.Object) error {
	resourceexportlog.Info("validate update", "name", r.Name)
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ResourceExport) ValidateDelete() error {
	resourceexportlog.Info("validate delete", "name", r.Name)
	return nil
}
