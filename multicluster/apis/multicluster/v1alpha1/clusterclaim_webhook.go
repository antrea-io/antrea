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
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func (r *ClusterClaim) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-multicluster-crd-antrea-io-v1alpha1-clusterclaim,mutating=true,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clusterclaims,verbs=create;update,versions=v1alpha1,name=mclusterclaim.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ClusterClaim{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ClusterClaim) Default() {
	klog.InfoS("default", "name", r.Name)

	// TODO(user): fill in your defaulting logic.
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-clusterclaim,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clusterclaims,verbs=create;update,versions=v1alpha1,name=vclusterclaim.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ClusterClaim{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterClaim) ValidateCreate() error {
	klog.InfoS("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterClaim) ValidateUpdate(old runtime.Object) error {
	klog.InfoS("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterClaim) ValidateDelete() error {
	klog.InfoS("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}
