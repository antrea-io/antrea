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
)

// log is for logging in this package.
var clustersetlog = logf.Log.WithName("clusterset-resource")

func (r *ClusterSet) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-multicluster-crd-antrea-io-v1alpha1-clusterset,mutating=true,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clustersets,verbs=create;update,versions=v1alpha1,name=mclusterset.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ClusterSet{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ClusterSet) Default() {
	clustersetlog.Info("default", "name", r.Name)
}

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-clusterset,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clustersets,verbs=create;update,versions=v1alpha1,name=vclusterset.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ClusterSet{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterSet) ValidateCreate() error {
	clustersetlog.Info("validate create", "name", r.Name)
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterSet) ValidateUpdate(old runtime.Object) error {
	clustersetlog.Info("validate update", "name", r.Name)
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterSet) ValidateDelete() error {
	clustersetlog.Info("validate delete", "name", r.Name)
	return nil
}
