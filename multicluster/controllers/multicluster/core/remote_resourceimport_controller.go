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

package core

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

// ResourceImportReconciler reconciles a ResourceImport object
type ResourceImportReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	localClusterClient client.Client
	remoteCommonArea   RemoteCommonArea
}

func NewResourceImportReconciler(client client.Client, scheme *runtime.Scheme, localClusterClient client.Client, remoteCommonArea RemoteCommonArea) *ResourceImportReconciler {
	return &ResourceImportReconciler{
		Client:             client,
		Scheme:             scheme,
		localClusterClient: localClusterClient,
		remoteCommonArea:   remoteCommonArea,
	}
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch;update;create;patch;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;create;patch;delete

// Reconcile will attempt to ensure that the imported Resource is installed in local cluster as per the
// ResourceImport object.
func (r *ResourceImportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("reconciling ResourceImport", "resourceimport", req.NamespacedName)

	// TODO: handle for other ResImport Kinds
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ResourceImportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ResourceImport{}).
		Complete(r)
}
