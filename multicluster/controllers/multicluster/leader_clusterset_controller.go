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

package multicluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// LeaderClusterSetReconciler reconciles a ClusterSet object in the leader cluster deployment.
// There will be one MC Controller running in each Namespace of the leader for multiple ClusterSet support.
// So each MC Controller will only be handling a single ClusterSet in the given Namespace.
type LeaderClusterSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	clusterSetConfig *multiclusterv1alpha1.ClusterSet
	clusterSetID     common.ClusterSetID
	clusterID        common.ClusterID
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *LeaderClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	if err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// if errors.IsNotFound(err)
		klog.InfoS("Received ClusterSet delete", "config", klog.KObj(clusterSet))
		r.clusterSetConfig = nil
		r.clusterID = common.InvalidClusterID
		r.clusterSetID = common.InvalidClusterSetID

		return ctrl.Result{}, nil
	}

	klog.InfoS("Received ClusterSet add/update", "config", klog.KObj(clusterSet))

	// Handle create or update
	// If create, make sure the local ClusterClaim is part of the leader config
	clusterId, clusterSetId, err := validateLocalClusterClaim(r.Client, clusterSet)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err = validateConfigExists(clusterId, clusterSet.Spec.Leaders); err != nil {
		err = fmt.Errorf("local cluster %s is not defined as leader in ClusterSet", clusterId)
		return ctrl.Result{}, err
	}
	if err = validateClusterSetNamespace(clusterSet); err != nil {
		return ctrl.Result{}, err
	}
	r.clusterID = clusterId
	r.clusterSetID = clusterSetId
	r.clusterSetConfig = clusterSet.DeepCopy()

	// if update, leader has nothing to do
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LeaderClusterSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ClusterSet{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5, // TODO: Use a constant after merging with Lan's changes
		}).
		Complete(r)
}
