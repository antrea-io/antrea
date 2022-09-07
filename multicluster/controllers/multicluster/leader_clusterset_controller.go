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
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	NoReadyCluster = "NoReadyCluster"
)

// LeaderClusterSetReconciler reconciles a ClusterSet object in the leader cluster deployment.
// There will be one MC Controller running in each Namespace of the leader for multiple ClusterSet support.
// So each MC Controller will only be handling a single ClusterSet in the given Namespace.
type LeaderClusterSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	mutex  sync.Mutex

	clusterSetConfig *multiclusterv1alpha1.ClusterSet
	clusterSetID     common.ClusterSetID
	clusterID        common.ClusterID

	StatusManager MemberClusterStatusManager
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *LeaderClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		klog.InfoS("Received ClusterSet delete", "clusterset", req.NamespacedName)
		r.clusterSetConfig = nil
		r.clusterID = common.InvalidClusterID
		r.clusterSetID = common.InvalidClusterSetID

		return ctrl.Result{}, nil
	}

	klog.InfoS("Received ClusterSet add/update", "clusterset", klog.KObj(clusterSet))

	// Handle create or update
	// If create, make sure the required local ClusterClaims are defined, and the cluster and ClusterSet
	// IDs are included in the leader cluster's ClusterSet CR.
	if r.clusterSetConfig == nil {
		clusterID, clusterSetID, err := validateLocalClusterClaim(r.Client, clusterSet)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err = validateConfigExists(clusterID, clusterSet.Spec.Leaders); err != nil {
			err = fmt.Errorf("local cluster %s is not defined as leader in ClusterSet", clusterID)
			return ctrl.Result{}, err
		}
		r.clusterID = clusterID
		r.clusterSetID = clusterSetID
	} else {
		// Make sure clusterSetID has not changed
		if string(r.clusterSetID) != clusterSet.Name {
			return ctrl.Result{}, fmt.Errorf("ClusterSet Name %s cannot be changed to %s",
				r.clusterSetID, clusterSet.Name)
		}
	}

	r.clusterSetConfig = clusterSet.DeepCopy()
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LeaderClusterSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.runBackgroundTasks()
	// Ignore status update event via GenerationChangedPredicate
	instance := predicate.GenerationChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ClusterSet{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

func (r *LeaderClusterSetReconciler) runBackgroundTasks() {
	// Update status periodically
	go func() {
		for {
			<-time.After(time.Second * 30)
			r.updateStatus()
		}
	}()
}

// updateStatus updates ClusterSet Status as follows:
//  1. TotalClusters is the number of member clusters in the
//     ClusterSet resource last processed.
//  2. ObservedGeneration is the Generation from the last processed
//     ClusterSet resource.
//  3. Individual cluster status is obtained from MemberClusterAnnounce
//     controller.
//  4. ReadyClusters is the number of member clusters with "Ready" = "True"
//  5. Overall condition of the ClusterSet is also computed as follows:
//     a. "Ready" = "True" if all clusters have "Ready" = "True".
//     Message & Reason will be absent.
//     b. "Ready" = "Unknown" if all clusters have "Ready" = "Unknown".
//     Message will be "All clusters have an unknown status"
//     and Reason will be "NoReadyCluster"
//     c. "Ready" = "False" for any other combination of cluster
//     statues across all clusters. Message will be empty and Reason
//     will be "NoReadyCluster"
func (r *LeaderClusterSetReconciler) updateStatus() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.clusterSetConfig == nil {
		// Nothing to do.
		return
	}

	status := multiclusterv1alpha1.ClusterSetStatus{}
	status.ObservedGeneration = r.clusterSetConfig.Generation
	clusterStatuses := r.StatusManager.GetMemberClusterStatuses()
	status.ClusterStatuses = clusterStatuses
	sizeOfMembers := len(clusterStatuses)
	status.TotalClusters = int32(sizeOfMembers)
	readyClusters := 0
	unknownClusters := 0
	for _, cluster := range clusterStatuses {
		for _, condition := range cluster.Conditions {
			if condition.Type == multiclusterv1alpha1.ClusterReady {
				switch condition.Status {
				case v1.ConditionTrue:
					readyClusters += 1
				case v1.ConditionUnknown:
					unknownClusters += 1
				}
			}
		}
	}
	status.ReadyClusters = int32(readyClusters)
	overallCondition := multiclusterv1alpha1.ClusterSetCondition{
		Type:               multiclusterv1alpha1.ClusterSetReady,
		Status:             v1.ConditionFalse,
		Message:            "",
		Reason:             NoReadyCluster,
		LastTransitionTime: metav1.Now(),
	}
	if readyClusters == sizeOfMembers {
		overallCondition.Status = v1.ConditionTrue
		overallCondition.Reason = ""
	} else if unknownClusters == sizeOfMembers {
		overallCondition.Status = v1.ConditionUnknown
		overallCondition.Message = "All clusters have an unknown status"
	}

	namespacedName := types.NamespacedName{
		Namespace: r.clusterSetConfig.Namespace,
		Name:      r.clusterSetConfig.Name,
	}
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(context.TODO(), namespacedName, clusterSet)
	if err != nil {
		klog.ErrorS(err, "Failed to read ClusterSet", "name", namespacedName)
	}
	status.Conditions = clusterSet.Status.Conditions
	if (len(clusterSet.Status.Conditions) == 1 && clusterSet.Status.Conditions[0].Status != overallCondition.Status) ||
		len(clusterSet.Status.Conditions) == 0 {
		status.Conditions = []multiclusterv1alpha1.ClusterSetCondition{overallCondition}
	}
	clusterSet.Status = status
	err = r.Status().Update(context.TODO(), clusterSet)
	if err != nil {
		klog.ErrorS(err, "Failed to update Status of ClusterSet", "name", namespacedName)
	}
}
