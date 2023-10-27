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

package leader

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	NoReadyCluster = "NoReadyCluster"
)

// LeaderClusterSetReconciler reconciles a ClusterSet object in the leader cluster deployment.
// Each ClusterSet should have one Multi-cluster Controller running in the ClusterSet' leader
// Namespace, so a MC Controller will be handling only a single ClusterSet in the given Namespace.
type LeaderClusterSetReconciler struct {
	client.Client
	namespace                string
	clusterCalimCRDAvailable bool
	statusManager            MemberClusterStatusManager

	clusterSetID common.ClusterSetID
	clusterID    common.ClusterID
	mutex        sync.Mutex
}

func NewLeaderClusterSetReconciler(client client.Client, namespace string,
	clusterCalimCRDAvailable bool,
	statusManager MemberClusterStatusManager) *LeaderClusterSetReconciler {
	return &LeaderClusterSetReconciler{
		Client:                   client,
		namespace:                namespace,
		clusterCalimCRDAvailable: clusterCalimCRDAvailable,
		statusManager:            statusManager,
		clusterID:                common.InvalidClusterID,
		clusterSetID:             common.InvalidClusterSetID,
	}
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *LeaderClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &mcv1alpha2.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		klog.InfoS("Received ClusterSet delete", "clusterset", req.NamespacedName)
		if r.clusterSetID != common.ClusterSetID(req.Name) {
			// Not the current ClusterSet.
			return ctrl.Result{}, nil
		}
		r.clusterID = common.InvalidClusterID
		r.clusterSetID = common.InvalidClusterSetID
		return ctrl.Result{}, nil
	}

	klog.InfoS("Received ClusterSet add/update", "clusterset", klog.KObj(clusterSet))

	// Handle create or update
	if r.clusterID == common.InvalidClusterID {
		r.clusterID, err = common.GetClusterID(r.clusterCalimCRDAvailable, req, r.Client, clusterSet)
		if err != nil {
			return ctrl.Result{}, err
		}
		r.clusterSetID = common.ClusterSetID(clusterSet.Name)
		if err = validateMemberClusterExists(r.clusterID, clusterSet.Spec.Leaders); err != nil {
			err = fmt.Errorf("local cluster %s is not defined as leader in ClusterSet", r.clusterID)
			return ctrl.Result{}, err
		}

		if clusterSet.Spec.ClusterID == "" {
			// ClusterID is a required field, and the empty value case should only happen
			// when Antrea Multi-cluster is upgraded from an old version prior to v1.13.
			// Here we try to update the ClusterSet's ClusterID when it's configured in an
			// existing ClusterClaim.
			clusterSet.Spec.ClusterID = string(r.clusterID)
			err = r.Update(context.TODO(), clusterSet)
			if err != nil {
				klog.ErrorS(err, "Failed to update ClusterSet's ClusterID", "clusterset", req.NamespacedName)
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LeaderClusterSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.runBackgroundTasks()
	// Ignore status update event via GenerationChangedPredicate
	instance := predicate.GenerationChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcv1alpha2.ClusterSet{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
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

	if r.clusterID == common.InvalidClusterID {
		// Nothing to do.
		return
	}

	namespacedName := types.NamespacedName{
		Namespace: r.namespace,
		Name:      string(r.clusterSetID),
	}
	clusterSet := &mcv1alpha2.ClusterSet{}
	err := r.Get(context.TODO(), namespacedName, clusterSet)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get ClusterSet", "name", namespacedName)
		}
		return
	}

	status := mcv1alpha2.ClusterSetStatus{}
	status.ObservedGeneration = clusterSet.Generation
	clusterStatuses := r.statusManager.GetMemberClusterStatuses()
	status.ClusterStatuses = clusterStatuses
	sizeOfMembers := len(clusterStatuses)
	status.TotalClusters = int32(sizeOfMembers)
	readyClusters := 0
	unknownClusters := 0
	for _, cluster := range clusterStatuses {
		for _, condition := range cluster.Conditions {
			if condition.Type == mcv1alpha2.ClusterReady {
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
	overallCondition := mcv1alpha2.ClusterSetCondition{
		Type:               mcv1alpha2.ClusterSetReady,
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

	status.Conditions = clusterSet.Status.Conditions
	if (len(clusterSet.Status.Conditions) == 1 && clusterSet.Status.Conditions[0].Status != overallCondition.Status) ||
		len(clusterSet.Status.Conditions) == 0 {
		status.Conditions = []mcv1alpha2.ClusterSetCondition{overallCondition}
	}
	clusterSet.Status = status
	err = r.Status().Update(context.TODO(), clusterSet)
	if err != nil {
		klog.ErrorS(err, "Failed to update Status of ClusterSet", "name", namespacedName)
	}
}

func validateMemberClusterExists(clusterID common.ClusterID, clusters []mcv1alpha2.LeaderClusterInfo) (err error) {
	configExists := false
	for _, cluster := range clusters {
		if string(clusterID) == cluster.ClusterID {
			configExists = true
			break
		}
	}
	if !configExists {
		err = fmt.Errorf("validating cluster %s exists in %v failed", clusterID, clusters)
		return
	}
	return
}
