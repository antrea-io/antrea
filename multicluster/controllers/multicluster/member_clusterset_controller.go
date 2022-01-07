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

	"go.uber.org/multierr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

// MemberClusterSetReconciler reconciles a ClusterSet object in the member cluster deployment.
type MemberClusterSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	mutex  sync.Mutex

	clusterSetConfig *multiclusterv1alpha1.ClusterSet
	clusterSetID     common.ClusterSetID
	clusterID        common.ClusterID

	RemoteCommonAreaManager commonarea.RemoteCommonAreaManager
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *MemberClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	defer r.mutex.Unlock()
	r.mutex.Lock()
	if err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		klog.InfoS("Received ClusterSet delete", "config", klog.KObj(clusterSet))
		stopErr := r.RemoteCommonAreaManager.Stop()
		r.RemoteCommonAreaManager = nil
		r.clusterSetConfig = nil
		r.clusterID = common.InvalidClusterID
		r.clusterSetID = common.InvalidClusterSetID

		return ctrl.Result{}, stopErr
	}

	klog.InfoS("Received ClusterSet add/update", "config", klog.KObj(clusterSet))

	// Handle create or update
	if r.clusterSetConfig == nil {
		// If create, make sure the local ClusterClaim is part of the member config
		clusterId, clusterSetId, err := validateLocalClusterClaim(r.Client, clusterSet)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err = validateConfigExists(clusterId, clusterSet.Spec.Members); err != nil {
			err = fmt.Errorf("local cluster %s is not defined as member in ClusterSet", clusterId)
			return ctrl.Result{}, err
		}
		r.clusterID = clusterId
		r.clusterSetID = clusterSetId
	} else {
		if string(r.clusterSetID) != clusterSet.Name {
			return ctrl.Result{}, fmt.Errorf("ClusterSet Name %s cannot be changed to %s",
				r.clusterSetID, req.Name)
		}
	}
	r.clusterSetConfig = clusterSet.DeepCopy()

	// handle create and update
	err = r.updateMultiClusterSetOnMemberCluster(clusterSet)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MemberClusterSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Update status periodically
	go func() {
		for {
			<-time.After(time.Second * 30)
			r.updateStatus()
		}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ClusterSet{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

func (r *MemberClusterSetReconciler) updateMultiClusterSetOnMemberCluster(clusterSet *multiclusterv1alpha1.ClusterSet) error {
	if r.RemoteCommonAreaManager == nil {
		r.RemoteCommonAreaManager = commonarea.NewRemoteCommonAreaManager(r.clusterSetID, r.clusterID)
		err := r.RemoteCommonAreaManager.Start()
		if err != nil {
			klog.ErrorS(err, "error starting RemoteCommonAreaManager")
			r.RemoteCommonAreaManager = nil
			r.clusterSetID = common.InvalidClusterSetID
			r.clusterID = common.InvalidClusterID
			r.clusterSetConfig = nil
			return err
		}
	}

	currentLeaders := r.RemoteCommonAreaManager.GetRemoteCommonAreas()
	newLeaders := clusterSet.Spec.Leaders

	var addedLeaders []*multiclusterv1alpha1.MemberCluster
	var removedLeaders map[common.ClusterID]commonarea.RemoteCommonArea

	for _, leader := range newLeaders {
		leaderID := common.ClusterID(leader.ClusterID)
		_, found := currentLeaders[leaderID]
		if !found {
			addedLeaders = append(addedLeaders, leader.DeepCopy())
		} else {
			// In the end currentLeaders will only have removed leaders
			delete(currentLeaders, leaderID)
			// TODO: Leader is updated, the leader url or secret could have changed,
			// so, we need to recreate the RemoteCommonArea.
		}
	}

	klog.InfoS("ClusterSet update", "addedLeaders", addedLeaders, "removedLeaders", removedLeaders)

	var multiErr error
	for _, addedLeader := range addedLeaders {
		clusterID := common.ClusterID(addedLeader.ClusterID)
		url := addedLeader.Server
		secretName := addedLeader.Secret

		klog.InfoS("Creating RemoteCommonArea", "Cluster", clusterID)
		// Read secret to access the leader cluster. Assume secret is present in the same Namespace as the ClusterSet.
		secret, err := r.getSecretForLeader(secretName, clusterSet.GetNamespace())
		if err == nil {
			_, err = commonarea.NewRemoteCommonArea(clusterID, r.clusterSetID, url, secret, r.Scheme,
				r.Client, r.RemoteCommonAreaManager, clusterSet.Spec.Namespace)
		}
		if err != nil {
			klog.ErrorS(err, "Unable to create RemoteCommonArea", "Cluster", clusterID)
		} else {
			klog.InfoS("Created RemoteCommonArea", "Cluster", clusterID)
		}
		multiErr = multierr.Append(multiErr, err)
	}

	removedLeaders = currentLeaders
	for _, remoteCommonArea := range removedLeaders {
		r.RemoteCommonAreaManager.RemoveRemoteCommonArea(remoteCommonArea)
		klog.InfoS("Deleted RemoteCommonArea", "Cluster", remoteCommonArea.GetClusterID())
	}

	return multiErr
}

// getSecretForLeader returns the Secret associated with this local cluster(which is a member)
// for the given leader.
// When a member is added to a ClusterSet, a specific ServiceAccount is created on the
// leader cluster which allows the member access into the CommonArea. This ServiceAccount
// has an associated Secret which must be copied into the member cluster as an opaque secret.
// Name of this secret is part of the ClusterSet spec for this leader. This method reads
// the Secret given by that name.
func (r *MemberClusterSetReconciler) getSecretForLeader(secretName string, secretNs string) (secretObj *v1.Secret, err error) {
	secretObj = &v1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Namespace: secretNs,
		Name:      secretName,
	}
	if err = r.Get(context.TODO(), secretNamespacedName, secretObj); err != nil {
		klog.ErrorS(err, "Error reading secret", "Name", secretName, "Namespace", secretNs)
		return
	}
	return
}

func (r *MemberClusterSetReconciler) updateStatus() {
	defer r.mutex.Unlock()
	r.mutex.Lock()

	if r.clusterSetConfig == nil {
		// Nothing to do.
		return
	}

	status := multiclusterv1alpha1.ClusterSetStatus{}
	status.TotalClusters = int32(len(r.clusterSetConfig.Spec.Members) + len(r.clusterSetConfig.Spec.Leaders))
	status.ObservedGeneration = r.clusterSetConfig.Generation
	status.ClusterStatuses = r.RemoteCommonAreaManager.GetMemberClusterStatues()

	overallCondition := multiclusterv1alpha1.ClusterSetCondition{
		Type:               multiclusterv1alpha1.ClusterSetReady,
		Status:             v1.ConditionUnknown,
		Message:            "Leader not yet elected",
		Reason:             "",
		LastTransitionTime: metav1.Now(),
	}
	readyClusters := 0
	for _, cluster := range status.ClusterStatuses {
		connected := false
		isLeader := false
		for _, condition := range cluster.Conditions {
			switch condition.Type {
			case multiclusterv1alpha1.ClusterReady:
				{
					if condition.Status == v1.ConditionTrue {
						connected = true
						readyClusters += 1
					}
				}
			case multiclusterv1alpha1.ClusterIsElectedLeader:
				{
					if condition.Status == v1.ConditionTrue {
						isLeader = true
					}
				}
			}
		}
		if connected && isLeader {
			overallCondition.Status = v1.ConditionTrue
			overallCondition.Message = ""
			overallCondition.Reason = ""
		}
	}
	if readyClusters == 0 {
		overallCondition.Status = v1.ConditionFalse
		overallCondition.LastTransitionTime = metav1.Now()
		overallCondition.Message = "Disconnected from all leaders"
	}
	status.ReadyClusters = int32(readyClusters)

	namespacedName := types.NamespacedName{
		Namespace: r.clusterSetConfig.Namespace,
		Name:      r.clusterSetConfig.Name,
	}
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(context.TODO(), namespacedName, clusterSet)
	if err != nil {
		klog.ErrorS(err, "failed to read ClusterSet", "Name", namespacedName)
	}
	status.Conditions = clusterSet.Status.Conditions
	if (len(clusterSet.Status.Conditions) == 1 && clusterSet.Status.Conditions[0].Status != overallCondition.Status) ||
		len(clusterSet.Status.Conditions) == 0 {
		status.Conditions = []multiclusterv1alpha1.ClusterSetCondition{overallCondition}
	}
	clusterSet.Status = status
	err = r.Status().Update(context.TODO(), clusterSet)
	if err != nil {
		klog.ErrorS(err, "failed to update Status of ClusterSet", "Name", namespacedName)
	}
}
