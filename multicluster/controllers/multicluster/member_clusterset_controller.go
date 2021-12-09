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

	"go.uber.org/multierr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/core"
)

// MemberClusterSetReconciler reconciles a ClusterSet object in the member cluster deployment.
type MemberClusterSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	clusterSetConfig *multiclusterv1alpha1.ClusterSet
	clusterSetID     common.ClusterSetID
	clusterID        common.ClusterID

	RemoteCommonAreaManager core.RemoteCommonAreaManager
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *MemberClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
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
	r.clusterSetConfig = clusterSet.DeepCopy()

	// if update and if leaders have changed, handle accordingly, else, nothing to do.
	err = r.updateMultiClusterSetOnMemberCluster(clusterSet)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MemberClusterSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ClusterSet{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5, // TODO: Use a constant after merging with Lan's changes
		}).
		Complete(r)
}

func (r *MemberClusterSetReconciler) updateMultiClusterSetOnMemberCluster(clusterSet *multiclusterv1alpha1.ClusterSet) error {
	if r.RemoteCommonAreaManager == nil {
		r.RemoteCommonAreaManager = core.NewRemoteCommonAreaManager(r.clusterSetID, r.clusterID)
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
	var removedLeaders map[common.ClusterID]core.RemoteCommonArea

	for _, leader := range newLeaders {
		leaderID := common.ClusterID(leader.ClusterID)
		_, found := currentLeaders[leaderID]
		if !found {
			addedLeaders = append(addedLeaders, leader.DeepCopy())
		} else {
			// In the end currentLeaders will only have removed leaders
			delete(currentLeaders, leaderID)
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
			_, err = core.NewRemoteCommonArea(clusterID, r.clusterSetID, url, secret, r.Scheme,
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
