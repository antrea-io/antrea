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

	"github.com/go-logr/logr"
	"go.uber.org/multierr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/internal"
)

// ClusterSetReconciler reconciles a ClusterSet object
// There will be one controller running in each namespace of the leader for multiple cluster-set support
// so each controller will only be handling a single cluster set in the given namespace.
// TODO: Split the reconciler for member and leader to avoid if checks. In case a cluster is both a
//       member and a leader, 2 instances of the controller will need to be run, one as a leader
//		 the second as a member.
type ClusterSetReconciler struct {
	client.Client
	mutex    sync.Mutex
	Scheme   *runtime.Scheme
	Log      logr.Logger
	IsLeader bool

	clusterSetConfig *multiclusterv1alpha1.ClusterSet
	clusterSetID     common.ClusterSetID
	clusterID        common.ClusterID

	// These fields are only applicable on leader cluster
	LocalClusterManager internal.LocalClusterManager

	// These fields are only applicable on member cluster
	RemoteClusterManager internal.RemoteClusterManager
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet CRD changes
func (r *ClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("ClusterSet", req.Namespace)

	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	if err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// if errors.IsNotFound(err)
		r.Log.Info("Received ClusterSet delete", "config", clusterSet, "leader", r.IsLeader)
		if !r.IsLeader {
			if err := r.RemoteClusterManager.Stop(); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			if err := r.LocalClusterManager.Stop(); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	r.Log.Info("Received ClusterSet add/update", "config", clusterSet, "leader", r.IsLeader)

	// Handle create or update
	// If create
	//   if leader, make sure the local cluster claim is part of the leader config
	//   if not leader, make sure the local cluster claim is part of the member config
	if err = r.validateLocalClusterClaim(clusterSet); err != nil {
		return ctrl.Result{}, err
	}

	// if update,
	//    if leader - nothing to do in inbound mode
	//    if member - if leaders have changed handle accordingly, else nothing to do.
	if !r.IsLeader {
		err = r.updateMultiClusterSetOnMemberCluster(clusterSet)
		if err != nil {
			return ctrl.Result{}, err
		}
	} else {
		r.createOrUpdateMultiClusterSetOnLeaderCluster(clusterSet)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ClusterSet{}).
		Complete(r)
}

func (r *ClusterSetReconciler) validateLocalClusterClaim(clusterSet *multiclusterv1alpha1.ClusterSet) error {
	// read the cluster claim in the cluster
	configNamespace := clusterSet.GetNamespace()

	clusterClaimList := &multiclusterv1alpha1.ClusterClaimList{}
	r.Log.Info("Validating cluster claim in", "namespace", configNamespace)
	if err := r.List(context.TODO(), clusterClaimList, client.InNamespace(configNamespace)); err != nil {
		return err
	}
	if len(clusterClaimList.Items) == 0 {
		return fmt.Errorf("cluster claim is not configured for the cluster")
	}

	var clusterSetClaimID string
	wellKnownClusterSetClaimIDExist := false
	var clusterClaimID string
	wellKnownClusterClaimIDExist := false
	for _, clusterClaim := range clusterClaimList.Items {
		r.Log.Info("Processing clusterclaim", "name", clusterClaim.Name, "value", clusterClaim.Value)
		if clusterClaim.Name == multiclusterv1alpha1.WellKnownClusterClaimClusterSet {
			wellKnownClusterSetClaimIDExist = true
			clusterSetClaimID = clusterClaim.Value
		} else if clusterClaim.Name == multiclusterv1alpha1.WellKnownClusterClaimID {
			wellKnownClusterClaimIDExist = true
			clusterClaimID = clusterClaim.Value
		}
	}

	if !wellKnownClusterSetClaimIDExist {
		return fmt.Errorf("clusterset claim ID not configured for the cluster")
	}

	if !wellKnownClusterClaimIDExist {
		return fmt.Errorf("cluster claim ID not configured for the cluster")
	}

	configExists := false
	if r.IsLeader {
		//  validate the namespace is the same
		if clusterSet.Spec.Namespace != clusterSet.GetNamespace() {
			return fmt.Errorf("cluster set namespace " + clusterSet.Spec.Namespace + " is different from " +
				clusterSet.GetNamespace())
		}
		for _, leader := range clusterSet.Spec.Leaders {
			if clusterClaimID == leader.ClusterID {
				configExists = true
				break
			}
		}
		if !configExists {
			return fmt.Errorf("cluster not defined as leader in cluster set")
		}
	} else {
		for _, member := range clusterSet.Spec.Members {
			if clusterClaimID == member.ClusterID {
				configExists = true
				break
			}
		}
		if !configExists {
			return fmt.Errorf("cluster not defined as member in cluster set")
		}
	}

	r.clusterID = common.ClusterID(clusterClaimID)
	r.clusterSetID = common.ClusterSetID(clusterSetClaimID)
	r.clusterSetConfig = clusterSet.DeepCopy()

	return nil
}

func (r *ClusterSetReconciler) createOrUpdateMultiClusterSetOnLeaderCluster(clusterSet *multiclusterv1alpha1.ClusterSet) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.LocalClusterManager == nil {
		// TODO: refer to Antrea code to provide a method like NewClusterSetReconciler to do initialization in one place?
		// antrea/multicluster/controllers/multicluster/resourceexport_controller.go and
		r.LocalClusterManager = internal.NewLocalClusterManager(r.Client, r.clusterID, clusterSet.GetNamespace(), r.Log)
	}
}

func (r *ClusterSetReconciler) updateMultiClusterSetOnMemberCluster(clusterSet *multiclusterv1alpha1.ClusterSet) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.RemoteClusterManager == nil {
		r.RemoteClusterManager = internal.NewRemoteClusterManager(r.clusterSetID, r.Log, r.clusterID)
		go func() {
			r.Log.Info("Starting remote cluster manager", "clusterSetID", r.clusterSetID)
			var err error
			err = r.RemoteClusterManager.Start()
			if err != nil {
				r.Log.Error(err, "Error starting remote cluster manager")
			}
			r.mutex.Lock()
			r.RemoteClusterManager = nil
			r.clusterSetID = common.INVALID_CLUSTER_SET_ID
			r.clusterID = common.INVALID_CLUSTER_ID
			r.clusterSetConfig = nil
			r.mutex.Unlock()
		}()
	}

	currentLeaders := r.RemoteClusterManager.GetRemoteClusters()
	newLeaders := clusterSet.Spec.Leaders

	var addedLeaders []*multiclusterv1alpha1.MemberCluster
	var removedLeaders map[common.ClusterID]internal.RemoteCluster

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

	ch := make(chan error)
	var wg sync.WaitGroup
	wg.Add(len(addedLeaders))
	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, addedLeader := range addedLeaders {
		clusterID := common.ClusterID(addedLeader.ClusterID)
		url := addedLeader.Server
		secretName := addedLeader.Secret

		r.Log.Info("creating remote cluster", "clusterID", clusterID)

		go func(clusterID common.ClusterID, url string, secretName string) {
			defer wg.Done()

			_, err := internal.NewRemoteCluster(clusterID, r.clusterSetID, url, secretName, r.Scheme,
				r.Log, r.RemoteClusterManager, clusterSet.Spec.Namespace, clusterSet.GetNamespace())
			if err != nil {
				r.Log.Error(err, "Unable to create remote cluster", "clusterID", clusterID)
			} else {
				r.Log.Info("Created", "clusterID", clusterID)
			}

			ch <- err
		}(clusterID, url, secretName)
	}

	var err error
	for errFromCh := range ch {
		if errFromCh != nil {
			r.Log.Error(errFromCh, "Received error")
			err = multierr.Append(err, errFromCh)
		}
	}

	removedLeaders = currentLeaders
	for _, remoteCluster := range removedLeaders {
		r.RemoteClusterManager.RemoveRemoteCluster(remoteCluster)
		r.Log.Info("Deleted", "clusterID", remoteCluster.GetClusterID())
	}

	r.Log.Error(err, "Final error")
	return err
}
