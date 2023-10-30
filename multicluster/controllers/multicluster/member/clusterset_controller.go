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

package member

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

type leaderClusterInfo struct {
	clusterID  string
	serverUrl  string
	secretName string
}

var getRemoteConfigAndClient = commonarea.GetRemoteConfigAndClient

// MemberClusterSetReconciler reconciles a ClusterSet object in the member cluster deployment.
type MemberClusterSetReconciler struct {
	client.Client
	scheme                   *runtime.Scheme
	namespace                string
	clusterCalimCRDAvailable bool

	// commonAreaLock protects the access to RemoteCommonArea.
	commonAreaLock       sync.RWMutex
	commonAreaCreationCh chan struct{}

	clusterSetID    common.ClusterSetID
	clusterID       common.ClusterID
	installedLeader leaderClusterInfo

	remoteCommonArea             commonarea.RemoteCommonArea
	enableStretchedNetworkPolicy bool
}

func NewMemberClusterSetReconciler(client client.Client,
	scheme *runtime.Scheme,
	namespace string,
	enableStretchedNetworkPolicy bool,
	clusterCalimCRDAvailable bool,
	commonAreaCreationCh chan struct{},
) *MemberClusterSetReconciler {
	return &MemberClusterSetReconciler{
		Client:                       client,
		scheme:                       scheme,
		namespace:                    namespace,
		enableStretchedNetworkPolicy: enableStretchedNetworkPolicy,
		clusterCalimCRDAvailable:     clusterCalimCRDAvailable,
		commonAreaCreationCh:         commonAreaCreationCh,
		clusterID:                    common.InvalidClusterID,
		clusterSetID:                 common.InvalidClusterSetID,
	}
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *MemberClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &mcv1alpha2.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	var clusterSetNotFound bool
	var clusterSetCreated bool
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if r.clusterSetID != common.ClusterSetID(req.Name) {
			// Not the current ClusterSet.
			return ctrl.Result{}, nil
		}
		clusterSetNotFound = true
	}

	processClusterSet := func() error {
		r.commonAreaLock.Lock()
		defer r.commonAreaLock.Unlock()

		if clusterSetNotFound {
			klog.InfoS("Received ClusterSet delete", "clusterset", req.NamespacedName)
			if err := r.cleanUpResources(ctx); err != nil {
				return err
			}
			return nil
		}

		klog.InfoS("Received ClusterSet add/update", "clusterset", klog.KObj(clusterSet))

		// Handle create or update

		newLeader := clusterSet.Spec.Leaders[0]

		clusterSetCreated = r.clusterID != common.ClusterID(clusterSet.Spec.ClusterID) || r.clusterSetID != common.ClusterSetID(clusterSet.Name)
		leaderChanged := r.installedLeader.clusterID != newLeader.ClusterID || r.installedLeader.serverUrl != newLeader.Server ||
			r.installedLeader.secretName != newLeader.Secret

		if !leaderChanged && !clusterSetCreated {
			klog.V(2).InfoS("No change for leader cluster configuration")
			return nil
		}

		if clusterSetCreated {
			// ClusterSet deletion may fail and retry, but a ClusterSet may have been created just right before the retry.
			// In that case, ClusterSet deletion retry will be like an update action, so try to delete stale resources
			// here before initilizing a new ClusterSet.
			if err := r.cleanUpResources(ctx); err != nil {
				return err
			}

			r.clusterID, err = common.GetClusterID(r.clusterCalimCRDAvailable, req, r.Client, clusterSet)
			if err != nil {
				return err
			}
			r.clusterSetID = common.ClusterSetID(clusterSet.Name)
			if clusterSet.Spec.ClusterID == "" {
				// ClusterID is a required field, and the empty value case should only happen
				// when Antrea Multi-cluster is upgraded from an old version prior to v1.13.
				// Here we try to update the ClusterSet's ClusterID when it's configured in an
				// existing ClusterClaim.
				clusterSet.Spec.ClusterID = string(r.clusterID)
				err = r.Update(context.TODO(), clusterSet)
				if err != nil {
					klog.ErrorS(err, "Failed to update ClusterSet's ClusterID", "clusterset", req.NamespacedName)
					return err
				}
			}
		}
		return r.createRemoteCommonArea(clusterSet)
	}

	if err := processClusterSet(); err != nil {
		return ctrl.Result{}, err
	}

	if clusterSetCreated {
		// The CommonArea creation succeeded here and so notify StaleController to
		// clean up stale imported resources and ResourceExports.
		select {
		case r.commonAreaCreationCh <- struct{}{}:
		default:
			// The notification has been sent and hasn't been consumed yet,
			// no need to send another one.
		}
	}
	return ctrl.Result{}, nil
}

func (r *MemberClusterSetReconciler) cleanUpResources(ctx context.Context) error {
	if r.remoteCommonArea != nil {
		// Any ResourceExports belong to this member cluster will be cleaned up by the leader cluster
		// when the MemberClusterAnnounce is deleted.
		if err := r.deleteMemberClusterAnnounce(ctx); err != nil {
			// MemberClusterAnnounce could be kept in the leader cluster, if antrea-mc-controller crashes after the failure.
			// Leader cluster will delete the stale MemberClusterAnnounce with a garbage collection mechanism in this case.
			return fmt.Errorf("failed to delete MemberClusterAnnounce in the leader cluster: %v", err)
		}
		r.remoteCommonArea.Stop()
		r.remoteCommonArea = nil
		r.installedLeader = leaderClusterInfo{}
	}

	if r.clusterID != common.InvalidClusterID {
		klog.InfoS("Clean up all resources created by Antrea Multi-cluster Controller")
		if err := cleanUpResourcesCreatedByMC(ctx, r.Client); err != nil {
			return err
		}
		r.clusterID = common.InvalidClusterID
		r.clusterSetID = common.InvalidClusterSetID
	}
	return nil
}

func (r *MemberClusterSetReconciler) deleteMemberClusterAnnounce(ctx context.Context) error {
	memberClusterAnnounce := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-" + r.remoteCommonArea.GetLocalClusterID(),
			Namespace: r.remoteCommonArea.GetNamespace(),
		},
	}
	if err := r.remoteCommonArea.Delete(ctx, memberClusterAnnounce, &client.DeleteOptions{}); err != nil {
		return client.IgnoreNotFound(err)
	}
	return nil
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

	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcv1alpha2.ClusterSet{}).
		WithEventFilter(generationPredicate).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

func (r *MemberClusterSetReconciler) createRemoteCommonArea(clusterSet *mcv1alpha2.ClusterSet) error {
	if r.remoteCommonArea != nil {
		r.remoteCommonArea.Stop()
		r.remoteCommonArea = nil
	}

	newLeader := clusterSet.Spec.Leaders[0]
	clusterID := common.ClusterID(newLeader.ClusterID)
	url := newLeader.Server
	secretName := newLeader.Secret

	klog.InfoS("Creating RemoteCommonArea", "cluster", clusterID)
	// Read Secret to access the leader cluster. Assume Secret is present in the same Namespace as the ClusterSet.
	secret, err := r.getSecretForLeader(secretName, clusterSet.GetNamespace())
	if err != nil {
		klog.ErrorS(err, "Failed to get Secret to create RemoteCommonArea", "secret", secretName, "cluster", clusterID)
		return err
	}

	config, remoteCommonAreaMgr, remoteClient, err := getRemoteConfigAndClient(secret, url, clusterID, clusterSet, r.scheme)
	if err != nil {
		return err
	}

	remoteNamespace := clusterSet.Spec.Namespace
	r.remoteCommonArea, err = commonarea.NewRemoteCommonArea(clusterID, r.clusterSetID, r.clusterID,
		remoteCommonAreaMgr, remoteClient, r.scheme, r.Client, remoteNamespace, r.namespace,
		config, r.enableStretchedNetworkPolicy)
	if err != nil {
		klog.ErrorS(err, "Unable to create RemoteCommonArea", "cluster", clusterID)
		return err
	}

	// Create import reconcilers and add them to RemoteCommonArea (to be started with
	// RemoteCommonArea.StartWatching).
	resImportReconciler := newResourceImportReconciler(
		r.Client,
		string(r.clusterID),
		r.namespace,
		r.remoteCommonArea,
	)
	r.remoteCommonArea.AddImportReconciler(resImportReconciler)

	if r.enableStretchedNetworkPolicy {
		labelIdentityImpReconciler := newLabelIdentityResourceImportReconciler(
			r.Client,
			string(clusterID),
			remoteNamespace,
			r.remoteCommonArea,
		)
		r.remoteCommonArea.AddImportReconciler(labelIdentityImpReconciler)
	}

	r.remoteCommonArea.Start()
	klog.InfoS("Created RemoteCommonArea", "cluster", clusterID)

	r.installedLeader = leaderClusterInfo{
		clusterID:  newLeader.ClusterID,
		serverUrl:  newLeader.Server,
		secretName: newLeader.Secret,
	}

	return nil
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
		klog.ErrorS(err, "Error reading Secret", "name", secretName, "namespace", secretNs)
		return
	}
	return
}

func (r *MemberClusterSetReconciler) updateStatus() {
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
	status.ClusterStatuses = []mcv1alpha2.ClusterStatus{}
	r.commonAreaLock.RLock()
	if r.remoteCommonArea != nil {
		status.ClusterStatuses = append(status.ClusterStatuses,
			mcv1alpha2.ClusterStatus{
				ClusterID:  string(r.remoteCommonArea.GetClusterID()),
				Conditions: r.remoteCommonArea.GetStatus(),
			},
		)
	}
	r.commonAreaLock.RUnlock()

	overallCondition := mcv1alpha2.ClusterSetCondition{
		Type:               mcv1alpha2.ClusterSetReady,
		Status:             v1.ConditionUnknown,
		Message:            "Leader not yet connected",
		Reason:             "",
		LastTransitionTime: metav1.Now(),
	}
	readyClusters := 0
	for _, cluster := range status.ClusterStatuses {
		connected := false
		isLeader := false
		for _, condition := range cluster.Conditions {
			switch condition.Type {
			case mcv1alpha2.ClusterReady:
				{
					if condition.Status == v1.ConditionTrue {
						connected = true
						readyClusters += 1
					}
				}
			case mcv1alpha2.ClusterIsLeader:
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
		overallCondition.Message = "Disconnected from leader"
	}
	// The total cluster should always be 1 to include the member cluster itself.
	status.TotalClusters = 1
	status.ReadyClusters = int32(readyClusters)

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

// SetRemoteCommonArea is for testing only
func (r *MemberClusterSetReconciler) SetRemoteCommonArea(commanArea commonarea.RemoteCommonArea) commonarea.RemoteCommonArea {
	r.remoteCommonArea = commanArea
	return r.remoteCommonArea
}

func (r *MemberClusterSetReconciler) GetRemoteCommonAreaAndLocalID() (commonarea.RemoteCommonArea, string, error) {
	r.commonAreaLock.RLock()
	defer r.commonAreaLock.RUnlock()
	if r.remoteCommonArea == nil {
		return nil, "", errors.New("ClusterSet has not been initialized, no available Common Area")
	}

	if r.remoteCommonArea.IsConnected() {
		localClusterID := string(r.remoteCommonArea.GetLocalClusterID())
		return r.remoteCommonArea, localClusterID, nil
	}
	return nil, "", errors.New("no connected remote Common Area")
}
