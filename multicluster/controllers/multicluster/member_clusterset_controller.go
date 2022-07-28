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

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

type RemoteCommonAreaGetter interface {
	GetRemoteCommonAreaAndLocalID() (commonarea.RemoteCommonArea, string, error)
}

type leaderClusterInfo struct {
	clusterID  string
	serverUrl  string
	secretName string
}

// MemberClusterSetReconciler reconciles a ClusterSet object in the member cluster deployment.
type MemberClusterSetReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string
	// commonAreaLock protects the access to RemoteCommonArea.
	commonAreaLock sync.RWMutex

	clusterSetConfig *multiclusterv1alpha1.ClusterSet
	clusterSetID     common.ClusterSetID
	clusterID        common.ClusterID
	installedLeader  leaderClusterInfo

	remoteCommonArea commonarea.RemoteCommonArea
}

func NewMemberClusterSetReconciler(client client.Client,
	scheme *runtime.Scheme,
	namespace string,
) *MemberClusterSetReconciler {
	return &MemberClusterSetReconciler{
		Client:    client,
		Scheme:    scheme,
		Namespace: namespace,
	}
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clustersets/finalizers,verbs=update

// Reconcile ClusterSet changes
func (r *MemberClusterSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	err := r.Get(ctx, req.NamespacedName, clusterSet)
	r.commonAreaLock.Lock()
	defer r.commonAreaLock.Unlock()
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		klog.InfoS("Received ClusterSet delete", "clusterset", req.NamespacedName)
		if r.remoteCommonArea != nil {
			if err := r.deleteMemberClusterAnnounce(ctx); err != nil {
				// MemberClusterAnnounce could be kept in the leader cluster, if antrea-mc-controller crashes after the failure.
				// Leader cluster will delete the stale MemberClusterAnnounce with a garbage collection mechanism in this case.
				return ctrl.Result{}, fmt.Errorf("failed to delete MemberClusterAnnounce in the leader cluster: %v", err)
			}
			r.remoteCommonArea.Stop()
			r.remoteCommonArea = nil
			r.clusterSetConfig = nil
			r.clusterID = common.InvalidClusterID
			r.clusterSetID = common.InvalidClusterSetID
		}
		return ctrl.Result{}, nil
	}

	klog.InfoS("Received ClusterSet add/update", "clusterset", klog.KObj(clusterSet))

	// Handle create or update
	if r.clusterSetConfig == nil {
		// If create, make sure the local ClusterClaim is part of the member ClusterSet.
		clusterID, clusterSetID, err := validateLocalClusterClaim(r.Client, clusterSet)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err = validateConfigExists(clusterID, clusterSet.Spec.Members); err != nil {
			err = fmt.Errorf("local cluster %s is not defined as member in ClusterSet", clusterID)
			return ctrl.Result{}, err
		}
		r.clusterID = clusterID
		r.clusterSetID = clusterSetID
	} else {
		if string(r.clusterSetID) != clusterSet.Name {
			return ctrl.Result{}, fmt.Errorf("ClusterSet Name %s cannot be changed to %s",
				r.clusterSetID, clusterSet.Name)
		}
	}
	r.clusterSetConfig = clusterSet.DeepCopy()

	// handle create and update
	err = r.createOrUpdateRemoteCommonArea(clusterSet)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *MemberClusterSetReconciler) deleteMemberClusterAnnounce(ctx context.Context) error {
	memberClusterAnnounce := &multiclusterv1alpha1.MemberClusterAnnounce{
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

	// Only register this controller to reconcile the ClusterSet in the same Namespace
	namespaceFilter := func(object client.Object) bool {
		if clusterSet, ok := object.(*multiclusterv1alpha1.ClusterSet); ok {
			return clusterSet.Namespace == r.Namespace
		}
		return false
	}
	namespacePredicate := predicate.NewPredicateFuncs(namespaceFilter)

	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	filter := predicate.And(generationPredicate, namespacePredicate)

	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ClusterSet{}).
		WithEventFilter(filter).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

func (r *MemberClusterSetReconciler) createOrUpdateRemoteCommonArea(clusterSet *multiclusterv1alpha1.ClusterSet) error {
	currentCommonArea := r.remoteCommonArea
	newLeader := clusterSet.Spec.Leaders[0]

	clusterID := common.ClusterID(newLeader.ClusterID)
	url := newLeader.Server
	secretName := newLeader.Secret

	if currentCommonArea != nil {
		if r.installedLeader.clusterID == newLeader.ClusterID && r.installedLeader.serverUrl == newLeader.Server &&
			r.installedLeader.secretName == newLeader.Secret {
			klog.V(2).InfoS("No change for leader cluster configuration")
			return nil
		}

		klog.InfoS("ClusterSet update", "old", currentCommonArea.GetClusterID(), "new", newLeader)
		klog.InfoS("Stopping old RemoteCommonArea", "cluster", clusterID)
		currentCommonArea.Stop()
		r.remoteCommonArea = nil
	}

	klog.InfoS("Creating RemoteCommonArea", "cluster", clusterID)
	// Read Secret to access the leader cluster. Assume Secret is present in the same Namespace as the ClusterSet.
	secret, err := r.getSecretForLeader(secretName, clusterSet.GetNamespace())
	if err != nil {
		klog.ErrorS(err, "Failed to get Secret to create RemoteCommonArea", "secret", secretName, "cluster", clusterID)
		return err
	}

	r.remoteCommonArea, err = commonarea.NewRemoteCommonArea(clusterID, r.clusterSetID, common.ClusterSetID(r.clusterID), url, secret, r.Scheme,
		r.Client, clusterSet.Spec.Namespace, r.Namespace)
	if err != nil {
		klog.ErrorS(err, "Unable to create RemoteCommonArea", "cluster", clusterID)
		return err
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
	if r.clusterSetConfig == nil {
		// Nothing to do.
		return
	}

	status := multiclusterv1alpha1.ClusterSetStatus{}
	status.TotalClusters = int32(len(r.clusterSetConfig.Spec.Members))
	status.ObservedGeneration = r.clusterSetConfig.Generation
	status.ClusterStatuses = []multiclusterv1alpha1.ClusterStatus{}
	r.commonAreaLock.RLock()
	if r.remoteCommonArea != nil {
		status.ClusterStatuses = append(status.ClusterStatuses,
			multiclusterv1alpha1.ClusterStatus{
				ClusterID:  string(r.remoteCommonArea.GetClusterID()),
				Conditions: r.remoteCommonArea.GetStatus(),
			},
		)
	}
	r.commonAreaLock.RUnlock()

	overallCondition := multiclusterv1alpha1.ClusterSetCondition{
		Type:               multiclusterv1alpha1.ClusterSetReady,
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
			case multiclusterv1alpha1.ClusterReady:
				{
					if condition.Status == v1.ConditionTrue {
						connected = true
						readyClusters += 1
					}
				}
			case multiclusterv1alpha1.ClusterIsLeader:
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
	status.ReadyClusters = int32(readyClusters)

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
