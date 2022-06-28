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

// memberclusterannounce_controller is for leader cluster only.
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

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclusterv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	ReasonNeverConnected  = "NeverConnected"
	ReasonConnected       = "Connected"
	ReasonDisconnected    = "Disconnected"
	ReasonConnectedLeader = "ConnectedLeader"
	ReasonNotLeader       = "NotLeader"

	MemberClusterAnnounceFinalizer = "memberclusterannounce.finalizer.antrea.io"

	TimerInterval     = 5 * time.Second
	ConnectionTimeout = 3 * TimerInterval
)

type leaderStatus struct {
	// connectedLeader indicates this member has connected to the local cluster which is the leader.
	connectedLeader v1.ConditionStatus
	message         string
	reason          string
}

type timerData struct {
	connected      bool
	lastUpdateTime time.Time
	leaderStatus   leaderStatus
}

// MemberClusterAnnounceReconciler reconciles a MemberClusterAnnounce object
type MemberClusterAnnounceReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	mapLock      sync.RWMutex
	memberStatus map[common.ClusterID]*multiclusterv1alpha1.ClusterStatus
	timerData    map[common.ClusterID]*timerData
}

type MemberClusterStatusManager interface {
	AddMember(memberID common.ClusterID)
	RemoveMember(memberID common.ClusterID)

	GetMemberClusterStatuses() []multiclusterv1alpha1.ClusterStatus
}

func NewMemberClusterAnnounceReconciler(client client.Client, scheme *runtime.Scheme) *MemberClusterAnnounceReconciler {
	return &MemberClusterAnnounceReconciler{
		Client:       client,
		Scheme:       scheme,
		memberStatus: make(map[common.ClusterID]*multiclusterv1alpha1.ClusterStatus),
		timerData:    make(map[common.ClusterID]*timerData),
	}
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=memberclusterannounces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=memberclusterannounces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=memberclusterannounces/finalizers,verbs=update
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterclaims,verbs=get;list;watch;

// Reconcile implements cluster status management on the leader cluster
func (r *MemberClusterAnnounceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	memberAnnounce := &multiclusterv1alpha1.MemberClusterAnnounce{}
	err := r.Get(ctx, req.NamespacedName, memberAnnounce)
	if err != nil {
		if !errors.IsNotFound(err) {
			// Cannot read the requested resource. Return error, so reconciliation will be retried.
			return ctrl.Result{}, err
		}
		// If MemberClusterAnnounce is deleted, no need to process because RemoveMember must already
		// be called.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	r.mapLock.Lock()
	// If the member is not found in timerData, it means the member is not added to the ClusterSet or was deleted.
	if data, ok := r.timerData[common.ClusterID(memberAnnounce.ClusterID)]; ok {
		klog.V(2).InfoS("Reset lastUpdateTime", "cluster", memberAnnounce.ClusterID)
		// Reset lastUpdateTime and connectedLeader for this member.
		data.lastUpdateTime = time.Now()
		if len(memberAnnounce.LeaderClusterID) == 0 {
			data.leaderStatus.connectedLeader = v1.ConditionUnknown
			data.leaderStatus.message = "Not connected to leader yet"
			data.leaderStatus.reason = ""
		} else {
			data.leaderStatus.connectedLeader = v1.ConditionFalse
			data.leaderStatus.message = fmt.Sprintf("Local cluster is not the leader of member: %v",
				memberAnnounce.ClusterID)
			data.leaderStatus.reason = ReasonNotLeader
			// Check whether this local cluster is the leader for this member.
			clusterClaim := &multiclusterv1alpha2.ClusterClaim{}
			if err := r.Get(context.TODO(), types.NamespacedName{Name: multiclusterv1alpha2.WellKnownClusterClaimID, Namespace: req.Namespace}, clusterClaim); err == nil {
				if clusterClaim.Value == memberAnnounce.LeaderClusterID {
					data.leaderStatus.connectedLeader = v1.ConditionTrue
					data.leaderStatus.message = fmt.Sprintf("Local cluster is the leader of member: %v",
						memberAnnounce.ClusterID)
					data.leaderStatus.reason = ReasonConnectedLeader
				}
			}
			// If err != nil, probably ClusterClaims were deleted during the processing of MemberClusterAnnounce.
			// Nothing to handle in this case and MemberClusterAnnounce will also be deleted soon.
			// TODO: Add ClusterClaim webhook to make sure it cannot be deleted while ClusterSet is present.
		}
	}
	r.mapLock.Unlock()

	finalizer := fmt.Sprintf("%s/%s", MemberClusterAnnounceFinalizer, memberAnnounce.ClusterID)
	if !memberAnnounce.DeletionTimestamp.IsZero() {
		if err := r.removeMemberFromClusterSet(memberAnnounce); err != nil {
			klog.ErrorS(err, "Failed to remove member cluster from the ClusterSet", "cluster", memberAnnounce.ClusterID)
			return ctrl.Result{}, err
		}
		memberAnnounce.Finalizers = common.RemoveStringFromSlice(memberAnnounce.Finalizers, finalizer)
		if err := r.Update(context.TODO(), memberAnnounce); err != nil {
			klog.ErrorS(err, "Failed to update MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(memberAnnounce))
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	if common.StringExistsInSlice(memberAnnounce.Finalizers, finalizer) {
		return ctrl.Result{}, nil
	}
	klog.InfoS("Adding member cluster to ClusterSet", "cluster", memberAnnounce.ClusterID)
	if err := r.addMemberToClusterSet(memberAnnounce); err != nil {
		klog.ErrorS(err, "Failed to add member cluster to ClusterSet", "cluster", memberAnnounce.ClusterID)
		return ctrl.Result{}, err
	}
	klog.InfoS("Adding finalizer to MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(memberAnnounce))
	memberAnnounce.Finalizers = append(memberAnnounce.Finalizers, finalizer)
	if err := r.Update(context.TODO(), memberAnnounce); err != nil {
		klog.ErrorS(err, "Failed to update MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(memberAnnounce))
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MemberClusterAnnounceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	go func() {
		// Running background task here.
		for {
			<-time.After(TimerInterval)
			r.processMCSStatus()
		}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.MemberClusterAnnounce{}).
		Complete(r)
}

func (r *MemberClusterAnnounceReconciler) processMCSStatus() {
	r.mapLock.Lock()
	defer r.mapLock.Unlock()

	for member, data := range r.timerData {
		if data.lastUpdateTime.IsZero() {
			// Member has never connected to the local cluster, no status update
			continue
		}
		status := r.memberStatus[member]
		// Check if the member has connected at least once in the last 3 intervals.
		duration := time.Since(data.lastUpdateTime)
		klog.V(2).InfoS("Timer processing", "cluster", member, "duration", duration)
		if duration <= ConnectionTimeout {
			// Member has updated MemberClusterStatus at least once in the last 3 intervals.
			// If last status is not connected, then update the status.
			for index := range status.Conditions {
				condition := &status.Conditions[index]
				switch condition.Type {
				case multiclusterv1alpha1.ClusterReady:
					{
						if condition.Status != v1.ConditionTrue {
							condition.Status = v1.ConditionTrue
							condition.LastTransitionTime = metav1.Now()
							condition.Message = ""
							condition.Reason = ReasonConnected
						}
					}
				case multiclusterv1alpha1.ClusterConnected:
					{
						if data.leaderStatus.connectedLeader != condition.Status {
							condition.Status = data.leaderStatus.connectedLeader
							condition.Message = data.leaderStatus.message
							condition.LastTransitionTime = metav1.Now()
							condition.Reason = data.leaderStatus.reason
						}
					}
				}
			}
		} else {
			// Member has not updated MemberClusterStatus in the last 3 intervals, assume it is disconnected
			for index := range status.Conditions {
				condition := &status.Conditions[index]
				switch condition.Type {
				case multiclusterv1alpha1.ClusterReady:
					{
						if condition.Status != v1.ConditionFalse {
							condition.Status = v1.ConditionFalse
							condition.LastTransitionTime = metav1.Now()
							condition.Message = fmt.Sprintf("No MemberClusterAnnounce update after %v", data.lastUpdateTime)
							condition.Reason = ReasonDisconnected
						}
					}
				case multiclusterv1alpha1.ClusterConnected:
					{
						if condition.Status != v1.ConditionFalse || condition.Reason != ReasonDisconnected {
							condition.Status = v1.ConditionFalse
							condition.Message = fmt.Sprintf("No MemberClusterAnnounce update after %v", data.lastUpdateTime)
							condition.LastTransitionTime = metav1.Now()
							condition.Reason = ReasonDisconnected
						}
					}
				}
			}
		}
	}
}

/******************************* MemberClusterStatusManager methods *******************************/

func (r *MemberClusterAnnounceReconciler) AddMember(memberID common.ClusterID) {
	r.mapLock.Lock()
	defer r.mapLock.Unlock()
	if _, ok := r.memberStatus[memberID]; ok {
		// already present
		return
	}

	conditions := make([]multiclusterv1alpha1.ClusterCondition, 0, 2)
	conditions = append(conditions, multiclusterv1alpha1.ClusterCondition{
		Type:               multiclusterv1alpha1.ClusterReady,
		Status:             v1.ConditionUnknown,
		LastTransitionTime: metav1.Now(),
		Message:            "Member created",
		Reason:             ReasonNeverConnected,
	})
	conditions = append(conditions, multiclusterv1alpha1.ClusterCondition{
		Type:               multiclusterv1alpha1.ClusterConnected,
		Status:             v1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Message:            "Member created",
		Reason:             ReasonNeverConnected,
	})

	r.memberStatus[memberID] = &multiclusterv1alpha1.ClusterStatus{ClusterID: string(memberID),
		Conditions: conditions}

	r.timerData[memberID] = &timerData{connected: false, lastUpdateTime: time.Time{}}
	klog.InfoS("Added member", "member", memberID)
}

func (r *MemberClusterAnnounceReconciler) RemoveMember(memberID common.ClusterID) {
	r.mapLock.Lock()
	defer r.mapLock.Unlock()

	delete(r.memberStatus, memberID)
	delete(r.timerData, memberID)
	klog.InfoS("Removed member", "member", memberID)
}

func (r *MemberClusterAnnounceReconciler) GetMemberClusterStatuses() []multiclusterv1alpha1.ClusterStatus {
	r.mapLock.RLock()
	defer r.mapLock.RUnlock()

	status := make([]multiclusterv1alpha1.ClusterStatus, len(r.memberStatus))

	index := 0
	for _, v := range r.memberStatus {
		status[index] = *v // This will do a deep copy
		index += 1
	}

	return status
}

func (r *MemberClusterAnnounceReconciler) addMemberToClusterSet(memberClusterAnnounce *multiclusterv1alpha1.MemberClusterAnnounce) error {
	clusterSetID := memberClusterAnnounce.ClusterSetID
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	if err := r.Get(context.TODO(), types.NamespacedName{Namespace: memberClusterAnnounce.Namespace, Name: clusterSetID}, clusterSet); err != nil {
		klog.ErrorS(err, "Failed to get ClusterSet in leader cluster", "ClusterSet", clusterSetID)
		return err
	}

	exist := false
	// ClusterSet ID of MemberClusterAnnounce cannot change. It is guaranteed by the MemberClusterAnnounce webhook.
	for _, member := range clusterSet.Spec.Members {
		if member.ClusterID == memberClusterAnnounce.ClusterID {
			exist = true
			break
		}
	}

	if exist {
		return fmt.Errorf("member cluster %s already exists in ClusterSet %s", memberClusterAnnounce.ClusterID, clusterSetID)
	}

	clusterSet.Spec.Members = append(clusterSet.Spec.Members, multiclusterv1alpha1.MemberCluster{ClusterID: memberClusterAnnounce.ClusterID})
	if err := r.Update(context.TODO(), clusterSet); err != nil {
		klog.ErrorS(err, "Failed to update ClusterSet in leader cluster", "ClusterSet", clusterSetID, "Namespace", clusterSet.Namespace)
		return err
	}
	return nil
}

func (r *MemberClusterAnnounceReconciler) removeMemberFromClusterSet(memberClusterAnnounce *multiclusterv1alpha1.MemberClusterAnnounce) error {
	clusterSetID := memberClusterAnnounce.ClusterSetID
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	if err := r.Get(context.TODO(), types.NamespacedName{Namespace: memberClusterAnnounce.Namespace, Name: clusterSetID}, clusterSet); err != nil {
		klog.ErrorS(err, "Failed to get ClusterSet in leader cluster", "ClusterSet", clusterSetID)
		return err
	}

	found := false
	for i, member := range clusterSet.Spec.Members {
		if member.ClusterID == memberClusterAnnounce.ClusterID {
			found = true
			clusterSet.Spec.Members = append(clusterSet.Spec.Members[:i], clusterSet.Spec.Members[i+1:]...)
			break
		}
	}
	if !found {
		klog.InfoS("Member cluster not found in ClusterSet", "ClusterSet", clusterSetID, "cluster", memberClusterAnnounce.ClusterID)
		return nil
	}

	klog.InfoS("Removing member cluster from the ClusterSet", "cluster", memberClusterAnnounce.ClusterID, "ClusterSet", klog.KObj(clusterSet))
	if err := r.Update(context.TODO(), clusterSet); err != nil {
		klog.ErrorS(err, "Failed to update ClusterSet in leader cluster", "ClusterSet", clusterSetID, "Namespace", clusterSet.Namespace)
		return err
	}
	return nil
}
