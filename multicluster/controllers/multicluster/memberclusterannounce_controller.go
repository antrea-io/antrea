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
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	ReasonNeverConnected   = "NeverConnected"
	ReasonConnected        = "Connected"
	ReasonDisconnected     = "Disconnected"
	ReasonElectedLeader    = "ElectedLeader"
	ReasonNotElectedLeader = "NotElectedLeader"

	TimerInterval     = 5 * time.Second
	ConnectionTimeout = 3 * TimerInterval
)

type leaderStatus struct {
	// electedLocalAsLeaderCluster indicates the member has elected the local cluster
	// as the elected leader from which it watches resources for the MCS resource exchange
	// pipeline.
	electedLocalAsLeaderCluster v1.ConditionStatus
	message                     string
	reason                      string
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

	mapLock      sync.Mutex
	memberStatus map[common.ClusterID]*multiclusterv1alpha1.ClusterStatus
	timerData    map[common.ClusterID]*timerData
}

type MemberClusterStatusManager interface {
	AddMember(MemberId common.ClusterID)
	RemoveMember(MemberId common.ClusterID)

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

	defer r.mapLock.Unlock()
	r.mapLock.Lock()

	if data, ok := r.timerData[common.ClusterID(memberAnnounce.ClusterID)]; ok {
		klog.V(2).InfoS("Reset lastUpdateTime", "Cluster", memberAnnounce.ClusterID)
		// Reset lastUpdateTime and electedLocalAsLeaderCluster for this member.
		data.lastUpdateTime = time.Now()
		if len(memberAnnounce.LeaderClusterID) == 0 {
			data.leaderStatus.electedLocalAsLeaderCluster = v1.ConditionUnknown
			data.leaderStatus.message = "Leader has not been elected yet"
			data.leaderStatus.reason = ""
		} else {
			data.leaderStatus.electedLocalAsLeaderCluster = v1.ConditionFalse
			data.leaderStatus.message = fmt.Sprintf("Local cluster is not the elected leader of member: %v",
				memberAnnounce.ClusterID)
			data.leaderStatus.reason = ReasonNotElectedLeader
			// Check whether this local cluster is the leader for this member.
			clusterClaimList := &multiclusterv1alpha1.ClusterClaimList{}
			if err := r.List(context.TODO(), clusterClaimList, client.InNamespace(req.Namespace)); err == nil {
				for _, clusterClaim := range clusterClaimList.Items {
					if clusterClaim.Name == multiclusterv1alpha1.WellKnownClusterClaimID &&
						clusterClaim.Value == memberAnnounce.LeaderClusterID {
						data.leaderStatus.electedLocalAsLeaderCluster = v1.ConditionTrue
						data.leaderStatus.message = fmt.Sprintf("Local cluster is the elected leader of member: %v",
							memberAnnounce.ClusterID)
						data.leaderStatus.reason = ReasonElectedLeader
						break
					}
				}
			}
		}
		// If err != nil, probably ClusterClaims were deleted during the processing of MemberClusterAnnounce.
		// Nothing to handle in this case and MemberClusterAnnounce will also be deleted soon.
		// TODO: Add ClusterClaim webhook to make sure it cannot be deleted while ClusterSet is present.
	}
	// Member not found. If this happens, the MemberClusterAnnounce should soon be deleted.
	// Nothing to do here.

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
	defer r.mapLock.Unlock()
	r.mapLock.Lock()

	for member, data := range r.timerData {
		if data.lastUpdateTime.IsZero() {
			// Member has never connected to the local cluster, no status update
			continue
		}
		status := r.memberStatus[member]
		// Check if the member has connected atleast once in the last 3 intervals.
		duration := time.Since(data.lastUpdateTime)
		klog.V(2).InfoS("Timer processing", "Cluster", member, "duration", duration)
		if duration <= ConnectionTimeout {
			// Member has updated MemberClusterStatus atleast once in the last 3 intervals.
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
				case multiclusterv1alpha1.ClusterImportsResources:
					{
						if data.leaderStatus.electedLocalAsLeaderCluster != condition.Status {
							condition.Status = data.leaderStatus.electedLocalAsLeaderCluster
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
				case multiclusterv1alpha1.ClusterImportsResources:
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

func (r *MemberClusterAnnounceReconciler) AddMember(MemberId common.ClusterID) {
	defer r.mapLock.Unlock()
	r.mapLock.Lock()
	if _, ok := r.memberStatus[MemberId]; ok {
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
		Type:               multiclusterv1alpha1.ClusterImportsResources,
		Status:             v1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Message:            "Member created",
		Reason:             ReasonNeverConnected,
	})

	r.memberStatus[MemberId] = &multiclusterv1alpha1.ClusterStatus{ClusterID: string(MemberId),
		Conditions: conditions}

	r.timerData[MemberId] = &timerData{connected: false, lastUpdateTime: time.Time{}}
}

func (r *MemberClusterAnnounceReconciler) RemoveMember(MemberId common.ClusterID) {
	defer r.mapLock.Unlock()
	r.mapLock.Lock()

	if _, ok := r.memberStatus[MemberId]; ok {
		delete(r.memberStatus, MemberId)
		return
	}

	if _, ok := r.timerData[MemberId]; ok {
		delete(r.timerData, MemberId)
		return
	}
}

func (r *MemberClusterAnnounceReconciler) GetMemberClusterStatuses() []multiclusterv1alpha1.ClusterStatus {
	defer r.mapLock.Unlock()
	r.mapLock.Lock()

	status := make([]multiclusterv1alpha1.ClusterStatus, len(r.memberStatus))

	index := 0
	for _, v := range r.memberStatus {
		status[index] = *v // This will do a deep copy
		index += 1
	}

	return status
}
