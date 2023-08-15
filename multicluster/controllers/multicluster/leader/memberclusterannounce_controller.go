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
package leader

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	ReasonConnected    = "Connected"
	ReasonDisconnected = "Disconnected"

	MemberClusterAnnounceFinalizer = "memberclusterannounce.finalizer.antrea.io"

	TimerInterval     = 10 * time.Second
	ConnectionTimeout = 3 * TimerInterval
)

type memberData struct {
	lastUpdateTime time.Time
	status         *mcv1alpha2.ClusterStatus
}

// MemberClusterAnnounceReconciler reconciles a MemberClusterAnnounce object
type MemberClusterAnnounceReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	mapLock         sync.RWMutex
	memberStatusMap map[common.ClusterID]*memberData
}

type MemberClusterStatusManager interface {
	GetMemberClusterStatuses() []mcv1alpha2.ClusterStatus
}

func NewMemberClusterAnnounceReconciler(client client.Client, scheme *runtime.Scheme) *MemberClusterAnnounceReconciler {
	return &MemberClusterAnnounceReconciler{
		Client:          client,
		Scheme:          scheme,
		memberStatusMap: make(map[common.ClusterID]*memberData),
	}
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=memberclusterannounces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=memberclusterannounces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=memberclusterannounces/finalizers,verbs=update

// Reconcile implements cluster status management on the leader cluster
func (r *MemberClusterAnnounceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	memberAnnounce := &mcv1alpha1.MemberClusterAnnounce{}
	err := r.Get(ctx, req.NamespacedName, memberAnnounce)
	if err != nil {
		// If MemberClusterAnnounce is deleted, no further processing is needed, as cleanup
		// must have been done when the Finalizer was removed.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	memberID := common.ClusterID(memberAnnounce.ClusterID)
	finalizer := fmt.Sprintf("%s/%s", MemberClusterAnnounceFinalizer, memberAnnounce.ClusterID)
	if !memberAnnounce.DeletionTimestamp.IsZero() {
		r.removeMemberStatus(memberID)
		return ctrl.Result{}, nil
	}

	r.addOrUpdateMemberStatus(memberID)
	if common.StringExistsInSlice(memberAnnounce.Finalizers, finalizer) {
		return ctrl.Result{}, nil
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
		For(&mcv1alpha1.MemberClusterAnnounce{}).
		Complete(r)
}

func (r *MemberClusterAnnounceReconciler) processMCSStatus() {
	r.mapLock.Lock()
	defer r.mapLock.Unlock()

	for member, data := range r.memberStatusMap {
		status := r.memberStatusMap[member].status
		// Check if the member has connected at least once in the last 3 intervals.
		duration := time.Since(data.lastUpdateTime)
		klog.V(2).InfoS("Timer processing", "cluster", member, "duration", duration)
		if duration <= ConnectionTimeout {
			// Member has updated MemberClusterStatus at least once in the last 3 intervals.
			// If last status is not connected, then update the status.
			for index := range status.Conditions {
				condition := &status.Conditions[index]
				switch condition.Type {
				case mcv1alpha2.ClusterReady:
					{
						if condition.Status != v1.ConditionTrue {
							condition.Status = v1.ConditionTrue
							condition.LastTransitionTime = metav1.Now()
							condition.Message = "Member Connected"
							condition.Reason = ReasonConnected
						}
					}
				}
			}
		} else {
			// Member has not updated MemberClusterStatus in the last 3 intervals, assume it is disconnected
			for index := range status.Conditions {
				condition := &status.Conditions[index]
				switch condition.Type {
				case mcv1alpha2.ClusterReady:
					{
						if condition.Status != v1.ConditionFalse {
							condition.Status = v1.ConditionFalse
							condition.LastTransitionTime = metav1.Now()
							condition.Message = fmt.Sprintf("No MemberClusterAnnounce update after %s", data.lastUpdateTime.Format(time.UnixDate))
							condition.Reason = ReasonDisconnected
						}
					}
				}
			}
		}
	}
}

func (r *MemberClusterAnnounceReconciler) addOrUpdateMemberStatus(memberID common.ClusterID) {
	r.mapLock.Lock()
	defer r.mapLock.Unlock()
	if data, ok := r.memberStatusMap[memberID]; ok {
		klog.V(2).InfoS("Reset lastUpdateTime", "cluster", memberID)
		// Reset lastUpdateTime for this member.
		data.lastUpdateTime = time.Now()
		for i, c := range data.status.Conditions {
			if c.Type == mcv1alpha2.ClusterConnected && data.status.Conditions[i].Reason != ReasonConnected {
				data.status.Conditions[i].LastTransitionTime = metav1.Now()
				data.status.Conditions[i].Message = "Member Connected"
				data.status.Conditions[i].Reason = ReasonConnected
			}
		}
		return
	}

	conditions := make([]mcv1alpha2.ClusterCondition, 0, 1)
	conditions = append(conditions, mcv1alpha2.ClusterCondition{
		Type:               mcv1alpha2.ClusterReady,
		Status:             v1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Message:            "Member Connected",
		Reason:             ReasonConnected,
	})

	status := &mcv1alpha2.ClusterStatus{
		ClusterID:  string(memberID),
		Conditions: conditions,
	}
	r.memberStatusMap[memberID] = &memberData{status: status, lastUpdateTime: time.Now()}

	klog.InfoS("Added member cluster", "cluster", memberID)
}

func (r *MemberClusterAnnounceReconciler) removeMemberStatus(memberID common.ClusterID) {
	r.mapLock.Lock()
	defer r.mapLock.Unlock()

	delete(r.memberStatusMap, memberID)
	klog.InfoS("Removed member cluster", "cluster", memberID)
}

/******************************* MemberClusterStatusManager methods *******************************/

func (r *MemberClusterAnnounceReconciler) GetMemberClusterStatuses() []mcv1alpha2.ClusterStatus {
	r.mapLock.RLock()
	defer r.mapLock.RUnlock()

	status := make([]mcv1alpha2.ClusterStatus, len(r.memberStatusMap))

	index := 0
	for _, v := range r.memberStatusMap {
		status[index] = *v.status.DeepCopy()
		index += 1
	}

	return status
}
