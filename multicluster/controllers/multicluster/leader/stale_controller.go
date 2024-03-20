/*
Copyright 2023 Antrea Authors.

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
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

const (
	indexKey                       = "spec.clusterID"
	memberClusterAnnounceStaleTime = 24 * time.Hour
)

var getResourceExportsByClusterIDFunc = getResourceExportsByClusterID

// StaleResCleanupController will run periodically (memberClusterAnnounceStaleTime / 2 = 12 Hours)
// to clean up stale MemberClusterAnnounce resources in the leader cluster if the MemberClusterAnnounce
// timestamp annotation has not been updated for memberClusterAnnounceStaleTime (24 Hours).
// It will remove all ResourceExports belong to a member cluster when the corresponding MemberClusterAnnounce
// CR is deleted. It will also try to clean up all stale ResourceExports during start.
type StaleResCleanupController struct {
	client.Client
	Scheme *runtime.Scheme
}

func NewStaleResCleanupController(
	Client client.Client,
	Scheme *runtime.Scheme,
) *StaleResCleanupController {
	reconciler := &StaleResCleanupController{
		Client: Client,
		Scheme: Scheme,
	}
	return reconciler
}

// cleanUpExpiredMemberClusterAnnounces will delete any MemberClusterAnnounce if its
// last update timestamp is over 24 hours.
func (c *StaleResCleanupController) cleanUpExpiredMemberClusterAnnounces(ctx context.Context) {
	memberClusterAnnounceList := &mcv1alpha1.MemberClusterAnnounceList{}
	if err := c.List(ctx, memberClusterAnnounceList, &client.ListOptions{}); err != nil {
		klog.ErrorS(err, "Fail to get MemberClusterAnnounces")
		return
	}

	for _, m := range memberClusterAnnounceList.Items {
		memberClusterAnnounce := m
		lastUpdateTime, err := time.Parse(time.RFC3339, memberClusterAnnounce.Annotations[commonarea.TimestampAnnotationKey])
		if err == nil && time.Since(lastUpdateTime) < memberClusterAnnounceStaleTime {
			continue
		}
		if err == nil {
			klog.InfoS("Cleaning up stale MemberClusterAnnounce. It has not been updated within the agreed period",
				"MemberClusterAnnounce", klog.KObj(&memberClusterAnnounce), "agreedPeriod", memberClusterAnnounceStaleTime)
		} else {
			klog.InfoS("Cleaning up stale MemberClusterAnnounce. The latest update time is not in RFC3339 format",
				"MemberClusterAnnounce", klog.KObj(&memberClusterAnnounce))
		}

		if err := c.Client.Delete(ctx, &memberClusterAnnounce, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to delete stale MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(&memberClusterAnnounce))
			return
		}
	}
}

func (c *StaleResCleanupController) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting StaleResCleanupController")
	defer klog.InfoS("Shutting down StaleResCleanupController")

	ctx := wait.ContextForChannel(stopCh)
	go wait.UntilWithContext(ctx, c.cleanUpExpiredMemberClusterAnnounces, memberClusterAnnounceStaleTime/2)
	<-stopCh
}

func (c *StaleResCleanupController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	memberAnnounce := &mcv1alpha1.MemberClusterAnnounce{}
	err := c.Get(ctx, req.NamespacedName, memberAnnounce)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err == nil && memberAnnounce.DeletionTimestamp.IsZero() {
		// Ignore the event if it's not with non-zero DeletionTimestamp
		return ctrl.Result{}, nil
	}

	// Clean up all corresponding ResourceExports when the member cluster's
	// MemberClusterAnnounce is deleted.
	clusterID := getClusterIDFromName(req.Name)
	staleResExports, err := getResourceExportsByClusterIDFunc(c, ctx, clusterID)
	if err != nil {
		klog.ErrorS(err, "Failed to get ResourceExports by ClusterID", "clusterID", clusterID)
		return ctrl.Result{}, err
	}
	if !deleteResourceExports(ctx, c.Client, staleResExports) {
		return ctrl.Result{}, fmt.Errorf("failed to clean up all stale ResourceExports for the member cluster %s, retry later", clusterID)
	}

	// When cleanup is done, remove the Finalizer of this MemberClusterAnnounce.
	finalizer := fmt.Sprintf("%s/%s", MemberClusterAnnounceFinalizer, memberAnnounce.ClusterID)
	memberAnnounce.Finalizers = common.RemoveStringFromSlice(memberAnnounce.Finalizers, finalizer)
	if err := c.Update(context.TODO(), memberAnnounce); err != nil {
		klog.ErrorS(err, "Failed to update MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(memberAnnounce))
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (c *StaleResCleanupController) SetupWithManager(mgr ctrl.Manager) error {
	// Add an Indexer for ResourceExport, so it can be filtered by the ClusterID.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &mcv1alpha1.ResourceExport{}, indexKey, func(rawObj client.Object) []string {
		resExport := rawObj.(*mcv1alpha1.ResourceExport)
		return []string{resExport.Spec.ClusterID}
	}); err != nil {
		klog.ErrorS(err, "Failed to create the index")
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&mcv1alpha1.MemberClusterAnnounce{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(c)
}

func deleteResourceExports(ctx context.Context, mgrClient client.Client, resouceExports []mcv1alpha1.ResourceExport) bool {
	cleanupSucceed := true
	for _, resourceExport := range resouceExports {
		tmpResExp := resourceExport
		if resourceExport.DeletionTimestamp.IsZero() {
			klog.V(2).InfoS("Clean up the stale ResourceExport from the member cluster",
				"resourceexport", klog.KObj(&tmpResExp), "clusterID", tmpResExp.Spec.ClusterID)
			err := mgrClient.Delete(ctx, &tmpResExp, &client.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				klog.ErrorS(err, "Failed to clean up the stale ResourceExport from the member cluster",
					"resourceexport", klog.KObj(&tmpResExp), "clusterID", tmpResExp.Spec.ClusterID)
				cleanupSucceed = false
			}
		}
	}
	return cleanupSucceed
}

func getClusterIDFromName(name string) string {
	return strings.TrimPrefix(name, "member-announce-from-")
}

func getResourceExportsByClusterID(c *StaleResCleanupController, ctx context.Context, clusterID string) ([]mcv1alpha1.ResourceExport, error) {
	resourceExports := &mcv1alpha1.ResourceExportList{}
	err := c.Client.List(ctx, resourceExports, &client.ListOptions{}, client.MatchingFields{indexKey: clusterID})
	if err != nil {
		klog.ErrorS(err, "Failed to get ResourceExports by ClusterID", "clusterID", clusterID)
		return nil, err
	}
	return resourceExports.Items, nil
}
