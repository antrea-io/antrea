/*
Copyright 2022 Antrea Authors.

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
	"sync"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

// LabelIdentityReconciler watches relevant Pod and Namespace events in the member cluster,
// computes the label identities added to and deleted from the cluster, and exports them to the
// leader cluster for further processing.
type (
	LabelIdentityReconciler struct {
		client.Client
		Scheme           *runtime.Scheme
		commonAreaGetter RemoteCommonAreaGetter
		remoteCommonArea commonarea.RemoteCommonArea
		// labelMutex prevents concurrent access to labelToPodsCache and podLabelCache.
		// It also prevents concurrent updates to ResourceExports.
		labelMutex sync.Mutex
		// labelToPodsCache stores mapping from label identities to Pods that have this label identity
		labelToPodsCache map[string]sets.String
		// podLabelCache stores mapping from Pods to their label identities
		podLabelCache  map[string]string
		localClusterID string
	}
)

func NewLabelIdentityReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	commonAreaGetter RemoteCommonAreaGetter) *LabelIdentityReconciler {
	return &LabelIdentityReconciler{
		Client:           client,
		Scheme:           scheme,
		commonAreaGetter: commonAreaGetter,
		labelToPodsCache: map[string]sets.String{},
		podLabelCache:    map[string]string{},
	}
}

// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
func (r *LabelIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling Pod/Namespace for label identity", "pod/ns", req.NamespacedName)
	var commonArea commonarea.RemoteCommonArea
	var err error
	commonArea, r.localClusterID, err = r.commonAreaGetter.GetRemoteCommonAreaAndLocalID()
	if commonArea == nil {
		return ctrl.Result{Requeue: true}, err
	}
	r.remoteCommonArea = commonArea
	var pod v1.Pod
	var ns v1.Namespace

	if err := r.Client.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(2).InfoS("Pod is deleted", "pod", req.NamespacedName)
			return ctrl.Result{}, r.onPodDelete(ctx, req.NamespacedName.String())
		}
		return ctrl.Result{}, err
	}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
		klog.ErrorS(err, "Cannot get corresponding Namespace of the Pod", "pod", req.NamespacedName)
		return ctrl.Result{}, err
	}
	nsLabels, podLabels := ns.Labels, pod.Labels
	return ctrl.Result{}, r.onPodCreateOrUpdate(ctx, req.NamespacedName.String(), getNormalizedLabel(nsLabels, podLabels, ns.Name))
}

// SetupWithManager sets up the controller with the Manager.
func (r *LabelIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Pod{}).
		WithEventFilter(predicate.LabelChangedPredicate{}).
		Watches(&source.Kind{Type: &v1.Namespace{}}, handler.EnqueueRequestsFromMapFunc(r.namespaceMapFunc)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

// namespaceMapFunc handles Namespace update events (Namespace label change) by enqueuing
// all Pods in the Namespace into the reconciler processing queue.
func (r *LabelIdentityReconciler) namespaceMapFunc(ns client.Object) []reconcile.Request {
	podList := &v1.PodList{}
	r.Client.List(context.TODO(), podList, client.InNamespace(ns.GetName()))
	requests := make([]reconcile.Request, len(podList.Items))
	for i, pod := range podList.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      pod.GetName(),
				Namespace: pod.GetNamespace(),
			},
		}
	}
	return requests
}

// onPodDelete removes the Pod and label identity mapping from the cache, and
// updates label identity ResourceExport if necessary (the Pod deletion event
// causes a label identity no longer present in the cluster).
func (r *LabelIdentityReconciler) onPodDelete(ctx context.Context, podNamespacedName string) error {
	r.labelMutex.Lock()
	defer r.labelMutex.Unlock()

	labelToDelete := r.getLabelToDelete(podNamespacedName)
	if labelToDelete != "" {
		if err := r.deleteLabelIdentityResExport(ctx, labelToDelete); err != nil {
			return err
		}
		r.deleteFromLabelCache(podNamespacedName, labelToDelete)
	}
	return nil
}

// onPodCreateOrUpdate updates the Pod and label identity mapping in the cache, and
// updates label identity ResourceExport if necessary (the Pod creation/update
// event causes a new label identity to appear in the cluster or a label identity
// no longer present in the cluster).
func (r *LabelIdentityReconciler) onPodCreateOrUpdate(ctx context.Context, podNamespacedName, normalizedLabel string) error {
	r.labelMutex.Lock()
	defer r.labelMutex.Unlock()

	labelToAdd, labelToDelete := r.getLabelToUpdate(podNamespacedName, normalizedLabel)
	if labelToDelete != "" {
		if err := r.deleteLabelIdentityResExport(ctx, labelToDelete); err != nil {
			return err
		}
		r.deleteFromLabelCache(podNamespacedName, labelToDelete)
	}
	if labelToAdd != "" {
		if err := r.createLabelIdentityResExport(ctx, labelToAdd); err != nil {
			return err
		}
		r.updateLabelCache(podNamespacedName, labelToAdd)
	}
	return nil
}

// getLabelToUpdate gets all label identities to be added and to be deleted due to Pod
// update event. It needs to be protected with labelMutex so that concurrent Pod update
// events will not interfere with the label cache update calculations.
func (r *LabelIdentityReconciler) getLabelToUpdate(podNamespacedName, normalizedLabel string) (labelToAdd string, labelToDelete string) {
	originalLabel, isCached := r.podLabelCache[podNamespacedName]
	if !isCached {
		return normalizedLabel, ""
	} else if originalLabel != normalizedLabel {
		// Pod has updated labels. Check if the original label is stale.
		if podNames, ok := r.labelToPodsCache[originalLabel]; ok && len(podNames) == 1 && podNames.Has(podNamespacedName) {
			klog.V(2).InfoS("Label no longer exists in the cluster", "label", originalLabel)
			return normalizedLabel, originalLabel
		}
	}
	return "", ""
}

// getLabelToDelete gets all label identities to be deleted due to Pod delete event.
// It needs to be protected with labelMutex so that concurrent Pod update events
// will not interfere with the label cache update calculations.
func (r *LabelIdentityReconciler) getLabelToDelete(podNamespacedName string) string {
	if originalLabel, isCached := r.podLabelCache[podNamespacedName]; isCached {
		if podNames, ok := r.labelToPodsCache[originalLabel]; ok && len(podNames) == 1 && podNames.Has(podNamespacedName) {
			klog.V(2).InfoS("Label no longer exists in the cluster", "label", originalLabel)
			return originalLabel
		} else if ok {
			// No ResourceExport deletion is needed. Update the caches immediately.
			delete(r.podLabelCache, podNamespacedName)
			podNames.Delete(podNamespacedName)
		}
	}
	return ""
}

// updateLabelCache updates podLabelCache and labelToPodsCache once the ResourceExport
// create/update operation is successful.
func (r *LabelIdentityReconciler) updateLabelCache(podNamespacedName, updatedLabel string) {
	r.podLabelCache[podNamespacedName] = updatedLabel
	if _, ok := r.labelToPodsCache[updatedLabel]; !ok {
		r.labelToPodsCache[updatedLabel] = sets.NewString(podNamespacedName)
	}
	r.labelToPodsCache[updatedLabel].Insert(podNamespacedName)
}

// deleteFromLabelCache deletes a label from the podLabelCache and labelToPodsCache once
// the ResourceExport delete operation is successful.
func (r *LabelIdentityReconciler) deleteFromLabelCache(podNamespacedName, deletedLabel string) {
	delete(r.podLabelCache, podNamespacedName)
	if podNames, ok := r.labelToPodsCache[deletedLabel]; ok {
		podNames.Delete(podNamespacedName)
		delete(r.labelToPodsCache, deletedLabel)
	}
}

func (r *LabelIdentityReconciler) createLabelIdentityResExport(ctx context.Context, normalizedLabel string) error {
	resExportName := getResourceExportNameForLabelIdentity(r.localClusterID, normalizedLabel)
	labelResExport := r.getLabelIdentityResourceExport(r.remoteCommonArea.GetNamespace(), resExportName, normalizedLabel)
	if err := r.remoteCommonArea.Create(ctx, labelResExport, &client.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (r *LabelIdentityReconciler) deleteLabelIdentityResExport(ctx context.Context, normalizedLabel string) error {
	labelResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getResourceExportNameForLabelIdentity(r.localClusterID, normalizedLabel),
			Namespace: r.remoteCommonArea.GetNamespace(),
		},
	}
	if err := r.remoteCommonArea.Delete(ctx, labelResExport, &client.DeleteOptions{}); err != nil {
		return client.IgnoreNotFound(err)
	}
	return nil
}

func (r *LabelIdentityReconciler) getLabelIdentityResourceExport(resExportNamespace, name string, normalizedLabel string) *mcsv1alpha1.ResourceExport {
	return &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: resExportNamespace,
			Labels: map[string]string{
				common.SourceKind:      common.LabelIdentityKind,
				common.SourceClusterID: r.localClusterID,
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: r.localClusterID,
			Kind:      common.LabelIdentityKind,
			LabelIdentity: &mcsv1alpha1.LabelIdentityExport{
				NormalizedLabel: normalizedLabel,
			},
		},
	}
}

func getNormalizedLabel(nsLabels, podLabels map[string]string, ns string) string {
	if _, ok := nsLabels[v1.LabelMetadataName]; !ok {
		// NamespaceDefaultLabelName is supported from K8s v1.21. For K8s versions before v1.21,
		// we append the Namespace name label to the Namespace label set, so that the exported
		// label is guaranteed to have Namespace name information.
		nsLabels[v1.LabelMetadataName] = ns
	}
	return "ns:" + labels.FormatLabels(nsLabels) + "&pod:" + labels.FormatLabels(podLabels)
}

// getResourceExportNameForLabelIdentity retrieves the ResourceExport name for exporting
// label identities in that cluster.
func getResourceExportNameForLabelIdentity(clusterID string, normalizedLabel string) string {
	return clusterID + "-" + common.HashLabelIdentity(normalizedLabel)
}
