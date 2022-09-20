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
		// It also prevents concurrent updates to labelExportUpdatesInProgress.
		labelMutex sync.Mutex
		// labelToPodsCache stores mapping from label identities to Pods that have this label identity.
		labelToPodsCache map[string]sets.String
		// labelExportUpdatesInProgress keeps track of label identities whose corresponding ResourceExports are
		// currently being created/deleted in the CommonArea. It is protected by labelMutex.
		labelExportUpdatesInProgress sets.String
		// podLabelCache stores mapping from Pods to their label identities.
		podLabelCache  map[string]string
		localClusterID string
	}
)

func NewLabelIdentityReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	commonAreaGetter RemoteCommonAreaGetter) *LabelIdentityReconciler {
	return &LabelIdentityReconciler{
		Client:                       client,
		Scheme:                       scheme,
		commonAreaGetter:             commonAreaGetter,
		labelToPodsCache:             map[string]sets.String{},
		labelExportUpdatesInProgress: sets.NewString(),
		podLabelCache:                map[string]string{},
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
			defer r.labelMutex.Unlock()
			return r.removeLabelForPod(ctx, req.NamespacedName.String())
		}
		return ctrl.Result{}, err
	}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
		klog.ErrorS(err, "Cannot get corresponding Namespace of the Pod", "pod", req.NamespacedName)
		return ctrl.Result{}, err
	}
	normalizedLabel := getNormalizedLabel(ns.Labels, pod.Labels, ns.Name)
	return r.onPodCreateOrUpdate(ctx, req.NamespacedName.String(), normalizedLabel)
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

// This function needs to be called with labelMutex acquired.
func (r *LabelIdentityReconciler) setLabelExportUpdatesInProgress(label string) {
	r.labelExportUpdatesInProgress.Insert(label)
	// Unlock the labelMutex to allow cache updates for other labels. Any worker operating on
	// the label will be blocked as it is added into labelExportUpdateInProgress.
	r.labelMutex.Unlock()
}

func (r *LabelIdentityReconciler) unsetLabelExportUpdatesInProgress(label string) {
	r.labelMutex.Lock()
	r.labelExportUpdatesInProgress.Delete(label)
}

// removeLabelForPod removes the Pod and label identity mapping from the cache, and deletes label
// identity ResourceExport if necessary (the Pod update/deletion event causes a label identity no
// longer present in the cluster).
// Note that this function will acquire the reconciler's labelMutex, and will keep it locked after
// it returns. This is useful for eliminating additional context switching when handling Pod
// update events, since after deleting stale label the labelMutex will immediately need to be held
// again for checking label add.
func (r *LabelIdentityReconciler) removeLabelForPod(ctx context.Context, podNamespacedName string) (ctrl.Result, error) {
	r.labelMutex.Lock()
	if originalLabel, isCached := r.podLabelCache[podNamespacedName]; isCached {
		if r.labelExportUpdatesInProgress.Has(originalLabel) {
			return ctrl.Result{Requeue: true}, nil
		}
		// Check if the original label is stale.
		if podNames, ok := r.labelToPodsCache[originalLabel]; ok && len(podNames) == 1 && podNames.Has(podNamespacedName) {
			klog.V(2).InfoS("Label no longer exists in the cluster, deleting corresponding ResourceExport", "label", originalLabel)
			r.setLabelExportUpdatesInProgress(originalLabel)
			err := r.deleteLabelIdentityResExport(ctx, originalLabel)
			r.unsetLabelExportUpdatesInProgress(originalLabel)
			if err != nil {
				return ctrl.Result{}, err
			}
			r.deleteFromLabelCache(podNamespacedName, originalLabel)
		} else {
			// The original label still has other Pod that refers to it. Update the cache with
			// labelMutex acquired.
			podNames.Delete(podNamespacedName)
			delete(r.podLabelCache, podNamespacedName)
		}
	}
	return ctrl.Result{}, nil
}

// onPodCreateOrUpdate updates the Pod and label identity mapping in the cache, and
// updates label identity ResourceExport if necessary (the Pod creation/update
// event causes a new label identity to appear in the cluster or a label identity
// no longer present in the cluster or both).
func (r *LabelIdentityReconciler) onPodCreateOrUpdate(ctx context.Context, podNamespacedName, currentLabel string) (ctrl.Result, error) {
	// Based on the reconciler's predicate, the Pod has updated labels.
	// Remove any original Pod-label mapping.
	if result, err := r.removeLabelForPod(ctx, podNamespacedName); err != nil || result.Requeue {
		r.labelMutex.Unlock()
		return result, err
	}
	if r.labelExportUpdatesInProgress.Has(currentLabel) {
		r.labelMutex.Unlock()
		return ctrl.Result{Requeue: true}, nil
	}
	defer r.labelMutex.Unlock()
	// Check if ResourceExport creation is needed for the updated label.
	// If the previous part of the function did not return, the labelMutex is still
	// locked at this point.
	podNames, ok := r.labelToPodsCache[currentLabel]
	if ok {
		// This is a seen label and there's no other worker trying to delete the ResourceExport
		// of the label concurrently. Update the cache immediately.
		podNames.Insert(podNamespacedName)
		r.podLabelCache[podNamespacedName] = currentLabel
	} else {
		// Create a ResourceExport for this label as this is a new label.
		klog.V(2).InfoS("Creating ResourceExport for label", "label", currentLabel)
		r.setLabelExportUpdatesInProgress(currentLabel)
		err := r.createLabelIdentityResExport(ctx, currentLabel)
		r.unsetLabelExportUpdatesInProgress(currentLabel)
		if err != nil {
			return ctrl.Result{}, err
		}
		r.updateLabelCache(podNamespacedName, currentLabel)
	}
	return ctrl.Result{}, nil
}

// updateLabelCache updates podLabelCache and labelToPodsCache once the ResourceExport
// create operation is successful.
func (r *LabelIdentityReconciler) updateLabelCache(podNamespacedName, updatedLabel string) {
	r.labelExportUpdatesInProgress.Delete(updatedLabel)
	r.podLabelCache[podNamespacedName] = updatedLabel
	r.labelToPodsCache[updatedLabel] = sets.NewString(podNamespacedName)
}

// deleteFromLabelCache deletes a label from the podLabelCache and labelToPodsCache once
// the ResourceExport delete operation is successful.
func (r *LabelIdentityReconciler) deleteFromLabelCache(podNamespacedName, deletedLabel string) {
	r.labelExportUpdatesInProgress.Delete(deletedLabel)
	delete(r.podLabelCache, podNamespacedName)
	delete(r.labelToPodsCache, deletedLabel)
}

// createLabelIdentityResExport creates a ResourceExport for a newly added label. The function should be
// invoked with the labelMutex locked, and will return with labelMutex remain locked.
func (r *LabelIdentityReconciler) createLabelIdentityResExport(ctx context.Context, labelToAdd string) error {
	resExportName := getResourceExportNameForLabelIdentity(r.localClusterID, labelToAdd)
	labelResExport := r.getLabelIdentityResourceExport(r.remoteCommonArea.GetNamespace(), resExportName, labelToAdd)
	klog.V(4).InfoS("Creating ResourceExport for label", "resourceExport", labelResExport.Name, "label", labelToAdd)
	err := r.remoteCommonArea.Create(ctx, labelResExport, &client.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// deleteLabelIdentityResExport deletes a ResourceExport for a stale label. The function should be
// invoked with the labelMutex locked, and will return with labelMutex remain locked.
func (r *LabelIdentityReconciler) deleteLabelIdentityResExport(ctx context.Context, labelToDelete string) error {
	labelResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getResourceExportNameForLabelIdentity(r.localClusterID, labelToDelete),
			Namespace: r.remoteCommonArea.GetNamespace(),
		},
	}
	klog.V(4).InfoS("Deleting ResourceExport for label", "resourceExport", labelResExport.Name, "label", labelToDelete)
	err := r.remoteCommonArea.Delete(ctx, labelResExport, &client.DeleteOptions{})
	return client.IgnoreNotFound(err)
}

func (r *LabelIdentityReconciler) getLabelIdentityResourceExport(resExportNamespace, name, normalizedLabel string) *mcsv1alpha1.ResourceExport {
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
func getResourceExportNameForLabelIdentity(clusterID, normalizedLabel string) string {
	return clusterID + "-" + common.HashLabelIdentity(normalizedLabel)
}
