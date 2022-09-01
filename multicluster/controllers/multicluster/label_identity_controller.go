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
		// labelMutex prevents concurrent access to labelToPodsCache and podLabelCache
		labelMutex sync.RWMutex
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
	return ctrl.Result{}, r.onPodCreateOrUpdate(ctx, req.NamespacedName.String(), getNormalizedLabel(nsLabels, podLabels))
}

// SetupWithManager sets up the controller with the Manager.
func (r *LabelIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Ignore status update event via GenerationChangedPredicate
	instance := predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{})
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Pod{}).
		WithEventFilter(instance).
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
// causes a label identity to no longer being present in the cluster).
func (r *LabelIdentityReconciler) onPodDelete(ctx context.Context, podKey string) error {
	_, labelToDelete := r.getLabelToUpdate(podKey, "")
	if labelToDelete != "" {
		if err := r.deleteLabelIdentityResourceExport(ctx, labelToDelete); err != nil {
			return err
		}
		r.updateLabelCache(podKey, "", labelToDelete)
	}
	return nil
}

// onPodCreateOrUpdate updates the Pod and label identity mapping in the cache, and
// updates label identity ResourceExport if necessary (the Pod creation/update
// event causes a new label identity to appear in the cluster or a label identity
// to no longer being present in the cluster).
func (r *LabelIdentityReconciler) onPodCreateOrUpdate(ctx context.Context, podKey, normalizedLabel string) error {
	labelToAdd, labelToDelete := r.getLabelToUpdate(podKey, normalizedLabel)
	if labelToDelete != "" {
		if err := r.deleteLabelIdentityResourceExport(ctx, labelToDelete); err != nil {
			return err
		}
		r.updateLabelCache(podKey, "", labelToDelete)
	}
	if labelToAdd != "" {
		if err := r.addLabelIdentityResourceExport(ctx, labelToAdd); err != nil {
			return err
		}
		r.updateLabelCache(podKey, labelToAdd, "")
	}
	return nil
}

// getLabelToUpdate gets all label identities to be added and to be deleted due to Pod
// update event. It is protected with labelMutex so that concurrent Pod update events
// will not interfere with the label update calculations.
func (r *LabelIdentityReconciler) getLabelToUpdate(podKey, normalizedLabel string) (labelToAdd string, labelToDelete string) {
	r.labelMutex.RLock()
	defer r.labelMutex.RUnlock()

	originalLabel, isCached := r.podLabelCache[podKey]
	if isCached && originalLabel != normalizedLabel {
		labelToDelete = originalLabel
	}
	if normalizedLabel != "" {
		labelToAdd = normalizedLabel
	}
	return
}

// updateLabelCache updates podLabelCache and labelToPodsCache once the ResourceExport
// create/update/delete operation is successful.
func (r *LabelIdentityReconciler) updateLabelCache(podKey, updatedLabel, deletedLabel string) {
	r.labelMutex.Lock()
	defer r.labelMutex.Unlock()

	if updatedLabel != "" {
		r.podLabelCache[podKey] = updatedLabel
		if _, ok := r.labelToPodsCache[updatedLabel]; !ok {
			r.labelToPodsCache[updatedLabel] = sets.NewString(podKey)
		}
		r.labelToPodsCache[updatedLabel].Insert(podKey)
	}
	if deletedLabel != "" {
		delete(r.podLabelCache, podKey)
		if podNames, ok := r.labelToPodsCache[deletedLabel]; ok {
			podNames.Delete(podKey)
			if len(podNames) == 0 {
				klog.V(2).InfoS("Label no longer exists in the cluster", "label", deletedLabel)
				delete(r.labelToPodsCache, deletedLabel)
			}
		}
	}
}

func (r *LabelIdentityReconciler) addLabelIdentityResourceExport(ctx context.Context, normalizedLabel string) error {
	existingResExport := &mcsv1alpha1.ResourceExport{}
	resNamespaced := types.NamespacedName{
		Name:      getResourceExportNameForLabelIdentity(r.localClusterID, normalizedLabel),
		Namespace: r.remoteCommonArea.GetNamespace(),
	}
	err := r.remoteCommonArea.Get(ctx, resNamespaced, existingResExport)
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to get ResourceExport in remote cluster", "resourceexport", resNamespaced)
		return err
	}
	if apierrors.IsNotFound(err) {
		labelResExport := r.getLabelIdentityResourceExport(r.remoteCommonArea.GetNamespace(), resNamespaced.Name, normalizedLabel)
		if err = r.remoteCommonArea.Create(ctx, labelResExport, &client.CreateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func (r *LabelIdentityReconciler) deleteLabelIdentityResourceExport(ctx context.Context, normalizedLabel string) error {
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

func getNormalizedLabel(nsLabels, podLabels map[string]string) string {
	return "ns:" + labels.FormatLabels(nsLabels) + "&pod:" + labels.FormatLabels(podLabels)
}

// getResourceExportNameForLabelIdentity retrieves the ResourceExport name for exporting
// label identities in that cluster.
func getResourceExportNameForLabelIdentity(clusterID string, normalizedLabel string) string {
	return clusterID + "-" + common.HashLabelIdentity(normalizedLabel)
}
