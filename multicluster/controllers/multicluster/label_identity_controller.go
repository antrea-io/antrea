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
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
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
		labelMutex sync.RWMutex
		// labelToPodsCache stores mapping from label identities to Pods that have this label identity.
		labelToPodsCache map[string]sets.String
		// podLabelCache stores mapping from Pods to their label identities.
		podLabelCache map[string]string
		// labelQueue maintains the normalized labels whose corresponding ResourceExport objects are
		// determined to be created/deleted by the reconciler.
		labelQueue     workqueue.RateLimitingInterface
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
		labelQueue:       workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
	}
}

// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
func (r *LabelIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling Pod for label identity", "pod", req.NamespacedName)
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
			r.onPodDelete(req.NamespacedName.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
		klog.ErrorS(err, "Cannot get corresponding Namespace of the Pod", "pod", req.NamespacedName)
		return ctrl.Result{}, err
	}
	normalizedLabel := getNormalizedLabel(ns.Labels, pod.Labels, ns.Name)
	r.onPodCreateOrUpdate(req.NamespacedName.String(), normalizedLabel)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LabelIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Pod{}).
		WithEventFilter(predicate.LabelChangedPredicate{}).
		Watches(&source.Kind{Type: &v1.Namespace{}},
			handler.EnqueueRequestsFromMapFunc(r.namespaceMapFunc),
			builder.WithPredicates(predicate.LabelChangedPredicate{})).
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

// onPodDelete removes the Pod and label identity mapping from the cache, and queues the
// label identity for ResourceExport deletion if necessary (the Pod update/deletion event causes
// a label identity no longer present in the cluster).
func (r *LabelIdentityReconciler) onPodDelete(podNamespacedName string) {
	r.labelMutex.Lock()
	defer r.labelMutex.Unlock()

	if originalLabel, isCached := r.podLabelCache[podNamespacedName]; isCached {
		r.removeLabelForPod(podNamespacedName, originalLabel)
	}
}

// removeLabelForPod removes the Pod and label identity mapping from the cache.
// It must be invoked with labelMutex held.
func (r *LabelIdentityReconciler) removeLabelForPod(podNamespacedName, originalLabel string) {
	delete(r.podLabelCache, podNamespacedName)
	// Check if the original label is stale.
	if podNames, ok := r.labelToPodsCache[originalLabel]; ok && len(podNames) == 1 && podNames.Has(podNamespacedName) {
		klog.V(2).InfoS("Label no longer exists in the cluster, queuing for ResourceExport deletion", "label", originalLabel)
		delete(r.labelToPodsCache, originalLabel)
		r.labelQueue.Add(originalLabel)
	} else {
		// The original label still has other Pod that refers to it. Simply update the cache.
		podNames.Delete(podNamespacedName)
	}
}

// onPodCreateOrUpdate updates the Pod and label identity mapping in the cache, and
// updates label identity ResourceExport if necessary (the Pod creation/update
// event causes a new label identity to appear in the cluster or a label identity
// no longer present in the cluster or both).
func (r *LabelIdentityReconciler) onPodCreateOrUpdate(podNamespacedName, currentLabel string) {
	r.labelMutex.Lock()
	defer r.labelMutex.Unlock()

	if originalLabel, isCached := r.podLabelCache[podNamespacedName]; isCached && originalLabel != currentLabel {
		r.removeLabelForPod(podNamespacedName, originalLabel)
	}
	r.podLabelCache[podNamespacedName] = currentLabel
	podNames, ok := r.labelToPodsCache[currentLabel]
	if !ok {
		// Create a ResourceExport for this label as this is a new label.
		klog.V(2).InfoS("New label in cluster, queuing for ResourceExport creation", "label", currentLabel)
		r.labelToPodsCache[currentLabel] = sets.NewString(podNamespacedName)
		r.labelQueue.Add(currentLabel)
	} else {
		// This is a seen label. Simply update the cache.
		podNames.Insert(podNamespacedName)
	}
}

// Run begins syncing of ResourceExports for label identities.
func (r *LabelIdentityReconciler) Run(stopCh <-chan struct{}) {
	defer r.labelQueue.ShutDown()

	for i := 0; i < common.DefaultWorkerCount; i++ {
		go wait.Until(r.labelQueueWorker, time.Second, stopCh)
	}
	<-stopCh
}

func (r *LabelIdentityReconciler) labelQueueWorker() {
	for r.processLabelForResourceExport() {
	}
}

// Processes an item in the labelQueue. If syncLabelResourceExport returns an error,
// this function handles it by re-queuing the item so that it can be processed again
// later. If syncLabelResourceExport is successful, the label is removed from the queue
// until we get notified of a new change. This function return false if and only if the
// work queue was shutdown (no more items will be processed).
func (r *LabelIdentityReconciler) processLabelForResourceExport() bool {
	key, quit := r.labelQueue.Get()
	if quit {
		return false
	}
	defer r.labelQueue.Done(key)
	err := r.syncLabelResourceExport(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		r.labelQueue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync ResourceExport for label identity", "label", key)
		return true
	}

	// If no error occurs, we forget this item so that it does not get queued again until
	// another change happens.
	r.labelQueue.Forget(key)
	return true
}

// syncLabelResourceExport checks labelToPodsCache and determines whether a ResourceExport
// needs to be created or deleted for the label identity.
func (r *LabelIdentityReconciler) syncLabelResourceExport(label string) error {
	r.labelMutex.RLock()
	_, exists := r.labelToPodsCache[label]
	r.labelMutex.RUnlock()
	if exists {
		// The queue received an event for this label, and there are Pods referring
		// to this label. Either 1) a new label is encountered, and we need to create
		// a ResourceExport for it, or 2) a Pod update/delete event triggered a label
		// deletion, but is immediately followed by another Pod event triggering
		// add for the same label, which is a quite improbable event. We can simply
		// ignore AlreadyExists error in ResourceExport creation for the second case.
		if err := r.createLabelIdentityResExport(ctx, label); err != nil {
			return err
		}
	} else {
		if err := r.deleteLabelIdentityResExport(ctx, label); err != nil {
			return err
		}
	}
	return nil
}

// createLabelIdentityResExport creates a ResourceExport for a newly added label.
func (r *LabelIdentityReconciler) createLabelIdentityResExport(ctx context.Context, labelToAdd string) error {
	resExportName := getResourceExportNameForLabelIdentity(r.localClusterID, labelToAdd)
	labelResExport := r.getLabelIdentityResourceExport(resExportName, labelToAdd)
	klog.V(4).InfoS("Creating ResourceExport for label", "resourceExport", labelResExport.Name, "label", labelToAdd)
	err := r.remoteCommonArea.Create(ctx, labelResExport, &client.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// deleteLabelIdentityResExport deletes a ResourceExport for a stale label.
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

func (r *LabelIdentityReconciler) getLabelIdentityResourceExport(name, normalizedLabel string) *mcsv1alpha1.ResourceExport {
	return &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: r.remoteCommonArea.GetNamespace(),
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
