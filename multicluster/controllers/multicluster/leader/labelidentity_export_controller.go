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

package leader

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/container/intsets"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

const (
	// 24 bits are available in VNI. The max value 16777215 is reserved for unknown ID.
	maxIDForAllocation = 16777214
)

// LabelIdentityExportReconciler watches LabelIdentity ResourceExport events in the Common Area,
// computes if such an event causes a new LabelIdentity to become present/stale in the entire
// ClusterSet, and updates ResourceImports accordingly.
type (
	LabelIdentityExportReconciler struct {
		client.Client
		Scheme           *runtime.Scheme
		mutex            sync.RWMutex
		namespace        string
		clusterToLabels  map[string]sets.Set[string]
		labelsToClusters map[string]sets.Set[string]
		hashToLabels     map[string]string
		labelQueue       workqueue.RateLimitingInterface
		numWorkers       int
		labelsToID       sync.Map
		allocator        *idAllocator
	}
)

func NewLabelIdentityExportReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	namespace string) *LabelIdentityExportReconciler {
	return &LabelIdentityExportReconciler{
		Client:           client,
		Scheme:           scheme,
		namespace:        namespace,
		clusterToLabels:  map[string]sets.Set[string]{},
		labelsToClusters: map[string]sets.Set[string]{},
		hashToLabels:     map[string]string{},
		labelQueue:       workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
		numWorkers:       common.DefaultWorkerCount,
		labelsToID:       sync.Map{},
		allocator:        newIDAllocator(1, maxIDForAllocation),
	}
}

// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/status,verbs=get;update;patch
func (r *LabelIdentityExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var resExport mcsv1alpha1.ResourceExport
	clusterID, labelHash := parseLabelIdentityExportNamespacedName(req.NamespacedName)
	if err := r.Client.Get(ctx, req.NamespacedName, &resExport); err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(2).InfoS("ResourceExport is deleted", "resourceexport", req.NamespacedName, "cluster", clusterID)
			r.onLabelExportDelete(clusterID, labelHash)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	normalizedLabel := resExport.Spec.LabelIdentity.NormalizedLabel
	r.onLabelExportAdd(clusterID, labelHash, normalizedLabel)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LabelIdentityExportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	// Only register this controller to reconcile LabelIdentity kind of ResourceExport.
	// We expect LabelIdentity ResourceExport events to have higher volume than the other (i.e. Service or
	// ACNP ResourceExport), and do not want sync of these resources to be blocked by potentially huge number
	// of LabelIdentity ResourceExport requests. Hence, LabelIdentity reconciler has dedicated workers.
	labelIdentityResExportFilter := func(object client.Object) bool {
		if resExport, ok := object.(*mcsv1alpha1.ResourceExport); ok {
			return resExport.Spec.Kind == constants.LabelIdentityKind
		}
		return false
	}
	labelIdentityResExportPredicate := predicate.NewPredicateFuncs(labelIdentityResExportFilter)
	instance := predicate.And(generationPredicate, labelIdentityResExportPredicate)
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcsv1alpha1.ResourceExport{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.LabelIdentityWorkerCount,
		}).
		Complete(r)
}

// onLabelExportDelete updates the label to cluster caches, and deletes stale LabelIdentity kind of
// ResourceImport object if needed.
func (r *LabelIdentityExportReconciler) onLabelExportDelete(clusterID, labelHash string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if clusterLabels, ok := r.clusterToLabels[clusterID]; ok {
		clusterLabels.Delete(labelHash)
	}
	if clusters, ok := r.labelsToClusters[labelHash]; ok && len(clusters) == 1 && clusters.Has(clusterID) {
		// The cluster where the label identity is being deleted was the only cluster that has
		// the label identity. Hence, the label identity is no longer present in the ClusterSet.
		delete(r.labelsToClusters, labelHash)
		delete(r.hashToLabels, labelHash)
		r.labelQueue.Add(labelHash)
	} else {
		// Remove mapping from label to cluster
		clusters.Delete(clusterID)
	}
}

// onLabelExportAdd updates the label to cluster caches, and creates LabelIdentity kind of
// ResourceImport object if needed.
func (r *LabelIdentityExportReconciler) onLabelExportAdd(clusterID, labelHash, label string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if labels, ok := r.clusterToLabels[clusterID]; ok {
		labels.Insert(labelHash)
	} else {
		r.clusterToLabels[clusterID] = sets.New[string](labelHash)
	}
	if clusters, ok := r.labelsToClusters[labelHash]; !ok {
		// This is a new label identity in the entire ClusterSet.
		r.labelsToClusters[labelHash] = sets.New[string](clusterID)
		r.hashToLabels[labelHash] = label
		r.labelQueue.Add(labelHash)
	} else {
		clusters.Insert(clusterID)
	}
}

// Run begins syncing of ResourceImports for label identities.
func (r *LabelIdentityExportReconciler) Run(stopCh <-chan struct{}) {
	defer r.labelQueue.ShutDown()

	for i := 0; i < common.LabelIdentityWorkerCount; i++ {
		go wait.Until(r.labelQueueWorker, time.Second, stopCh)
	}
	<-stopCh
}

func (r *LabelIdentityExportReconciler) labelQueueWorker() {
	for r.processLabelForResourceImport() {
	}
}

// Processes an item in the labelQueue. If syncLabelResourceImport returns an error,
// this function handles it by re-queuing the item so that it can be processed again
// later. If syncLabelResourceExport is successful, the label is removed from the queue
// until we get notified of a new change.
func (r *LabelIdentityExportReconciler) processLabelForResourceImport() bool {
	key, quit := r.labelQueue.Get()
	if quit {
		return false
	}
	defer r.labelQueue.Done(key)
	err := r.syncLabelResourceImport(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		r.labelQueue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync ResourceImport for label identity", "label", key)
		return true
	}
	// If no error occurs, we forget this item so that it does not get queued again until
	// another change happens.
	r.labelQueue.Forget(key)
	return true
}

// syncLabelResourceImport checks the label cache and determines whether a ResourceImport
// needs to be created or deleted for the queued label hash.
func (r *LabelIdentityExportReconciler) syncLabelResourceImport(labelHash string) error {
	r.mutex.RLock()
	normalizedLabel, exists := r.hashToLabels[labelHash]
	r.mutex.RUnlock()
	ctx := context.Background()
	if exists {
		if err := r.handleLabelIdentityAdd(ctx, labelHash, normalizedLabel); err != nil {
			return err
		}
	} else {
		// If a label hash does not exist in hashToLabels, it means no cluster in the
		// ClusterSet still has the corresponding label identity.
		if err := r.handleLabelIdentityDelete(ctx, labelHash); err != nil {
			klog.ErrorS(err, "Failed to delete LabelIdentity kind of ResourceImport for stale label", "label", normalizedLabel)
			return err
		}
	}
	return nil
}

// handleLabelIdentityDelete deletes the ResourceImport of a label identity hash that no longer exists
// in the ClusterSet. Note that the ID of a label identity hash is only released if the deletion of its
// corresponding ResourceImport succeeded.
func (r *LabelIdentityExportReconciler) handleLabelIdentityDelete(ctx context.Context, deletedLabelHash string) error {
	labelIdentityImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deletedLabelHash,
			Namespace: r.namespace,
		},
	}
	if err := r.Client.Delete(ctx, labelIdentityImport, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	// Delete caches for the label ID mapping and release the ID assigned for the label
	if id, ok := r.labelsToID.Load(deletedLabelHash); ok {
		r.allocator.release(id.(uint32))
		r.labelsToID.Delete(deletedLabelHash)
	}
	return nil
}

// handleLabelIdentityAdd creates ResourceImport of a label identity that is added in the ClusterSet.
// Note that the ID of a label identity is only allocated and stored if the creation of its corresponding
// ResourceImport succeeded.
func (r *LabelIdentityExportReconciler) handleLabelIdentityAdd(ctx context.Context, labelHash, label string) error {
	labelIdentityResImport := &mcsv1alpha1.ResourceImport{}
	ResImpKey := types.NamespacedName{Name: labelHash, Namespace: r.namespace}
	err := r.Client.Get(ctx, ResImpKey, labelIdentityResImport)
	if err == nil {
		// ResourceImport for this label hash could already exist if the reconciler restarted
		// and has an outdated cache. In that case, simply restore the ID originally assigned
		// for the label hash.
		idPreviouslyAllocated := labelIdentityResImport.Spec.LabelIdentity.ID
		if err := r.allocator.setAllocated(idPreviouslyAllocated); err == nil {
			r.labelsToID.Store(labelHash, idPreviouslyAllocated)
			return nil
		} else {
			if err := r.Client.Delete(ctx, labelIdentityResImport, &client.DeleteOptions{}); err != nil {
				klog.ErrorS(err, "Failed to delete outdated LabelIdentity kind of ResourceImport for label", "label", label)
				return err
			}
			// Continue with the normal id allocation process.
		}
	}
	id, err := r.allocator.allocate()
	if err != nil {
		klog.ErrorS(err, "Failed to allocate ID for new label", "label", label)
		return err
	}
	labelIdentityResImport = getLabelIdentityResImport(labelHash, label, r.namespace, id)
	if err = r.Client.Create(ctx, labelIdentityResImport, &client.CreateOptions{}); err != nil {
		klog.ErrorS(err, "Failed to create LabelIdentity kind of ResourceImport for new label", "label", label)
		r.allocator.release(id)
		return err
	}
	r.labelsToID.Store(labelHash, id)
	return nil
}

func getLabelIdentityResImport(labelHash, label, ns string, id uint32) *mcsv1alpha1.ResourceImport {
	return &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      labelHash,
			Namespace: ns,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind: constants.LabelIdentityKind,
			LabelIdentity: &mcsv1alpha1.LabelIdentitySpec{
				Label: label,
				ID:    id,
			},
		},
	}
}

// parseLabelIdentityExportNamespacedName gets the clusterID and label identity
// hash from the API request.
func parseLabelIdentityExportNamespacedName(namespacedName types.NamespacedName) (string, string) {
	lastIdx := strings.LastIndex(namespacedName.Name, "-")
	clusterID := namespacedName.Name[:lastIdx]
	labelHash := namespacedName.Name[lastIdx+1:]
	return clusterID, labelHash
}

// idAllocator allocates an unique uint32 ID for each label identity.
type idAllocator struct {
	sync.Mutex
	maxID                  uint32
	nextID                 uint32
	previouslyAllocatedIDs intsets.Sparse
	releasedIDs            intsets.Sparse
}

// allocate will first try to allocate an ID within the pool of IDs that has been
// released (due to label identity deletions). If there's no such IDs, it will
// then allocate the first ID that has not been pre-allocated, or return an error
// if all IDs have been exhausted.
func (a *idAllocator) allocate() (uint32, error) {
	a.Lock()
	defer a.Unlock()

	available := -1
	if ok := a.releasedIDs.TakeMin(&available); ok {
		return uint32(available), nil
	}
	for a.previouslyAllocatedIDs.Has(int(a.nextID)) {
		a.nextID += 1
	}
	if a.nextID <= a.maxID {
		allocated := a.nextID
		a.nextID += 1
		return allocated, nil
	}
	return 0, fmt.Errorf("no ID available")
}

// setAllocated reserves IDs allocated during the previous round of label identity
// ResourceExport reconcilaion, before controller restarted.
func (a *idAllocator) setAllocated(id uint32) error {
	a.Lock()
	defer a.Unlock()

	if a.releasedIDs.Has(int(id)) {
		a.releasedIDs.Remove(int(id))
		return nil
	} else if id >= a.nextID {
		a.previouslyAllocatedIDs.Insert(int(id))
		return nil
	}
	return fmt.Errorf("ID %d has already been allocated", id)
}

func (a *idAllocator) release(id uint32) {
	a.Lock()
	defer a.Unlock()

	a.releasedIDs.Insert(int(id))
	if a.previouslyAllocatedIDs.Has(int(a.nextID)) {
		a.previouslyAllocatedIDs.Remove(int(id))
	}
}

func newIDAllocator(minID, maxID uint32) *idAllocator {
	preAllocated, availableIDs := intsets.Sparse{}, intsets.Sparse{}
	return &idAllocator{
		nextID:                 minID,
		maxID:                  maxID,
		previouslyAllocatedIDs: preAllocated,
		releasedIDs:            availableIDs,
	}
}
