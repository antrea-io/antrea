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
	"fmt"
	"strings"
	"sync"

	"golang.org/x/tools/container/intsets"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

const (
	// 24 bits are available in VNI. The max value 16777215 is reserved for unknown ID.
	maxIDForAllocation = 16777214
)

// LabelIdentityExportReconciler watches LabelIdentity ResourceExport events in the Common Area,
// computes if such event cause a new LabelIdentity to become present/stale in the entire
// ClusterSet, and update ResourceImports accordingly.
type (
	LabelIdentityExportReconciler struct {
		client.Client
		Scheme                    *runtime.Scheme
		mutex                     sync.RWMutex
		namespace                 string
		clusterToLabels           map[string]sets.String
		labelsToClusters          map[string]sets.String
		labelImpUpdatesInProgress sets.String
		labelsToID                map[string]uint32
		allocator                 *idAllocator
	}
)

func NewLabelIdentityExportReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	namespace string) *LabelIdentityExportReconciler {
	return &LabelIdentityExportReconciler{
		Client:                    client,
		Scheme:                    scheme,
		namespace:                 namespace,
		clusterToLabels:           map[string]sets.String{},
		labelsToClusters:          map[string]sets.String{},
		labelImpUpdatesInProgress: sets.NewString(),
		labelsToID:                map[string]uint32{},
		allocator:                 newIDAllocator(1, maxIDForAllocation),
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
			return r.onLabelExportDelete(ctx, clusterID, labelHash)
		}
		return ctrl.Result{}, err
	}
	normalizedLabel := resExport.Spec.LabelIdentity.NormalizedLabel
	return r.onLabelExportAdd(ctx, clusterID, labelHash, normalizedLabel)
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
			return resExport.Spec.Kind == common.LabelIdentityKind
		}
		return false
	}
	labelIdentityResExportPredicate := predicate.NewPredicateFuncs(labelIdentityResExportFilter)
	instance := predicate.And(generationPredicate, labelIdentityResExportPredicate)
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcsv1alpha1.ResourceExport{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

// This function needs to be called with labelMutex acquired.
func (r *LabelIdentityExportReconciler) setLabelExportUpdatesInProgress(labelHash string) {
	r.labelImpUpdatesInProgress.Insert(labelHash)
	// Unlock the mutex to allow cache updates for other labelHashes. Any worker operating on
	// the same labelHash will be blocked as it is added into labelImpUpdatesInProgress.
	r.mutex.Unlock()
}

func (r *LabelIdentityExportReconciler) unsetLabelExportUpdatesInProgress(labelHash string) {
	r.mutex.Lock()
	r.labelImpUpdatesInProgress.Delete(labelHash)
}

// onLabelExportDelete updates the label to cluster caches, and deletes stale LabelIdentity kind of
// ResourceImport object if needed.
func (r *LabelIdentityExportReconciler) onLabelExportDelete(ctx context.Context, clusterID, labelHash string) (ctrl.Result, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.labelImpUpdatesInProgress.Has(labelHash) {
		return ctrl.Result{Requeue: true}, nil
	}
	if clusters, ok := r.labelsToClusters[labelHash]; ok && len(clusters) == 1 && clusters.Has(clusterID) {
		// The cluster where the label identity is being deleted was the only cluster that has
		// the label identity. Hence, the label identity is no longer present in the ClusterSet.
		return r.handleLabelIdentityDelete(ctx, labelHash, clusterID)
	} else {
		// Remove mapping from label to cluster
		clusters.Delete(clusterID)
		if clusterLabels, ok := r.clusterToLabels[clusterID]; ok {
			clusterLabels.Delete(labelHash)
		}
		return ctrl.Result{}, nil
	}
}

// handleLabelIdentityDelete deletes the ResourceImport of a label identity hash that no longer exists
// in the ClusterSet. Note that the ID of a label identity hash is only released if the deletion of its
// corresponding ResourceImport succeeded.
// This function needs to be called with reconciler's mutex acquired, and will return with the mutex
// remain locked.
func (r *LabelIdentityExportReconciler) handleLabelIdentityDelete(ctx context.Context,
	deletedLabelHash, clusterID string) (ctrl.Result, error) {
	r.setLabelExportUpdatesInProgress(deletedLabelHash)
	labelIdentityImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deletedLabelHash,
			Namespace: r.namespace,
		},
	}
	err := r.Client.Delete(ctx, labelIdentityImport, &client.DeleteOptions{})
	r.unsetLabelExportUpdatesInProgress(deletedLabelHash)
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete LabelIdentity kind of ResourceImport for stale label", "label", deletedLabelHash)
		return ctrl.Result{}, err
	}
	// Delete caches for the label and release the ID assigned for the label
	id := r.labelsToID[deletedLabelHash]
	r.allocator.release(id)
	delete(r.labelsToID, deletedLabelHash)
	delete(r.labelsToClusters, deletedLabelHash)
	if clusterLabels, ok := r.clusterToLabels[clusterID]; ok {
		clusterLabels.Delete(deletedLabelHash)
	}
	return ctrl.Result{}, nil
}

// onLabelExportAdd updates the label to cluster caches, and creates LabelIdentity kind of
// ResourceImport object if needed.
func (r *LabelIdentityExportReconciler) onLabelExportAdd(ctx context.Context, clusterID, labelHash, label string) (ctrl.Result, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.labelImpUpdatesInProgress.Has(labelHash) {
		return ctrl.Result{Requeue: true}, nil
	}
	if clusters, ok := r.labelsToClusters[labelHash]; !ok {
		// This is a new label identity in the entire ClusterSet.
		return r.handleLabelIdentityAdd(ctx, labelHash, label, clusterID)
	} else {
		clusters.Insert(clusterID)
		if labels, ok := r.clusterToLabels[clusterID]; ok {
			labels.Insert(labelHash)
		} else {
			r.clusterToLabels[clusterID] = sets.NewString(labelHash)
		}
		return ctrl.Result{}, nil
	}
}

// handleLabelIdentityAdd creates ResourceImport of a label identity that is added in the ClusterSet.
// Note that the ID of a label identity is only allocated and stored if the creation of its corresponding
// ResourceImport succeeded.
// This function needs to be called with reconciler's mutex acquired, and will return with the mutex
// remain locked.
func (r *LabelIdentityExportReconciler) handleLabelIdentityAdd(ctx context.Context,
	labelHash, label, clusterID string) (ctrl.Result, error) {

	labelIdentityResImport := &mcsv1alpha1.ResourceImport{}
	ResImpKey := types.NamespacedName{Name: labelHash, Namespace: r.namespace}
	err := r.Client.Get(ctx, ResImpKey, labelIdentityResImport)
	if err == nil {
		idAllocated := labelIdentityResImport.Spec.LabelIdentity.ID
		if err := r.allocator.setAllocated(idAllocated); err == nil {
			r.updateClusterLabelIDCache(clusterID, labelHash, idAllocated)
			return ctrl.Result{}, nil
		} else {
			if err := r.Client.Delete(ctx, labelIdentityResImport, &client.DeleteOptions{}); err != nil {
				klog.ErrorS(err, "Failed to delete outdated LabelIdentity kind of ResourceImport for label", "label", label)
				return ctrl.Result{}, err
			}
		}
	}
	id, err := r.allocator.allocate()
	if err != nil {
		klog.ErrorS(err, "Failed to allocate ID for new label", "label", label)
		return ctrl.Result{}, err
	}
	r.setLabelExportUpdatesInProgress(labelHash)
	labelIdentityResImport = getLabelIdentityResImport(labelHash, label, r.namespace, id)
	err = r.Client.Create(ctx, labelIdentityResImport, &client.CreateOptions{})
	r.unsetLabelExportUpdatesInProgress(labelHash)
	if err != nil {
		klog.ErrorS(err, "Failed to create LabelIdentity kind of ResourceImport for new label", "label", label)
		r.allocator.release(id)
		return ctrl.Result{}, err
	}
	r.updateClusterLabelIDCache(clusterID, labelHash, id)
	return ctrl.Result{}, nil
}

func (r *LabelIdentityExportReconciler) updateClusterLabelIDCache(clusterID, labelHash string, id uint32) {
	r.labelsToID[labelHash] = id
	if clusters, ok := r.labelsToClusters[labelHash]; ok {
		clusters.Insert(clusterID)
	} else {
		r.labelsToClusters[labelHash] = sets.NewString(clusterID)
	}
	if labels, ok := r.clusterToLabels[clusterID]; ok {
		labels.Insert(labelHash)
	} else {
		r.clusterToLabels[clusterID] = sets.NewString(labelHash)
	}
}

func getLabelIdentityResImport(labelHash, label, ns string, id uint32) *mcsv1alpha1.ResourceImport {
	return &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      labelHash,
			Namespace: ns,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind: common.LabelIdentityKind,
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

// idAllocator allocates an unqiue uint32 ID for each label identity.
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
