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

package commonarea

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// LabelIdentityResourceImportReconciler reconciles a LabelIdentity kind of ResourceImport object in the member cluster.
type LabelIdentityResourceImportReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	localClusterClient    client.Client
	localClusterID        string
	namespace             string
	remoteCommonArea      RemoteCommonArea
	installedLabelImports cache.Indexer
}

func NewLabelIdentityResourceImportReconciler(client client.Client, scheme *runtime.Scheme, localClusterClient client.Client,
	localClusterID string, namespace string, remoteCommonArea RemoteCommonArea) *LabelIdentityResourceImportReconciler {
	return &LabelIdentityResourceImportReconciler{
		Client:                client,
		Scheme:                scheme,
		localClusterClient:    localClusterClient,
		localClusterID:        localClusterID,
		namespace:             namespace,
		remoteCommonArea:      remoteCommonArea,
		installedLabelImports: cache.NewIndexer(resourceImportIndexerKeyFunc, cache.Indexers{}),
	}
}

func resourceImportIndexerKeyFunc(obj interface{}) (string, error) {
	ri := obj.(multiclusterv1alpha1.ResourceImport)
	return common.NamespacedName(ri.Namespace, ri.Name), nil
}

func (r *LabelIdentityResourceImportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling LabelIdentity kind of ResourceImport", "resourceImport", req.NamespacedName)
	if r.localClusterClient == nil {
		return ctrl.Result{}, errors.New("localClusterClient has not been initialized properly, no local cluster client")
	}
	if r.remoteCommonArea == nil {
		return ctrl.Result{}, errors.New("remoteCommonArea has not been initialized properly, no remote common area")
	}
	var labelIdentityResImport multiclusterv1alpha1.ResourceImport
	err := r.remoteCommonArea.Get(ctx, req.NamespacedName, &labelIdentityResImport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Unable to fetch LabelIdentity kind of ResourceImport", "resourceImport", req.NamespacedName)
			return ctrl.Result{}, err
		}
		labelIdentityResImportObj, exist, _ := r.installedLabelImports.GetByKey(req.NamespacedName.String())
		if !exist {
			// Stale controller will clean up any stale LabelIdentities
			klog.ErrorS(err, "No cached data for LabelIdentity kind of ResourceImport", "resoureImport", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		labelIdentityResImport = labelIdentityResImportObj.(multiclusterv1alpha1.ResourceImport)
		return r.handleLabelIdentityImpDelete(ctx, &labelIdentityResImport)
	}
	return r.handleLabelIdentityImpCreateOrUpdate(ctx, &labelIdentityResImport)
}

func (r *LabelIdentityResourceImportReconciler) handleLabelIdentityImpCreateOrUpdate(ctx context.Context,
	labelResImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	labelIdentityName := types.NamespacedName{
		Name: labelResImp.Name,
	}
	labelIdentity := &multiclusterv1alpha1.LabelIdentity{}
	err := r.localClusterClient.Get(ctx, labelIdentityName, labelIdentity)
	labelIdentityNotFound := apierrors.IsNotFound(err)
	if err != nil && !labelIdentityNotFound {
		return ctrl.Result{}, err
	}
	if labelIdentityNotFound {
		newLabelIdentity := &multiclusterv1alpha1.LabelIdentity{
			ObjectMeta: metav1.ObjectMeta{
				Name: labelResImp.Name,
			},
			Spec: multiclusterv1alpha1.LabelIdentitySpec{
				Label: labelResImp.Spec.LabelIdentity.Label,
				ID:    labelResImp.Spec.LabelIdentity.ID,
			},
		}
		if err = r.localClusterClient.Create(ctx, newLabelIdentity, &client.CreateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to create LabelIdentity", "clusterID", r.localClusterID, "label", labelResImp.Spec.LabelIdentity.Label)
			return ctrl.Result{}, err
		}
		r.installedLabelImports.Add(*labelResImp)
	} else if labelIdentity.Spec.ID != labelResImp.Spec.LabelIdentity.ID {
		labelIdentity.Spec.ID = labelResImp.Spec.LabelIdentity.ID
		if err = r.localClusterClient.Update(ctx, labelIdentity, &client.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to update LabelIdentity", "clusterID", r.localClusterID, "label", labelResImp.Spec.LabelIdentity.Label)
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *LabelIdentityResourceImportReconciler) handleLabelIdentityImpDelete(ctx context.Context,
	labelResImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	klog.V(2).InfoS("Deleting LabelIdentity corresponding to LabelIdentity kind of ResourceImport", "resourceImport", klog.KObj(labelResImp))
	labelIdentity := &multiclusterv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: labelResImp.Name,
		},
	}
	if err := r.localClusterClient.Delete(ctx, labelIdentity, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete LabelIdentity", "labelIdentity", labelIdentity.Name)
		return ctrl.Result{}, err
	}
	r.installedLabelImports.Delete(*labelResImp)
	return ctrl.Result{}, nil
}

func (r *LabelIdentityResourceImportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	// Only register this controller to reconcile LabelIdentity kind of ResourceImport
	labelIdentityResImportFilter := func(object client.Object) bool {
		if resImport, ok := object.(*multiclusterv1alpha1.ResourceImport); ok {
			return resImport.Spec.Kind == common.LabelIdentityKind
		}
		return false
	}
	labelIdentityResImportPredicate := predicate.NewPredicateFuncs(labelIdentityResImportFilter)
	instance := predicate.And(generationPredicate, labelIdentityResImportPredicate)
	return ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ResourceImport{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}
