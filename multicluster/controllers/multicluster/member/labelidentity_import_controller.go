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

package member

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

// LabelIdentityResourceImportReconciler reconciles a LabelIdentity kind of ResourceImport object in the member cluster.
type LabelIdentityResourceImportReconciler struct {
	localClusterClient client.Client
	localClusterID     string
	namespace          string
	remoteCommonArea   commonarea.RemoteCommonArea
	// Saved Manager to indicate SetupWithManager() is done or not.
	manager ctrl.Manager
}

func newLabelIdentityResourceImportReconciler(localClusterClient client.Client,
	localClusterID string, namespace string, remoteCommonArea commonarea.RemoteCommonArea) *LabelIdentityResourceImportReconciler {
	return &LabelIdentityResourceImportReconciler{
		localClusterClient: localClusterClient,
		localClusterID:     localClusterID,
		namespace:          namespace,
		remoteCommonArea:   remoteCommonArea,
	}
}

func (r *LabelIdentityResourceImportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling LabelIdentity kind of ResourceImport", "resourceImport", req.NamespacedName)
	var labelIdentityResImport multiclusterv1alpha1.ResourceImport
	err := r.remoteCommonArea.Get(ctx, req.NamespacedName, &labelIdentityResImport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Unable to fetch LabelIdentity kind of ResourceImport", "resourceImport", req.NamespacedName)
			return ctrl.Result{}, err
		}
		return r.handleLabelIdentityImpDelete(ctx, req.NamespacedName)
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
	resImpName types.NamespacedName) (ctrl.Result, error) {
	klog.V(2).InfoS("Deleting LabelIdentity corresponding to LabelIdentity kind of ResourceImport", "resourceImport", resImpName.String())
	labelIdentity := &multiclusterv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: resImpName.Name,
		},
	}
	if err := r.localClusterClient.Delete(ctx, labelIdentity, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete LabelIdentity", "clusterID", r.localClusterID, "labelIdentity", labelIdentity.Name)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *LabelIdentityResourceImportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.manager == mgr {
		// SetupWithManager was called by a previous RemoteManager.StartWatch() call and already
		// completed with no error.
		return nil
	}

	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	// Only register this controller to reconcile LabelIdentity kind of ResourceImport
	labelIdentityResImportFilter := func(object client.Object) bool {
		if resImport, ok := object.(*multiclusterv1alpha1.ResourceImport); ok {
			return resImport.Spec.Kind == constants.LabelIdentityKind
		}
		return false
	}
	labelIdentityResImportPredicate := predicate.NewPredicateFuncs(labelIdentityResImportFilter)
	instance := predicate.And(generationPredicate, labelIdentityResImportPredicate)
	err := ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ResourceImport{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.LabelIdentityWorkerCount,
		}).
		Complete(r)

	if err == nil {
		r.manager = mgr
	}
	return err
}
