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

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func (r *ResourceImportReconciler) handleResImpUpdateForClusterNetworkPolicy(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	acnpImpName := types.NamespacedName{
		Namespace: "",
		Name:      resImp.Spec.Name,
	}
	acnpName := types.NamespacedName{
		Namespace: "",
		Name:      common.AntreaMCSPrefix + resImp.Spec.Name,
	}
	klog.InfoS("Updating ACNP and ACNPImport corresponding to ResourceImport",
		"acnp", acnpName.String(), "resourceimport", klog.KObj(resImp))

	acnp := &v1alpha1.ClusterNetworkPolicy{}
	err := r.localClusterClient.Get(ctx, acnpName, acnp)
	acnpNotFound := apierrors.IsNotFound(err)
	if err != nil && !acnpNotFound {
		return ctrl.Result{}, err
	}
	if !acnpNotFound {
		if _, ok := acnp.Annotations[common.AntreaMCACNPAnnotation]; !ok {
			err := errors.New("unable to import Antrea ClusterNetworkPolicy which conflicts with existing one")
			klog.ErrorS(err, "", "acnp", klog.KObj(acnp))
			return ctrl.Result{}, err
		}
	}
	acnpObj := getMCAntreaClusterPolicy(resImp)
	tierKind, tierName := &v1alpha1.Tier{}, acnpObj.Spec.Tier
	err = r.localClusterClient.Get(ctx, types.NamespacedName{Namespace: "", Name: tierName}, tierKind)
	tierNotFound := apierrors.IsNotFound(err)
	if !tierNotFound {
		// If the ACNP Tier exists in the importing member cluster, then the policy is realizable.
		// Create or update the ACNP if necessary.
		if acnpNotFound {
			if err = r.localClusterClient.Create(ctx, acnpObj, &client.CreateOptions{}); err != nil {
				klog.ErrorS(err, "failed to create imported Antrea ClusterNetworkPolicy", "acnp", klog.KObj(acnpObj))
				return ctrl.Result{}, err
			}
		} else if !apiequality.Semantic.DeepEqual(acnp.Spec, acnpObj.Spec) {
			acnp.Spec = acnpObj.Spec
			if err = r.localClusterClient.Update(ctx, acnp, &client.UpdateOptions{}); err != nil {
				klog.ErrorS(err, "failed to update imported Antrea ClusterNetworkPolicy", "acnp", klog.KObj(acnpObj))
				return ctrl.Result{}, err
			}
		}
	} else if tierNotFound && !acnpNotFound {
		// The ACNP Tier does not exist, and the policy cannot be realized in this particular importing member cluster.
		// If there is an ACNP previously created via import (which has a valid Tier by then), it should be cleaned up.
		if err = r.localClusterClient.Delete(ctx, acnpObj, &client.DeleteOptions{}); err != nil {
			klog.ErrorS(err, "failed to delete imported Antrea ClusterNetworkPolicy that no longer has a valid Tier for the current cluster", "acnp", klog.KObj(acnpObj))
			return ctrl.Result{}, err
		}
	}
	acnpImp := &multiclusterv1alpha1.ACNPImport{}
	err = r.localClusterClient.Get(ctx, acnpImpName, acnpImp)
	acnpImpNotFound := apierrors.IsNotFound(err)
	if err != nil && !acnpImpNotFound {
		klog.ErrorS(err, "failed to get existing ACNPImports")
		return ctrl.Result{}, err
	}
	// acnpImport status will be realizable=False if Tier is not found on this member cluster, and realizable=True otherwise.
	acnpImpObj, isRealizable := getACNPImport(resImp, tierNotFound)
	if acnpImpNotFound {
		err := r.localClusterClient.Create(ctx, acnpImpObj, &client.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "failed to create ACNPImport", "acnpimport", klog.KObj(acnpImpObj))
			return ctrl.Result{}, err
		}
		r.installedResImports.Add(*resImp)
	}
	patchACNPImportStatus := false
	if len(acnpImp.Status.Conditions) == 0 {
		acnpImp.Status = acnpImpObj.Status
		patchACNPImportStatus = true
	} else {
		for _, c := range acnpImp.Status.Conditions {
			if c.Type == multiclusterv1alpha1.ACNPImportRealizable && c.Status != isRealizable {
				acnpImp.Status = acnpImpObj.Status
				patchACNPImportStatus = true
			}
		}
	}
	// Patch ACNPImport status if realizable state has changed.
	if patchACNPImportStatus {
		if err := r.localClusterClient.Status().Update(ctx, acnpImp); err != nil {
			klog.ErrorS(err, "failed to update acnpImport status", "acnpImport", klog.KObj(acnpImp))
		}
	}
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpDeleteForClusterNetworkPolicy(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	acnpImpName := types.NamespacedName{
		Namespace: "",
		Name:      resImp.Spec.Name,
	}
	acnpName := types.NamespacedName{
		Namespace: "",
		Name:      common.AntreaMCSPrefix + resImp.Spec.Name,
	}
	klog.InfoS("Deleting ACNP and ACNPImport corresponding to ResourceImport",
		"acnp", acnpName.String(), "resourceimport", klog.KObj(resImp))

	var err error
	cleanupACNPImport := func() (ctrl.Result, error) {
		acnpImp := &multiclusterv1alpha1.ACNPImport{}
		err = r.localClusterClient.Get(ctx, acnpImpName, acnpImp)
		if err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		err = r.localClusterClient.Delete(ctx, acnpImp, &client.DeleteOptions{})
		if err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, nil
	}

	acnp := &v1alpha1.ClusterNetworkPolicy{}
	err = r.localClusterClient.Get(ctx, acnpName, acnp)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(2).InfoS("ACNP corresponding to ResourceImport has already been deleted",
				"acnp", acnpName.String(), "resourceimport", klog.KObj(resImp))
			return cleanupACNPImport()
		}
		return ctrl.Result{}, err
	}
	err = r.localClusterClient.Delete(ctx, acnp, &client.DeleteOptions{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return cleanupACNPImport()
}

func getMCAntreaClusterPolicy(resImp *multiclusterv1alpha1.ResourceImport) *v1alpha1.ClusterNetworkPolicy {
	if resImp.Spec.ClusterNetworkPolicy == nil {
		return nil
	}
	return &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: common.AntreaMCSPrefix + resImp.Spec.Name,
			Annotations: map[string]string{
				common.AntreaMCACNPAnnotation: "true",
			},
		},
		Spec: *resImp.Spec.ClusterNetworkPolicy,
	}
}

func getACNPImport(resImp *multiclusterv1alpha1.ResourceImport, tierNotFound bool) (*multiclusterv1alpha1.ACNPImport, corev1.ConditionStatus) {
	if resImp.Spec.ClusterNetworkPolicy == nil {
		return nil, corev1.ConditionFalse
	}
	status, isRealizable := getACNPImportStatus(tierNotFound)
	return &multiclusterv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: resImp.Spec.Name,
		},
		Status: multiclusterv1alpha1.ACNPImportStatus{
			Conditions: []multiclusterv1alpha1.ACNPImportCondition{status},
		},
	}, isRealizable
}

func getACNPImportStatus(tierNotFound bool) (multiclusterv1alpha1.ACNPImportCondition, corev1.ConditionStatus) {
	tierNotFoundReason := "TierNotFound"
	tierNotFoundMessage := "ACNP Tier does not exist in the importing cluster"
	time := metav1.Now()
	if tierNotFound {
		return multiclusterv1alpha1.ACNPImportCondition{
			Type:               multiclusterv1alpha1.ACNPImportRealizable,
			Status:             corev1.ConditionFalse,
			LastTransitionTime: &time,
			Reason:             &tierNotFoundReason,
			Message:            &tierNotFoundMessage,
		}, corev1.ConditionFalse
	}
	return multiclusterv1alpha1.ACNPImportCondition{
		Type:               multiclusterv1alpha1.ACNPImportRealizable,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: &time,
	}, corev1.ConditionTrue
}
