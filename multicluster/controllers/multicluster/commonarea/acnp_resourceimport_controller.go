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
	"fmt"

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

const acnpImportFailed string = "ACNPImportFailed"

var (
	resourceImportAPIVersion     = "multicluster.crd.antrea.io/v1alpha1"
	resourceImportKind           = "ResourceImport"
	acnpEventReportingController = "resourceimport-controller"
	// TODO(yang): add run-time pod suffix
	acnpEventReportingInstance = "antrea-mc-controller"
)

func (r *ResourceImportReconciler) handleResImpUpdateForClusterNetworkPolicy(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	acnpName := types.NamespacedName{
		Namespace: "",
		Name:      common.AntreaMCSPrefix + resImp.Spec.Name,
	}
	klog.InfoS("Updating ACNP corresponding to ResourceImport",
		"acnp", acnpName.String(), "resourceimport", klog.KObj(resImp))

	acnp := &v1alpha1.ClusterNetworkPolicy{}
	err := r.localClusterClient.Get(ctx, acnpName, acnp)
	acnpNotFound := apierrors.IsNotFound(err)
	if err != nil && !acnpNotFound {
		return ctrl.Result{}, err
	}
	if !acnpNotFound {
		if _, ok := acnp.Annotations[common.AntreaMCACNPAnnotation]; !ok {
			msg := "Unable to import Antrea ClusterNetworkPolicy which conflicts with existing one in cluster " + r.localClusterID
			err := errors.New(msg)
			klog.ErrorS(err, "", "acnp", klog.KObj(acnp))
			return ctrl.Result{}, r.reportStatusEvent(msg, ctx, resImp)
		}
	}
	acnpObj := getMCAntreaClusterPolicy(resImp)
	tierObj, tierName := &v1alpha1.Tier{}, acnpObj.Spec.Tier
	err = r.localClusterClient.Get(ctx, types.NamespacedName{Namespace: "", Name: tierName}, tierObj)
	tierNotFound := apierrors.IsNotFound(err)
	if err != nil && !tierNotFound {
		msg := fmt.Sprintf("Failed to get Tier %s in member cluster %s", tierName, r.localClusterID)
		return ctrl.Result{}, r.reportStatusEvent(msg, ctx, resImp)
	}
	tierNotFoundMsg := fmt.Sprintf("ACNP Tier %s does not exist in importing cluster %s", tierName, r.localClusterID)
	if !tierNotFound {
		// If the ACNP Tier exists in the importing member cluster, then the policy is realizable.
		// Create or update the ACNP if necessary.
		if acnpNotFound {
			if err = r.localClusterClient.Create(ctx, acnpObj, &client.CreateOptions{}); err != nil {
				msg := "Failed to create imported Antrea ClusterNetworkPolicy in cluster " + r.localClusterID
				klog.ErrorS(err, msg, "acnp", klog.KObj(acnpObj))
				return ctrl.Result{}, r.reportStatusEvent(msg, ctx, resImp)
			}
			r.installedResImports.Add(*resImp)
		} else if !apiequality.Semantic.DeepEqual(acnp.Spec, acnpObj.Spec) {
			acnp.Spec = acnpObj.Spec
			if err = r.localClusterClient.Update(ctx, acnp, &client.UpdateOptions{}); err != nil {
				msg := "Failed to update imported Antrea ClusterNetworkPolicy in cluster " + r.localClusterID
				klog.ErrorS(err, msg, "acnp", klog.KObj(acnpObj))
				return ctrl.Result{}, r.reportStatusEvent(msg, ctx, resImp)
			}
		}
	} else if !acnpNotFound {
		// The ACNP Tier does not exist, and the policy cannot be realized in this particular importing member cluster.
		// If there is an ACNP previously created via import (which has a valid Tier by then), it should be cleaned up.
		if err = r.localClusterClient.Delete(ctx, acnpObj, &client.DeleteOptions{}); err != nil {
			msg := "Failed to delete imported Antrea ClusterNetworkPolicy that no longer has a valid Tier for cluster " + r.localClusterID
			klog.ErrorS(err, msg, "acnp", klog.KObj(acnpObj))
			return ctrl.Result{}, r.reportStatusEvent(msg, ctx, resImp)
		}
		return ctrl.Result{}, r.reportStatusEvent(tierNotFoundMsg, ctx, resImp)
	} else {
		return ctrl.Result{}, r.reportStatusEvent(tierNotFoundMsg, ctx, resImp)
	}
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpDeleteForClusterNetworkPolicy(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	acnpName := types.NamespacedName{
		Namespace: "",
		Name:      common.AntreaMCSPrefix + resImp.Spec.Name,
	}
	klog.InfoS("Deleting ACNP corresponding to ResourceImport",
		"acnp", acnpName.String(), "resourceimport", klog.KObj(resImp))

	acnp := &v1alpha1.ClusterNetworkPolicy{}
	err := r.localClusterClient.Get(ctx, acnpName, acnp)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(2).InfoS("ACNP corresponding to ResourceImport has already been deleted",
				"acnp", acnpName.String(), "resourceimport", klog.KObj(resImp))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if err = r.localClusterClient.Delete(ctx, acnp, &client.DeleteOptions{}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func getMCAntreaClusterPolicy(resImp *multiclusterv1alpha1.ResourceImport) *v1alpha1.ClusterNetworkPolicy {
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

func (r *ResourceImportReconciler) reportStatusEvent(errMsg string, ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) error {
	t := metav1.Now()
	statusEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", resImp.Name, t.UnixNano()),
			Namespace: resImp.Namespace,
		},
		Type:    corev1.EventTypeWarning,
		Reason:  acnpImportFailed,
		Message: errMsg,
		InvolvedObject: corev1.ObjectReference{
			APIVersion: resourceImportAPIVersion,
			Kind:       resourceImportKind,
			Name:       resImp.Name,
			Namespace:  resImp.Namespace,
			UID:        resImp.GetUID(),
		},
		FirstTimestamp:      metav1.Now(),
		LastTimestamp:       metav1.Now(),
		ReportingController: acnpEventReportingController,
		ReportingInstance:   acnpEventReportingInstance,
		Action:              "synced",
	}
	if err := r.remoteCommonArea.Create(ctx, statusEvent, &client.CreateOptions{}); err != nil {
		klog.ErrorS(err, "Failed to create ACNP import event for ResourceImport", "resImp", klog.KObj(resImp))
		return err
	}
	return nil
}
