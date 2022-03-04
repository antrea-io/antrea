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
	"math/rand"

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

const (
	nameSuffixLength       int    = 5
	acnpImportStatusPrefix string = "acnp-import-status-"
	acnpImportSucceeded    string = "ACNPImportSucceeded"
	acnpImportFailed       string = "ACNPImportFailed"
)

var (
	resourceImportAPIVersion     = "multicluster.crd.antrea.io/v1alpha1"
	resourceImportKind           = "ResourceImport"
	acnpEventReportingController = "resourceimport-controller"
	// TODO(yang): add run-time pod suffix
	acnpEventReportingInstance = "antrea-mc-controller"
	lettersAndDigits           = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
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

	statusEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      randName(acnpImportStatusPrefix + r.localClusterID + "-"),
			Namespace: resImp.Namespace,
		},
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
		Action:              "reconciled",
	}
	if tierNotFound {
		statusEvent.Type = corev1.EventTypeWarning
		statusEvent.Reason = acnpImportFailed
		statusEvent.Message = "ACNP Tier does not exist in the importing cluster " + r.localClusterID
	} else {
		statusEvent.Type = corev1.EventTypeNormal
		statusEvent.Reason = acnpImportSucceeded
		statusEvent.Message = "ACNP successfully created in the importing cluster " + r.localClusterID
	}
	if err = r.remoteCommonArea.Create(ctx, statusEvent, &client.CreateOptions{}); err != nil {
		klog.ErrorS(err, "failed to create acnp import event for resourceimport", "resImp", klog.KObj(resImp))
		return ctrl.Result{}, err
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

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		// #nosec G404: random number generator not used for security purposes
		randIdx := rand.Intn(len(lettersAndDigits))
		b[i] = lettersAndDigits[randIdx]
	}
	return string(b)
}

func randName(prefix string) string {
	return prefix + randSeq(nameSuffixLength)
}
