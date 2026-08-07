/*
Copyright 2021 Antrea Authors.

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

package main

import (
	"context"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha2"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-memberclusterannounce,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=memberclusterannounces,verbs=create;update;delete,versions=v1alpha1,name=vmemberclusterannounce.kb.io,admissionReviewVersions={v1}

type memberClusterAnnounceValidator struct {
	Client    client.Client
	decoder   admission.Decoder
	namespace string
	saName    string
}

// Handle handles admission requests.
func (v *memberClusterAnnounceValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var newObj, oldObj *mcv1alpha1.MemberClusterAnnounce

	if len(req.Object.Raw) > 0 {
		newObj = &mcv1alpha1.MemberClusterAnnounce{}
		if err := v.decoder.DecodeRaw(req.Object, newObj); err != nil {
			klog.ErrorS(err, "Error while decoding new MemberClusterAnnounce")
			return admission.Errored(http.StatusBadRequest, err)
		}
	}
	if len(req.OldObject.Raw) > 0 {
		oldObj = &mcv1alpha1.MemberClusterAnnounce{}
		if err := v.decoder.DecodeRaw(req.OldObject, oldObj); err != nil {
			klog.ErrorS(err, "Error while decoding old MemberClusterAnnounce")
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	var memberClusterAnnounce *mcv1alpha1.MemberClusterAnnounce
	if req.Operation == admissionv1.Delete {
		memberClusterAnnounce = oldObj
	} else {
		memberClusterAnnounce = newObj
	}

	if memberClusterAnnounce == nil {
		err := fmt.Errorf("no content to decode")
		klog.ErrorS(err, "Error while decoding")
		return admission.Errored(http.StatusBadRequest, err)
	}

	ui := req.UserInfo
	saNamespace, saName, err := serviceaccount.SplitUsername(ui.Username)
	if err != nil {
		if req.Operation == admissionv1.Delete {
			// Allow non-ServiceAccount users (like kubernetes-admin) to delete
			return admission.Allowed("")
		}
		klog.ErrorS(err, "Error getting ServiceAccount name", "MemberClusterAnnounce", req.Namespace+"/"+req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Exempt the leader controller's own ServiceAccount for Update and Delete operations
	// (finalizer management and stale cleanup). Create is intentionally not exempted: the
	// leader controller never creates MemberClusterAnnounces, so exempting it would widen
	// the bypass without need. The Namespace from the caller identity (not req.Namespace,
	// which is the object's Namespace) must match, so that a ServiceAccount with the same
	// name in another Namespace is not exempted.
	if saNamespace == v.namespace && saName == v.saName && req.Operation != admissionv1.Create {
		return v.validateOperation(ctx, req, newObj, oldObj, memberClusterAnnounce)
	}

	// A member caller must be a ServiceAccount in the leader Namespace: the ClusterID
	// binding is only meaningful for ServiceAccounts in that Namespace. Deny other
	// callers on non-Delete operations, and defer Delete to RBAC so that the Namespace
	// controller and the garbage collector can clean up when the leader Namespace is
	// torn down (their lookup here would otherwise fail with Forbidden).
	if saNamespace != v.namespace {
		if req.Operation == admissionv1.Delete {
			return admission.Allowed("")
		}
		return admission.Denied(fmt.Sprintf("ServiceAccount %q is not in Namespace %q", ui.Username, v.namespace))
	}

	serviceAccount := &v1.ServiceAccount{}
	if err := v.Client.Get(ctx, client.ObjectKey{Namespace: saNamespace, Name: saName}, serviceAccount); err != nil {
		if req.Operation == admissionv1.Delete && apierrors.IsNotFound(err) {
			// Allow GC to delete when SA is missing
			return admission.Allowed("")
		}
		klog.ErrorS(err, "Error getting ServiceAccount", "ServiceAccount", saName, "Namespace", saNamespace, "MemberClusterAnnounce", klog.KObj(memberClusterAnnounce))
		return admission.Errored(http.StatusPreconditionFailed, err)
	}

	// Bind the announced ClusterID to the authenticated caller: it must match the
	// multicluster.antrea.io/cluster-id annotation on the caller's ServiceAccount,
	// so one onboarded member cannot announce, modify, or delete as another.
	permittedClusterID, ok := serviceAccount.Annotations[constants.ServiceAccountClusterIDAnnotation]
	if !ok || permittedClusterID != memberClusterAnnounce.ClusterID {
		klog.InfoS("Denying MemberClusterAnnounce: ClusterID not bound to caller ServiceAccount",
			"ServiceAccount", saName, "announcedClusterID", memberClusterAnnounce.ClusterID, "permittedClusterID", permittedClusterID)
		return admission.Denied(fmt.Sprintf("ClusterID %q is not permitted for ServiceAccount %q (expected %s annotation to match)",
			memberClusterAnnounce.ClusterID, saName, constants.ServiceAccountClusterIDAnnotation))
	}

	return v.validateOperation(ctx, req, newObj, oldObj, memberClusterAnnounce)
}

func (v *memberClusterAnnounceValidator) validateOperation(ctx context.Context, req admission.Request, newObj, oldObj, memberClusterAnnounce *mcv1alpha1.MemberClusterAnnounce) admission.Response {
	switch req.Operation {
	case admissionv1.Create:
		// Read the ClusterSet info
		clusterSetList := &mcv1alpha2.ClusterSetList{}
		if err := v.Client.List(ctx, clusterSetList, client.InNamespace(v.namespace)); err != nil {
			klog.ErrorS(err, "Error reading ClusterSet", "Namespace", v.namespace)
			return admission.Errored(http.StatusPreconditionFailed, err)
		}

		if len(clusterSetList.Items) == 0 {
			klog.ErrorS(nil, "No ClusterSet found", "Namespace", v.namespace)
			return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("no ClusterSet found in Namespace %s", v.namespace))
		}
		clusterSet := clusterSetList.Items[0]
		if clusterSet.Name != memberClusterAnnounce.ClusterSetID {
			return admission.Denied("Unknown ClusterSet ID")
		}
		if clusterSet.Spec.Leaders[0].ClusterID != memberClusterAnnounce.LeaderClusterID {
			return admission.Denied("Leader cluster ID in the MemberClusterAnnounce does not match that in the ClusterSet")
		}

		expectedName := constants.MemberClusterAnnouncePrefix + memberClusterAnnounce.ClusterID
		if memberClusterAnnounce.Name != expectedName {
			klog.InfoS("Denying MemberClusterAnnounce: Name does not match ClusterID",
				"Name", memberClusterAnnounce.Name, "expectedName", expectedName)
			return admission.Denied(fmt.Sprintf("MemberClusterAnnounce name must be %q", expectedName))
		}

		return admission.Allowed("")
	case admissionv1.Update:
		if oldObj == nil {
			// oldObject is always populated by a conformant v1 API server, but guard
			// against nil to avoid panicking in a failurePolicy=fail webhook.
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("old MemberClusterAnnounce is missing in the Update request"))
		}
		// Member cluster will never change ClusterSet ID in MemberClusterAnnounce
		if newObj.ClusterSetID != oldObj.ClusterSetID || newObj.LeaderClusterID != oldObj.LeaderClusterID {
			return admission.Denied("ClusterSet ID or Leader Cluster ID cannot be changed")
		}
		if newObj.ClusterID != oldObj.ClusterID {
			return admission.Denied("ClusterID cannot be changed")
		}
		return admission.Allowed("")
	default:
		return admission.Allowed("")
	}
}
