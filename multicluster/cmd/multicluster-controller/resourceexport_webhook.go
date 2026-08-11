/*
Copyright 2026 Antrea Authors.

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
	"slices"

	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/common"
)

var memberAllowedResourceExportKinds = sets.New(
	constants.ServiceKind,
	constants.EndpointsKind,
	constants.ClusterInfoKind,
	constants.LabelIdentityKind,
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-resourceexport,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=create;update;delete,versions=v1alpha1,name=vresourceexport.kb.io,admissionReviewVersions={v1}

type resourceExportValidator struct {
	Client    client.Client
	decoder   admission.Decoder
	namespace string
	saName    string
}

// expectedResourceExportName returns the name a member cluster with the given
// ClusterID must use for the ResourceExport, matching the member-side
// controllers' naming conventions, and whether the name can be derived from the
// export spec.
func expectedResourceExportName(clusterID string, re *mcv1alpha1.ResourceExport) (string, bool) {
	switch re.Spec.Kind {
	case constants.ServiceKind:
		return common.NewResourceExportName(clusterID, re.Spec.Namespace, re.Spec.Name, "service"), true
	case constants.EndpointsKind:
		return common.NewResourceExportName(clusterID, re.Spec.Namespace, re.Spec.Name, "endpoints"), true
	case constants.LabelIdentityKind:
		if re.Spec.LabelIdentity == nil {
			return "", false
		}
		return common.NewLabelIdentityResourceExportName(clusterID, re.Spec.LabelIdentity.NormalizedLabel), true
	case constants.ClusterInfoKind:
		return common.NewClusterInfoResourceExportName(clusterID), true
	}
	return "", false
}

// Handle handles admission requests.
func (v *resourceExportValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update && req.Operation != admissionv1.Delete {
		return admission.Allowed("")
	}

	ui := req.UserInfo
	saNamespace, saName, err := serviceaccount.SplitUsername(ui.Username)
	if err != nil {
		// Not a ServiceAccount, allow by default (e.g. cluster admins creating ACNP exports)
		return admission.Allowed("")
	}

	// We only restrict member cluster SAs which are in the leader namespace.
	// Members always authenticate with a ServiceAccount created in the leader
	// Namespace (see 'antctl mc create membertoken'), so ServiceAccounts in any
	// other Namespace - and non-ServiceAccount users - are trusted callers (e.g.
	// cluster admins creating AntreaClusterNetworkPolicy exports).
	if saNamespace != v.namespace {
		return admission.Allowed("")
	}

	// Exempt the leader controller's own ServiceAccount for Update and Delete operations
	// (finalizer removal and stale ResourceExport cleanup). Create is intentionally not
	// exempted: the leader controller never creates ResourceExports, so exempting it would
	// widen the bypass without need. The Namespace boundary check above already guarantees
	// the caller is in the leader Namespace, so a same-named ServiceAccount in another
	// Namespace cannot be exempted.
	if isLeaderControllerServiceAccount(saNamespace, saName, v.namespace, v.saName, req.Operation) {
		return admission.Allowed("")
	}

	serviceAccount := &v1.ServiceAccount{}
	if err := v.Client.Get(ctx, client.ObjectKey{Namespace: saNamespace, Name: saName}, serviceAccount); err != nil {
		if apierrors.IsNotFound(err) {
			if req.Operation == admissionv1.Delete {
				// The caller's identity cannot be verified when its ServiceAccount is
				// missing, so only allow the Delete if the object is already being
				// removed (e.g. leader Namespace teardown), when the GC just needs the
				// finalizer released. Anything else would let any caller whose SA is
				// gone delete arbitrary ResourceExports.
				oldExport := &mcv1alpha1.ResourceExport{}
				if err := v.decoder.DecodeRaw(req.OldObject, oldExport); err != nil {
					klog.ErrorS(err, "Error while decoding old ResourceExport")
					return admission.Errored(http.StatusBadRequest, err)
				}
				if !oldExport.DeletionTimestamp.IsZero() {
					return admission.Allowed("")
				}
			}
			klog.InfoS("Denying ResourceExport: ServiceAccount not found", "user", ui.Username)
			return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("ServiceAccount not found"))
		}
		klog.ErrorS(err, "Failed to get ServiceAccount", "namespace", saNamespace, "name", saName)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Policy: any ServiceAccount in the leader Namespace without the ClusterID
	// annotation is fully trusted, for every kind, AntreaClusterNetworkPolicy
	// included. This is deliberate - an escape hatch for cluster admins creating
	// ACNP exports on the leader (the leader controller's own SA is exempted for
	// Update/Delete above, but not for Create). It is the annotation, not the
	// RBAC, that gates every check below.
	//
	// Consequence: the pre-migration shared antrea-mc-member-access-sa lands in
	// exactly this branch, so none of the identity checks apply to a cluster
	// still holding that credential. The MemberClusterAnnounce binding bounds
	// but does not close the bypass: an unmigrated member's heartbeat is denied
	// at the leader webhook and its ResourceExports are reaped ~24h later. The
	// shared SA itself is only deleted at upgrade step 5, so an operator who
	// skips that step leaves a live, webhook-exempt member credential on the
	// leader indefinitely.
	clusterID, isMember := serviceAccount.Annotations[constants.ServiceAccountClusterIDAnnotation]
	if !isMember {
		// Not a member cluster SA
		return admission.Allowed("")
	}
	if clusterID == "" {
		klog.InfoS("Denying ResourceExport: ServiceAccount has empty clusterID annotation", "user", ui.Username)
		return admission.Denied("ClusterID annotation on ServiceAccount is empty")
	}

	oldExport := &mcv1alpha1.ResourceExport{}
	if req.Operation == admissionv1.Update || req.Operation == admissionv1.Delete {
		if err := v.decoder.DecodeRaw(req.OldObject, oldExport); err != nil {
			klog.ErrorS(err, "Error while decoding old ResourceExport")
			return admission.Errored(http.StatusBadRequest, err)
		}
		if oldExport.Spec.ClusterID != clusterID {
			klog.InfoS(
				"Denying ResourceExport: attempt to modify or delete another member's ResourceExport",
				"callerClusterID", clusterID,
				"ownerClusterID", oldExport.Spec.ClusterID,
				"user", ui.Username,
				"operation", req.Operation,
			)
			return admission.Denied("Member cluster is not authorized to modify or delete ResourceExports owned by another member")
		}
	}

	if req.Operation == admissionv1.Delete {
		return admission.Allowed("")
	}

	resourceExport := &mcv1alpha1.ResourceExport{}
	if err := v.decoder.Decode(req, resourceExport); err != nil {
		klog.ErrorS(err, "Error while decoding ResourceExport")
		return admission.Errored(http.StatusBadRequest, err)
	}

	// The ResourceExportFinalizer is what lets the leader clean up the
	// ResourceImport (and the member's Gateway info with it) when the export is
	// deleted. A member that drops it before deleting its export would leave the
	// ResourceImport behind, imported by every other member indefinitely.
	if req.Operation == admissionv1.Update {
		oldHasFinalizer := slices.Contains(oldExport.Finalizers, constants.ResourceExportFinalizer) || slices.Contains(oldExport.Finalizers, constants.LegacyResourceExportFinalizer)
		newHasFinalizer := slices.Contains(resourceExport.Finalizers, constants.ResourceExportFinalizer) || slices.Contains(resourceExport.Finalizers, constants.LegacyResourceExportFinalizer)
		if oldHasFinalizer && !newHasFinalizer {
			klog.InfoS(
				"Denying ResourceExport: member cluster not authorized to remove finalizer",
				"clusterID", clusterID,
				"name", resourceExport.Name,
				"user", ui.Username,
			)
			return admission.Denied("Member cluster is not authorized to remove the ResourceExport finalizer")
		}
	}

	// For Service and Endpoints exports the spec tuple (Namespace, Name, Kind)
	// derives both the export name and the ResourceImport name (see
	// GetResourceImportName); the object name is fixed for the lifetime of the
	// export, so the tuple must not move under it on UPDATE. Without this, a
	// member could flip its own tuple to an ambiguous equivalent (e.g. ns "a" /
	// name "b-c" -> ns "a-b" / name "c") that derives the same export name but a
	// different ResourceImport, orphaning the import and breaking reconciles.
	// The guard is deliberately scoped to these two kinds: for LabelIdentity and
	// ClusterInfo the export name does not embed the tuple (it derives from the
	// label hash and the ClusterID respectively), and a ClusterInfo update can
	// legitimately change Spec.Namespace when the member controller is redeployed
	// into a different local Namespace.
	if req.Operation == admissionv1.Update &&
		(resourceExport.Spec.Kind == constants.ServiceKind || resourceExport.Spec.Kind == constants.EndpointsKind) {
		if resourceExport.Spec.Namespace != oldExport.Spec.Namespace ||
			resourceExport.Spec.Name != oldExport.Spec.Name ||
			resourceExport.Spec.Kind != oldExport.Spec.Kind {
			klog.InfoS(
				"Denying ResourceExport: spec tuple is immutable",
				"clusterID", clusterID,
				"name", resourceExport.Name,
				"user", ui.Username,
			)
			return admission.Denied("Spec.Namespace, Spec.Name and Spec.Kind are immutable")
		}
	}

	// Validate identity-to-kind
	// Member clusters are only allowed to export certain kinds.
	// They are NOT allowed to export AntreaClusterNetworkPolicy.
	if !memberAllowedResourceExportKinds.Has(resourceExport.Spec.Kind) {
		klog.InfoS(
			"Denying ResourceExport: member cluster not authorized for kind",
			"clusterID", clusterID,
			"kind", resourceExport.Spec.Kind,
			"user", ui.Username,
		)
		// Do not return caller's clusterID in the error message
		return admission.Denied("Member cluster is not authorized to export this kind")
	}

	// Validate the kind-specific payload is present. The leader controller
	// dereferences these fields when reconciling the export (e.g. Service
	// exports to build the ServiceImport, Endpoints exports to build the
	// Endpoints import), so a member must not be able to submit a kind with a
	// nil payload and crash the leader. LabelIdentity exports are already
	// covered by the name derivation below, and ClusterInfo payloads are never
	// dereferenced by the leader.
	if resourceExport.Spec.Kind == constants.ServiceKind && resourceExport.Spec.Service == nil {
		klog.InfoS(
			"Denying ResourceExport: Service kind with nil payload",
			"clusterID", clusterID,
			"name", resourceExport.Name,
			"user", ui.Username,
		)
		return admission.Denied("Member cluster is not authorized to create a Service ResourceExport without Spec.Service")
	}
	if resourceExport.Spec.Kind == constants.EndpointsKind && resourceExport.Spec.Endpoints == nil {
		klog.InfoS(
			"Denying ResourceExport: Endpoints kind with nil payload",
			"clusterID", clusterID,
			"name", resourceExport.Name,
			"user", ui.Username,
		)
		return admission.Denied("Member cluster is not authorized to create an Endpoints ResourceExport without Spec.Endpoints")
	}

	// Spec.Namespace and Spec.Name reach name construction here and the label
	// selectors on the leader, but nothing else validates them. A member can
	// submit values containing '/', whitespace, or 200 characters; the derived
	// name is then either rejected by the API server (and the member's
	// reconcile loops forever) or over-length. The check does NOT close the dash
	// ambiguity - "1-default" is a perfectly legal DNS-1123 label.
	if resourceExport.Spec.Kind == constants.ServiceKind || resourceExport.Spec.Kind == constants.EndpointsKind {
		if errs := validation.IsDNS1123Label(resourceExport.Spec.Namespace); len(errs) > 0 {
			klog.InfoS(
				"Denying ResourceExport: Spec.Namespace is not a valid DNS-1123 label",
				"clusterID", clusterID,
				"name", resourceExport.Name,
				"user", ui.Username,
			)
			return admission.Denied("Spec.Namespace must be a valid DNS-1123 label")
		}
		if errs := validation.IsDNS1123Label(resourceExport.Spec.Name); len(errs) > 0 {
			klog.InfoS(
				"Denying ResourceExport: Spec.Name is not a valid DNS-1123 label",
				"clusterID", clusterID,
				"name", resourceExport.Name,
				"user", ui.Username,
			)
			return admission.Denied("Spec.Name must be a valid DNS-1123 label")
		}
	}

	// Bind identity to ClusterID
	if resourceExport.Spec.ClusterID != clusterID {
		klog.InfoS(
			"Denying ResourceExport: ClusterID spoofing attempt",
			"callerClusterID", clusterID,
			"payloadClusterID", resourceExport.Spec.ClusterID,
			"user", ui.Username,
		)
		// Do not return callerClusterID or payloadClusterID to the user to prevent information leakage
		return admission.Denied("Member cluster is not authorized to spoof ClusterID in ResourceExport")
	}

	// Bind identity to the SourceClusterID label
	// The leader controller attributes ResourceExports to clusters via the
	// SourceClusterID label set by the exporting member (see the leader
	// ResourceExportReconciler), so it must match the caller's identity as well.
	if resourceExport.Labels[constants.SourceClusterID] != clusterID {
		klog.InfoS(
			"Denying ResourceExport: SourceClusterID label does not match caller identity",
			"callerClusterID", clusterID,
			"labelClusterID", resourceExport.Labels[constants.SourceClusterID],
			"user", ui.Username,
		)
		// Do not return callerClusterID or labelClusterID to the user to prevent information leakage
		return admission.Denied("Member cluster is not authorized to spoof SourceClusterID in ResourceExport")
	}

	// Bind identity to the remaining source labels
	// The leader's ResourceExportReconciler groups sibling exports by the
	// sourceNamespace/sourceName/sourceKind labels (getLabelSelector) and merges
	// their Endpoints subsets into a single ResourceImport, so those labels must
	// match the export spec; otherwise a member could inject subsets into - or
	// nil-dereference the leader controller while processing - another member's
	// import. The member controllers set sourceKind for every kind, and
	// sourceName/sourceNamespace for Service and Endpoints exports.
	if resourceExport.Labels[constants.SourceKind] != resourceExport.Spec.Kind {
		klog.InfoS(
			"Denying ResourceExport: SourceKind label does not match export kind",
			"callerClusterID", clusterID,
			"labelKind", resourceExport.Labels[constants.SourceKind],
			"kind", resourceExport.Spec.Kind,
			"user", ui.Username,
		)
		return admission.Denied("Member cluster is not authorized to spoof SourceKind label in ResourceExport")
	}
	if resourceExport.Spec.Kind == constants.ServiceKind || resourceExport.Spec.Kind == constants.EndpointsKind {
		if resourceExport.Labels[constants.SourceName] != resourceExport.Spec.Name ||
			resourceExport.Labels[constants.SourceNamespace] != resourceExport.Spec.Namespace {
			klog.InfoS(
				"Denying ResourceExport: source labels do not match export spec",
				"callerClusterID", clusterID,
				"labelName", resourceExport.Labels[constants.SourceName],
				"labelNamespace", resourceExport.Labels[constants.SourceNamespace],
				"specName", resourceExport.Spec.Name,
				"specNamespace", resourceExport.Spec.Namespace,
				"user", ui.Username,
			)
			return admission.Denied("Member cluster is not authorized to spoof source labels in ResourceExport")
		}
	}

	// Bind identity to the ResourceExport name
	// Member export names embed the owning ClusterID and are fully derivable from
	// the export spec (member getResourceExportName and
	// getResourceExportNameForLabelIdentity). Matching the exact expected name -
	// rather than just a "<clusterID>-" prefix - prevents a member from creating
	// the names that its peers' controllers compute, including the direct
	// dash-prefix case: a member whose ClusterID is a prefix of another member's
	// (e.g. "east" vs "east-1") cannot take the peer's names verbatim.
	//
	// Residual: a member can still claim an ambiguous tuple (e.g. ns "1-default" /
	// name "nginx") that derives the same name as the peer's (default/nginx). This
	// is accepted: it is a targeted denial of one Service export, not a hijack
	// (GetResourceImportName derives from the tuple, so imports do not collide),
	// it requires an already-onboarded member whose ClusterID is a dash-prefix of
	// the victim's, and the MemberClusterAnnounce webhook and antctl refuse to
	// register such a pair in the first place.
	expectedName, derivable := expectedResourceExportName(clusterID, resourceExport)
	if !derivable {
		klog.InfoS(
			"Denying ResourceExport: cannot derive expected name for kind",
			"callerClusterID", clusterID,
			"kind", resourceExport.Spec.Kind,
			"user", ui.Username,
		)
		return admission.Denied("Invalid ResourceExport for this member cluster")
	}
	if resourceExport.Name != expectedName {
		klog.InfoS(
			"Denying ResourceExport: name does not match caller identity",
			"callerClusterID", clusterID,
			"name", resourceExport.Name,
			"user", ui.Username,
		)
		// Do not return the expected name pattern to the user
		return admission.Denied("Invalid ResourceExport name for this member cluster")
	}

	// ClusterInfo specific validation
	if resourceExport.Spec.Kind == constants.ClusterInfoKind {
		if resourceExport.Spec.ClusterInfo != nil && resourceExport.Spec.ClusterInfo.ClusterID != clusterID {
			klog.InfoS(
				"Denying ResourceExport: ClusterInfo.ClusterID spoofing attempt",
				"callerClusterID", clusterID,
				"payloadClusterID", resourceExport.Spec.ClusterInfo.ClusterID,
			)
			// Do not return callerClusterID or payloadClusterID to the user
			return admission.Denied("Member cluster is not authorized to spoof ClusterInfo.ClusterID")
		}
	}

	// The ResourceExportFinalizer is what lets the leader clean up the
	// ResourceImport when the export is deleted (see the finalizer check on
	// UPDATE above). A member that creates an export without it can delete the
	// export later without the leader ever observing the deletion, leaving the
	// ResourceImport behind. The member controllers always set the finalizer on
	// create; LabelIdentity exports are exempt because their imports are not
	// cleaned up through this mechanism.
	if req.Operation == admissionv1.Create && resourceExport.Spec.Kind != constants.LabelIdentityKind {
		if !slices.Contains(resourceExport.Finalizers, constants.ResourceExportFinalizer) &&
			!slices.Contains(resourceExport.Finalizers, constants.LegacyResourceExportFinalizer) {
			klog.InfoS(
				"Denying ResourceExport: member cluster not authorized to create without the ResourceExport finalizer",
				"clusterID", clusterID,
				"kind", resourceExport.Spec.Kind,
				"name", resourceExport.Name,
				"user", ui.Username,
			)
			return admission.Denied("Member cluster is not authorized to create a ResourceExport without the ResourceExport finalizer")
		}
	}

	return admission.Allowed("")
}
