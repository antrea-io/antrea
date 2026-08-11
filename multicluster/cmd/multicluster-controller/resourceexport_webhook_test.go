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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/common"
)

func TestResourceExportWebhook(t *testing.T) {
	existingServiceAccounts := &corev1.ServiceAccountList{
		Items: []corev1.ServiceAccount{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "east-access-sa",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "east",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "west-access-sa",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "west",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "admin-sa",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "empty-anno-sa",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "other-ns",
					Name:      "east-access-sa",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "east",
					},
				},
			},
		},
	}

	existingOtherMemberExport := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "west-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "west",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "west",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "west",
				PodCIDRs:  []string{"192.168.1.0/24", "2001:db8:1::/64"},
			},
		},
	}

	reValid := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ClusterInfoKind,
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "east",
				PodCIDRs:  []string{"192.168.0.0/24", "2001:db8:2::/64"},
			},
		},
	}

	// Same as reValid but without the ResourceExport finalizer: used as the new
	// object for the finalizer-removal deny and as the CREATE payload for the
	// finalizer-requirement deny.
	reValidNoFinalizer := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ClusterInfoKind,
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "east",
				PodCIDRs:  []string{"192.168.0.0/24", "2001:db8:2::/64"},
			},
		},
	}

	reValidService := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Same identity fields as reValidService but with no Service payload. The
	// leader dereferences Spec.Service when reconciling the export, so the
	// webhook must deny it.
	reNilServicePayload := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
		},
	}

	reValidEndpoints := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-endpoints",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.EndpointsKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.EndpointsKind,
			Name:      "nginx",
			Namespace: "default",
			Endpoints: &mcv1alpha1.EndpointsExport{},
		},
	}

	// Same identity fields as reValidEndpoints but with no Endpoints payload. The
	// leader dereferences Spec.Endpoints when reconciling the export, so the
	// webhook must deny it.
	reNilEndpointsPayload := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-endpoints",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.EndpointsKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.EndpointsKind,
			Name:      "nginx",
			Namespace: "default",
		},
	}

	normalizedLabel := "ns:app=web&pod:app=web"
	reValidLabelIdentity := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-" + common.HashLabelIdentity(normalizedLabel),
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.LabelIdentityKind,
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.LabelIdentityKind,
			LabelIdentity: &mcv1alpha1.LabelIdentityExport{
				NormalizedLabel: normalizedLabel,
			},
		},
	}

	reSpoofed := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "west-clusterinfo",
			Namespace: "mcs1",
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "west",
			Kind:      constants.ClusterInfoKind,
		},
	}

	reInvalidName := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wrong-name-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ClusterInfoKind,
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ClusterInfoKind,
		},
	}

	reSpoofedClusterInfoID := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ClusterInfoKind,
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "west",
			},
		},
	}

	// A ClusterID that is a prefix of another member's (e.g. "east-1") must not be
	// able to create the export names that the "east-1" controllers would compute.
	rePrefixAmbiguity := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-1-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Same identity fields as reValidService but a SourceKind label that does not
	// match Spec.Kind.
	reSpoofedSourceKind := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.EndpointsKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Same identity fields as reValidService but the SourceName label does not
	// match Spec.Name.
	reSpoofedSourceName := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "other",
				constants.SourceNamespace: "default",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Same identity fields as reValidService but the SourceNamespace label does
	// not match Spec.Namespace. Kept separate from reSpoofedSourceName so that
	// removing either label check fails its dedicated test.
	reSpoofedSourceNamespace := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "other",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	reWithFinalizer := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ClusterInfoKind,
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "east",
				PodCIDRs:  []string{"192.168.0.0/24", "2001:db8:2::/64"},
			},
		},
	}

	// A terminating export of a departed member, usable as the OldObject for the
	// SA-missing DELETE case.
	reTerminating := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "south2-clusterinfo",
			Namespace:         "mcs1",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers:        []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "south2",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "south2",
				PodCIDRs:  []string{"192.168.0.0/16"},
			},
		},
	}

	// The two tuples below concatenate to the same export name
	// ("east-a-b-c-service") but derive different ResourceImport names. The
	// UPDATE immutability guard must reject switching from one to the other on
	// an existing export; the object name cannot change, so the tuple is
	// required to stay put.
	reServiceTupleA := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-a-b-c-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "b-c",
				constants.SourceNamespace: "a",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "b-c",
			Namespace: "a",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	reServiceTupleB := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-a-b-c-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "c",
				constants.SourceNamespace: "a-b",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "c",
			Namespace: "a-b",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// The ClusterInfo export name does not embed the tuple (it derives from the
	// ClusterID alone), and the member controller sets Spec.Namespace to its own
	// local Namespace, which legitimately changes when the controller is
	// redeployed elsewhere without a clean leave. The UPDATE tuple guard must not
	// apply to this kind: switching to a different local Namespace under the same
	// name is allowed.
	reClusterInfoNamespace := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-clusterinfo",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ClusterInfoKind,
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Namespace: "kube-system",
			Kind:      constants.ClusterInfoKind,
			ClusterInfo: &mcv1alpha1.ClusterInfo{
				ClusterID: "east",
				PodCIDRs:  []string{"192.168.0.0/24", "2001:db8:2::/64"},
			},
		},
	}
	reClusterInfoNamespaceOther := reClusterInfoNamespace.DeepCopy()
	reClusterInfoNamespaceOther.Spec.Namespace = "antrea-multicluster"

	// Same identity fields as reValidService but with a Spec.Namespace that is
	// not a DNS-1123 label (contains '/').
	reInvalidDNSNamespace := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default/ns",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Same identity fields as reValidService but with a Spec.Name that is not a
	// DNS-1123 label (uppercase).
	reInvalidDNSName := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "Nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Documents the accepted residual of the exact-name binding: "east" claims a
	// tuple (ns "1-default" / name "nginx") that derives the same export name as
	// "east-1"'s (default/nginx) export. "1-default" is a legal DNS-1123 label and
	// the name matches the derived name, so every check passes; the import names
	// differ, so this is a targeted denial of one Service export, not a hijack.
	// Prefix pairs cannot be newly registered (MemberClusterAnnounce webhook and
	// antctl), which is what bounds this residual.
	reDashAmbiguousTuple := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-1-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "1-default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "1-default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	reInvalidKind := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-acnp",
			Namespace: "mcs1",
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.AntreaClusterNetworkPolicyKind,
		},
	}

	// Spoofs the SourceClusterID label while keeping Spec.ClusterID bound to the caller.
	// Same tuple as reValidService and carries the finalizer so the UPDATE denial is
	// attributed to the label, not to a finalizer removal or a tuple mutation.
	reSpoofedLabel := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "east-default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "west",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	// Valid identity fields (tuple and labels) but a name that does not embed the
	// caller's ClusterID.
	reWrongNamePrefix := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-nginx-service",
			Namespace: "mcs1",
			Labels: map[string]string{
				constants.SourceClusterID: "east",
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceName:      "nginx",
				constants.SourceNamespace: "default",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "east",
			Kind:      constants.ServiceKind,
			Name:      "nginx",
			Namespace: "default",
			Service:   &mcv1alpha1.ServiceExport{},
		},
	}

	reValidMarshaled, _ := json.Marshal(reValid)
	reValidNoFinalizerMarshaled, _ := json.Marshal(reValidNoFinalizer)
	reValidServiceMarshaled, _ := json.Marshal(reValidService)
	reValidEndpointsMarshaled, _ := json.Marshal(reValidEndpoints)
	reNilServicePayloadMarshaled, _ := json.Marshal(reNilServicePayload)
	reNilEndpointsPayloadMarshaled, _ := json.Marshal(reNilEndpointsPayload)
	reValidLabelIdentityMarshaled, _ := json.Marshal(reValidLabelIdentity)
	reSpoofedMarshaled, _ := json.Marshal(reSpoofed)
	reInvalidKindMarshaled, _ := json.Marshal(reInvalidKind)
	reSpoofedLabelMarshaled, _ := json.Marshal(reSpoofedLabel)
	reWrongNamePrefixMarshaled, _ := json.Marshal(reWrongNamePrefix)

	reInvalidNameMarshaled, _ := json.Marshal(reInvalidName)
	reSpoofedClusterInfoIDMarshaled, _ := json.Marshal(reSpoofedClusterInfoID)
	rePrefixAmbiguityMarshaled, _ := json.Marshal(rePrefixAmbiguity)
	reSpoofedSourceKindMarshaled, _ := json.Marshal(reSpoofedSourceKind)
	reSpoofedSourceNameMarshaled, _ := json.Marshal(reSpoofedSourceName)
	reSpoofedSourceNamespaceMarshaled, _ := json.Marshal(reSpoofedSourceNamespace)
	reWithFinalizerMarshaled, _ := json.Marshal(reWithFinalizer)
	reTerminatingMarshaled, _ := json.Marshal(reTerminating)
	reServiceTupleAMarshaled, _ := json.Marshal(reServiceTupleA)
	reServiceTupleBMarshaled, _ := json.Marshal(reServiceTupleB)
	reClusterInfoNamespaceMarshaled, _ := json.Marshal(reClusterInfoNamespace)
	reClusterInfoNamespaceOtherMarshaled, _ := json.Marshal(reClusterInfoNamespaceOther)
	reInvalidDNSNamespaceMarshaled, _ := json.Marshal(reInvalidDNSNamespace)
	reInvalidDNSNameMarshaled, _ := json.Marshal(reInvalidDNSName)
	reDashAmbiguousTupleMarshaled, _ := json.Marshal(reDashAmbiguousTuple)
	existingOtherMemberExportMarshaled, _ := json.Marshal(existingOtherMemberExport)

	eastUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:east-access-sa",
	}
	adminUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:admin-sa",
	}
	emptyAnnoUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:empty-anno-sa",
	}
	otherNSUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:other-ns:east-access-sa",
	}
	missingSAUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:missing-sa",
	}
	leaderUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:" + mcControllerSAName,
	}
	nonSAUserInfo := authenticationv1.UserInfo{
		Username: "system:user:alice",
	}

	reqAllow := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowService := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidServiceMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowEndpoints := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidEndpointsMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowLabelIdentity := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidLabelIdentityMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyNilServicePayload := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reNilServicePayloadMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyNilEndpointsPayload := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reNilEndpointsPayloadMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenySpoofed := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reSpoofedMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyInvalidKind := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidKindMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowAdminACNP := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidKindMarshaled,
			},
			UserInfo: adminUserInfo,
		},
	}

	reqAllowNonSA := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidKindMarshaled,
			},
			UserInfo: nonSAUserInfo,
		},
	}

	reqAllowOtherNS := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidKindMarshaled,
			},
			UserInfo: otherNSUserInfo,
		},
	}

	reqDenyMissingSA := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: missingSAUserInfo,
		},
	}

	reqDenyEmptyAnno := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: emptyAnnoUserInfo,
		},
	}

	// The leader controller SA is exempted for Update and Delete (finalizer removal and
	// stale cleanup), but not for Create. The SA is deliberately absent from the fixture
	// to prove that the exemption short-circuits the ServiceAccount lookup.
	reqAllowLeaderUpdate := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: existingOtherMemberExportMarshaled,
			},
			UserInfo: leaderUserInfo,
		},
	}

	reqAllowLeaderDelete := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Delete,
			OldObject: runtime.RawExtension{
				Raw: existingOtherMemberExportMarshaled,
			},
			UserInfo: leaderUserInfo,
		},
	}

	reqDenyLeaderCreate := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: leaderUserInfo,
		},
	}

	reqAllowDeleteMissingSATerminating := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Delete,
			OldObject: runtime.RawExtension{
				Raw: reTerminatingMarshaled,
			},
			UserInfo: missingSAUserInfo,
		},
	}

	reqDenyDeleteMissingSANonTerminating := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Delete,
			OldObject: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: missingSAUserInfo,
		},
	}

	reqDenyInvalidName := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidNameMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenySpoofedClusterInfoID := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reSpoofedClusterInfoIDMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	// "east" borrows the name that "east-1"'s ServiceExport controller computes.
	reqDenyPrefixAmbiguity := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: rePrefixAmbiguityMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenySpoofedSourceKind := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reSpoofedSourceKindMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenySpoofedSourceName := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reSpoofedSourceNameMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenySpoofedSourceNamespace := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reSpoofedSourceNamespaceMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowUpdateWithFinalizer := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reWithFinalizerMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reWithFinalizerMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyFinalizerRemoval := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reValidNoFinalizerMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reWithFinalizerMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyCreateNoFinalizer := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reValidNoFinalizerMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowUpdate := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyUpdateOtherMember := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: existingOtherMemberExportMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: existingOtherMemberExportMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenySpoofedLabel := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reSpoofedLabelMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyWrongNamePrefix := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reWrongNamePrefixMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	// UPDATE flipping the tuple from "a"/"b-c" to "a-b"/"c" under the same name.
	reqDenyUpdateTupleMutation := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reServiceTupleBMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reServiceTupleAMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowUpdateSameTuple := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reServiceTupleAMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reServiceTupleAMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	// ClusterInfo UPDATE switching Spec.Namespace to a different local Namespace
	// (member controller redeployed elsewhere without a clean leave): the tuple
	// guard does not apply to this kind, so the update is allowed.
	reqAllowUpdateClusterInfoNamespace := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reClusterInfoNamespaceOtherMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reClusterInfoNamespaceMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyInvalidDNSNamespace := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidDNSNamespaceMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyInvalidDNSName := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reInvalidDNSNameMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	// Documents the accepted residual: an ambiguous tuple (ns "1-default") that
	// derives the same export name as "east-1"'s export is allowed.
	reqAllowDashAmbiguousTuple := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: reDashAmbiguousTupleMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyUpdateSpoofedLabel := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: reSpoofedLabelMarshaled,
			},
			OldObject: runtime.RawExtension{
				Raw: reValidServiceMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqAllowDelete := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Delete,
			OldObject: runtime.RawExtension{
				Raw: reValidMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	reqDenyDeleteOtherMember := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Operation: v1.Delete,
			OldObject: runtime.RawExtension{
				Raw: existingOtherMemberExportMarshaled,
			},
			UserInfo: eastUserInfo,
		},
	}

	type testCase struct {
		name        string
		req         admission.Request
		isAllowed   bool
		code        int32
		expectedMsg string
	}

	tests := []testCase{
		{
			name:      "Allow valid ResourceExport from member",
			req:       reqAllow,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow valid Service ResourceExport from member",
			req:       reqAllowService,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow valid Endpoints ResourceExport from member",
			req:       reqAllowEndpoints,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow valid LabelIdentity ResourceExport from member",
			req:       reqAllowLabelIdentity,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow UPDATE owned ResourceExport",
			req:       reqAllowUpdate,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:        "Deny UPDATE another member's ResourceExport",
			req:         reqDenyUpdateOtherMember,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "modify or delete ResourceExports owned by another member",
		},
		{
			name:      "Allow DELETE owned ResourceExport",
			req:       reqAllowDelete,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:        "Deny DELETE another member's ResourceExport",
			req:         reqDenyDeleteOtherMember,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "modify or delete ResourceExports owned by another member",
		},
		{
			name:        "Deny valid ResourceExport with invalid name for ClusterInfo",
			req:         reqDenyInvalidName,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "Invalid ResourceExport name",
		},
		{
			name:        "Deny name that borrows another member's ClusterID prefix",
			req:         reqDenyPrefixAmbiguity,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "Invalid ResourceExport name",
		},
		{
			name:        "Deny valid ResourceExport with spoofed ClusterInfo.ClusterID",
			req:         reqDenySpoofedClusterInfoID,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof ClusterInfo.ClusterID",
		},
		{
			name:        "Deny spoofed ClusterID from member",
			req:         reqDenySpoofed,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof ClusterID in ResourceExport",
		},
		{
			name:        "Deny spoofed SourceClusterID label from member",
			req:         reqDenySpoofedLabel,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof SourceClusterID",
		},
		{
			name:        "Deny ResourceExport with name not bound to caller ClusterID",
			req:         reqDenyWrongNamePrefix,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "Invalid ResourceExport name",
		},
		{
			name:        "Deny UPDATE with spoofed SourceClusterID label",
			req:         reqDenyUpdateSpoofedLabel,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof SourceClusterID",
		},
		{
			name:        "Deny invalid kind from member",
			req:         reqDenyInvalidKind,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "not authorized to export this kind",
		},
		{
			name:      "Allow ACNP from admin",
			req:       reqAllowAdminACNP,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow non-ServiceAccount user",
			req:       reqAllowNonSA,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow ServiceAccount in another Namespace",
			req:       reqAllowOtherNS,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Deny missing ServiceAccount",
			req:       reqDenyMissingSA,
			isAllowed: false,
			code:      http.StatusPreconditionFailed,
		},
		{
			name:      "Allow leader controller SA to UPDATE another member's ResourceExport",
			req:       reqAllowLeaderUpdate,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow leader controller SA to DELETE another member's ResourceExport",
			req:       reqAllowLeaderDelete,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:        "Deny leader controller SA CREATE (not exempted)",
			req:         reqDenyLeaderCreate,
			isAllowed:   false,
			code:        http.StatusPreconditionFailed,
			expectedMsg: "ServiceAccount not found",
		},
		{
			name:      "Allow DELETE of a terminating export when member ServiceAccount is missing",
			req:       reqAllowDeleteMissingSATerminating,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:        "Deny DELETE of a live export when member ServiceAccount is missing",
			req:         reqDenyDeleteMissingSANonTerminating,
			isAllowed:   false,
			code:        http.StatusPreconditionFailed,
			expectedMsg: "ServiceAccount not found",
		},
		{
			name:        "Deny ServiceAccount with empty clusterID annotation",
			req:         reqDenyEmptyAnno,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "ClusterID annotation on ServiceAccount is empty",
		},
		{
			name:        "Deny ResourceExport with spoofed SourceKind label",
			req:         reqDenySpoofedSourceKind,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof SourceKind label",
		},
		{
			name:        "Deny Service CREATE with nil payload",
			req:         reqDenyNilServicePayload,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "without Spec.Service",
		},
		{
			name:        "Deny Endpoints CREATE with nil payload",
			req:         reqDenyNilEndpointsPayload,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "without Spec.Endpoints",
		},
		{
			name:        "Deny ResourceExport with spoofed source labels",
			req:         reqDenySpoofedSourceName,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof source labels",
		},
		{
			name:        "Deny ResourceExport with spoofed SourceNamespace label",
			req:         reqDenySpoofedSourceNamespace,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "spoof source labels",
		},
		{
			name:      "Allow UPDATE keeping the ResourceExport finalizer",
			req:       reqAllowUpdateWithFinalizer,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:        "Deny UPDATE removing the ResourceExport finalizer",
			req:         reqDenyFinalizerRemoval,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "remove the ResourceExport finalizer",
		},
		{
			name:        "Deny CREATE without the ResourceExport finalizer",
			req:         reqDenyCreateNoFinalizer,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "without the ResourceExport finalizer",
		},
		{
			name:        "Deny UPDATE mutating the spec tuple under the same name",
			req:         reqDenyUpdateTupleMutation,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "are immutable",
		},
		{
			name:      "Allow UPDATE keeping the spec tuple unchanged",
			req:       reqAllowUpdateSameTuple,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:      "Allow ClusterInfo UPDATE changing Spec.Namespace",
			req:       reqAllowUpdateClusterInfoNamespace,
			isAllowed: true,
			code:      http.StatusOK,
		},
		{
			name:        "Deny Service CREATE with non-DNS-1123 Spec.Namespace",
			req:         reqDenyInvalidDNSNamespace,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "Spec.Namespace must be a valid DNS-1123 label",
		},
		{
			name:        "Deny Service CREATE with non-DNS-1123 Spec.Name",
			req:         reqDenyInvalidDNSName,
			isAllowed:   false,
			code:        http.StatusForbidden,
			expectedMsg: "Spec.Name must be a valid DNS-1123 label",
		},
		{
			name:      "Allow ambiguous tuple that derives the same name as a peer's export (accepted residual)",
			req:       reqAllowDashAmbiguousTuple,
			isAllowed: true,
			code:      http.StatusOK,
		},
	}

	decoder := admission.NewDecoder(common.TestScheme)
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(existingServiceAccounts).WithRuntimeObjects(existingOtherMemberExport, reTerminating).Build()
	validator := &resourceExportValidator{
		Client:    fakeClient,
		decoder:   decoder,
		namespace: "mcs1",
		saName:    mcControllerSAName,
	}

	runCases := func(v *resourceExportValidator, cases []testCase) {
		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				response := v.Handle(context.Background(), tt.req)
				assert.Equal(t, tt.isAllowed, response.Allowed)
				if response.Result != nil {
					assert.Equal(t, tt.code, response.Result.Code)
					if !tt.isAllowed && tt.expectedMsg != "" {
						assert.Contains(t, response.Result.Message, tt.expectedMsg)
					}
				} else if tt.isAllowed {
					// admission.Allowed("") returns a response with nil Result.
					// We consider this equivalent to StatusOK for our test cases.
					assert.Equal(t, int32(http.StatusOK), tt.code)
				} else {
					t.Errorf("Expected denied response to have a Result code, but got nil")
				}
			})
		}
	}

	runCases(validator, tests)
}
