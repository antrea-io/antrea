// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package supportbundlecollection

import (
	"encoding/json"
	"fmt"
	"reflect"

	"golang.org/x/crypto/ssh"
	admv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/controller/validation"
)

// validateAuthSecretAccess checks that the user who issued the admission request is themselves
// authorized to read the Secret referenced by spec.authentication.authSecret, so that the
// antrea-controller's privileged client cannot be used as a confused deputy to read Secrets on
// their behalf and upload their contents to an arbitrary file server. The check is equivalent to
// the get that the antrea-controller will later perform on that Secret.
func validateAuthSecretAccess(kubeClient kubernetes.Interface, ui authnv1.UserInfo, secretRef *corev1.SecretReference) error {
	status, err := validation.AuthorizeSecretGet(kubeClient, ui, secretRef.Namespace, secretRef.Name)
	if err != nil {
		return fmt.Errorf("failed to authorize access to authSecret %s/%s: %w", secretRef.Namespace, secretRef.Name, err)
	}
	if !status.Allowed {
		klog.InfoS("Rejecting SupportBundleCollection: requester cannot read the referenced authSecret",
			"user", ui.Username, "secret", klog.KRef(secretRef.Namespace, secretRef.Name),
			"reason", status.Reason, "evaluationError", status.EvaluationError)
		return fmt.Errorf("user %q is not authorized to get Secret %s/%s referenced in spec.authentication.authSecret", ui.Username, secretRef.Namespace, secretRef.Name)
	}
	return nil
}

func (c *Controller) Validate(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	klog.V(2).InfoS("Validating SupportBundleCollection", "request", review.Request)
	var newObj, oldObj crdv1alpha1.SupportBundleCollection
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current SupportBundleCollection")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing old SupportBundleCollection")
			return newAdmissionResponseForErr(err)
		}
	}

	// oldBundle is the version of the object being replaced, and is nil for a CREATE request.
	validate := func(bundle, oldBundle *crdv1alpha1.SupportBundleCollection) error {
		if bundle.Spec.FileServer.HostPublicKey != nil {
			if _, err := ssh.ParsePublicKey(bundle.Spec.FileServer.HostPublicKey); err != nil {
				return fmt.Errorf("invalid host public key: %w", err)
			}
		}
		if secretRef := bundle.Spec.Authentication.AuthSecret; secretRef != nil {
			// Both fields are optional in a SecretReference, but the controller reads the
			// Secret as a namespaced object. Requiring them keeps the authorization check
			// equivalent to the read that the controller will later perform: an empty
			// Namespace would otherwise turn the SubjectAccessReview into a cluster-scoped
			// check, which is evaluated against different RBAC rules.
			if secretRef.Name == "" || secretRef.Namespace == "" {
				return fmt.Errorf("spec.authentication.authSecret must specify both name and namespace")
			}
			// Only authorize the reference when the request actually changes
			// spec.authentication, or changes the file server the Secret is used to
			// authenticate to. That combination was already authorized when it was set, and
			// re-checking it would make unrelated updates (e.g. adding a label) fail for a
			// user who cannot read the Secret.
			// The whole of spec.authentication is compared, not just authSecret: authType
			// selects which keys of the Secret are read, so changing it sends different
			// contents of that Secret to the file server.
			// The file server must be part of the comparison too: a requester who cannot read
			// the Secret could otherwise leave spec.authentication untouched and repoint
			// spec.fileServer at a server they control, which is the same confused deputy, as
			// the antrea-agents authenticate to that URL with the Secret's credentials.
			if oldBundle == nil ||
				!reflect.DeepEqual(oldBundle.Spec.Authentication, bundle.Spec.Authentication) ||
				!reflect.DeepEqual(oldBundle.Spec.FileServer, bundle.Spec.FileServer) {
				if err := validateAuthSecretAccess(c.kubeClient, review.Request.UserInfo, secretRef); err != nil {
					return err
				}
			}
		}
		return nil
	}

	validateProcessingCollection := func() *admv1.AdmissionResponse {
		var msg string
		allowed := true
		_, exists, _ := c.supportBundleCollectionStore.Get(oldObj.Name)
		if exists {
			allowed = reflect.DeepEqual(oldObj.Spec, newObj.Spec)
			if !allowed {
				msg = fmt.Sprintf("SupportBundleCollection %s is started, cannot be updated", oldObj.Name)
			}
		}
		return validationResult(allowed, msg)
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for SupportBundleCollection")
		if err := validate(&newObj, nil); err != nil {
			return newAdmissionResponseForErr(err)
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for SupportBundleCollection")
		// A completed or already started collection is rejected whatever the new spec
		// contains, so check that before validate, which issues a SubjectAccessReview to the
		// kube-apiserver when the request changes spec.authentication or spec.fileServer.
		if isCollectionCompleted(&oldObj) {
			return validationResult(false, fmt.Sprintf("SupportBundleCollection %s is completed, cannot be updated", oldObj.Name))
		}
		if resp := validateProcessingCollection(); !resp.Allowed {
			return resp
		}
		if err := validate(&newObj, &oldObj); err != nil {
			return newAdmissionResponseForErr(err)
		}
	}

	return &admv1.AdmissionResponse{Allowed: true}
}

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func validationResult(allowed bool, msg string) *admv1.AdmissionResponse {
	var result *metav1.Status

	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
}
