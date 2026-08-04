// Copyright 2026 Antrea Authors
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

package packetcapture

import (
	"encoding/json"
	"fmt"
	"reflect"

	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/validation"
)

// Validator validates PacketCapture admission requests.
type Validator struct {
	client kubernetes.Interface
	// fileServerAuthNamespace is the Namespace holding the file server authentication Secret
	// (the Antrea Namespace).
	fileServerAuthNamespace string
}

// NewValidator returns a Validator for PacketCapture CRs. fileServerAuthNamespace is the
// Namespace where the file server authentication Secret lives (the Antrea Namespace).
func NewValidator(client kubernetes.Interface, fileServerAuthNamespace string) *Validator {
	return &Validator{
		client:                  client,
		fileServerAuthNamespace: fileServerAuthNamespace,
	}
}

func (v *Validator) Validate(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	klog.V(2).InfoS("Validating PacketCapture", "request", review.Request)
	var newObj, oldObj crdv1alpha1.PacketCapture
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current PacketCapture")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing old PacketCapture")
			return newAdmissionResponseForErr(err)
		}
	}

	// oldPC is the version of the object being replaced, and is nil for a CREATE request.
	switch review.Request.Operation {
	case admv1.Create:
		if err := v.validate(&newObj, nil, review.Request.UserInfo); err != nil {
			return newAdmissionResponseForErr(err)
		}
	case admv1.Update:
		if err := v.validate(&newObj, &oldObj, review.Request.UserInfo); err != nil {
			return newAdmissionResponseForErr(err)
		}
	}

	return &admv1.AdmissionResponse{Allowed: true}
}

func (v *Validator) validate(pc, oldPC *crdv1alpha1.PacketCapture, userInfo authenticationv1.UserInfo) error {
	// When the CR references a file server, the antrea-agent reads the fixed authentication
	// Secret with its own privileged ServiceAccount and sends the credential to the URL given
	// in the CR. Ensure the requesting user is themselves authorized to read that Secret, so the
	// agent's client cannot be used as a confused deputy to exfiltrate a Secret the requester
	// cannot read directly.
	if pc.Spec.FileServer == nil {
		return nil
	}
	// Only authorize the file server when the request actually sets or changes it. An unchanged
	// fileServer was already authorized when it was set, and re-checking it would make
	// unrelated updates (e.g. adding a label) fail for a user who cannot read the Secret.
	if oldPC != nil && reflect.DeepEqual(oldPC.Spec.FileServer, pc.Spec.FileServer) {
		return nil
	}
	status, err := validation.AuthorizeSecretGet(v.client, userInfo, v.fileServerAuthNamespace, apis.AntreaPacketCaptureFileServerAuthSecretName)
	if err != nil {
		return fmt.Errorf("failed to authorize access to file server authentication Secret %s/%s: %w", v.fileServerAuthNamespace, apis.AntreaPacketCaptureFileServerAuthSecretName, err)
	}
	if !status.Allowed {
		klog.InfoS("Rejecting PacketCapture: requester cannot read the file server authentication Secret",
			"user", userInfo.Username, "secret", klog.KRef(v.fileServerAuthNamespace, apis.AntreaPacketCaptureFileServerAuthSecretName),
			"reason", status.Reason, "evaluationError", status.EvaluationError)
		return fmt.Errorf("user %q is not authorized to get Secret %s/%s used to authenticate to the file server", userInfo.Username, v.fileServerAuthNamespace, apis.AntreaPacketCaptureFileServerAuthSecretName)
	}
	return nil
}

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
