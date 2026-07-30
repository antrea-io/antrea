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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/apis"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const testNamespace = "kube-system"

var (
	authorizedUserInfo = authenticationv1.UserInfo{
		Username: "authorized-user",
		UID:      "authorized-uid",
		Groups:   []string{"system:authenticated", "packet-capturers"},
		Extra:    map[string]authenticationv1.ExtraValue{"scopes.authorization.openshift.io": {"user:info"}},
	}
	unauthorizedUserInfo = authenticationv1.UserInfo{
		Username: "unauthorized-user",
		UID:      "unauthorized-uid",
		Groups:   []string{"system:authenticated"},
	}
)

// expectedSARSpecForUser returns the SubjectAccessReview the webhook must issue on behalf of the
// given user: the requester's full identity is forwarded, and the resource attributes must match
// the get that the antrea-agent would later perform on the file server authentication Secret.
func expectedSARSpecForUser(ui authenticationv1.UserInfo) *authorizationv1.SubjectAccessReviewSpec {
	var extra map[string]authorizationv1.ExtraValue
	if len(ui.Extra) > 0 {
		extra = make(map[string]authorizationv1.ExtraValue, len(ui.Extra))
		for k, v := range ui.Extra {
			extra[k] = authorizationv1.ExtraValue(v)
		}
	}
	return &authorizationv1.SubjectAccessReviewSpec{
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: testNamespace,
			Verb:      "get",
			Resource:  "secrets",
			Name:      apis.AntreaPacketCaptureFileServerAuthSecretName,
		},
		User:   ui.Username,
		Groups: ui.Groups,
		UID:    ui.UID,
		Extra:  extra,
	}
}

func marshal(t *testing.T, object runtime.Object) []byte {
	t.Helper()
	raw, err := json.Marshal(object)
	require.NoError(t, err)
	return raw
}

func newPacketCapture(fileServerURL string) *crdv1alpha1.PacketCapture {
	pc := &crdv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Name: "pc"},
		Spec:       crdv1alpha1.PacketCaptureSpec{},
	}
	if fileServerURL != "" {
		pc.Spec.FileServer = &crdv1alpha1.PacketCaptureFileServer{URL: fileServerURL}
	}
	return pc
}

const (
	trustedURL  = "sftp://sftp.example.com:22/upload/"
	attackerURL = "sftp://attacker.example.com:22/upload/"
)

func TestValidate(t *testing.T) {
	unauthorizedResponse := &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: `user "unauthorized-user" is not authorized to get Secret kube-system/antrea-packetcapture-fileserver-auth used to authenticate to the file server`,
		},
	}

	tests := []struct {
		name      string
		operation admv1.Operation
		userInfo  authenticationv1.UserInfo
		oldPC     *crdv1alpha1.PacketCapture
		pc        *crdv1alpha1.PacketCapture
		// sarError, when set, is returned instead of answering the SubjectAccessReview.
		sarError         error
		expectedResponse *admv1.AdmissionResponse
		// expectedSARSpec is the SubjectAccessReview the webhook is expected to issue. When
		// nil, no SubjectAccessReview must be issued.
		expectedSARSpec *authorizationv1.SubjectAccessReviewSpec
	}{
		{
			name:             "no file server is allowed without authorization",
			operation:        admv1.Create,
			userInfo:         unauthorizedUserInfo,
			pc:               newPacketCapture(""),
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:             "file server with authorized user is allowed",
			operation:        admv1.Create,
			userInfo:         authorizedUserInfo,
			pc:               newPacketCapture(attackerURL),
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
			expectedSARSpec:  expectedSARSpecForUser(authorizedUserInfo),
		},
		{
			name:             "file server with unauthorized user is rejected",
			operation:        admv1.Create,
			userInfo:         unauthorizedUserInfo,
			pc:               newPacketCapture(attackerURL),
			expectedResponse: unauthorizedResponse,
			expectedSARSpec:  expectedSARSpecForUser(unauthorizedUserInfo),
		},
		{
			name:             "update adding a file server with unauthorized user is rejected",
			operation:        admv1.Update,
			userInfo:         unauthorizedUserInfo,
			oldPC:            newPacketCapture(""),
			pc:               newPacketCapture(attackerURL),
			expectedResponse: unauthorizedResponse,
			expectedSARSpec:  expectedSARSpecForUser(unauthorizedUserInfo),
		},
		{
			// An existing CR must not be repointed at a file server of the requester's
			// choosing without the requester being able to read the Secret.
			name:             "update repointing the file server with unauthorized user is rejected",
			operation:        admv1.Update,
			userInfo:         unauthorizedUserInfo,
			oldPC:            newPacketCapture(trustedURL),
			pc:               newPacketCapture(attackerURL),
			expectedResponse: unauthorizedResponse,
			expectedSARSpec:  expectedSARSpecForUser(unauthorizedUserInfo),
		},
		{
			// The file server was already authorized when it was set, so an update which
			// leaves it untouched (e.g. a metadata-only edit) must not require the
			// requester to be able to read the Secret.
			name:             "update leaving the file server unchanged",
			operation:        admv1.Update,
			userInfo:         unauthorizedUserInfo,
			oldPC:            newPacketCapture(trustedURL),
			pc:               newPacketCapture(trustedURL),
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			// The check is fail-closed: when the SubjectAccessReview cannot be completed
			// (e.g. the kube-apiserver is too slow to answer before authorizationTimeout),
			// the request must be denied rather than admitted.
			name:      "create when the SubjectAccessReview fails",
			operation: admv1.Create,
			userInfo:  authorizedUserInfo,
			pc:        newPacketCapture(attackerURL),
			sarError:  errors.New("etcdserver: request timed out"),
			expectedResponse: &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: "failed to authorize access to file server authentication Secret kube-system/antrea-packetcapture-fileserver-auth: etcdserver: request timed out",
				},
			},
			expectedSARSpec: expectedSARSpecForUser(authorizedUserInfo),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			// Record every SubjectAccessReview and authorize all requesters except
			// unauthorizedUserInfo, so the check rejects only the confused-deputy case.
			var gotSARs []*authorizationv1.SubjectAccessReview
			client.PrependReactor("create", "subjectaccessreviews",
				func(action k8stesting.Action) (bool, runtime.Object, error) {
					sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
					gotSARs = append(gotSARs, sar)
					if tt.sarError != nil {
						return true, nil, tt.sarError
					}
					sar.Status.Allowed = sar.Spec.User != unauthorizedUserInfo.Username
					return true, sar, nil
				})
			v := NewValidator(client, testNamespace)
			review := &admv1.AdmissionReview{
				Request: &admv1.AdmissionRequest{
					Name:      tt.pc.Name,
					Operation: tt.operation,
					UserInfo:  tt.userInfo,
					Object:    runtime.RawExtension{Raw: marshal(t, tt.pc)},
				},
			}
			if tt.oldPC != nil {
				review.Request.OldObject = runtime.RawExtension{Raw: marshal(t, tt.oldPC)}
			}
			assert.Equal(t, tt.expectedResponse, v.Validate(review))
			if tt.expectedSARSpec == nil {
				assert.Empty(t, gotSARs, "No SubjectAccessReview should have been issued")
			} else {
				require.Len(t, gotSARs, 1)
				assert.Equal(t, *tt.expectedSARSpec, gotSARs[0].Spec)
			}
		})
	}
}
