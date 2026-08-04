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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	adminv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	sftptesting "antrea.io/antrea/v2/pkg/util/sftp/testing"
)

var (
	authorizedUserInfo = authnv1.UserInfo{
		Username: "authorized-user",
		UID:      "authorized-uid",
		Groups:   []string{"system:authenticated", "bundle-collectors"},
		Extra:    map[string]authnv1.ExtraValue{"scopes.authorization.openshift.io": {"user:info"}},
	}
	unauthorizedUserInfo = authnv1.UserInfo{
		Username: "unauthorized-user",
		UID:      "unauthorized-uid",
		Groups:   []string{"system:authenticated"},
	}
)

// expectedSARSpecForUser returns the SubjectAccessReview the webhook must issue for the
// "kube-system/sftp-auth" Secret on behalf of the given user: the requester's full identity
// is forwarded, and the resource attributes must match the get that the antrea-controller
// would later perform on that Secret.
func expectedSARSpecForUser(ui authnv1.UserInfo) *authzv1.SubjectAccessReviewSpec {
	var extra map[string]authzv1.ExtraValue
	if len(ui.Extra) > 0 {
		extra = make(map[string]authzv1.ExtraValue, len(ui.Extra))
		for k, v := range ui.Extra {
			extra[k] = authzv1.ExtraValue(v)
		}
	}
	return &authzv1.SubjectAccessReviewSpec{
		ResourceAttributes: &authzv1.ResourceAttributes{
			Namespace: "kube-system",
			Verb:      "get",
			Resource:  "secrets",
			Name:      "sftp-auth",
		},
		User:   ui.Username,
		Groups: ui.Groups,
		UID:    ui.UID,
		Extra:  extra,
	}
}

// authSecretName is the referenced Secret name used throughout this test; it is not a
// credential itself, only the name of a Secret containing one.
const authSecretName = "sftp-auth" // #nosec G101: not actual credentials

// newAuthSecretConfig returns a *bundleConfig referencing authSecretName in secretNamespace,
// with the given authType and fileServerURL, for the tests exercising the authSecret
// authorization check.
func newAuthSecretConfig(name string, authType crdv1alpha1.BundleServerAuthType, secretNamespace, fileServerURL string) *bundleConfig {
	return &bundleConfig{
		name:            name,
		authType:        authType,
		secretName:      authSecretName,
		secretNamespace: secretNamespace,
		fileServerURL:   fileServerURL,
	}
}

func TestValidateSupportBundleCollection(t *testing.T) {
	const name = "b1"
	existingConfig := &bundleConfig{
		name: name,
		nodes: &bundleNodes{
			labels: map[string]string{"test": "selected"},
		},
		externalNodes: &bundleExternalNodes{
			namespace: "ns1",
			labels:    map[string]string{"test": "selected"},
		},
		authType: crdv1alpha1.APIKey,
	}
	authentication := &controlplane.BundleServerAuthConfiguration{
		APIKey: "bundle_api_key", // #nosec G101: not actual credentials
	}
	nodeSpan := sets.New[string]("n1", "n2", "n3", "n4")
	expiredAt := metav1.NewTime(time.Now().Add(time.Minute))

	hostPublicKey, _, err := sftptesting.GenerateEd25519Key()
	require.NoError(t, err)

	tests := []struct {
		name               string
		requestOperation   adminv1.Operation
		requestUserInfo    authnv1.UserInfo
		existingCollection *bundleConfig
		collection         *bundleConfig
		existsInCache      bool
		existingStatus     *crdv1alpha1.SupportBundleCollectionStatus
		// sarError, when set, is returned instead of answering the SubjectAccessReview.
		sarError         error
		expectedResponse *adminv1.AdmissionResponse
		// expectedSARSpec is the SubjectAccessReview the webhook is expected to issue for
		// the referenced authSecret. When nil, no SubjectAccessReview must be issued.
		expectedSARSpec *authzv1.SubjectAccessReviewSpec
	}{
		{
			name:               "update before started",
			requestOperation:   adminv1.Update,
			existingCollection: existingConfig,
			collection: &bundleConfig{
				name: name,
				nodes: &bundleNodes{
					labels: map[string]string{"test": "selected"},
				},
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					labels:    map[string]string{"test": "selected"},
					names:     []string{"en1"},
				},
				authType: crdv1alpha1.APIKey,
			},
			existsInCache:    false,
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:               "delete before started",
			requestOperation:   adminv1.Delete,
			existingCollection: existingConfig,
			existsInCache:      false,
			expectedResponse:   &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:               "update after started",
			requestOperation:   adminv1.Update,
			existingCollection: existingConfig,
			collection: &bundleConfig{
				name: name,
				nodes: &bundleNodes{
					labels: map[string]string{"test": "selected"},
				},
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					labels:    map[string]string{"test": "selected"},
					names:     []string{"en1"},
				},
				authType: crdv1alpha1.APIKey,
			},
			existsInCache: true,
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is started, cannot be updated",
				},
			},
		}, {
			name:               "update status after started",
			requestOperation:   adminv1.Update,
			existingCollection: existingConfig,
			collection: &bundleConfig{
				name: name,
				nodes: &bundleNodes{
					labels: map[string]string{"test": "selected"},
				},
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					labels:    map[string]string{"test": "selected"},
				},
				authType: crdv1alpha1.APIKey,
				conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Status: metav1.ConditionTrue, Type: crdv1alpha1.CollectionStarted},
					{Status: metav1.ConditionTrue, Type: crdv1alpha1.BundleCollected},
				},
			},
			existsInCache: true,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:               "update after completed",
			requestOperation:   adminv1.Update,
			existingCollection: existingConfig,
			collection: &bundleConfig{
				name: name,
				nodes: &bundleNodes{
					labels: map[string]string{"test": "selected"},
				},
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					labels:    map[string]string{"test": "selected"},
					names:     []string{"en1"},
				},
				authType: crdv1alpha1.APIKey,
			},
			existsInCache: true,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: crdv1alpha1.CollectionCompleted, Status: metav1.ConditionTrue},
				},
			},
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is completed, cannot be updated",
				},
			},
		}, {
			name:               "update status after completed",
			requestOperation:   adminv1.Update,
			existingCollection: existingConfig,
			collection: &bundleConfig{
				name: name,
				nodes: &bundleNodes{
					labels: map[string]string{"test": "selected"},
				},
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					labels:    map[string]string{"test": "selected"},
				},
				authType: crdv1alpha1.APIKey,
				conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Status: metav1.ConditionTrue, Type: crdv1alpha1.CollectionStarted},
					{Status: metav1.ConditionTrue, Type: crdv1alpha1.BundleCollected},
				},
			},
			existsInCache: true,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: crdv1alpha1.CollectionCompleted, Status: metav1.ConditionTrue},
				},
			},
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is completed, cannot be updated",
				},
			},
		}, {
			name:               "delete after started",
			requestOperation:   adminv1.Delete,
			existingCollection: existingConfig,
			existsInCache:      true,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:               "delete after completed",
			requestOperation:   adminv1.Delete,
			existingCollection: existingConfig,
			existsInCache:      true,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: crdv1alpha1.CollectionCompleted, Status: metav1.ConditionTrue},
				},
			},
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:             "create with host public key",
			requestOperation: adminv1.Create,
			collection: &bundleConfig{
				name:          name,
				authType:      crdv1alpha1.APIKey,
				hostPublicKey: hostPublicKey.Marshal(),
			},
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:             "create with invalid host public key",
			requestOperation: adminv1.Create,
			collection: &bundleConfig{
				name:     name,
				authType: crdv1alpha1.APIKey,
				// invalid key
				hostPublicKey: []byte("abc"),
			},
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "invalid host public key: ssh: short read",
				},
			},
		}, {
			name:             "create referencing an authSecret the user can get",
			requestOperation: adminv1.Create,
			requestUserInfo:  authorizedUserInfo,
			collection:       newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
			expectedSARSpec:  expectedSARSpecForUser(authorizedUserInfo),
		}, {
			name:             "create referencing an authSecret the user cannot get",
			requestOperation: adminv1.Create,
			requestUserInfo:  unauthorizedUserInfo,
			collection:       newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: `user "unauthorized-user" is not authorized to get Secret kube-system/sftp-auth referenced in spec.authentication.authSecret`,
				},
			},
			expectedSARSpec: expectedSARSpecForUser(unauthorizedUserInfo),
		}, {
			name:             "update repointing an authSecret to one the user cannot get",
			requestOperation: adminv1.Update,
			requestUserInfo:  unauthorizedUserInfo,
			existingCollection: &bundleConfig{
				name:     name,
				authType: crdv1alpha1.APIKey,
			},
			collection: newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: `user "unauthorized-user" is not authorized to get Secret kube-system/sftp-auth referenced in spec.authentication.authSecret`,
				},
			},
			expectedSARSpec: expectedSARSpecForUser(unauthorizedUserInfo),
		}, {
			// The reference was already authorized when it was set, so an update which
			// leaves it untouched (e.g. a metadata-only edit) must not require the
			// requester to be able to read the Secret.
			name:               "update leaving the authSecret unchanged",
			requestOperation:   adminv1.Update,
			requestUserInfo:    unauthorizedUserInfo,
			existingCollection: newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			collection:         newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			expectedResponse:   &adminv1.AdmissionResponse{Allowed: true},
		}, {
			// The antrea-agents authenticate to spec.fileServer.url with the credentials
			// read from the referenced Secret, so repointing the file server sends those
			// credentials somewhere new and must be authorized, even though the reference
			// itself is untouched.
			name:               "update repointing the file server with an unchanged authSecret",
			requestOperation:   adminv1.Update,
			requestUserInfo:    unauthorizedUserInfo,
			existingCollection: newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", "sftp://good.example.com:22/upload"),
			collection:         newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", "sftp://evil.example.com:22/upload"),
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: `user "unauthorized-user" is not authorized to get Secret kube-system/sftp-auth referenced in spec.authentication.authSecret`,
				},
			},
			expectedSARSpec: expectedSARSpecForUser(unauthorizedUserInfo),
		}, {
			// authType selects which keys of the Secret the antrea-controller reads, so
			// changing it sends different contents of that Secret to the file server and
			// must be authorized, even though the reference itself is untouched.
			name:               "update changing the authType with an unchanged authSecret",
			requestOperation:   adminv1.Update,
			requestUserInfo:    unauthorizedUserInfo,
			existingCollection: newAuthSecretConfig(name, crdv1alpha1.BasicAuthentication, "kube-system", ""),
			collection:         newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: `user "unauthorized-user" is not authorized to get Secret kube-system/sftp-auth referenced in spec.authentication.authSecret`,
				},
			},
			expectedSARSpec: expectedSARSpecForUser(unauthorizedUserInfo),
		}, {
			// A started collection cannot be updated whatever the new spec contains, so the
			// webhook must reject it without spending a SubjectAccessReview on it.
			name:               "update repointing the file server after started",
			requestOperation:   adminv1.Update,
			requestUserInfo:    unauthorizedUserInfo,
			existingCollection: newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", "sftp://good.example.com:22/upload"),
			collection:         newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", "sftp://evil.example.com:22/upload"),
			existsInCache:      true,
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is started, cannot be updated",
				},
			},
		}, {
			name:             "create referencing an authSecret without a Namespace",
			requestOperation: adminv1.Create,
			requestUserInfo:  authorizedUserInfo,
			collection:       newAuthSecretConfig(name, crdv1alpha1.APIKey, "", ""),
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: "spec.authentication.authSecret must specify both name and namespace",
				},
			},
		}, {
			// The check is fail-closed: when the SubjectAccessReview cannot be completed
			// (e.g. the kube-apiserver is too slow to answer before authorizationTimeout),
			// the request must be denied rather than admitted.
			name:             "create when the SubjectAccessReview fails",
			requestOperation: adminv1.Create,
			requestUserInfo:  authorizedUserInfo,
			collection:       newAuthSecretConfig(name, crdv1alpha1.APIKey, "kube-system", ""),
			sarError:         errors.New("etcdserver: request timed out"),
			expectedResponse: &adminv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: "failed to authorize access to authSecret kube-system/sftp-auth: etcdserver: request timed out",
				},
			},
			expectedSARSpec: expectedSARSpecForUser(authorizedUserInfo),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			testClient := newTestClient(nil, nil)
			// Record every SubjectAccessReview and authorize all requesters except
			// unauthorizedUserInfo, so the authSecret check rejects only the
			// confused-deputy case.
			var gotSARs []*authzv1.SubjectAccessReview
			testClient.client.(*fake.Clientset).PrependReactor("create", "subjectaccessreviews",
				func(action k8stesting.Action) (bool, runtime.Object, error) {
					sar := action.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
					gotSARs = append(gotSARs, sar)
					if tt.sarError != nil {
						return true, nil, tt.sarError
					}
					sar.Status.Allowed = sar.Spec.User != unauthorizedUserInfo.Username
					return true, sar, nil
				})
			controller := newController(testClient)
			testClient.start(stopCh)
			testClient.waitForSync(stopCh)
			var bundleCollection, existingBundleCollection *crdv1alpha1.SupportBundleCollection
			if tt.existingCollection != nil {
				existingBundleCollection = generateSupportBundleResource(*tt.existingCollection)
			}
			if tt.collection != nil {
				bundleCollection = generateSupportBundleResource(*tt.collection)
			}
			if tt.existsInCache {
				controller.addInternalSupportBundleCollection(existingBundleCollection, nodeSpan, authentication, expiredAt)
			}
			if tt.existingStatus != nil {
				existingBundleCollection.Status = *tt.existingStatus
			}
			review := &adminv1.AdmissionReview{
				Request: &adminv1.AdmissionRequest{
					Name:      name,
					Operation: tt.requestOperation,
					UserInfo:  tt.requestUserInfo,
					OldObject: runtime.RawExtension{Raw: marshal(existingBundleCollection)},
					Object:    runtime.RawExtension{Raw: marshal(bundleCollection)},
				},
			}
			gotResponse := controller.Validate(review)
			assert.Equal(t, tt.expectedResponse, gotResponse)
			if tt.expectedSARSpec == nil {
				assert.Empty(t, gotSARs, "No SubjectAccessReview should have been issued")
			} else {
				require.Len(t, gotSARs, 1)
				assert.Equal(t, *tt.expectedSARSpec, gotSARs[0].Spec)
			}
		})
	}
}

func marshal(object runtime.Object) []byte {
	if object == nil {
		return nil
	}
	raw, _ := json.Marshal(object)
	return raw
}
