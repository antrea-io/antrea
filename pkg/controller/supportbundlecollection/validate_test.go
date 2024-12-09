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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	adminv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

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
		APIKey: "bundle_api_key",
	}
	nodeSpan := sets.New[string]("n1", "n2", "n3", "n4")
	expiredAt := metav1.NewTime(time.Now().Add(time.Minute))

	hostPublicKey, _, err := sftptesting.GenerateEd25519Key()
	require.NoError(t, err)

	tests := []struct {
		name               string
		requestOperation   adminv1.Operation
		existingCollection *bundleConfig
		collection         *bundleConfig
		existsInCache      bool
		existingStatus     *crdv1alpha1.SupportBundleCollectionStatus
		expectedResponse   *adminv1.AdmissionResponse
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			testClient := newTestClient(nil, nil)
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
					OldObject: runtime.RawExtension{Raw: marshal(existingBundleCollection)},
					Object:    runtime.RawExtension{Raw: marshal(bundleCollection)},
				},
			}
			gotResponse := controller.Validate(review)
			assert.Equal(t, tt.expectedResponse, gotResponse)
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
