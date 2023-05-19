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
	adminv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestValidateSupportBundleCollection(t *testing.T) {
	bundleCollection := generateSupportBundleResource(bundleConfig{
		name: "b1",
		nodes: &bundleNodes{
			labels: map[string]string{"test": "selected"},
		},
		externalNodes: &bundleExternalNodes{
			namespace: "ns1",
			labels:    map[string]string{"test": "selected"},
		},
		authType: crdv1alpha1.APIKey,
	})
	authentication := &controlplane.BundleServerAuthConfiguration{
		APIKey: "bundle_api_key",
	}
	nodeSpan := sets.New[string]("n1", "n2", "n3", "n4")
	expiredAt := metav1.NewTime(time.Now().Add(time.Minute))

	tests := []struct {
		name              string
		existsInCache     bool
		existingStatus    *crdv1alpha1.SupportBundleCollectionStatus
		updatedCollection *bundleConfig
		requestOperation  adminv1.Operation
		expectedResponse  *adminv1.AdmissionResponse
	}{
		{
			name:             "update before started",
			existsInCache:    false,
			requestOperation: adminv1.Update,
			updatedCollection: &bundleConfig{
				name: "b1",
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
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:             "delete before started",
			existsInCache:    false,
			requestOperation: adminv1.Delete,
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:             "update after started",
			existsInCache:    true,
			requestOperation: adminv1.Update,
			updatedCollection: &bundleConfig{
				name: "b1",
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
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is started, cannot be updated",
				},
			},
		}, {
			name:             "update status after started",
			existsInCache:    true,
			requestOperation: adminv1.Update,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			updatedCollection: &bundleConfig{
				name: "b1",
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
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:             "update after completed",
			existsInCache:    true,
			requestOperation: adminv1.Update,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: crdv1alpha1.CollectionCompleted, Status: metav1.ConditionTrue},
				},
			},
			updatedCollection: &bundleConfig{
				name: "b1",
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
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is completed, cannot be updated",
				},
			},
		}, {
			name:             "update status after completed",
			existsInCache:    true,
			requestOperation: adminv1.Update,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: crdv1alpha1.CollectionCompleted, Status: metav1.ConditionTrue},
				},
			},
			updatedCollection: &bundleConfig{
				name: "b1",
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
			expectedResponse: &adminv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "SupportBundleCollection b1 is completed, cannot be updated",
				},
			},
		}, {
			name:          "delete after started",
			existsInCache: true,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			requestOperation: adminv1.Delete,
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
		}, {
			name:             "delete after completed",
			existsInCache:    true,
			requestOperation: adminv1.Delete,
			existingStatus: &crdv1alpha1.SupportBundleCollectionStatus{
				Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
					{Type: crdv1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: crdv1alpha1.CollectionCompleted, Status: metav1.ConditionTrue},
				},
			},
			expectedResponse: &adminv1.AdmissionResponse{Allowed: true},
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
			if tt.existsInCache {
				controller.addInternalSupportBundleCollection(bundleCollection, nodeSpan, authentication, expiredAt)
			}
			oldBundleCollection := bundleCollection
			if tt.existingStatus != nil {
				oldBundleCollection.Status = *tt.existingStatus
			}
			newBundleCollection := oldBundleCollection
			if tt.updatedCollection != nil {
				newBundleCollection = generateSupportBundleResource(*tt.updatedCollection)
			}
			review := &adminv1.AdmissionReview{
				Request: &adminv1.AdmissionRequest{
					Name:      bundleCollection.Name,
					Operation: tt.requestOperation,
					OldObject: runtime.RawExtension{Raw: marshal(oldBundleCollection)},
					Object:    runtime.RawExtension{Raw: marshal(newBundleCollection)},
				},
			}
			gotResponse := controller.Validate(review)
			assert.Equal(t, tt.expectedResponse, gotResponse)
		})
	}
}

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}
