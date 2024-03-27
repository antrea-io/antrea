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

package main

import (
	"context"
	j "encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var clusterSetWebhookUnderTest *clusterSetValidator

func TestWebhookClusterSetEvents(t *testing.T) {
	newClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "clusterset1",
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			ClusterID: "east",
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
				}},
			Namespace: "mcs-A",
		},
	}

	existingClusterSet1 := newClusterSet.DeepCopy()

	existingClusterSet2 := newClusterSet.DeepCopy()
	existingClusterSet2.Name = "clusterset2"
	leaderUpdatedClusterSet := newClusterSet.DeepCopy()
	leaderUpdatedClusterSet.Spec.Leaders = []mcv1alpha2.LeaderClusterInfo{
		{ClusterID: "leader1-1"},
	}

	clusterIDUpdatedClusterSet := newClusterSet.DeepCopy()
	clusterIDUpdatedClusterSet.Spec.ClusterID = "newclusterid"

	newCS, _ := j.Marshal(newClusterSet)
	leaderUpdatedCS, _ := j.Marshal(leaderUpdatedClusterSet)
	clusterIDUpdatedCS, _ := j.Marshal(clusterIDUpdatedClusterSet)

	newReq := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID: "07e52e8d-4513-11e9-a716-42010a800270",
			Kind: metav1.GroupVersionKind{
				Group:   "multicluster.crd.antrea.io",
				Version: "v1alpha1",
				Kind:    "ClusterSet",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "multicluster.crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "ClusterSets",
			},
			Name:      "clusterset1",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: newCS,
			},
		},
	}
	leaderNewReqCopy := newReq.DeepCopy()
	leaderNewReqCopy.Object = runtime.RawExtension{
		Raw: leaderUpdatedCS,
	}
	leaderNewReqCopy.OldObject = runtime.RawExtension{
		Raw: newCS,
	}
	leaderUpdatedReq := admission.Request{
		AdmissionRequest: *leaderNewReqCopy,
	}

	deleteReq := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			Name:      "clusterset1",
			Namespace: "mcs1",
			Operation: v1.Delete,
		},
	}

	clusterIDNewReqCopy := newReq.DeepCopy()
	clusterIDNewReqCopy.Object = runtime.RawExtension{
		Raw: clusterIDUpdatedCS,
	}
	clusterIDNewReqCopy.OldObject = runtime.RawExtension{
		Raw: newCS,
	}
	clusterIDUpdatedReq := admission.Request{
		AdmissionRequest: *clusterIDNewReqCopy,
	}

	tests := []struct {
		name                          string
		req                           admission.Request
		existingClusterSet            *mcv1alpha2.ClusterSet
		existingMemberClusterAnnounce *mcv1alpha1.MemberClusterAnnounce
		role                          string
		isAllowed                     bool
	}{
		{
			name:      "create a new ClusterSet",
			req:       newReq,
			role:      leaderRole,
			isAllowed: true,
		},
		{
			name:               "create a new ClusterSet when there is an existing ClusterSet",
			existingClusterSet: existingClusterSet2,
			req:                newReq,
			role:               leaderRole,
			isAllowed:          false,
		},
		{
			name:               "update a new ClusterSet's ClusterID when there is an existing ClusterSet",
			existingClusterSet: existingClusterSet1,
			req:                clusterIDUpdatedReq,
			role:               leaderRole,
			isAllowed:          false,
		},
		{
			name:               "update a new ClusterSet's leader ClusterID when there is an existing ClusterSet",
			existingClusterSet: existingClusterSet1,
			req:                leaderUpdatedReq,
			role:               leaderRole,
			isAllowed:          false,
		},
		{
			name: "fail to delete a ClusterSet with a MemberClusterAnnounce in a leader cluster",
			existingMemberClusterAnnounce: &mcv1alpha1.MemberClusterAnnounce{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "mca-from-cluster-1",
				},
			},
			req:       deleteReq,
			role:      leaderRole,
			isAllowed: false,
		},
		{
			name:      "succeed to delete a ClusterSet without any MemberClusterAnnounce in a leader cluster",
			req:       deleteReq,
			role:      leaderRole,
			isAllowed: true,
		},
		{
			name:      "succeed to delete a ClusterSet in a member cluster",
			req:       deleteReq,
			role:      memberRole,
			isAllowed: true,
		},
	}

	decoder := admission.NewDecoder(common.TestScheme)
	for _, tt := range tests {
		objects := []client.Object{}
		if tt.existingClusterSet != nil {
			objects = append(objects, tt.existingClusterSet)
		}
		if tt.existingMemberClusterAnnounce != nil {
			objects = append(objects, tt.existingMemberClusterAnnounce)
		}
		fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(objects...).Build()
		clusterSetWebhookUnderTest = &clusterSetValidator{
			Client:    fakeClient,
			decoder:   decoder,
			namespace: "mcs1",
			role:      tt.role,
		}

		t.Run(tt.name, func(t *testing.T) {
			response := clusterSetWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}
}
