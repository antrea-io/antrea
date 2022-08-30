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
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var clusterSetWebhookUnderTest *clusterSetValidator

func TestWebhookClusterSetEvents(t *testing.T) {
	newClusterSet := &mcsv1alpha1.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "clusterset1",
		},
		Spec: mcsv1alpha1.ClusterSetSpec{
			Leaders: []mcsv1alpha1.MemberCluster{
				{
					ClusterID: "leader1",
				}},
			Members: []mcsv1alpha1.MemberCluster{
				{
					ClusterID:      "east",
					ServiceAccount: "east-access-sa",
				},
				{
					ClusterID:      "west",
					ServiceAccount: "west-access-sa",
				},
			},
			Namespace: "mcs-A",
		},
	}

	existingClusterSet1 := newClusterSet.DeepCopy()

	existingClusterSet2 := newClusterSet.DeepCopy()
	existingClusterSet2.Name = "clusterset2"
	leaderUpdatedClusterSet := newClusterSet.DeepCopy()
	leaderUpdatedClusterSet.Spec.Leaders = []mcsv1alpha1.MemberCluster{
		{ClusterID: "leader1-1"},
	}

	memberUpdatedClusterSet := newClusterSet.DeepCopy()
	memberUpdatedClusterSet.Spec.Members = []mcsv1alpha1.MemberCluster{
		{
			ClusterID:      "east",
			ServiceAccount: "east-access-sa",
		},
		{
			ClusterID:      "west",
			ServiceAccount: "west-access-sa-1",
		},
	}

	labelUpdatedClusterSet := existingClusterSet1.DeepCopy()
	labelUpdatedClusterSet.Labels = map[string]string{"test": "true"}

	newCS, _ := j.Marshal(newClusterSet)
	leaderUpdatedCS, _ := j.Marshal(leaderUpdatedClusterSet)
	memberUpdatedCS, _ := j.Marshal(memberUpdatedClusterSet)
	labelUpdatedCS, _ := j.Marshal(labelUpdatedClusterSet)

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

	memberUpdateReq1Copy := newReq.DeepCopy()
	memberUpdateReq1Copy.Operation = v1.Update
	memberUpdateReq1Copy.Object = runtime.RawExtension{
		Raw: memberUpdatedCS,
	}
	memberUpdateReq1Copy.OldObject = runtime.RawExtension{
		Raw: newCS,
	}
	memberUpdateReq1Copy.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:antrea-mc-controller",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	memberUpdatedReq1 := admission.Request{
		AdmissionRequest: *memberUpdateReq1Copy,
	}

	memberUpdateReq2Copy := memberUpdateReq1Copy.DeepCopy()
	memberUpdateReq2Copy.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:east-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}
	memberUpdatedReq2 := admission.Request{
		AdmissionRequest: *memberUpdateReq2Copy,
	}

	labelUpdateReqCopy := memberUpdateReq2Copy.DeepCopy()
	labelUpdateReqCopy.Object = runtime.RawExtension{
		Raw: labelUpdatedCS,
	}
	labelUpdatedReq := admission.Request{
		AdmissionRequest: *labelUpdateReqCopy,
	}

	memberUpdatedReqInvalidUser := admission.Request{
		AdmissionRequest: *memberUpdateReq1Copy,
	}
	memberUpdatedReqInvalidUser.UserInfo = authenticationv1.UserInfo{
		Username: "system:user:east-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:authenticated",
		},
	}
	tests := []struct {
		name               string
		req                admission.Request
		existingClusterSet *mcsv1alpha1.ClusterSet
		newClusterSet      *mcsv1alpha1.ClusterSet
		isAllowed          bool
	}{
		{
			name:      "create a new ClusterSet",
			req:       newReq,
			isAllowed: true,
		},
		{
			name:               "create a new ClusterSet when there is an existing ClusterSet",
			existingClusterSet: existingClusterSet2,
			req:                newReq,
			isAllowed:          false,
		},
		{
			name:               "update a new ClusterSet's leader ClusterID when there is an existing ClusterSet",
			existingClusterSet: existingClusterSet1,
			newClusterSet:      leaderUpdatedClusterSet,
			req:                leaderUpdatedReq,
			isAllowed:          false,
		},
		{
			name:               "update a new ClusterSet's member list with mc ServiceAccount",
			existingClusterSet: existingClusterSet1,
			newClusterSet:      memberUpdatedClusterSet,
			req:                memberUpdatedReq1,
			isAllowed:          true,
		},
		{
			name:               "update a new ClusterSet's member list with  invalid user info",
			existingClusterSet: existingClusterSet1,
			newClusterSet:      memberUpdatedClusterSet,
			req:                memberUpdatedReqInvalidUser,
			isAllowed:          false,
		},
		{
			name:               "update a new ClusterSet's member list without mc ServiceAccount",
			existingClusterSet: existingClusterSet1,
			newClusterSet:      memberUpdatedClusterSet,
			req:                memberUpdatedReq2,
			isAllowed:          false,
		},
		{
			name:               "update a new ClusterSet's labels without mc ServiceAccount",
			existingClusterSet: existingClusterSet1,
			newClusterSet:      labelUpdatedClusterSet,
			req:                labelUpdatedReq,
			isAllowed:          true,
		},
	}

	newScheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(newScheme))
	utilruntime.Must(k8smcsv1alpha1.AddToScheme(newScheme))
	utilruntime.Must(mcsv1alpha1.AddToScheme(newScheme))
	decoder, err := admission.NewDecoder(newScheme)
	if err != nil {
		klog.ErrorS(err, "Error constructing a decoder")
	}

	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(newScheme).WithObjects().Build()
		if tt.existingClusterSet != nil {
			fakeClient = fake.NewClientBuilder().WithScheme(newScheme).WithObjects(tt.existingClusterSet).Build()
		}
		clusterSetWebhookUnderTest = &clusterSetValidator{
			Client:    fakeClient,
			namespace: "mcs1"}
		clusterSetWebhookUnderTest.InjectDecoder(decoder)

		t.Run(tt.name, func(t *testing.T) {
			response := clusterSetWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}
}
