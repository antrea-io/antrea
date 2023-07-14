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

package common

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

func TestDiscoverServiceCIDRByInvalidServiceCreation(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).Build()
	_, err := DiscoverServiceCIDRByInvalidServiceCreation(context.Background(), fakeClient, "default")
	if err != nil {
		assert.Contains(t, err.Error(), "expected a specific error but none was returned")
	}
}

func TestParseServiceCIDRFromError(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCIDR  string
		expectedError string
	}{
		{
			name:         "parse successfully with correct error message",
			input:        "The Service \"invalid-svc\" is invalid: spec.clusterIPs: Invalid value: []string{\"0.0.0.0\"}: failed to allocate IP 0.0.0.0: provided IP is not in the valid range. The range of valid IPs is 10.19.0.0/18",
			expectedCIDR: "10.19.0.0/18",
		},
		{
			name:  "failed to parse with incorrect error message",
			input: "The range of valid IPs are 10.19.0.0/18",
			expectedError: "could not determine the ClusterIP range via Service creation - the expected error " +
				"was not returned. The actual error was",
		},
	}

	for _, tt := range tests {
		cidr, err := parseServiceCIDRFromError(tt.input)
		if err != nil {
			assert.Contains(t, err.Error(), tt.expectedError)
		}
		assert.Equal(t, cidr, tt.expectedCIDR)
	}
}

func TestGetClusterIDFromClusterClaim(t *testing.T) {
	clusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-clusterset",
		},
	}
	clusterClaim1 := mcv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "id.k8s.io",
		},
		Value: "cluster-a",
	}
	clusterClaim2 := mcv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset.k8s.io",
		},
		Value: "test-clusterset",
	}

	tests := []struct {
		name             string
		clusterClaimList mcv1alpha2.ClusterClaimList
		expectedErr      string
	}{
		{
			name: "succeed to get clusterID",
			clusterClaimList: mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					clusterClaim1,
					clusterClaim2,
				},
			},
		},
		{
			name:             "empty ClusterClaims",
			clusterClaimList: mcv1alpha2.ClusterClaimList{},
			expectedErr:      "ClusterClaim is not configured for the cluster",
		},
		{
			name: "No ClusterClaim with ClusterID",
			clusterClaimList: mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					clusterClaim2,
				},
			},
			expectedErr: "ClusterClaim not configured for Name=id.k8s.io",
		},
	}

	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).WithLists(&tt.clusterClaimList).Build()
		t.Run(tt.name, func(t *testing.T) {
			actualClusterID, err := getClusterIDFromClusterClaim(fakeClient, clusterSet)
			if err != nil {
				assert.Equal(t, tt.expectedErr, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, clusterClaim1.Value, string(actualClusterID))
			}
		})
	}
}

func TestGetClusterID(t *testing.T) {
	tests := []struct {
		name             string
		clusterSet       *mcv1alpha2.ClusterSet
		clusterClaimList *mcv1alpha2.ClusterClaimList
		expectedErr      string
		expectedID       string
	}{
		{
			name: "succeed to get clusterID from ClusterClaim",
			clusterSet: &mcv1alpha2.ClusterSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-clusterset",
				},
				Spec: mcv1alpha2.ClusterSetSpec{},
			},
			clusterClaimList: &mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "id.k8s.io",
						},
						Value: "cluster-a",
					},
				},
			},
			expectedID: "cluster-a",
		},
		{
			name: "error to get clusterID from ClusterClaim",
			clusterSet: &mcv1alpha2.ClusterSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-clusterset",
				},
				Spec: mcv1alpha2.ClusterSetSpec{},
			},
			clusterClaimList: &mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "clusterset.k8s.io",
						},
						Value: "cluster-a",
					},
				},
			},
			expectedErr: "'clusterID' is not set in the ClusterSet default/test-clusterset spec",
		},
		{
			name: "succeed to get clusterID from ClusterSet",
			clusterSet: &mcv1alpha2.ClusterSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-clusterset",
				},
				Spec: mcv1alpha2.ClusterSetSpec{
					ClusterID: "cluster-1",
				},
			},
			clusterClaimList: &mcv1alpha2.ClusterClaimList{},
			expectedID:       "cluster-1",
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "test-clusterset",
		},
	}

	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).WithLists(tt.clusterClaimList).Build()
		t.Run(tt.name, func(t *testing.T) {
			actualID, err := GetClusterID(true, req, fakeClient, tt.clusterSet)
			if err != nil {
				assert.Equal(t, tt.expectedErr, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, string(actualID))
			}
		})
	}
}
