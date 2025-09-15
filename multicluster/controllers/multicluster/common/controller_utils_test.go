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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

func TestDiscoverServiceCIDRByInvalidServiceCreation(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).Build()
	_, err := discoverServiceCIDRByInvalidServiceCreation(context.Background(), fakeClient, "default")
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

type mockDiscovery struct {
	discovery.DiscoveryInterface
	serverVersion *version.Info
	err           error
}

func (m *mockDiscovery) ServerVersion() (*version.Info, error) {
	return m.serverVersion, m.err
}

func TestIsK8sVersionGreaterThanOrEqualTo(t *testing.T) {
	tests := []struct {
		name         string
		gitVersion   string
		discoveryErr error
		expected     bool
		expectedErr  string
	}{
		{
			name:       "EqualVersion",
			gitVersion: "v1.33.0",
			expected:   true,
		},
		{
			name:       "GreaterVersion",
			gitVersion: "v1.33.1",
			expected:   true,
		},
		{
			name:       "LowerVersion",
			gitVersion: "v1.32.0",
			expected:   false,
		},
		{
			name:        "InvalidGitVersion",
			gitVersion:  "not-a-version",
			expected:    false,
			expectedErr: "could not parse \"not-a-version\" as version",
		},
		{
			name:         "Error when getting version",
			discoveryErr: fmt.Errorf("unable to get K8s version"),
			expected:     false,
			expectedErr:  "unable to get K8s version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeDiscovery := &mockDiscovery{
				serverVersion: &version.Info{GitVersion: tt.gitVersion},
				err:           tt.discoveryErr,
			}
			got, err := isK8sVersionGreaterThanOrEqualTo(fakeDiscovery, "v1.33.0")
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func TestGetClusterServiceCIDR(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name         string
		cidr         *networkingv1.ServiceCIDR
		expectedErr  string
		expectedCIDR string
	}{
		{
			name: "success",
			cidr: &networkingv1.ServiceCIDR{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubernetes",
				},
				Spec: networkingv1.ServiceCIDRSpec{
					CIDRs: []string{"10.96.0.0/12"},
				},
			},
			expectedCIDR: "10.96.0.0/12",
		},
		{
			name: "IPv4 CIDR not found",
			cidr: &networkingv1.ServiceCIDR{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubernetes",
				},
				Spec: networkingv1.ServiceCIDRSpec{
					CIDRs: []string{},
				},
			},
			expectedErr: "IPv4 Service CIDR not found",
		},
		{
			name: "success with dual-stack",
			cidr: &networkingv1.ServiceCIDR{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubernetes",
				},
				Spec: networkingv1.ServiceCIDRSpec{
					CIDRs: []string{"10.96.0.0/12", "fd00::/64"},
				},
			},
			expectedCIDR: "10.96.0.0/12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).WithObjects(tt.cidr).Build()
			result, err := getClusterServiceCIDR(ctx, fakeClient)
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCIDR, result)
			}
		})
	}

}

func TestDiscoverClusterServiceCIDR(t *testing.T) {
	tests := []struct {
		name         string
		gitVersion   string
		discoveryErr error
		cidr         *networkingv1.ServiceCIDR
		expectedErr  string
		expectedCIDR string
	}{
		{
			name:       "success",
			gitVersion: "v1.33.1",
			cidr: &networkingv1.ServiceCIDR{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubernetes",
				},
				Spec: networkingv1.ServiceCIDRSpec{
					CIDRs: []string{"10.96.0.0/12"},
				},
			},
			expectedCIDR: "10.96.0.0/12",
		},
		{
			name:       "failed with empty CIDR",
			gitVersion: "v1.33.1",
			cidr: &networkingv1.ServiceCIDR{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kubernetes",
				},
				Spec: networkingv1.ServiceCIDRSpec{
					CIDRs: []string{},
				},
			},
			expectedErr: "IPv4 Service CIDR not found",
		},
		{
			name:        "version mismatched, fallback with error",
			gitVersion:  "v1.30.1",
			expectedErr: "expected a specific error but none was returned",
		},
		{
			name:         "fail to create client",
			discoveryErr: fmt.Errorf("failed to create discovery client"),
			expectedErr:  "failed to create discovery client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeDiscovery := &mockDiscovery{
				serverVersion: &version.Info{GitVersion: tt.gitVersion},
				err:           tt.discoveryErr,
			}
			createDiscoveryClientFn = func(mgrConfig *rest.Config) (discovery.DiscoveryInterface, error) {
				return fakeDiscovery, tt.discoveryErr
			}
			fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).Build()
			if tt.cidr != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(TestScheme).WithObjects(tt.cidr).Build()
			}
			actualCIDR, err := DiscoverClusterServiceCIDR(context.TODO(), nil, fakeClient, fakeClient, "kube-system")
			if err != nil {
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCIDR, actualCIDR)
			}
		})
	}
}
