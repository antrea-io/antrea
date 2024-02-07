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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/apiserver/certificate"
)

func TestCreateClients(t *testing.T) {
	testCases := []struct {
		name   string
		config *rest.Config
	}{
		{
			name:   "Create clients successfully",
			config: &rest.Config{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := createClients(tt.config)
			assert.NoError(t, err, "get error when running createClients")
		})
	}
}

func TestGetCAConfig(t *testing.T) {
	testCases := []struct {
		name         string
		isLeader     bool
		controllerNS string
		expectedRes  *certificate.CAConfig
	}{
		{
			name:     "member cluster",
			isLeader: false,
			expectedRes: &certificate.CAConfig{
				CAConfigMapName:           configMapName,
				PairName:                  "tls",
				CertDir:                   certDir,
				ServiceName:               serviceName,
				SelfSignedCertDir:         selfSignedCertDir,
				MutationWebhookSelector:   getWebhookLabel(false, ""),
				ValidatingWebhookSelector: getWebhookLabel(false, ""),
				CertReadyTimeout:          2 * time.Minute,
				MinValidDuration:          time.Hour * (24 * 90),
			},
		},
		{
			name:         "leader cluster",
			isLeader:     true,
			controllerNS: "testNS",
			expectedRes: &certificate.CAConfig{
				CAConfigMapName:           configMapName,
				PairName:                  "tls",
				CertDir:                   certDir,
				ServiceName:               serviceName,
				SelfSignedCertDir:         selfSignedCertDir,
				MutationWebhookSelector:   getWebhookLabel(true, "testNS"),
				ValidatingWebhookSelector: getWebhookLabel(true, "testNS"),
				CertReadyTimeout:          2 * time.Minute,
				MinValidDuration:          time.Hour * (24 * 90),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedRes, getCaConfig(tt.isLeader, tt.controllerNS))
		})
	}
}

func TestClusterClaimCRDAvailable(t *testing.T) {
	groupVersion := mcv1alpha2.SchemeGroupVersion.String()
	testCases := []struct {
		name              string
		resources         []*metav1.APIResourceList
		expectedAvailable bool
	}{
		{
			name:              "empty",
			expectedAvailable: false,
		},
		{
			name: "GroupVersion exists",
			resources: []*metav1.APIResourceList{
				{
					GroupVersion: groupVersion,
				},
			},
			expectedAvailable: false,
		},
		{
			name: "API exists",
			resources: []*metav1.APIResourceList{
				{
					GroupVersion: groupVersion,
					APIResources: []metav1.APIResource{{Kind: "ClusterClaim"}},
				},
			},
			expectedAvailable: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset()
			k8sClient.Resources = tt.resources
			available, err := clusterClaimCRDAvailable(k8sClient)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAvailable, available)
		})
	}
}
