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
	"k8s.io/client-go/rest"

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
		controllerNS string
		expectedRes  *certificate.CAConfig
	}{
		{
			name:         "controllerNS is empty",
			controllerNS: "",
			expectedRes: &certificate.CAConfig{
				CAConfigMapName:    configMapName,
				PairName:           "tls",
				CertDir:            certDir,
				ServiceName:        serviceName,
				SelfSignedCertDir:  selfSignedCertDir,
				MutationWebhooks:   getMutationWebhooks(""),
				ValidatingWebhooks: getValidationWebhooks(""),
				CertReadyTimeout:   2 * time.Minute,
				MaxRotateDuration:  time.Hour * (24 * 365),
			},
		},
		{
			name:         "controllerNS is not empty",
			controllerNS: "testNS",
			expectedRes: &certificate.CAConfig{
				CAConfigMapName:    configMapName,
				PairName:           "tls",
				CertDir:            certDir,
				ServiceName:        serviceName,
				SelfSignedCertDir:  selfSignedCertDir,
				MutationWebhooks:   getMutationWebhooks("testNS"),
				ValidatingWebhooks: getValidationWebhooks("testNS"),
				CertReadyTimeout:   2 * time.Minute,
				MaxRotateDuration:  time.Hour * (24 * 365),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedRes, getCaConfig(tt.controllerNS))
		})
	}
}
