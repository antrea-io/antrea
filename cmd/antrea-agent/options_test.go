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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	agentconfig "antrea.io/antrea/pkg/config/agent"
)

func TestOptionsValidateTLSOptions(t *testing.T) {
	tests := []struct {
		name        string
		config      *agentconfig.AgentConfig
		expectedErr string
	}{
		{
			name: "empty input",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "",
				TLSMinVersion:   "",
			},
			expectedErr: "",
		},
		{
			name: "invalid TLSMinVersion",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "",
				TLSMinVersion:   "foo",
			},
			expectedErr: "invalid TLSMinVersion",
		},
		{
			name: "invalid TLSCipherSuites",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, foo",
				TLSMinVersion:   "VersionTLS10",
			},
			expectedErr: "invalid TLSCipherSuites",
		},
		{
			name: "valid input",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_RSA_WITH_AES_128_GCM_SHA256",
				TLSMinVersion:   "VersionTLS12",
			},
			expectedErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{config: tt.config}
			err := o.validateTLSOptions()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}
