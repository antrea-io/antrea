// Copyright 2023 Antrea Authors
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

package k8s

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOverrideKubeAPIServer(t *testing.T) {
	originalHost := "10.96.0.1"
	originalPort := "6443"
	tests := []struct {
		name                  string
		kubeAPIServerOverride string
		expectHost            string
		expectPort            string
	}{
		{
			name:                  "empty",
			kubeAPIServerOverride: "",
			expectHost:            originalHost,
			expectPort:            originalPort,
		},
		{
			name:                  "url",
			kubeAPIServerOverride: "https://192.168.0.1",
			expectHost:            "192.168.0.1",
			expectPort:            "443",
		},
		{
			name:                  "url with port",
			kubeAPIServerOverride: "https://192.168.0.1:10443",
			expectHost:            "192.168.0.1",
			expectPort:            "10443",
		},
		{
			name:                  "host",
			kubeAPIServerOverride: "192.168.0.1",
			expectHost:            "192.168.0.1",
			expectPort:            "443",
		},
		{
			name:                  "host with port",
			kubeAPIServerOverride: "192.168.0.1:10443",
			expectHost:            "192.168.0.1",
			expectPort:            "10443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(kubeServiceHostEnvKey, originalHost)
			t.Setenv(kubeServicePortEnvKey, originalPort)

			OverrideKubeAPIServer(tt.kubeAPIServerOverride)
			assert.Equal(t, tt.expectHost, os.Getenv(kubeServiceHostEnvKey))
			assert.Equal(t, tt.expectPort, os.Getenv(kubeServicePortEnvKey))
		})
	}
}
