// Copyright 2026 Antrea Authors.
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

package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/v2/pkg/antctl/raw/check"
)

func runK8sVersionTest(ctx context.Context, client kubernetes.Interface) error {
	testContext := &testContext{
		Logger: check.NewLogger("[check-k8s-version] "),
		client: client,
	}
	return (&checkK8sVersion{}).Run(ctx, testContext)
}

func TestCheckK8sVersionRun(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name        string
		versionInfo *version.Info
		expectedErr string
	}{
		{
			name: "compatible k8s version with v prefix",
			versionInfo: &version.Info{
				GitVersion: "v1.28.0",
			},
		},
		{
			name: "compatible k8s version without v prefix",
			versionInfo: &version.Info{
				GitVersion: "1.28.0",
			},
		},
		{
			name: "compatible minimum k8s version",
			versionInfo: &version.Info{
				GitVersion: "v1.23.0",
			},
		},
		{
			name: "incompatible k8s version below minimum",
			versionInfo: &version.Info{
				GitVersion: "v1.22.0",
			},
			expectedErr: "Kubernetes min version required: v1.23.0",
		},
		{
			name: "invalid version string",
			versionInfo: &version.Info{
				GitVersion: "invalid.version",
			},
			expectedErr: "error parsing server version: invalid version \"invalid.version\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = tc.versionInfo
			err := runK8sVersionTest(ctx, client)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expectedErr)
			}
		})
	}
}
