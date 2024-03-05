// Copyright 2024 Antrea Authors
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

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"

	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

func TestNewNetworkPolicyEvaluation(t *testing.T) {
	tests := []struct {
		name           string
		args           map[string]string
		expectedObject runtime.Object
		expectedError  string
	}{
		{
			name: "Successful parsing",
			args: map[string]string{
				"source":      "ns/pod1",
				"destination": "ns/pod2",
			},
			expectedObject: &cpv1beta.NetworkPolicyEvaluation{
				Request: &cpv1beta.NetworkPolicyEvaluationRequest{
					Source:      cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: "ns", Name: "pod1"}},
					Destination: cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: "ns", Name: "pod2"}},
				},
			},
		},
		{
			name: "Invalid format",
			args: map[string]string{
				"destination": "ns",
			},
			expectedError: "missing entities for NetworkPolicyEvaluation request",
		},
		{
			name: "Default namespaces",
			args: map[string]string{
				"source":      "pod1",
				"destination": "pod2",
			},
			expectedObject: &cpv1beta.NetworkPolicyEvaluation{
				Request: &cpv1beta.NetworkPolicyEvaluationRequest{
					Source:      cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: "default", Name: "pod1"}},
					Destination: cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: "default", Name: "pod2"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotObject, err := NewNetworkPolicyEvaluation(tt.args)
			if tt.expectedError == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedObject, gotObject)
			} else {
				assert.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}
