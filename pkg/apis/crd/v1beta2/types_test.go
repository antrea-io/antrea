// Copyright 2026 Antrea Authors
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

package v1beta2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestEgressStatusSerialization(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     EgressStatus
		wantStatus bool
	}{
		{name: "zero status is omitted"},
		{name: "Node is preserved", status: EgressStatus{EgressNode: "node-a"}, wantStatus: true},
		{name: "IPs are preserved", status: EgressStatus{EgressIPs: []string{"192.0.2.10"}}, wantStatus: true},
		{
			name: "conditions are preserved",
			status: EgressStatus{Conditions: []metav1.Condition{{
				Type: IPAssigned, Status: metav1.ConditionTrue,
			}}},
			wantStatus: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			egress := &Egress{Spec: EgressSpec{EgressIPs: []string{"192.0.2.10"}}, Status: tc.status}
			raw, err := json.Marshal(egress)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &fields))
			_, found := fields["status"]
			assert.Equal(t, tc.wantStatus, found, "JSON status field presence")
			var decoded Egress
			require.NoError(t, json.Unmarshal(raw, &decoded))
			assert.Equal(t, tc.status, decoded.Status)

			// Local informer conversion uses the unstructured converter instead of JSON marshalling.
			object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(egress)
			require.NoError(t, err)
			_, found = object["status"]
			assert.Equal(t, tc.wantStatus, found, "unstructured status field presence")
			var converted Egress
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(object, &converted))
			assert.Equal(t, tc.status, converted.Status)
		})
	}
}

func TestExternalIPPoolStatusSerialization(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     ExternalIPPoolStatus
		wantStatus bool
	}{
		{name: "zero status is omitted"},
		{
			name:       "unused capacity is preserved",
			status:     ExternalIPPoolStatus{Usage: IPPoolUsage{Total: 16}},
			wantStatus: true,
		},
		{
			name:       "allocated usage is preserved",
			status:     ExternalIPPoolStatus{Usage: IPPoolUsage{Total: 16, Used: 2}},
			wantStatus: true,
		},
		{
			name:       "64-bit usage is preserved",
			status:     ExternalIPPoolStatus{Usage: IPPoolUsage{Total: 1 << 33, Used: 1 << 32}},
			wantStatus: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := &ExternalIPPool{
				Spec:   ExternalIPPoolSpec{IPRanges: []IPRange{{CIDR: "192.0.2.0/24"}}},
				Status: tc.status,
			}
			raw, err := json.Marshal(pool)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &fields))
			_, found := fields["status"]
			assert.Equal(t, tc.wantStatus, found, "JSON status field presence")
			var decoded ExternalIPPool
			require.NoError(t, json.Unmarshal(raw, &decoded))
			assert.Equal(t, tc.status, decoded.Status)

			object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pool)
			require.NoError(t, err)
			_, found = object["status"]
			assert.Equal(t, tc.wantStatus, found, "unstructured status field presence")
			var converted ExternalIPPool
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(object, &converted))
			assert.Equal(t, tc.status, converted.Status)
		})
	}
}
