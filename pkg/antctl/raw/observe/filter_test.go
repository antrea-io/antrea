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

package observe

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

func TestBuildRequest(t *testing.T) {
	t.Run("defaults match everything", func(t *testing.T) {
		req, err := buildRequest(&options{direction: "both"})
		require.NoError(t, err)
		require.Len(t, req.Filters, 1)
		assert.Nil(t, req.Since)
		assert.Equal(t, flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH, req.Filters[0].GetDirection())
	})

	t.Run("maps every filter field", func(t *testing.T) {
		req, err := buildRequest(&options{
			namespaces: []string{"ns1", "ns2"},
			podNames:   []string{"pod1"},
			selector:   "app=frontend",
			services:   []string{"svc1"},
			flowTypes:  []string{"Inter-Node", "to-external"},
			ips:        []string{"10.0.0.1", "10.0.0.0/24"},
			direction:  "from",
			maxCount:   5,
			follow:     true,
		})
		require.NoError(t, err)
		f := req.Filters[0]
		assert.Equal(t, []string{"ns1", "ns2"}, f.GetNamespaces())
		assert.Equal(t, []string{"pod1"}, f.GetPodNames())
		assert.Equal(t, "app=frontend", f.GetPodLabelSelector())
		assert.Equal(t, []string{"svc1"}, f.GetServiceNames())
		assert.Equal(t, []flowpb.FlowType{flowpb.FlowType_FLOW_TYPE_INTER_NODE, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL}, f.GetFlowTypes())
		assert.Equal(t, []string{"10.0.0.1", "10.0.0.0/24"}, f.GetIps())
		assert.Equal(t, flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM, f.GetDirection())
		assert.EqualValues(t, 5, req.GetMaxCount())
		assert.True(t, req.GetFollow())
	})

	t.Run("rejects invalid direction", func(t *testing.T) {
		_, err := buildRequest(&options{direction: "sideways"})
		assert.Error(t, err)
	})

	t.Run("rejects invalid flow type", func(t *testing.T) {
		_, err := buildRequest(&options{direction: "both", flowTypes: []string{"diagonal"}})
		assert.Error(t, err)
	})

	t.Run("rejects malformed IP and CIDR", func(t *testing.T) {
		_, err := buildRequest(&options{direction: "both", ips: []string{"not-an-ip"}})
		assert.Error(t, err)
		_, err = buildRequest(&options{direction: "both", ips: []string{"10.0.0.1/99"}})
		assert.Error(t, err)
	})

	t.Run("accepts a relative duration for --since", func(t *testing.T) {
		before := time.Now().Add(-5 * time.Minute)
		req, err := buildRequest(&options{direction: "both", since: "5m"})
		require.NoError(t, err)
		require.NotNil(t, req.Since)
		assert.WithinDuration(t, before, req.Since.AsTime(), 5*time.Second)
	})

	t.Run("accepts an absolute RFC3339 timestamp for --since", func(t *testing.T) {
		req, err := buildRequest(&options{direction: "both", since: "2026-01-01T00:00:00Z"})
		require.NoError(t, err)
		require.NotNil(t, req.Since)
		assert.Equal(t, "2026-01-01T00:00:00Z", req.Since.AsTime().Format(time.RFC3339))
	})

	t.Run("rejects an unparsable --since", func(t *testing.T) {
		_, err := buildRequest(&options{direction: "both", since: "not-a-time"})
		assert.Error(t, err)
	})
}
