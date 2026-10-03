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

package endpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"
)

func TestCanServe(t *testing.T) {
	tests := []struct {
		name       string
		conditions discoveryv1.EndpointConditions
		expected   bool
	}{
		{
			name: "Ready nil, Serving nil",
			conditions: discoveryv1.EndpointConditions{
				Ready:   nil,
				Serving: nil,
			},
			expected: true,
		},
		{
			name: "Ready nil, Serving true",
			conditions: discoveryv1.EndpointConditions{
				Ready:   nil,
				Serving: ptr.To(true),
			},
			expected: true,
		},
		{
			name: "Ready nil, Serving false",
			conditions: discoveryv1.EndpointConditions{
				Ready:   nil,
				Serving: ptr.To(false),
			},
			expected: true,
		},
		{
			name: "Ready true, Serving nil",
			conditions: discoveryv1.EndpointConditions{
				Ready:   ptr.To(true),
				Serving: nil,
			},
			expected: true,
		},
		{
			name: "Ready true, Serving true",
			conditions: discoveryv1.EndpointConditions{
				Ready:   ptr.To(true),
				Serving: ptr.To(true),
			},
			expected: true,
		},
		{
			// Ready wins, as AntreaProxy takes every ready endpoint before it looks at anything else.
			name: "Ready true, Serving false",
			conditions: discoveryv1.EndpointConditions{
				Ready:   ptr.To(true),
				Serving: ptr.To(false),
			},
			expected: true,
		},
		{
			// Serving is nil on a cluster which predates the condition, so it reads as true, but the
			// endpoint is not terminating and AntreaProxy would not fall back to it.
			name: "Ready false, Serving nil",
			conditions: discoveryv1.EndpointConditions{
				Ready:   ptr.To(false),
				Serving: nil,
			},
			expected: false,
		},
		{
			// Serving without Terminating contradicts the API, which defines Serving as readiness
			// regardless of the terminating state. AntreaProxy only falls back to a terminating
			// endpoint, so neither does this.
			name: "Ready false, Serving true, not terminating",
			conditions: discoveryv1.EndpointConditions{
				Ready:   ptr.To(false),
				Serving: ptr.To(true),
			},
			expected: false,
		},
		{
			name: "Ready false, Serving true, Terminating true (drain state)",
			conditions: discoveryv1.EndpointConditions{
				Ready:       ptr.To(false),
				Serving:     ptr.To(true),
				Terminating: ptr.To(true),
			},
			expected: true,
		},
		{
			name: "Ready false, Serving false",
			conditions: discoveryv1.EndpointConditions{
				Ready:   ptr.To(false),
				Serving: ptr.To(false),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := discoveryv1.Endpoint{
				Conditions: tt.conditions,
			}
			assert.Equal(t, tt.expected, CanServe(ep))
		})
	}
}
