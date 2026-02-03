// Copyright 2020 Antrea Authors
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

package traceflow

import (
	"bytes"
	"strings"
	"testing"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRenderTree(t *testing.T) {
	tf := &v1beta1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-traceflow",
		},
		Spec: v1beta1.TraceflowSpec{
			Source: v1beta1.Source{
				Namespace: "default",
				Pod:       "pod-a",
			},
			Destination: v1beta1.Destination{
				Namespace: "default",
				Pod:       "pod-b",
			},
		},
		Status: v1beta1.TraceflowStatus{
			Results: []v1beta1.NodeResult{
				{
					Node: "node-1",
					Observations: []v1beta1.Observation{
						{
							Component: v1beta1.ComponentSpoofGuard,
							Action:    v1beta1.ActionForwarded,
						},
						{
							Component: v1beta1.ComponentRouting,
							Action:    v1beta1.ActionForwarded,
						},
					},
				},
				{
					Node: "node-2",
					Observations: []v1beta1.Observation{
						{
							Component: v1beta1.ComponentForwarding,
							Action:    v1beta1.ActionReceived,
						},
						{
							Component: v1beta1.ComponentNetworkPolicy,
							Action:    v1beta1.ActionDelivered,
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := renderTree(tf, &buf)
	if err != nil {
		t.Fatalf("renderTree returned error: %v", err)
	}

	output := buf.String()

	// Expected strings to be present
	expectedSubstrings := []string{
		"TRACE ID: test-traceflow",
		"SOURCE:   default/pod-a",
		"DEST:     default/pod-b",
		"[Node: node-1]",
		"├── SpoofGuard           [Forwarded] ->",
		"└── Routing              [Forwarded] ->",
		"(Cross-Node Traffic)",
		"[Node: node-2]",
		"├── Forwarding           [Received]",
		"└── NetworkPolicy        [Delivered] ✅",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(output, s) {
			t.Errorf("Expected output to contain %q, but it didn't.\nGot:\n%s", s, output)
		}
	}
}
