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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
)

// TestParseFlow tests if a flow can be parsed correctly.
func TestParseFlow(t *testing.T) {
	type testcase struct {
		flow     string
		success  bool
		expected *v1alpha1.Traceflow
	}

	tcs := []testcase{
		{
			flow:    "udp,udp_src=1234,udp_dst=4321",
			success: true,
			expected: &v1alpha1.Traceflow{
				Spec: v1alpha1.TraceflowSpec{
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 17,
						},
						TransportHeader: v1alpha1.TransportHeader{
							UDP: &v1alpha1.UDPHeader{
								SrcPort: 1234,
								DstPort: 4321,
							},
						},
					},
				},
			},
		},
		{
			flow:    " icmp,",
			success: true,
			expected: &v1alpha1.Traceflow{
				Spec: v1alpha1.TraceflowSpec{
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 1,
						},
					},
				},
			},
		},
		{
			flow:    "tcp,tcp_dst=4321",
			success: true,
			expected: &v1alpha1.Traceflow{
				Spec: v1alpha1.TraceflowSpec{
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 6,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tcs {
		option.flow = tc.flow
		pkt, err := parseFlow()
		if err != nil {
			if tc.success {
				t.Errorf("error when running parseFlow(): %w", err)
			}
		} else {
			assert.Equal(t, *pkt, tc.expected.Spec.Packet)
		}
	}
}

// TestGetFieldPortValue tests if corresponding value can be got of a key in a string.
func TestGetFieldPortValue(t *testing.T) {
	type testcase struct {
		flow     string
		field    string
		expected int
		success  bool
	}

	tcs := []testcase{
		{
			flow:     "ab=1,abc=2",
			field:    "abc",
			expected: 2,
			success:  true,
		},
		{
			flow:     "ab=1,abc=2",
			field:    "ab",
			expected: 1,
			success:  true,
		},
		{
			flow:     "ab=1,abc=2",
			field:    "a",
			expected: 0,
			success:  false,
		},
	}

	for _, tc := range tcs {
		n, ok, err := getFieldPortValue(tc.flow, tc.field)
		if err != nil {
			t.Errorf("testcase error: %v", tc)
		}
		if tc.success {
			assert.Equal(t, ok, true)
			assert.Equal(t, tc.expected, n)
		} else {
			assert.Equal(t, ok, false)
		}
	}
}
