// Copyright 2025 Antrea Authors.
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

package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	tcp  = inverseServiceProtocolMap[corev1.ProtocolTCP]
	udp  = inverseServiceProtocolMap[corev1.ProtocolUDP]
	sctp = inverseServiceProtocolMap[corev1.ProtocolSCTP]
)

func TestNewProtocolFilter(t *testing.T) {
	testCases := []struct {
		name           string
		protocolFilter []string
		want           sets.Set[uint8]
	}{
		{
			"No protocols",
			[]string{},
			sets.New[uint8](),
		},
		{
			"Valid protocols",
			[]string{"TCP", "UDP"},
			sets.New(tcp, udp),
		},
		{
			"Valid protocols and some invalid typo'd protocols",
			[]string{"TCP", "scctp"},
			sets.New(tcp),
		},
		{
			"Mixed case protocols",
			[]string{"TCP", "udp", "sctp"},
			sets.New(tcp, udp, sctp),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewProtocolFilter(tc.protocolFilter).protocolNumbers
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProtocolFilter_Allow(t *testing.T) {
	testCases := []struct {
		name           string
		protocolFilter []string
		protocol       uint8
		want           bool
	}{
		{
			"Filter is nil",
			nil,
			tcp,
			true,
		},
		{
			"tcp filtered out",
			[]string{},
			tcp,
			false,
		},
		{
			"tcp not filtered out",
			[]string{"tcp"},
			tcp,
			true,
		},
		{
			"udp filtered out",
			[]string{"tcp", "udp"},
			udp,
			true,
		},
		{
			"sctp not filtered out",
			[]string{"tcp", "udp"},
			sctp,
			false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewProtocolFilter(tc.protocolFilter)
			got := filter.Allow(tc.protocol)
			assert.Equal(t, tc.want, got)
		})
	}
}
