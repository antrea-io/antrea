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

package portcache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/nodeportlocal/rules"
)

const (
	startPort = 61000
	endPort   = 65000
	podIP     = "10.0.0.1"
	podKey    = "default/test-pod"
	nodePort1 = startPort
	nodePort2 = startPort + 1
)

func newPortTable(mockIPTables rules.PodPortRules, mockPortOpener LocalPortOpener, isIPv6 bool) *PortTable {
	return &PortTable{
		PortTableCache: cache.NewIndexer(GetPortTableKey, cache.Indexers{
			NodePortIndex:    NodePortIndexFunc,
			PodEndpointIndex: PodEndpointIndexFunc,
			PodKeyIndex:      PodKeyIndexFunc,
		}),
		StartPort:       startPort,
		EndPort:         endPort,
		PortSearchStart: startPort,
		PodPortRules:    mockIPTables,
		LocalPortOpener: mockPortOpener,
		IsIPv6:          isIPv6,
	}
}

func TestNextFreePortCandidate(t *testing.T) {
	pt := &PortTable{
		StartPort:       61000,
		EndPort:         61002, // range: 61000, 61001, 61002 (3 ports)
		PortSearchStart: 61001,
	}
	numPorts := pt.EndPort - pt.StartPort + 1 // 3

	tests := []struct {
		name     string
		i        int
		wantPort int
	}{
		{
			name:     "no wrap: i=0 starts at PortSearchStart",
			i:        0,
			wantPort: 61001,
		},
		{
			name:     "no wrap: i=1",
			i:        1,
			wantPort: 61002,
		},
		{
			name:     "wrap: i=2 exceeds EndPort, wraps to StartPort",
			i:        2,
			wantPort: 61000,
		},
		{
			name:     "wrap: last iteration equals numPorts-1",
			i:        numPorts - 1,
			wantPort: 61000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pt.nextFreePortCandidate(tc.i)
			assert.Equal(t, tc.wantPort, got)
		})
	}
}

func TestAdvancePortSearchStart(t *testing.T) {
	tests := []struct {
		name          string
		portSearchStart int
		port          int
		wantNext      int
	}{
		{
			name:          "mid-range: bumps by 1",
			portSearchStart: 61000,
			port:          61001,
			wantNext:      61002,
		},
		{
			name:          "at EndPort: wraps to StartPort",
			portSearchStart: 61000,
			port:          65000,
			wantNext:      61000,
		},
		{
			name:          "one before EndPort: no wrap",
			portSearchStart: 61000,
			port:          64999,
			wantNext:      65000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pt := &PortTable{
				StartPort:       startPort,
				EndPort:         endPort,
				PortSearchStart: tc.portSearchStart,
			}
			pt.advancePortSearchStart(tc.port)
			assert.Equal(t, tc.wantNext, pt.PortSearchStart)
		})
	}
}

func TestNewNodePortData(t *testing.T) {
	protocol := ProtocolSocketData{Protocol: "tcp"}
	got := newNodePortData("default/my-pod", 61000, "192.168.1.1", 8080, protocol)

	assert.Equal(t, "default/my-pod", got.PodKey)
	assert.Equal(t, 61000, got.NodePort)
	assert.Equal(t, "192.168.1.1", got.PodIP)
	assert.Equal(t, 8080, got.PodPort)
	assert.Equal(t, protocol, got.Protocol)
	assert.False(t, got.Defunct(), "newly created NodePortData must not be defunct")
}

