// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package flowexporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

func TestIsConnectionDying(t *testing.T) {
	for _, tc := range []struct {
		tcpState       string
		statusFlag     uint32
		isPresent      bool
		expectedResult bool
	}{
		{"ESTABLISHED", 256, true, false},
		{"TIME_WAIT", 256, true, true},
		{"CLOSE", 256, true, true},
		{"", 512, true, true},
		{"ESTABLISHED", 256, false, true},
	} {
		conn := &Connection{
			TCPState:   tc.tcpState,
			StatusFlag: tc.statusFlag,
			IsPresent:  tc.isPresent,
		}
		result := IsConnectionDying(conn)
		assert.Equal(t, tc.expectedResult, result)
	}
}

func TestConntrackConnActive(t *testing.T) {
	for _, tc := range []struct {
		originalPackets, prevPackets, reversePackets, prevReversePackets uint64
		tcpState, prevTCPState                                           string
		expectedResult                                                   bool
	}{
		{1, 0, 0, 0, "ESTABLISHED", "ESTABLISHED", true},
		{0, 0, 1, 0, "ESTABLISHED", "ESTABLISHED", true},
		{0, 0, 0, 0, "TIME_WAIT", "ESTABLISHED", true},
		{0, 0, 0, 0, "ESTABLISHED", "ESTABLISHED", false},
	} {
		conn := &Connection{
			OriginalPackets:    tc.originalPackets,
			PrevPackets:        tc.prevPackets,
			ReversePackets:     tc.reversePackets,
			PrevReversePackets: tc.prevReversePackets,
			TCPState:           tc.tcpState,
			PrevTCPState:       tc.prevTCPState,
		}
		result := CheckConntrackConnActive(conn)
		assert.Equal(t, tc.expectedResult, result)
	}
}

func TestRuleActionToUint8(t *testing.T) {
	for _, tc := range []struct {
		action         string
		expectedResult uint8
	}{
		{"Allow", 1},
		{"Drop", 2},
		{"Reject", 3},
		{"", 0},
	} {
		result := RuleActionToUint8(tc.action)
		assert.Equal(t, tc.expectedResult, result)
	}
}

func TestPolicyTypeToUint8(t *testing.T) {
	for _, tc := range []struct {
		policyType     v1beta2.NetworkPolicyType
		expectedResult uint8
	}{
		{v1beta2.K8sNetworkPolicy, 1},
		{v1beta2.AntreaNetworkPolicy, 2},
		{v1beta2.AntreaClusterNetworkPolicy, 3},
	} {
		result := PolicyTypeToUint8(tc.policyType)
		assert.Equal(t, tc.expectedResult, result)
	}
}

func TestLookupProtocolMap(t *testing.T) {
	for _, tc := range []struct {
		protocol       string
		expectedResult uint8
	}{
		{"icmp", 1},
		{"igmp", 2},
		{"tcp", 6},
		{"udp", 17},
		{"ipv6-icmp", 58},
		{"IPV6-ICMP", 58},
		{"mockProtocol", 0},
	} {
		proto, err := LookupProtocolMap(tc.protocol)
		if tc.expectedResult == 0 {
			assert.ErrorContains(t, err, "unknown IP protocol specified")
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResult, proto)
		}
	}
}
