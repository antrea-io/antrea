//go:build !windows
// +build !windows

// Copyright 2023 Antrea Authors
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

package iptables

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/intstr"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

var (
	ipsetAlfa  = "alfa"
	ipsetBravo = "bravo"
	eth0       = "eth0"
	eth1       = "eth1"
	port8080   = &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}
	port137    = &intstr.IntOrString{Type: intstr.Int, IntVal: 137}
	port139    = int32(139)
	port40000  = int32(40000)
	port50000  = int32(50000)
	icmpType0  = int32(0)
	icmpCode0  = int32(0)
)

func TestBuilders(t *testing.T) {
	testCases := []struct {
		name      string
		chain     string
		buildFunc func(IPTablesRuleBuilder) IPTablesRuleBuilder
		expected  string
	}{
		{
			name:  "Accept TCP destination 8080 in FORWARD",
			chain: ForwardChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRuleBuilder {
				return builder.
					MatchIPSetSrc(ipsetAlfa).
					MatchIPSetDst(ipsetBravo).
					MatchInputInterface(eth0).
					MatchTransProtocol(v1beta2.ProtocolTCP).
					MatchDstPort(port8080, nil).
					SetComment(`"Accept TCP 8080"`).
					SetTarget(AcceptTarget)
			},
			expected: `-A FORWARD -m set --match-ipset alfa src -m set --match-ipset bravo dst -i eth0 -p tcp --dport 8080 -m comment --comment "Accept TCP 8080" -j ACCEPT`,
		},
		{
			name:  "Drop UDP destination 137-139 in INPUT",
			chain: "INPUT",
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRuleBuilder {
				return builder.
					MatchIPSetSrc(ipsetAlfa).
					MatchInputInterface(eth0).
					MatchTransProtocol(v1beta2.ProtocolUDP).
					MatchDstPort(port137, &port139).
					SetComment(`"Drop UDP 137-139"`).
					SetTarget(DROPTarget)
			},
			expected: `-A INPUT -m set --match-ipset alfa src -i eth0 -p udp --dport 137:139 -m comment --comment "Drop UDP 137-139" -j DROP`,
		},
		{
			name:  "Reject SCTP source 40000-50000 in OUTPUT",
			chain: OutputChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRuleBuilder {
				return builder.
					MatchOutputInterface(eth1).
					MatchTransProtocol(v1beta2.ProtocolSCTP).
					MatchSrcPort(&port40000, &port50000).
					SetComment(`"Drop SCTP 40000-50000"`).
					SetTarget(DROPTarget)
			},
			expected: `-A OUTPUT -o eth1 -p sctp --sport 40000:50000 -m comment --comment "Drop SCTP 40000-50000" -j DROP`,
		},
		{
			name:  "Accept ICMP IPv4",
			chain: ForwardChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRuleBuilder {
				return builder.
					MatchInputInterface(eth0).
					MatchICMP(&icmpType0, &icmpCode0, ProtocolIPv4).
					SetTarget(AcceptTarget)
			},
			expected: `-A FORWARD -i eth0 -p icmp --icmp-type 0/0 -j ACCEPT`,
		},
		{
			name:  "Accept ICMP IPv6",
			chain: ForwardChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRuleBuilder {
				return builder.
					MatchInputInterface(eth0).
					MatchICMP(&icmpType0, nil, ProtocolIPv6).
					SetTarget(AcceptTarget)
			},
			expected: `-A FORWARD -i eth0 -p icmpv6 --icmpv6-type 0 -j ACCEPT`,
		},
	}

	for _, tc := range testCases {
		builder := NewRuleBuilder(tc.chain)
		t.Run(tc.name, func(t *testing.T) {
			copiedBuilder := builder.CopyBuilder()
			rule := tc.buildFunc(copiedBuilder).Done()
			assert.Equal(t, tc.expected, rule.GetSpec())
		})
	}
}
