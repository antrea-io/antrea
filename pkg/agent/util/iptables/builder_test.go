//go:build !windows
// +build !windows

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

package iptables

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	cidr       = "192.168.1.0/24"
)

func TestBuilders(t *testing.T) {
	testCases := []struct {
		name      string
		chain     string
		buildFunc func(IPTablesRuleBuilder) IPTablesRule
		expected  string
	}{
		{
			name:  "Accept TCP destination 8080 in FORWARD",
			chain: ForwardChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRule {
				return builder.MatchIPSetSrc(ipsetAlfa).
					MatchIPSetDst(ipsetBravo).
					MatchInputInterface(eth0).
					MatchTransProtocol(ProtocolTCP).
					MatchDstPort(port8080, nil).
					MatchCIDRSrc(cidr).
					SetComment("Accept TCP 8080").
					SetTarget(AcceptTarget).
					Done()
			},
			expected: `-A FORWARD -m set --match-set alfa src -m set --match-set bravo dst -i eth0 -p tcp --dport 8080 -s 192.168.1.0/24 -m comment --comment "Accept TCP 8080" -j ACCEPT`,
		},
		{
			name:  "Drop UDP destination 137-139 in INPUT",
			chain: "INPUT",
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRule {
				return builder.MatchIPSetSrc(ipsetAlfa).
					MatchInputInterface(eth0).
					MatchTransProtocol(ProtocolUDP).
					MatchDstPort(port137, &port139).
					MatchCIDRDst(cidr).
					SetComment("Drop UDP 137-139").
					SetTarget(DropTarget).
					Done()
			},
			expected: `-A INPUT -m set --match-set alfa src -i eth0 -p udp --dport 137:139 -d 192.168.1.0/24 -m comment --comment "Drop UDP 137-139" -j DROP`,
		},
		{
			name:  "Reject SCTP source 40000-50000 in OUTPUT",
			chain: OutputChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRule {
				return builder.MatchOutputInterface(eth1).
					MatchTransProtocol(ProtocolSCTP).
					MatchSrcPort(&port40000, &port50000).
					SetComment("Drop SCTP 40000-50000").
					SetTarget(DropTarget).
					Done()
			},
			expected: `-A OUTPUT -o eth1 -p sctp --sport 40000:50000 -m comment --comment "Drop SCTP 40000-50000" -j DROP`,
		},
		{
			name:  "Accept ICMP IPv4",
			chain: ForwardChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRule {
				return builder.MatchInputInterface(eth0).
					MatchICMP(&icmpType0, &icmpCode0, ProtocolIPv4).
					SetTarget(AcceptTarget).
					Done()
			},
			expected: `-A FORWARD -i eth0 -p icmp --icmp-type 0/0 -j ACCEPT`,
		},
		{
			name:  "Accept ICMP IPv6",
			chain: ForwardChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRule {
				return builder.MatchInputInterface(eth0).
					MatchICMP(&icmpType0, nil, ProtocolIPv6).
					SetTarget(AcceptTarget).
					Done()
			},
			expected: `-A FORWARD -i eth0 -p icmpv6 --icmpv6-type 0 -j ACCEPT`,
		},
		{
			name:  "Accept packets of established TCP connections",
			chain: InputChain,
			buildFunc: func(builder IPTablesRuleBuilder) IPTablesRule {
				return builder.MatchTransProtocol(ProtocolTCP).
					MatchEstablishedOrRelated().
					SetTarget(AcceptTarget).
					Done()
			},
			expected: `-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewRuleBuilder(tc.chain)
			rule := tc.buildFunc(builder)
			assert.Equal(t, tc.expected, rule.GetRule())
		})
	}
}
