//go:build !windows

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

package rules

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/util/iptables"
	iptablestest "antrea.io/antrea/pkg/agent/util/iptables/testing"
)

func TestAddAndDeleteRule(t *testing.T) {
	tests := []struct {
		nodePort      int
		podIP         string
		podPort       int
		protocol      string
		expectedCalls func(iptables *iptablestest.MockInterfaceMockRecorder)
	}{
		{
			nodePort: 7,
			podIP:    "10.10.10.0",
			podPort:  17,
			protocol: "udp",
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain)
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain, []string{"-p", "udp", "-m", "udp", "--dport", "7", "-j", "DNAT", "--to-destination", "10.10.10.0:7"})
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain, []string{"-p", "udp", "-m", "udp", "--dport", "7", "-j", "DNAT", "--to-destination", "10.10.10.0:7"})
			},
		},
		{
			nodePort: 7,
			podIP:    "10.10.0.2",
			podPort:  17,
			protocol: "tcp",
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain)
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain, []string{"-p", "tcp", "-m", "tcp", "--dport", "7", "-j", "DNAT", "--to-destination", "10.10.0.2:7"})
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain, []string{"-p", "tcp", "-m", "tcp", "--dport", "7", "-j", "DNAT", "--to-destination", "10.10.0.2:7"})
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.podIP, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			rules := iptablesRules{
				name:  "test-rules",
				table: mockIPTables,
			}

			tt.expectedCalls(mockIPTables.EXPECT())

			err := rules.Init()
			require.NoError(t, err)

			err = rules.AddRule(tt.nodePort, tt.podIP, tt.nodePort, tt.protocol)
			require.NoError(t, err)

			err = rules.DeleteRule(tt.nodePort, tt.podIP, tt.nodePort, tt.protocol)
			require.NoError(t, err)
		})
	}
}

func TestAddAndDeleteAllRules(t *testing.T) {
	tests := []struct {
		name          string
		rules         []PodNodePort
		expectedCalls func(iptables *iptablestest.MockInterfaceMockRecorder)
	}{
		{
			name: "2 PodNodePort rules",
			rules: []PodNodePort{
				{
					NodePort: 8227,
					PodPort:  7237,
					PodIP:    "10.10.10.11",
					Protocol: "udp",
				},
				{
					NodePort: 8247,
					PodPort:  7257,
					PodIP:    "10.11.10.12",
					Protocol: "tcp",
				},
			},
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain)
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.Restore(`*nat
:ANTREA-NODE-PORT-LOCAL - [0:0]
COMMIT
`, false, false)
				// Set the expectation for ChainExists to return true
				mockIPTables.ChainExists(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain).Return(true, nil)
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.DeleteChain(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain)
			},
		},
		{
			name: "3 PodNodePort rules",
			rules: []PodNodePort{
				{
					NodePort: 7,
					PodPort:  17,
					PodIP:    "10.10.10.10",
					Protocol: "tcp",
				},
				{
					NodePort: 27,
					PodPort:  37,
					PodIP:    "10.10.10.11",
					Protocol: "udp",
				},
				{
					NodePort: 47,
					PodPort:  57,
					PodIP:    "10.11.10.12",
					Protocol: "tcp",
				},
			},
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain)
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.AppendRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.Restore(`*nat
:ANTREA-NODE-PORT-LOCAL - [0:0]
COMMIT
`, false, false)
				// Set the expectation for ChainExists to return true
				mockIPTables.ChainExists(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain).Return(true, nil)
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, []string{"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain})
				mockIPTables.DeleteChain(iptables.ProtocolIPv4, iptables.NATTable, NodePortLocalChain)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			rules := iptablesRules{
				name:  "test-rules",
				table: mockIPTables,
			}

			tt.expectedCalls(mockIPTables.EXPECT())

			err := rules.Init()
			require.NoError(t, err)

			err = rules.AddAllRules(tt.rules)
			require.NoError(t, err)

			err = rules.DeleteAllRules()
			require.NoError(t, err)
		})
	}
}
