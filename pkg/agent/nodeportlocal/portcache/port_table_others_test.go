//go:build !windows
// +build !windows

// Copyright 2021 Antrea Authors
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
	"fmt"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	portcachetesting "antrea.io/antrea/pkg/agent/nodeportlocal/portcache/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	rulestesting "antrea.io/antrea/pkg/agent/nodeportlocal/rules/testing"
)

func TestRestoreRules(t *testing.T) {
	allNPLPorts := []rules.PodNodePort{
		{
			NodePort: nodePort1,
			PodPort:  1001,
			PodIP:    podIP,
			Protocol: "tcp",
		},
		{
			NodePort: nodePort1,
			PodPort:  1001,
			PodIP:    podIP,
			Protocol: "udp",
		},
		{
			NodePort: nodePort2,
			PodPort:  1002,
			PodIP:    podIP,
			Protocol: "udp",
		},
	}

	runTest := func(t *testing.T, isIPv6 bool) {
		for _, failedRuleSyncs := range []int{0, 1, 10} {
			t.Run(fmt.Sprintf("with %d failed rule syncs", failedRuleSyncs), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					mockCtrl := gomock.NewController(t)
					mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)
					mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
					portTable := newPortTable(mockIPTables, mockPortOpener, isIPv6)

					gomock.InOrder(
						mockIPTables.EXPECT().AddAllRules(gomock.InAnyOrder(allNPLPorts)).Times(failedRuleSyncs).Return(fmt.Errorf("iptables error")),
						mockIPTables.EXPECT().AddAllRules(gomock.InAnyOrder(allNPLPorts)).Return(nil),
					)
					gomock.InOrder(
						mockPortOpener.EXPECT().OpenLocalPort(nodePort1, "tcp", isIPv6),
						mockPortOpener.EXPECT().OpenLocalPort(nodePort1, "udp", isIPv6),
						mockPortOpener.EXPECT().OpenLocalPort(nodePort2, "udp", isIPv6),
					)

					// Bubble time will automatically advance when goroutines are blocked.
					portTable.RestoreRules(t.Context(), allNPLPorts)
				})
			})
		}
	}

	t.Run("IPv4", func(t *testing.T) { runTest(t, false) })
	t.Run("IPv6", func(t *testing.T) { runTest(t, true) })
}

type mockCloser struct {
	closeErr error
}

func (m *mockCloser) Close() error {
	return m.closeErr
}

func TestDeleteRule(t *testing.T) {
	runTest := func(t *testing.T, isIPv6 bool) {
		mockCtrl := gomock.NewController(t)
		mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)
		mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
		portTable := newPortTable(mockIPTables, mockPortOpener, isIPv6)

		const (
			podPort  = 1001
			protocol = "tcp"
		)

		closer := &mockCloser{}

		data := &NodePortData{
			PodKey:   podKey,
			NodePort: nodePort1,
			PodPort:  podPort,
			PodIP:    podIP,
			Protocol: ProtocolSocketData{
				Protocol: protocol,
				socket:   closer,
			},
		}

		require.NoError(t, portTable.addPortTableCache(data))
		assert.False(t, data.Defunct())

		mockIPTables.EXPECT().DeleteRule(nodePort1, podIP, podPort, protocol).Return(fmt.Errorf("iptables error"))
		require.ErrorContains(t, portTable.DeleteRule(podKey, podPort, protocol), "iptables error")

		mockIPTables.EXPECT().DeleteRule(nodePort1, podIP, podPort, protocol)
		closer.closeErr = fmt.Errorf("close error")
		require.ErrorContains(t, portTable.DeleteRule(podKey, podPort, protocol), "close error")
		assert.True(t, data.Defunct())

		closer.closeErr = nil

		// First successful call to DeleteRule.
		mockIPTables.EXPECT().DeleteRule(nodePort1, podIP, podPort, protocol)
		assert.NoError(t, portTable.DeleteRule(podKey, podPort, protocol))

		// Calling DeleteRule again will return immediately as the NodePortData entry has been
		// removed from the cache.
		assert.NoError(t, portTable.DeleteRule(podKey, podPort, protocol))
	}

	t.Run("IPv4", func(t *testing.T) { runTest(t, false) })
	t.Run("IPv6", func(t *testing.T) { runTest(t, true) })
}
