//go:build windows
// +build windows

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
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	portcachetesting "antrea.io/antrea/pkg/agent/nodeportlocal/portcache/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	rulestesting "antrea.io/antrea/pkg/agent/nodeportlocal/rules/testing"
)

func TestRestoreRules(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockPortRules := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockPortRules, mockPortOpener)
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

	mockPortRules.EXPECT().AddRule(nodePort1, podIP, 1001, "tcp")
	mockPortRules.EXPECT().AddRule(nodePort1, podIP, 1001, "udp")
	mockPortRules.EXPECT().AddRule(nodePort2, podIP, 1002, "udp")

	syncedCh := make(chan struct{})
	err := portTable.RestoreRules(allNPLPorts, syncedCh)
	require.NoError(t, err)
}

func TestDeleteRule(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockPortRules := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockPortRules, mockPortOpener)
	npData := &NodePortData{
		NodePort: startPort,
		PodIP:    podIP,
		PodPort:  1001,
		Protocol: ProtocolSocketData{
			Protocol: "tcp",
		},
	}

	portTable.addPortTableCache(npData)
	mockPortRules.EXPECT().DeleteRule(startPort, podIP, 1001, "tcp")
	err := portTable.DeleteRule(podIP, 1001, "tcp")
	require.NoError(t, err)
}

func TestDeleteRulesForPod(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockPortRules := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockPortRules, mockPortOpener)

	npData := []*NodePortData{
		{
			NodePort: startPort,
			PodIP:    podIP,
			PodPort:  1001,
			Protocol: ProtocolSocketData{
				Protocol: "tcp",
			},
		},
		{
			NodePort: startPort + 1,
			PodIP:    podIP,
			PodPort:  1002,
			Protocol: ProtocolSocketData{
				Protocol: "udp",
			},
		},
	}

	for _, data := range npData {
		portTable.addPortTableCache(data)
		mockPortRules.EXPECT().DeleteRule(data.NodePort, podIP, data.PodPort, data.Protocol.Protocol)
	}

	err := portTable.DeleteRulesForPod(podIP)
	require.NoError(t, err)
}

func TestAddRule(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockPortRules := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockPortRules, mockPortOpener)
	podPort := 1001

	// Adding the rule the first time should succeed.
	mockPortRules.EXPECT().AddRule(startPort, podIP, podPort, "udp")
	gotNodePort, err := portTable.AddRule(podIP, podPort, "udp")
	require.NoError(t, err)
	assert.Equal(t, startPort, gotNodePort)

	// Add the same rule the second time should fail.
	_, err = portTable.AddRule(podIP, podPort, "udp")
	assert.ErrorContains(t, err, "existing Windows Nodeport entry for")
}
