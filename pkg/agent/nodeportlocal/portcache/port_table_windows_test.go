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
	"time"

	"github.com/golang/mock/gomock"

	portcachetesting "antrea.io/antrea/pkg/agent/nodeportlocal/portcache/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	rulestesting "antrea.io/antrea/pkg/agent/nodeportlocal/rules/testing"

	"k8s.io/client-go/tools/cache"
)

const (
	startPort = 61000
	endPort   = 65000
)

func newPortTable(mockIPTables rules.PodPortRules, mockPortOpener LocalPortOpener) *PortTable {
	return &PortTable{
		PortTableCache: cache.NewIndexer(GetPortTableKey, cache.Indexers{
			NodePortIndex:    NodePortIndexFunc,
			PodEndpointIndex: PodEndpointIndexFunc,
			PodIPIndex:       PodIPIndexFunc,
		}),
		StartPort:       startPort,
		EndPort:         endPort,
		PortSearchStart: startPort,
		PodPortRules:    mockIPTables,
		LocalPortOpener: mockPortOpener,
	}
}

func TestRestoreRules(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockIPTables, mockPortOpener)
	podIP := "10.0.0.1"
	nodePort1 := startPort
	nodePort2 := startPort + 1
	allNPLPorts := []rules.PodNodePort{
		{
			NodePort: nodePort1,
			PodPort:  1001,
			PodIP:    podIP,
			Protocol: "tcp",
			// Protocols: []string{"tcp"},
		},
		{
			NodePort: nodePort1,
			PodPort:  1001,
			PodIP:    podIP,
			Protocol: "udp",
			// Protocols: []string{"udp"},
		},
		{
			NodePort: nodePort2,
			PodPort:  1002,
			PodIP:    podIP,
			Protocol: "udp",
			// Protocols: []string{"udp"},
		},
	}

	mockIPTables.EXPECT().AddRule(nodePort1, podIP, 1001, "tcp")
	mockIPTables.EXPECT().AddRule(nodePort1, podIP, 1001, "udp")
	mockIPTables.EXPECT().AddRule(nodePort2, podIP, 1002, "udp")

	syncedCh := make(chan struct{})
	const timeout = 1 * time.Second
	portTable.RestoreRules(allNPLPorts, syncedCh)
	select {
	case <-syncedCh:
		break
	case <-time.After(timeout):
		// this will not kill the goroutine created by RestoreRules,
		// which should be acceptable.
		t.Fatalf("Rule restoration not complete after %v", timeout)
	}
}

func TestDeleteRule(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockIPTables, mockPortOpener)
	podIP := "10.0.0.1"
	// nodePort1 := startPort

	//mockIPTables.EXPECT().AddRule(nodePort1, podIP, 1001, "tcp")
	portTable.DeleteRule(podIP, 1001, "tcp")
}
