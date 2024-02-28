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
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	portcachetesting "antrea.io/antrea/pkg/agent/nodeportlocal/portcache/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	rulestesting "antrea.io/antrea/pkg/agent/nodeportlocal/rules/testing"
)

func TestRestoreRules(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockIPTables := rulestesting.NewMockPodPortRules(mockCtrl)
	mockPortOpener := portcachetesting.NewMockLocalPortOpener(mockCtrl)
	portTable := newPortTable(mockIPTables, mockPortOpener)
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

	mockIPTables.EXPECT().AddAllRules(gomock.InAnyOrder(allNPLPorts))
	gomock.InOrder(
		mockPortOpener.EXPECT().OpenLocalPort(nodePort1, "tcp"),
		mockPortOpener.EXPECT().OpenLocalPort(nodePort1, "udp"),
		mockPortOpener.EXPECT().OpenLocalPort(nodePort2, "udp"),
	)

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
