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
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

const (
	startPort = 61000
	endPort   = 65000
	podIP     = "10.0.0.1"
	nodePort1 = startPort
	nodePort2 = startPort + 1
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
