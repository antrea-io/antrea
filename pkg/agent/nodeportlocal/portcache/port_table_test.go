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
	"k8s.io/apimachinery/pkg/types"
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

func TestGetServiceForNPLPort(t *testing.T) {
	pt := newPortTable(nil, nil, false)
	// The NPL controller stores the protocol in lower case (see util.BuildPortProto).
	require.NoError(t, pt.addPortTableCache(&NodePortData{
		PodKey:           podKey,
		NodePort:         nodePort1,
		PodPort:          1001,
		PodIP:            podIP,
		Protocol:         ProtocolSocketData{Protocol: "tcp"},
		ServiceName:      "mysvc",
		ServiceNamespace: "myns",
	}))
	// An NPL mapping with no associated Service (e.g. a container hostPort rule).
	require.NoError(t, pt.addPortTableCache(&NodePortData{
		PodKey:   podKey,
		NodePort: nodePort2,
		PodPort:  1002,
		PodIP:    podIP,
		Protocol: ProtocolSocketData{Protocol: "tcp"},
	}))

	// The flow exporter passes an upper-case corev1.Protocol ("TCP"); the lookup must be
	// case-insensitive because the table is keyed with the lower-case protocol.
	assert.Equal(t, "myns/mysvc", pt.GetServiceForNPLPort(nodePort1, "TCP"))

	// Lower-case protocol resolves too.
	assert.Equal(t, "myns/mysvc", pt.GetServiceForNPLPort(nodePort1, "tcp"))

	// Mapping without a Service name does not resolve.
	assert.Empty(t, pt.GetServiceForNPLPort(nodePort2, "TCP"))

	// Wrong protocol does not resolve.
	assert.Empty(t, pt.GetServiceForNPLPort(nodePort1, "UDP"))

	// Unknown node port does not resolve.
	assert.Empty(t, pt.GetServiceForNPLPort(endPort, "TCP"))
}

func TestSetServiceForPodPort(t *testing.T) {
	pt := newPortTable(nil, nil, false)
	require.NoError(t, pt.addPortTableCache(&NodePortData{
		PodKey:   podKey,
		NodePort: nodePort1,
		PodPort:  1001,
		PodIP:    podIP,
		Protocol: ProtocolSocketData{Protocol: "tcp"},
	}))

	// Backfilling Service information for an existing rule updates the cache entry.
	pt.SetServiceForPodPort(podKey, 1001, "tcp", types.NamespacedName{Namespace: "myns", Name: "mysvc"})
	assert.Equal(t, "myns/mysvc", pt.GetServiceForNPLPort(nodePort1, "TCP"))

	// Backfilling for a rule that does not exist is a no-op.
	pt.SetServiceForPodPort(podKey, 1002, "tcp", types.NamespacedName{Namespace: "myns", Name: "mysvc"})
	assert.Empty(t, pt.GetServiceForNPLPort(nodePort2, "TCP"))
}
