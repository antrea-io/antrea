// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connections

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

func TestDenyConnectionStore_AddOrUpdateConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Create flow for testing adding and updating of same connection.
	refTime := time.Now()
	tuple := connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	servicePortName := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS1",
			Name:      "service1",
		},
		Port:     "255",
		Protocol: v1.ProtocolTCP,
	}
	tc := []struct {
		name string
		// flow for testing adding and updating
		testFlow                 connection.Connection
		isSvc                    bool
		protocolFilter           []string
		expectConnectionNotFound bool
	}{
		{
			name: "Flow not through service",
			testFlow: connection.Connection{
				StopTime:                   refTime.Add(-(time.Second * 20)),
				StartTime:                  refTime.Add(-(time.Second * 20)),
				FlowKey:                    tuple,
				OriginalDestinationAddress: tuple.DestinationAddress,
				OriginalDestinationPort:    tuple.DestinationPort,
				OriginalBytes:              uint64(60),
				OriginalPackets:            uint64(1),
				IsActive:                   true,
				Mark:                       0,
			},
			isSvc: false,
		}, {
			name: "Flow through service",
			testFlow: connection.Connection{
				StopTime:                   refTime.Add(-(time.Second * 20)),
				StartTime:                  refTime.Add(-(time.Second * 20)),
				FlowKey:                    tuple,
				OriginalDestinationAddress: tuple.DestinationAddress,
				OriginalDestinationPort:    tuple.DestinationPort,
				OriginalBytes:              uint64(60),
				OriginalPackets:            uint64(1),
				IsActive:                   true,
				Mark:                       openflow.ServiceCTMark.GetValue(),
			},
			isSvc: true,
		}, {
			name: "With SCTP protocol filter",
			testFlow: connection.Connection{
				StopTime:                   refTime.Add(-(time.Second * 20)),
				StartTime:                  refTime.Add(-(time.Second * 20)),
				FlowKey:                    tuple,
				OriginalDestinationAddress: tuple.DestinationAddress,
				OriginalDestinationPort:    tuple.DestinationPort,
				OriginalBytes:              uint64(60),
				OriginalPackets:            uint64(1),
				IsActive:                   true,
				Mark:                       openflow.ServiceCTMark.GetValue(),
			},
			isSvc:                    true,
			protocolFilter:           []string{"SCTP"},
			expectConnectionNotFound: true,
		}, {
			name: "With TCP protocol filter",
			testFlow: connection.Connection{
				StopTime:                   refTime.Add(-(time.Second * 20)),
				StartTime:                  refTime.Add(-(time.Second * 20)),
				FlowKey:                    tuple,
				OriginalDestinationAddress: tuple.DestinationAddress,
				OriginalDestinationPort:    tuple.DestinationPort,
				OriginalBytes:              uint64(60),
				OriginalPackets:            uint64(1),
				IsActive:                   true,
				Mark:                       openflow.ServiceCTMark.GetValue(),
			},
			isSvc:          true,
			protocolFilter: []string{"TCP"},
		},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			// Reset the metrics.
			metrics.TotalDenyConnections.Set(0)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			protocol, _ := lookupServiceProtocol(tuple.Protocol)
			serviceStr := fmt.Sprintf("%s:%d/%s", tuple.DestinationAddress.String(), tuple.DestinationPort, protocol)
			if !c.expectConnectionNotFound {
				if c.isSvc {
					mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
				}
				mockPodStore.EXPECT().GetPodByIPAndTime(tuple.SourceAddress.String(), gomock.Any()).Return(pod1, true)
				mockPodStore.EXPECT().GetPodByIPAndTime(tuple.DestinationAddress.String(), gomock.Any()).Return(pod1, true)
			}

			config := testFlowExporterOptions
			config.AllowedProtocols = c.protocolFilter
			denyConnStore := NewDenyConnectionStore(nil, mockPodStore, mockProxier, config)

			flow1 := c.testFlow
			denyConnStore.AddOrUpdateConn(&flow1)
			expConn := flow1
			if c.isSvc {
				expConn.DestinationServicePortName = servicePortName.String()
			}
			actualConn, ok := denyConnStore.GetConnByKey(connection.NewConnectionKey(&c.testFlow))
			if c.expectConnectionNotFound {
				assert.Equal(t, ok, false, "deny connection should not be there in deny connection store")
				return // The connection was filtered out, nothing to compare
			}

			assert.Equal(t, ok, true, "deny connection should be there in deny connection store")
			assert.Equal(t, expConn, *actualConn, "deny connections should be equal")
			assert.Equal(t, 1, denyConnStore.connectionStore.expirePriorityQueue.Len(), "Length of the expire priority queue should be 1")
			assert.Equal(t, refTime.Add(-(time.Second * 20)), actualConn.LastExportTime, "LastExportTime should be set to StartTime during Add")
			checkDenyConnectionMetrics(t, len(denyConnStore.connections))

			flow2 := c.testFlow
			flow2.StopTime = refTime.Add(-(time.Second * 10))
			denyConnStore.AddOrUpdateConn(&flow2)
			expConn.OriginalBytes = expConn.OriginalBytes + c.testFlow.OriginalBytes
			expConn.OriginalPackets = expConn.OriginalPackets + c.testFlow.OriginalPackets
			expConn.StopTime = refTime.Add(-(time.Second * 10))
			actualConn, ok = denyConnStore.GetConnByKey(connection.NewConnectionKey(&c.testFlow))
			assert.Equal(t, ok, true, "deny connection should be there in deny connection store")
			assert.Equal(t, expConn, *actualConn, "deny connections should be equal")
			assert.True(t, actualConn.IsActive)
			assert.Equal(t, 1, denyConnStore.connectionStore.expirePriorityQueue.Len())
			assert.Equal(t, refTime.Add(-(time.Second * 20)), actualConn.LastExportTime, "LastExportTime should not be changed during Update")
			checkDenyConnectionMetrics(t, len(denyConnStore.connections))
		})
	}
}

func TestDenyConnectionStore_AddOrUpdateConn_existing(t *testing.T) {
	tuple := connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	// Create flow for testing adding and updating of same connection.
	refTime := time.Now()

	existingConn := &connection.Connection{
		StopTime:                   refTime.Add(-(time.Second * 40)),
		StartTime:                  refTime.Add(-(time.Second * 40)),
		LastExportTime:             refTime.Add(-(time.Second * 40)),
		FlowKey:                    tuple,
		OriginalDestinationAddress: tuple.DestinationAddress,
		OriginalDestinationPort:    tuple.DestinationPort,
		OriginalBytes:              uint64(40),
		OriginalPackets:            uint64(5),
		IsActive:                   true,
		Mark:                       0,
	}

	connToAdd := &connection.Connection{
		StopTime:                   refTime.Add(-(time.Second * 20)),
		StartTime:                  refTime.Add(-(time.Second * 20)),
		FlowKey:                    tuple,
		OriginalDestinationAddress: tuple.DestinationAddress,
		OriginalDestinationPort:    tuple.DestinationPort,
		OriginalBytes:              uint64(60),
		OriginalPackets:            uint64(1),
		IsActive:                   true,
		Mark:                       0,
	}

	expConn := &connection.Connection{
		StopTime:                   refTime.Add(-(time.Second * 20)),
		StartTime:                  refTime.Add(-(time.Second * 40)),
		LastExportTime:             refTime.Add(-(time.Second * 40)),
		FlowKey:                    tuple,
		OriginalDestinationAddress: tuple.DestinationAddress,
		OriginalDestinationPort:    tuple.DestinationPort,
		OriginalBytes:              uint64(100),
		OriginalPackets:            uint64(6),
		IsActive:                   true,
		Mark:                       0,
	}

	ctrl := gomock.NewController(t)

	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
	mockProxier := proxytest.NewMockProxyQuerier(ctrl)

	denyConnStore := NewDenyConnectionStore(nil, mockPodStore, mockProxier, testFlowExporterOptions)

	// Setup existing connection
	denyConnStore.connections[connection.NewConnectionKey(existingConn)] = existingConn
	metrics.TotalDenyConnections.Set(1)

	denyConnStore.AddOrUpdateConn(connToAdd)

	actualConn, ok := denyConnStore.GetConnByKey(connection.NewConnectionKey(connToAdd))

	assert.Equal(t, ok, true, "deny connection should be there in deny connection store")
	assert.Equal(t, expConn, actualConn, "deny connections should be equal")
	assert.Equal(t, 1, denyConnStore.connectionStore.expirePriorityQueue.Len(), "Length of the expire priority queue should be 1")
	assert.Equal(t, existingConn.LastExportTime, actualConn.LastExportTime, "LastExportTime should not update during second add")
	checkDenyConnectionMetrics(t, len(denyConnStore.connections))
}
