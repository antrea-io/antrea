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

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	podstoretest "antrea.io/antrea/pkg/util/podstore/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

func TestDenyConnectionStore_AddOrUpdateConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Create flow for testing adding and updating of same connection.
	refTime := time.Now()
	tuple := flowexporter.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
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
		testFlow flowexporter.Connection
		isSvc    bool
	}{
		{
			name: "Flow not through service",
			testFlow: flowexporter.Connection{
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
			testFlow: flowexporter.Connection{
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
		},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			// Reset the metrics.
			metrics.TotalDenyConnections.Set(0)
			mockPodStore := podstoretest.NewMockInterface(ctrl)
			mockProxier := proxytest.NewMockProxier(ctrl)
			protocol, _ := lookupServiceProtocol(tuple.Protocol)
			serviceStr := fmt.Sprintf("%s:%d/%s", tuple.DestinationAddress.String(), tuple.DestinationPort, protocol)
			if c.isSvc {
				mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
			}
			mockPodStore.EXPECT().GetPodByIPAndTime(tuple.SourceAddress.String(), gomock.Any()).Return(pod1, true)
			mockPodStore.EXPECT().GetPodByIPAndTime(tuple.DestinationAddress.String(), gomock.Any()).Return(pod1, true)

			denyConnStore := NewDenyConnectionStore(mockPodStore, mockProxier, testFlowExporterOptions)

			denyConnStore.AddOrUpdateConn(&c.testFlow, refTime.Add(-(time.Second * 20)), uint64(60))
			expConn := c.testFlow
			if c.isSvc {
				expConn.DestinationServicePortName = servicePortName.String()
			}
			actualConn, ok := denyConnStore.GetConnByKey(flowexporter.NewConnectionKey(&c.testFlow))
			assert.Equal(t, ok, true, "deny connection should be there in deny connection store")
			assert.Equal(t, expConn, *actualConn, "deny connections should be equal")
			assert.Equal(t, 1, denyConnStore.connectionStore.expirePriorityQueue.Len(), "Length of the expire priority queue should be 1")
			assert.Equal(t, refTime.Add(-(time.Second * 20)), actualConn.LastExportTime, "LastExportTime should be set to StartTime during Add")
			checkDenyConnectionMetrics(t, len(denyConnStore.connections))

			denyConnStore.AddOrUpdateConn(&c.testFlow, refTime.Add(-(time.Second * 10)), uint64(60))
			expConn.OriginalBytes = uint64(120)
			expConn.OriginalPackets = uint64(2)
			expConn.StopTime = refTime.Add(-(time.Second * 10))
			actualConn, ok = denyConnStore.GetConnByKey(flowexporter.NewConnectionKey(&c.testFlow))
			assert.Equal(t, ok, true, "deny connection should be there in deny connection store")
			assert.Equal(t, expConn, *actualConn, "deny connections should be equal")
			assert.True(t, actualConn.IsActive)
			assert.Equal(t, 1, denyConnStore.connectionStore.expirePriorityQueue.Len())
			assert.Equal(t, refTime.Add(-(time.Second * 20)), actualConn.LastExportTime, "LastExportTime should not be changed during Update")
			checkDenyConnectionMetrics(t, len(denyConnStore.connections))
		})
	}
}
