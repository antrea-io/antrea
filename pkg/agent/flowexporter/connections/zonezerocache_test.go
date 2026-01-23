// Copyright 2026 Antrea Authors
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

//
//import (
//	"encoding/binary"
//	"fmt"
//	"net/netip"
//	"testing"
//	"time"
//
//	"github.com/stretchr/testify/assert"
//	"go.uber.org/mock/gomock"
//
//	"antrea.io/antrea/pkg/agent/flowexporter/connection"
//	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
//	"antrea.io/antrea/pkg/agent/flowexporter/utils"
//	"antrea.io/antrea/pkg/agent/openflow"
//	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
//	queriertest "antrea.io/antrea/pkg/querier/testing"
//	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
//)
//
//func TestZoneZeroCache_Delete(t *testing.T) { // todo fold into other test?
//	refTime := time.Now()
//	networkPolicyReadyTime := refTime.Add(-time.Hour)
//
//	oldConn := connection.Connection{
//		StartTime: refTime,
//		StopTime:  refTime,
//		FlowKey: connection.Tuple{
//			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//			Protocol:           6,
//			SourcePort:         52142,
//			DestinationPort:    80},
//		Mark:          openflow.ServiceCTMark.GetValue(),
//		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
//		ProxySnatPort: uint16(28392),
//	}
//	newConn := connection.Connection{
//		StartTime:      refTime.Add(-(time.Second * 50)),
//		StopTime:       refTime.Add(-(time.Second * 30)),
//		LastExportTime: refTime.Add(-(time.Second * 50)),
//		FlowKey: connection.Tuple{
//			SourceAddress:      netip.MustParseAddr("10.244.2.1"),
//			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//			Protocol:           6,
//			SourcePort:         28392,
//			DestinationPort:    80},
//		Mark:            openflow.ServiceCTMark.GetValue(),
//		Labels:          []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
//		ProxySnatIP:     netip.MustParseAddr("10.244.2.1"),
//		ProxySnatPort:   uint16(28392),
//		Zone:            65520,
//		OriginalPackets: 0xfff,
//	}
//	expectedConn := connection.Connection{
//		StartTime:      refTime.Add(-(time.Second * 50)),
//		StopTime:       refTime.Add(-(time.Second * 30)),
//		LastExportTime: refTime.Add(-(time.Second * 50)),
//		FlowKey: connection.Tuple{
//			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//			Protocol:           6,
//			SourcePort:         52142,
//			DestinationPort:    80},
//		Mark:                           openflow.ServiceCTMark.GetValue(),
//		Labels:                         []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
//		IsPresent:                      true,
//		IsActive:                       true,
//		DestinationPodName:             "pod1",
//		DestinationPodNamespace:        "ns1",
//		DestinationServicePortName:     servicePortName.String(),
//		IngressNetworkPolicyName:       np1.Name,
//		IngressNetworkPolicyNamespace:  np1.Namespace,
//		IngressNetworkPolicyUID:        string(np1.UID),
//		IngressNetworkPolicyType:       utils.PolicyTypeToUint8(np1.Type),
//		IngressNetworkPolicyRuleName:   rule1.Name,
//		IngressNetworkPolicyRuleAction: utils.RuleActionToUint8(string(*rule1.Action)),
//		Zone:                           65520,
//		OriginalPackets:                0xfff,
//		ProxySnatIP:                    netip.MustParseAddr("172.18.0.2"),
//		ProxySnatPort:                  uint16(28392),
//	}
//
//	ctrl := gomock.NewController(t)
//	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
//	mockProxier := proxytest.NewMockProxyQuerier(ctrl)
//	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
//	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
//	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, testFlowExporterOptions)
//	// Set the networkPolicyReadyTime to simulate that NetworkPolicies are ready
//	conntrackConnStore.networkPolicyReadyTime = networkPolicyReadyTime
//
//	// Add Zone Zero
//	protocol, _ := lookupServiceProtocol(expectedConn.FlowKey.Protocol)
//	serviceStr := fmt.Sprintf("%s:%d/%s", oldConn.OriginalDestinationAddress.String(), newConn.OriginalDestinationPort, protocol)
//	mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
//	conntrackConnStore.AddOrUpdateConn(&oldConn)
//
//	// Add Antrea Zone
//	mockPodStore.EXPECT().GetPodByIPAndTime(expectedConn.FlowKey.SourceAddress.String(), gomock.Any()).Return(nil, false)
//	mockPodStore.EXPECT().GetPodByIPAndTime(expectedConn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(pod1, true)
//	serviceStr = fmt.Sprintf("%s:%d/%s", expectedConn.OriginalDestinationAddress.String(), newConn.OriginalDestinationPort, protocol)
//	mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
//	ingressOfID := binary.BigEndian.Uint32(expectedConn.Labels[12:16])
//	npQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
//	newConnCopy := newConn
//	conntrackConnStore.AddOrUpdateConn(&newConn)
//
//	_, exist := conntrackConnStore.GetConnByKey(expectedConn.FlowKey)
//	assert.True(t, exist)
//
//	actualConn, _ := conntrackConnStore.GetConnByKey(expectedConn.FlowKey)
//	assert.Equal(t, expectedConn, *actualConn, "Connections should be equal")
//
//	conntrackConnStore.zoneZeroCache.Delete(actualConn)
//
//	matchingConn := conntrackConnStore.zoneZeroCache.GetMatching(&newConnCopy)
//	assert.Nil(t, matchingConn, "The connection should be deleted from the ZoneZeroCache")
//}
//
//func zoneZeroCacheLen(c *ZoneZeroCache) int {
//	count := 0
//	c.cache.Range(func(key, value interface{}) bool {
//		count++
//		return true
//	})
//	return count
//}
//
//func TestZoneZeroCache(t *testing.T) {
//	t.Run("Add", func(t *testing.T) {
//		t.Run("Adding a zone zero record", func(t *testing.T) {
//			cache := NewZoneZeroCache()
//			refTime := time.Now()
//			zoneZeroConn := &connection.Connection{
//				StartTime: refTime,
//				StopTime:  refTime,
//				FlowKey: connection.Tuple{
//					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//					Protocol:           6,
//					SourcePort:         52142,
//					DestinationPort:    80},
//				Mark:          openflow.ServiceCTMark.GetValue(),
//				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
//				ProxySnatPort: uint16(28392),
//			}
//			err := cache.Add(zoneZeroConn)
//			assert.Nil(t, err, "Expected adding zone 0 connection to not error")
//			assert.Equal(t, 1, zoneZeroCacheLen(cache), "Expected cache to contain newly added connection")
//		})
//		t.Run("Adding a record not from zone zero", func(t *testing.T) {
//			cache := NewZoneZeroCache()
//			refTime := time.Now()
//			zoneZeroConn := &connection.Connection{
//				StartTime: refTime,
//				StopTime:  refTime,
//				FlowKey: connection.Tuple{
//					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//					Protocol:           6,
//					SourcePort:         52142,
//					DestinationPort:    80},
//				Mark:          openflow.ServiceCTMark.GetValue(),
//				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
//				ProxySnatPort: uint16(28392),
//				Zone:          123,
//			}
//			assert.Error(t, cache.Add(zoneZeroConn), "Expected an error adding connection with zone 123")
//		})
//	})
//	t.Run("GetMatching", func(t *testing.T) {
//		t.Run("Has Match", func(t *testing.T) {
//			cache := NewZoneZeroCache()
//			refTime := time.Now()
//			zoneZeroConn := &connection.Connection{
//				StartTime: refTime,
//				StopTime:  refTime,
//				FlowKey: connection.Tuple{
//					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//					Protocol:           6,
//					SourcePort:         52142,
//					DestinationPort:    80},
//				Mark:          openflow.ServiceCTMark.GetValue(),
//				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
//				ProxySnatPort: uint16(28392),
//			}
//			antreaZeroConn := &connection.Connection{
//				StartTime: refTime,
//				StopTime:  refTime,
//				FlowKey: connection.Tuple{
//					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
//					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//					Protocol:           6,
//					SourcePort:         28392,
//					DestinationPort:    80},
//				Mark:          openflow.ServiceCTMark.GetValue(),
//				ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
//				ProxySnatPort: uint16(28392),
//			}
//			cache.Add(zoneZeroConn)
//			match := cache.GetMatching(antreaZeroConn)
//			assert.NotNil(t, match, "Expected a matching zone zero connection to have been cached")
//			assert.Equal(t, zoneZeroConn, match)
//		})
//		t.Run("Does Not Have Match", func(t *testing.T) {
//			cache := NewZoneZeroCache()
//			refTime := time.Now()
//			zoneZeroConn := &connection.Connection{
//				StartTime: refTime,
//				StopTime:  refTime,
//				FlowKey: connection.Tuple{
//					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//					Protocol:           6,
//					SourcePort:         52142,
//					DestinationPort:    80},
//				Mark:          openflow.ServiceCTMark.GetValue(),
//				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
//				ProxySnatPort: uint16(28392),
//			}
//			antreaZeroConn := &connection.Connection{
//				StartTime: refTime,
//				StopTime:  refTime,
//				FlowKey: connection.Tuple{
//					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
//					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//					Protocol:           6,
//					SourcePort:         55555,
//					DestinationPort:    80},
//				Mark:          openflow.ServiceCTMark.GetValue(),
//				ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
//				ProxySnatPort: uint16(28392),
//			}
//			cache.Add(zoneZeroConn)
//			match := cache.GetMatching(antreaZeroConn)
//			assert.Nil(t, match, "Expected cache to return a nil match")
//		})
//	})
//	t.Run("Expires stale records", func(t *testing.T) {
//		cache := ZoneZeroCache{}
//		refTime := time.Now()
//		zoneZeroConn := &connection.Connection{
//			StartTime: refTime,
//			StopTime:  refTime,
//			FlowKey: connection.Tuple{
//				SourceAddress:      netip.MustParseAddr("172.18.0.1"),
//				DestinationAddress: netip.MustParseAddr("10.244.2.2"),
//				Protocol:           6,
//				SourcePort:         52142,
//				DestinationPort:    80},
//			Mark:          openflow.ServiceCTMark.GetValue(),
//			ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
//			ProxySnatPort: uint16(28392),
//		}
//		err := cache.Add(zoneZeroConn)
//		assert.Nil(t, err, "Expected adding zone 0 connection to not error")
//		time.Sleep(1 * time.Millisecond)
//		cache.cleanup(1 * time.Millisecond)
//		assert.Equal(t, 0, zoneZeroCacheLen(&cache), "Expected cache to expire old records")
//	})
//}
