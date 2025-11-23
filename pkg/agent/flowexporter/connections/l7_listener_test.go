// Copyright 2023 Antrea Authors
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
	"bufio"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
)

var (
	fakeDestPod = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fakePod",
			Namespace: "fakeNS",
		},
	}
	fakeSrcPod = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fakePod",
			Namespace: "fakeNS",
		},
	}
)

type fakePodL7FlowExporterAttrGetter struct{}

func (fl *fakePodL7FlowExporterAttrGetter) IsL7FlowExporterRequested(podNN string, ingress bool) bool {
	podToDirectionMap := map[string]v1alpha2.Direction{
		"destPodNNDirIngress": v1alpha2.DirectionIngress,
		"destPodNNDirEgress":  v1alpha2.DirectionEgress,
		"destPodNNDirBoth":    v1alpha2.DirectionBoth,
		"srcPodNNDirIngress":  v1alpha2.DirectionIngress,
		"srcPodNNDirEgress":   v1alpha2.DirectionEgress,
		"srcPodNNDirBoth":     v1alpha2.DirectionBoth,
		"fakeNS/fakePod":      v1alpha2.DirectionIngress,
	}

	if direction, ok := podToDirectionMap[podNN]; ok {
		switch direction {
		case v1alpha2.DirectionIngress:
			return ingress
		case v1alpha2.DirectionEgress:
			return !ingress
		case v1alpha2.DirectionBoth:
			return true
		}
	}
	return false
}

func newFakeL7Listener(socketPath string, podStore *objectstoretest.MockPodStore) *L7Listener {
	return &L7Listener{
		l7Events:                    make(map[connection.ConnectionKey]connection.L7ProtocolFields),
		suricataEventSocketPath:     socketPath,
		podL7FlowExporterAttrGetter: &fakePodL7FlowExporterAttrGetter{},
		podStore:                    podStore,
	}
}

func TestFlowExporterL7ListenerHttp(t *testing.T) {
	testCases := []struct {
		name           string
		input          []JsonToEvent
		eventPresent   bool
		expectedEvents connection.L7ProtocolFields
	}{
		{
			name: "Invalid eventType",
			input: []JsonToEvent{
				{
					Timestamp:   time.Now().String(),
					FlowID:      1,
					InInterface: "mock_interface",
					EventType:   "mock_event1",
					VLAN:        []int32{1},
					SrcIP:       netip.MustParseAddr("10.10.0.1"),
					SrcPort:     59921,
					DestIP:      netip.MustParseAddr("10.10.0.2"),
					DestPort:    80,
					Proto:       "TCP",
					TxID:        0,
					HTTP: &connection.Http{
						Hostname:      "10.10.0.1",
						URL:           "/public/",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        200,
						ContentLength: 153,
					},
				},
			},
			eventPresent:   false,
			expectedEvents: connection.L7ProtocolFields{},
		}, {
			name: "Valid case",
			input: []JsonToEvent{
				{
					Timestamp:   "0001-01-01 00:00:00 +0000 UTC",
					FlowID:      1,
					InInterface: "mock_interface",
					EventType:   "http",
					VLAN:        []int32{1},
					SrcIP:       netip.MustParseAddr("10.10.0.1"),
					SrcPort:     59920,
					DestIP:      netip.MustParseAddr("10.10.0.2"),
					DestPort:    80,
					Proto:       "TCP",
					TxID:        0,
					HTTP: &connection.Http{
						Hostname:      "10.10.0.1",
						URL:           "/public/1",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        200,
						ContentLength: 153,
					},
				},
			},
			eventPresent: true,
			expectedEvents: connection.L7ProtocolFields{
				Http: map[int32]*connection.Http{
					0: {
						Hostname:      "10.10.0.1",
						URL:           "/public/1",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        200,
						ContentLength: 153,
					},
				},
			},
		}, {
			name: "Valid case for persistent http",
			input: []JsonToEvent{
				{
					Timestamp:   time.Now().String(),
					FlowID:      1,
					InInterface: "mock_interface",
					EventType:   "http",
					VLAN:        []int32{1},
					SrcIP:       netip.MustParseAddr("10.10.0.1"),
					SrcPort:     59920,
					DestIP:      netip.MustParseAddr("10.10.0.2"),
					DestPort:    80,
					Proto:       "TCP",
					TxID:        0,
					HTTP: &connection.Http{
						Hostname:      "10.10.0.1",
						URL:           "/public/2",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        200,
						ContentLength: 153,
					},
				}, {
					Timestamp:   time.Now().String(),
					FlowID:      1,
					InInterface: "mock_interface",
					EventType:   "http",
					VLAN:        []int32{1},
					SrcIP:       netip.MustParseAddr("10.10.0.1"),
					SrcPort:     59920,
					DestIP:      netip.MustParseAddr("10.10.0.2"),
					DestPort:    80,
					Proto:       "TCP",
					TxID:        1,
					HTTP: &connection.Http{
						Hostname:      "10.10.0.1",
						URL:           "/public/3",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        201,
						ContentLength: 154,
					},
				},
			},
			eventPresent: true,
			expectedEvents: connection.L7ProtocolFields{
				Http: map[int32]*connection.Http{
					0: {
						Hostname:      "10.10.0.1",
						URL:           "/public/2",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        200,
						ContentLength: 153,
					},
					1: {
						Hostname:      "10.10.0.1",
						URL:           "/public/3",
						UserAgent:     "curl/7.74.0",
						ContentType:   "text/html",
						Method:        "GET",
						Protocol:      "HTTP/1.1",
						Status:        201,
						ContentLength: 154,
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			timeNow, _ := time.Parse(time.RFC3339Nano, tc.input[0].Timestamp)
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockPodStore.EXPECT().GetPodByIPAndTime("10.10.0.1", timeNow).AnyTimes().Return(fakeSrcPod, true)
			mockPodStore.EXPECT().GetPodByIPAndTime("10.10.0.2", timeNow).AnyTimes().Return(fakeDestPod, true)
			socketFile, err := os.CreateTemp(".", "suricata_test_*.socket")
			require.NoError(t, err)
			socketFile.Close()
			socketPath := socketFile.Name()
			defer os.RemoveAll(socketPath)
			l := newFakeL7Listener(socketPath, mockPodStore)

			stopCh := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				l.Run(stopCh)
			}()
			defer wg.Wait()
			defer close(stopCh)

			var socketConn net.Conn
			require.EventuallyWithT(t, func(t *assert.CollectT) {
				var err error
				socketConn, err = net.Dial("unix", l.suricataEventSocketPath)
				assert.NoError(t, err)
			}, 1*time.Second, 100*time.Millisecond, "Failed to connect to Suricata event socket %s", l.suricataEventSocketPath)
			defer socketConn.Close()

			writer := bufio.NewWriter(socketConn)
			for _, msg := range tc.input {
				jsonData, err := json.Marshal(msg)
				if err != nil {
					t.Errorf("Error Marshaling data: %v\n", err)
				}
				writer.Write(jsonData)
				if err != nil {
					t.Errorf("Error writing event data: %v\n", err)
				}
				_, err = writer.Write([]byte("\n"))
				if err != nil {
					t.Errorf("Error writing newline: %v\n", err)
				}
			}
			writer.Flush()
			assert.EventuallyWithT(t, func(t *assert.CollectT) {
				protocol, _ := utils.LookupProtocolMap(tc.input[0].Proto)
				connKey := connection.Tuple{
					SourceAddress:      tc.input[0].SrcIP,
					DestinationAddress: tc.input[0].DestIP,
					Protocol:           protocol,
					SourcePort:         uint16(tc.input[0].SrcPort),
					DestinationPort:    uint16(tc.input[0].DestPort),
				}
				allL7Events := l.ConsumeL7EventMap()
				existingEvent, exists := allL7Events[connKey]
				assert.Equal(t, tc.eventPresent, exists)
				if exists {
					assert.Equal(t, tc.expectedEvents.Http, existingEvent.Http)
				}
			}, 1*time.Second, 100*time.Millisecond, "L7 event map does not match")
		})
	}
}
