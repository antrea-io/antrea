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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	podstoretest "antrea.io/antrea/pkg/util/podstore/testing"
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

func newFakeL7Listener(podStore *podstoretest.MockInterface) *L7Listener {
	return &L7Listener{
		l7Events:                    make(map[flowexporter.ConnectionKey]L7ProtocolFields),
		suricataEventSocketPath:     "suricata_Test.socket",
		podL7FlowExporterAttrGetter: &fakePodL7FlowExporterAttrGetter{},
		podStore:                    podStore,
	}
}

func TestFlowExporterL7ListenerHttp(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockPodStore := podstoretest.NewMockInterface(ctrl)
	l := newFakeL7Listener(mockPodStore)

	stopCh := make(chan struct{})
	defer func() {
		close(stopCh)
		os.RemoveAll(l.suricataEventSocketPath)
	}()
	go l.Run(stopCh)
	<-time.After(100 * time.Millisecond)

	testCases := []struct {
		name           string
		input          []JsonToEvent
		eventPresent   bool
		expectedErr    error
		expectedEvents L7ProtocolFields
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
					HTTP: &Http{
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
			expectedEvents: L7ProtocolFields{},
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
					HTTP: &Http{
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
			expectedEvents: L7ProtocolFields{
				http: map[int32]*Http{
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
					HTTP: &Http{
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
					HTTP: &Http{
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
			expectedEvents: L7ProtocolFields{
				http: map[int32]*Http{
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
			socketConn, err := net.Dial("unix", l.suricataEventSocketPath)
			if err != nil {
				t.Fatalf("Failed to connect to server: %s", err)
			}
			defer socketConn.Close()
			writer := bufio.NewWriter(socketConn)
			timeNow, _ := time.Parse(time.RFC3339Nano, tc.input[0].Timestamp)
			mockPodStore.EXPECT().GetPodByIPAndTime("10.10.0.1", timeNow).Return(fakeSrcPod, true)
			mockPodStore.EXPECT().GetPodByIPAndTime("10.10.0.2", timeNow).Return(fakeDestPod, true)
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
			socketConn.Close()
			<-time.After(100 * time.Millisecond)
			protocol, _ := flowexporter.LookupProtocolMap(tc.input[0].Proto)
			// Get 5-tuple information
			tuple := flowexporter.Tuple{
				SourceAddress:      tc.input[0].SrcIP,
				DestinationAddress: tc.input[0].DestIP,
				Protocol:           protocol,
				SourcePort:         uint16(tc.input[0].SrcPort),
				DestinationPort:    uint16(tc.input[0].DestPort),
			}
			conn := flowexporter.Connection{}
			conn.FlowKey = tuple
			connKey := flowexporter.NewConnectionKey(&conn)
			allL7Events := l.ConsumeL7EventMap()
			existingEvent, exists := allL7Events[connKey]
			assert.Equal(t, tc.eventPresent, exists)
			if exists {
				assert.Equal(t, tc.expectedEvents.http, existingEvent.http)
			}
		})
	}
}
