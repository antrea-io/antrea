// Copyright 2020 Antrea Authors
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

package networkpolicy

import (
	"net"
	"sync"
	"testing"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

// mockLogger implements PolicyCustomLogger.
type mockLogger struct {
	sync.Mutex
	logged chan string
}

func (l *mockLogger) Printf(format string, v ...interface{}) {
	l.Lock()
	defer l.Unlock()
	l.logged <- format
}

func newAntreaPolicyLogger() *AntreaPolicyLogger {
	return &AntreaPolicyLogger{
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
}

func newLogInfo(disposition string) (*logInfo, string) {
	expected := "AntreaPolicyIngressRule AntreaNetworkPolicy:default/test " + disposition + " 0 SRC: 0.0.0.0 DEST: 1.1.1.1 60 TCP"
	return &logInfo{
		tableName:   "AntreaPolicyIngressRule",
		npRef:       "AntreaNetworkPolicy:default/test",
		ofPriority:  "0",
		disposition: disposition,
		srcIP:       "0.0.0.0",
		destIP:      "1.1.1.1",
		pktLength:   60,
		protocolStr: "TCP",
	}, expected
}

func TestAllowPacketLog(t *testing.T) {
	mockAnpLogger := &mockLogger{logged: make(chan string, 100)}
	antreaLogger := newAntreaPolicyLogger()
	antreaLogger.anpLogger = mockAnpLogger
	ob, expected := newLogInfo("Allow")

	antreaLogger.logDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketLog(t *testing.T) {
	mockAnpLogger := &mockLogger{logged: make(chan string, 100)}
	antreaLogger := newAntreaPolicyLogger()
	antreaLogger.anpLogger = mockAnpLogger
	ob, expected := newLogInfo("Drop")

	antreaLogger.logDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketDedupLog(t *testing.T) {
	mockAnpLogger := &mockLogger{logged: make(chan string, 100)}
	antreaLogger := newAntreaPolicyLogger()
	antreaLogger.anpLogger = mockAnpLogger
	ob, expected := newLogInfo("Drop")
	// add the additional log info for duplicate packets
	expected += " ["

	go antreaLogger.logDedupPacket(ob)
	go antreaLogger.logDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestGetPacketInfo(t *testing.T) {
	type args struct {
		pktIn *ofctrl.PacketIn
		ob    *logInfo
	}
	tests := []struct {
		name       string
		pktIn      *ofctrl.PacketIn
		expectedOb logInfo
		wantErr    bool
	}{
		{
			"ipv4",
			&ofctrl.PacketIn{
				Reason: 1,
				Data: protocol.Ethernet{
					Ethertype: 0x0800,
					Data: util.Message(&protocol.IPv4{
						NWSrc:    net.IPv4(1, 1, 1, 1),
						NWDst:    net.IPv4(2, 2, 2, 2),
						Length:   1,
						Protocol: 6,
					}),
				},
			},
			logInfo{srcIP: "1.1.1.1", destIP: "2.2.2.2", pktLength: 1, protocolStr: "TCP"},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualOb := logInfo{}
			if err := getPacketInfo(tt.pktIn, &actualOb); (err != nil) != tt.wantErr {
				t.Errorf("getPacketInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.expectedOb, actualOb, "Expect to retrieve exact packet info while differed")
		})
	}
}
