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

package networkpolicy

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testBufferLength time.Duration = 100 * time.Millisecond
)

// mockLogger implements io.Writer.
type mockLogger struct {
	mu     sync.Mutex
	logged chan string
}

func (l *mockLogger) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if p == nil {
		return 0, errors.New("error writing to mock Logger")
	}
	msg := string(p[:])
	l.logged <- msg
	return len(msg), nil
}

func newTestAntreaPolicyLogger(bufferLength time.Duration) (*AntreaPolicyLogger, *mockLogger) {
	mockAnpLogger := &mockLogger{logged: make(chan string, 100)}
	antreaLogger := &AntreaPolicyLogger{
		bufferLength:     bufferLength,
		anpLogger:        log.New(mockAnpLogger, "", log.Ldate),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	return antreaLogger, mockAnpLogger
}

func newLogInfo(disposition string) (*logInfo, string) {
	expected := fmt.Sprintf("AntreaPolicyIngressRule AntreaNetworkPolicy:default/test %s 0 SRC: 0.0.0.0 DEST: 1.1.1.1 60 TCP", disposition)
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

func sendMultiplePackets(antreaLogger *AntreaPolicyLogger, ob *logInfo, numPackets int, sendInterval time.Duration) {
	count := 0
	for range time.Tick(sendInterval) {
		count += 1
		antreaLogger.LogDedupPacket(ob)
		if count == numPackets {
			break
		}
	}
}

func expectedLogWithCount(msg string, count int) string {
	return fmt.Sprintf("%s [%d", msg, count)
}

func TestAllowPacketLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength)
	ob, expected := newLogInfo("Allow")

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength)
	ob, expected := newLogInfo("Drop")

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketDedupLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength)
	ob, expected := newLogInfo("Drop")
	// Add the additional log info for duplicate packets.
	expected = expectedLogWithCount(expected, 2)

	go sendMultiplePackets(antreaLogger, ob, 2, time.Millisecond)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketMultiDedupLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength)
	ob, expected := newLogInfo("Drop")

	numPackets := 4
	go sendMultiplePackets(antreaLogger, ob, numPackets, 40*time.Millisecond)
	// Close the channel listening for logged msg after 500ms.
	time.AfterFunc(500*time.Millisecond, func() {
		mockAnpLogger.mu.Lock()
		defer mockAnpLogger.mu.Unlock()
		close(mockAnpLogger.logged)
	})

	receivedPacket, countLog := 0, 0
	for actual := range mockAnpLogger.logged {
		assert.Contains(t, actual, expected)
		countLog++
		begin := strings.Index(actual, "[")
		end := strings.Index(actual, " packets")
		if begin == -1 {
			receivedPacket += 1
		} else {
			countLoggedMsg, _ := strconv.Atoi(actual[(begin + 1):end])
			receivedPacket += countLoggedMsg
		}
	}
	// Test two messages are logged for all packets.
	assert.Equal(t, 2, countLog)
	// Test all packets are accounted for.
	assert.Equal(t, numPackets, receivedPacket)
}
