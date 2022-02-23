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
	"github.com/stretchr/testify/require"
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

type timer struct {
	ch    chan time.Time
	when  time.Time
	fired bool
}

type virtualClock struct {
	currentTime time.Time
	timers      []*timer
}

func NewVirtualClock(startTime time.Time) *virtualClock {
	return &virtualClock{
		currentTime: startTime,
	}
}

func (c *virtualClock) fireTimers() {
	for _, t := range c.timers {
		if !t.fired && c.currentTime.After(t.when) {
			t.ch <- t.when
			t.fired = true
		}
	}
}

func (c *virtualClock) Advance(d time.Duration) {
	c.currentTime = c.currentTime.Add(d)
	c.fireTimers()
}

func (c *virtualClock) Stop() {
	for _, t := range c.timers {
		close(t.ch)
	}
}

func (c *virtualClock) Now() time.Time {
	return c.currentTime
}

func (c *virtualClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, &timer{
		ch:    ch,
		when:  c.currentTime.Add(d),
		fired: false,
	})
	return ch
}

func newTestAntreaPolicyLogger(bufferLength time.Duration, clock Clock) (*AntreaPolicyLogger, *mockLogger) {
	mockAnpLogger := &mockLogger{logged: make(chan string, 100)}
	antreaLogger := &AntreaPolicyLogger{
		bufferLength:     bufferLength,
		clock:            clock,
		anpLogger:        log.New(mockAnpLogger, "", log.Ldate),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	return antreaLogger, mockAnpLogger
}

func newLogInfo(disposition string) (*logInfo, string) {
	testLogInfo := &logInfo{
		tableName:   "AntreaPolicyIngressRule",
		npRef:       "AntreaNetworkPolicy:default/test",
		ofPriority:  "0",
		disposition: disposition,
		srcIP:       "0.0.0.0",
		srcPort:     "35402",
		destIP:      "1.1.1.1",
		destPort:    "80",
		protocolStr: "TCP",
		pktLength:   60,
	}
	expected := fmt.Sprintf("%s %s %s %s %s %s %s %s %s %d", testLogInfo.tableName, testLogInfo.npRef, testLogInfo.disposition,
		testLogInfo.ofPriority, testLogInfo.srcIP, testLogInfo.srcPort, testLogInfo.destIP, testLogInfo.destPort,
		testLogInfo.protocolStr, testLogInfo.pktLength)
	return testLogInfo, expected
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
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, &realClock{})
	ob, expected := newLogInfo("Allow")

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, &realClock{})
	ob, expected := newLogInfo("Drop")

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketDedupLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, &realClock{})
	ob, expected := newLogInfo("Drop")
	// Add the additional log info for duplicate packets.
	expected = expectedLogWithCount(expected, 2)

	go sendMultiplePackets(antreaLogger, ob, 2, time.Millisecond)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

// TestDropPacketMultiDedupLog sends 3 packets, with a 60ms interval. The test
// is meant to verify that any given packet is never buffered for more than the
// configured bufferLength (100ms for this test). To avoid flakiness issues
// while ensuring that the test can run fast, we use a virtual clock and advance
// the time manually.
func TestDropPacketMultiDedupLog(t *testing.T) {
	clock := NewVirtualClock(time.Now())
	defer clock.Stop()
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, clock)
	ob, expected := newLogInfo("Drop")

	consumeLog := func() (int, error) {
		select {
		case l := <-mockAnpLogger.logged:
			if !strings.Contains(l, expected) {
				return 0, fmt.Errorf("unexpected log message received")
			}
			begin := strings.Index(l, "[")
			end := strings.Index(l, " packets")
			if begin == -1 {
				return 1, nil
			}
			c, err := strconv.Atoi(l[(begin + 1):end])
			if err != nil {
				return 0, fmt.Errorf("malformed log entry")
			}
			return c, nil
		case <-time.After(1 * time.Second):
			break
		}
		return 0, fmt.Errorf("did not receive log message in time")
	}

	// t=0ms
	antreaLogger.LogDedupPacket(ob)
	clock.Advance(60 * time.Millisecond)
	// t=60ms
	antreaLogger.LogDedupPacket(ob)
	clock.Advance(50 * time.Millisecond)
	// t=110ms, buffer is logged 100ms after the first packet
	c1, err := consumeLog()
	require.NoError(t, err)
	assert.Equal(t, 2, c1)
	clock.Advance(10 * time.Millisecond)
	// t=120ms
	antreaLogger.LogDedupPacket(ob)
	clock.Advance(110 * time.Millisecond)
	// t=230ms, buffer is logged
	c2, err := consumeLog()
	require.NoError(t, err)
	assert.Equal(t, 1, c2)
}
