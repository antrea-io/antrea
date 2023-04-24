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
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/openflow"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	testBufferLength time.Duration = 100 * time.Millisecond
)

var (
	actionAllow    = openflow.DispositionToString[openflow.DispositionAllow]
	actionDrop     = openflow.DispositionToString[openflow.DispositionDrop]
	actionRedirect = "Redirect"
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
		tableName:   openflow.AntreaPolicyIngressRuleTable.GetName(),
		npRef:       "AntreaNetworkPolicy:default/test",
		ruleName:    "test-rule",
		ofPriority:  "0",
		disposition: disposition,
		srcIP:       "0.0.0.0",
		srcPort:     "35402",
		destIP:      "1.1.1.1",
		destPort:    "80",
		protocolStr: "TCP",
		pktLength:   60,
	}
	expected := fmt.Sprintf("%s %s %s %s %s %s %s %s %s %s %d", testLogInfo.tableName, testLogInfo.npRef, testLogInfo.ruleName,
		testLogInfo.disposition, testLogInfo.ofPriority, testLogInfo.srcIP, testLogInfo.srcPort, testLogInfo.destIP, testLogInfo.destPort,
		testLogInfo.protocolStr, testLogInfo.pktLength)
	return testLogInfo, expected
}

func expectedLogWithCount(msg string, count int) string {
	return fmt.Sprintf("%s [%d", msg, count)
}

func TestAllowPacketLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, &realClock{})
	ob, expected := newLogInfo(actionAllow)

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, &realClock{})
	ob, expected := newLogInfo(actionDrop)

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketDedupLog(t *testing.T) {
	clock := NewVirtualClock(time.Now())
	defer clock.Stop()
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, clock)
	ob, expected := newLogInfo(actionDrop)
	// Add the additional log info for duplicate packets.
	expected = expectedLogWithCount(expected, 2)

	antreaLogger.LogDedupPacket(ob)
	clock.Advance(time.Millisecond)
	antreaLogger.LogDedupPacket(ob)
	clock.Advance(testBufferLength)
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
	ob, expected := newLogInfo(actionDrop)

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

func TestRedirectPacketLog(t *testing.T) {
	antreaLogger, mockAnpLogger := newTestAntreaPolicyLogger(testBufferLength, &realClock{})
	ob, expected := newLogInfo(actionRedirect)

	antreaLogger.LogDedupPacket(ob)
	actual := <-mockAnpLogger.logged
	assert.Contains(t, actual, expected)
}

func TestGetNetworkPolicyInfo(t *testing.T) {
	prepareMockOFTablesWithCache()
	generateMatch := func(regID int, data []byte) openflow15.MatchField {
		return openflow15.MatchField{
			Class:   openflow15.OXM_CLASS_PACKET_REGS,
			Field:   uint8(regID / 2),
			HasMask: false,
			Value:   &openflow15.ByteArrayField{Data: data},
		}
	}
	testANPRef := "AntreaNetworkPolicy:default/test-anp"
	testK8sRef := "K8sNetworkPolicy:default/test-anp"
	testPriority, testRule := "61800", "test-rule"
	allowDispositionData := []byte{0x11, 0x00, 0x00, 0x11}
	dropCNPDispositionData := []byte{0x11, 0x00, 0x0c, 0x11}
	dropK8sDispositionData := []byte{0x11, 0x00, 0x08, 0x11}
	redirectDispositionData := []byte{0x11, 0x10, 0x00, 0x11}
	ingressData := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	tests := []struct {
		name            string
		tableID         uint8
		expectedCalls   func(mockClient *openflowtest.MockClientMockRecorder)
		dispositionData []byte
		ob              *logInfo
		wantOb          *logInfo
		wantErr         error
	}{
		{
			name:    "ANP Allow",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtest.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					testANPRef, testPriority, testRule)
			},
			dispositionData: allowDispositionData,
			wantOb: &logInfo{
				tableName:   openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition: actionAllow,
				npRef:       testANPRef,
				ofPriority:  testPriority,
				ruleName:    testRule,
			},
		},
		{
			name:    "K8s Allow",
			tableID: openflow.IngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtest.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					testK8sRef, testPriority, "")
			},
			dispositionData: allowDispositionData,
			wantOb: &logInfo{
				tableName:   openflow.IngressRuleTable.GetName(),
				disposition: actionAllow,
				npRef:       testK8sRef,
				ofPriority:  testPriority,
				ruleName:    "<nil>",
			},
		},
		{
			name:    "ANP Drop",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtest.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					testANPRef, testPriority, testRule)
			},
			dispositionData: dropCNPDispositionData,
			wantOb: &logInfo{
				tableName:   openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition: actionDrop,
				npRef:       testANPRef,
				ofPriority:  testPriority,
				ruleName:    testRule,
			},
		},
		{
			name:            "K8s Drop",
			tableID:         openflow.IngressDefaultTable.GetID(),
			dispositionData: dropK8sDispositionData,
			wantOb: &logInfo{
				tableName:   openflow.IngressDefaultTable.GetName(),
				disposition: actionDrop,
				npRef:       "K8sNetworkPolicy",
				ofPriority:  "<nil>",
				ruleName:    "<nil>",
			},
		},
		{
			name:    "ANP Redirect",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtest.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					testANPRef, testPriority, testRule)
			},
			dispositionData: redirectDispositionData,
			wantOb: &logInfo{
				tableName:   openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition: actionRedirect,
				npRef:       testANPRef,
				ofPriority:  testPriority,
				ruleName:    testRule,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Inject disposition and redirect match.
			dispositionMatch := generateMatch(openflow.APDispositionField.GetRegID(), tc.dispositionData)
			matchers := []openflow15.MatchField{dispositionMatch}
			// Inject ingress/egress match when case is not K8s default drop.
			if tc.expectedCalls != nil {
				regID := openflow.TFIngressConjIDField.GetRegID()
				if tc.wantOb.disposition == actionDrop {
					regID = openflow.APConjIDField.GetRegID()
				}
				ingressMatch := generateMatch(regID, ingressData)
				matchers = append(matchers, ingressMatch)
			}
			pktIn := &ofctrl.PacketIn{TableId: tc.tableID, Match: openflow15.Match{Fields: matchers}}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			testClientInterface := openflowtest.NewMockClient(ctrl)
			if tc.expectedCalls != nil {
				tc.expectedCalls(testClientInterface.EXPECT())
			}
			c := &Controller{ofClient: testClientInterface}
			tc.ob = new(logInfo)
			gotErr := getNetworkPolicyInfo(pktIn, c, tc.ob)
			assert.Equal(t, tc.wantOb, tc.ob)
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestGetPacketInfo(t *testing.T) {
	tests := []struct {
		name   string
		packet *binding.Packet
		ob     *logInfo
		wantOb *logInfo
	}{
		{
			name: "TCP packet",
			packet: &binding.Packet{
				SourceIP:        net.IPv4zero,
				DestinationIP:   net.IPv4(1, 1, 1, 1),
				IPLength:        60,
				IPProto:         ip.TCPProtocol,
				SourcePort:      35402,
				DestinationPort: 80,
			},
			wantOb: &logInfo{
				srcIP:       "0.0.0.0",
				srcPort:     "35402",
				destIP:      "1.1.1.1",
				destPort:    "80",
				protocolStr: "TCP",
				pktLength:   60,
			},
		},
		{
			name: "ICMP packet",
			packet: &binding.Packet{
				SourceIP:      net.IPv4zero,
				DestinationIP: net.IPv4(1, 1, 1, 1),
				IPLength:      60,
				IPProto:       ip.ICMPProtocol,
			},
			wantOb: &logInfo{
				srcIP:       "0.0.0.0",
				srcPort:     "<nil>",
				destIP:      "1.1.1.1",
				destPort:    "<nil>",
				protocolStr: "ICMP",
				pktLength:   60,
			},
		},
	}

	for _, tc := range tests {
		tc.ob = new(logInfo)
		getPacketInfo(tc.packet, tc.ob)
		assert.Equal(t, tc.wantOb, tc.ob)
	}
}

func prepareMockOFTablesWithCache() {
	openflow.InitMockTables(mockOFTables)
	openflow.InitOFTableCache(mockOFTables)
}
