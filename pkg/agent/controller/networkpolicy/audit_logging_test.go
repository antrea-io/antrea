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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	openflowtesting "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
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
	testANNPRef    = &v1beta2.NetworkPolicyReference{
		Type:      v1beta2.AntreaNetworkPolicy,
		Namespace: "default",
		Name:      "test",
	}
	testK8sNPRef = &v1beta2.NetworkPolicyReference{
		Type:      v1beta2.K8sNetworkPolicy,
		Namespace: "default",
		Name:      "test",
	}
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

func newTestAuditLogger(bufferLength time.Duration, clock clock.Clock) (*AuditLogger, *mockLogger) {
	mockNPLogger := &mockLogger{logged: make(chan string, 100)}
	auditLogger := &AuditLogger{
		bufferLength:     bufferLength,
		clock:            clock,
		npLogger:         log.New(mockNPLogger, "", log.Ldate),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	return auditLogger, mockNPLogger
}

func newLogInfo(disposition string) (*logInfo, string) {
	testLogInfo := &logInfo{
		tableName:   openflow.AntreaPolicyIngressRuleTable.GetName(),
		npRef:       testANNPRef.ToString(),
		ruleName:    "test-rule",
		logLabel:    "test-label",
		ofPriority:  "0",
		disposition: disposition,
		srcIP:       "0.0.0.0",
		srcPort:     "35402",
		destIP:      "1.1.1.1",
		destPort:    "80",
		protocolStr: "TCP",
		pktLength:   "60",
	}
	return testLogInfo, buildLogMsg(testLogInfo)
}

func expectedLogWithCount(msg string, count int) string {
	return fmt.Sprintf("%s [%d", msg, count)
}

func TestAllowPacketLog(t *testing.T) {
	auditLogger, mockNPLogger := newTestAuditLogger(testBufferLength, clock.RealClock{})
	ob, expected := newLogInfo(actionAllow)

	auditLogger.LogDedupPacket(ob)
	actual := <-mockNPLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketLog(t *testing.T) {
	auditLogger, mockNPLogger := newTestAuditLogger(testBufferLength, clock.RealClock{})
	ob, expected := newLogInfo(actionDrop)

	auditLogger.LogDedupPacket(ob)
	actual := <-mockNPLogger.logged
	assert.Contains(t, actual, expected)
}

func TestDropPacketDedupLog(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Now())
	auditLogger, mockNPLogger := newTestAuditLogger(testBufferLength, clock)
	ob, expected := newLogInfo(actionDrop)
	// Add the additional log info for duplicate packets.
	expected = expectedLogWithCount(expected, 2)

	auditLogger.LogDedupPacket(ob)
	clock.Step(time.Millisecond)
	auditLogger.LogDedupPacket(ob)
	clock.Step(testBufferLength)
	actual := <-mockNPLogger.logged
	assert.Contains(t, actual, expected)
}

// TestDropPacketMultiDedupLog sends 3 packets, with a 60ms interval. The test
// is meant to verify that any given packet is never buffered for more than the
// configured bufferLength (100ms for this test). To avoid flakiness issues
// while ensuring that the test can run fast, we use a virtual clock and advance
// the time manually.
func TestDropPacketMultiDedupLog(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Now())
	auditLogger, mockNPLogger := newTestAuditLogger(testBufferLength, clock)
	ob, expected := newLogInfo(actionDrop)

	consumeLog := func() (int, error) {
		select {
		case l := <-mockNPLogger.logged:
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
	auditLogger.LogDedupPacket(ob)
	clock.Step(60 * time.Millisecond)
	// t=60ms
	auditLogger.LogDedupPacket(ob)
	clock.Step(50 * time.Millisecond)
	// t=110ms, buffer is logged 100ms after the first packet
	c1, err := consumeLog()
	require.NoError(t, err)
	assert.Equal(t, 2, c1)
	clock.Step(10 * time.Millisecond)
	// t=120ms
	auditLogger.LogDedupPacket(ob)
	clock.Step(110 * time.Millisecond)
	// t=230ms, buffer is logged
	c2, err := consumeLog()
	require.NoError(t, err)
	assert.Equal(t, 1, c2)
}

func TestRedirectPacketLog(t *testing.T) {
	auditLogger, mockNPLogger := newTestAuditLogger(testBufferLength, clock.RealClock{})
	ob, expected := newLogInfo(actionRedirect)

	auditLogger.LogDedupPacket(ob)
	actual := <-mockNPLogger.logged
	assert.Contains(t, actual, expected)
}

func TestGetNetworkPolicyInfo(t *testing.T) {
	prepareMockOFTablesWithCache()
	generateMatch := func(regID int, data []byte) openflow15.MatchField {
		baseData := make([]byte, 8, 8)
		if regID%2 == 0 {
			copy(baseData[0:4], data)
		} else {
			copy(baseData[4:8], data)
		}
		return openflow15.MatchField{
			Class: openflow15.OXM_CLASS_PACKET_REGS,
			// convert reg (4-byte) ID to xreg (8-byte) ID
			Field:   uint8(regID / 2),
			HasMask: false,
			Value:   &openflow15.ByteArrayField{Data: baseData},
		}
	}
	testPriority, testRule, testLogLabel := "61800", "test-rule", "test-log-label"
	// only need 4 bytes of register data for the disposition
	// this will go into the openflow.APDispositionField register
	allowDispositionData := []byte{0x11, 0x00, 0x00, 0x11}
	dropCNPDispositionData := []byte{0x11, 0x00, 0x0c, 0x11}
	dropK8sDispositionData := []byte{0x11, 0x00, 0x08, 0x11}
	redirectDispositionData := []byte{0x11, 0x10, 0x00, 0x11}
	// use 4 bytes of data for the conjunction identifier, this will be used for one of
	// the following registers depending on the test case:
	// openflow.APConjIDField, openflow.TFEgressConjIDField, openflow.TFIngressConjIDField
	// the data itself is not relevant
	conjunctionData := []byte{0x11, 0x11, 0x11, 0x11}
	srcIP := net.ParseIP("192.168.1.1")
	destIP := net.ParseIP("192.168.1.2")
	testPacket := &binding.Packet{
		SourceIP:      srcIP,
		DestinationIP: destIP,
	}

	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("srcPod", "default", "c1"),
		IPs:                      []net.IP{srcIP},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "srcPod", PodNamespace: "default", ContainerID: "c1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 1},
	})
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("destPod", "default", "c2"),
		IPs:                      []net.IP{destIP},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "destPod", PodNamespace: "default", ContainerID: "c2"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 2},
	})

	antreaIngressRuleTableID := openflow.AntreaPolicyIngressRuleTable.GetID()
	tests := []struct {
		name            string
		tableID         uint8
		expectedCalls   func(mockClient *openflowtesting.MockClientMockRecorder)
		dispositionData []byte
		ob              *logInfo
		wantOb          *logInfo
		wantErr         error
		tableIDInReg    *uint8
	}{
		{
			name:    "ANNP Allow Ingress",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testANNPRef, testPriority, testRule, testLogLabel)
			},
			dispositionData: allowDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition:  actionAllow,
				npRef:        testANNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     testRule,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     testLogLabel,
			},
		},
		{
			name:    "ANP Allow Egress",
			tableID: openflow.AntreaPolicyEgressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testANNPRef, testPriority, testRule, testLogLabel)
			},
			dispositionData: allowDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.AntreaPolicyEgressRuleTable.GetName(),
				disposition:  actionAllow,
				npRef:        testANNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     testRule,
				direction:    "Egress",
				appliedToRef: "default/srcPod",
				logLabel:     testLogLabel,
			},
		},
		{
			name:    "K8s Allow",
			tableID: openflow.IngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testK8sNPRef, testPriority, "", "")
			},
			dispositionData: allowDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.IngressRuleTable.GetName(),
				disposition:  actionAllow,
				npRef:        testK8sNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     nullPlaceholder,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     nullPlaceholder,
			},
		},
		{
			name:    "ANNP Drop",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testANNPRef, testPriority, testRule, testLogLabel)
			},
			dispositionData: dropCNPDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition:  actionDrop,
				npRef:        testANNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     testRule,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     testLogLabel,
			},
		},
		{
			name:            "K8s Drop",
			tableID:         openflow.IngressDefaultTable.GetID(),
			dispositionData: dropK8sDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.IngressDefaultTable.GetName(),
				disposition:  actionDrop,
				npRef:        "K8sNetworkPolicy",
				ofPriority:   nullPlaceholder,
				ruleName:     nullPlaceholder,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     nullPlaceholder,
			},
		},
		{
			name:    "ANNP Redirect",
			tableID: openflow.AntreaPolicyIngressRuleTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testANNPRef, testPriority, testRule, testLogLabel)
			},
			dispositionData: redirectDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition:  actionRedirect,
				npRef:        testANNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     testRule,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     testLogLabel,
			},
		},
		{
			name:    "Antrea-native Policy Allow from output table",
			tableID: openflow.OutputTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testANNPRef, testPriority, testRule, testLogLabel)
			},
			dispositionData: allowDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition:  actionAllow,
				npRef:        testANNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     testRule,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     testLogLabel,
			},
			tableIDInReg: &antreaIngressRuleTableID,
		},
		{
			name:    "Antrea-native Policy Drop from output table",
			tableID: openflow.OutputTable.GetID(),
			expectedCalls: func(mockClient *openflowtesting.MockClientMockRecorder) {
				mockClient.GetPolicyInfoFromConjunction(gomock.Any()).Return(
					true, testANNPRef, testPriority, testRule, testLogLabel)
			},
			dispositionData: dropCNPDispositionData,
			wantOb: &logInfo{
				tableName:    openflow.AntreaPolicyIngressRuleTable.GetName(),
				disposition:  actionDrop,
				npRef:        testANNPRef.ToString(),
				ofPriority:   testPriority,
				ruleName:     testRule,
				direction:    "Ingress",
				appliedToRef: "default/destPod",
				logLabel:     testLogLabel,
			},
			tableIDInReg: &antreaIngressRuleTableID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Inject disposition and redirect match.
			dispositionMatch := generateMatch(openflow.APDispositionField.GetRegID(), tc.dispositionData)
			matchers := []openflow15.MatchField{dispositionMatch}
			// Inject ingress/egress match when case is not K8s default drop.
			if tc.expectedCalls != nil {
				var regID int
				if tc.wantOb.disposition == actionDrop {
					regID = openflow.APConjIDField.GetRegID()
				} else if tc.wantOb.direction == "Ingress" {
					regID = openflow.TFIngressConjIDField.GetRegID()
				} else {
					regID = openflow.TFEgressConjIDField.GetRegID()
				}
				ingressMatch := generateMatch(regID, conjunctionData)
				matchers = append(matchers, ingressMatch)
			}
			if tc.tableIDInReg != nil {
				tableMatchRegID := openflow.PacketInTableField.GetRegID()
				tableRegData := make([]byte, 4, 4)
				binary.BigEndian.PutUint32(tableRegData[0:], uint32(*tc.tableIDInReg))
				found := false
				for _, m := range matchers {
					if m.Class == openflow15.OXM_CLASS_PACKET_REGS && m.Field == uint8(tableMatchRegID/2) {
						copy(m.Value.(*openflow15.ByteArrayField).Data[0:4], tableRegData)
						found = true
						break
					}
				}
				if !found {
					tableMatch := generateMatch(tableMatchRegID, tableRegData)
					matchers = append(matchers, tableMatch)
				}
			}
			pktIn := &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					TableId: tc.tableID,
					Match: openflow15.Match{
						Fields: matchers,
					},
				},
			}
			ctrl := gomock.NewController(t)
			testClientInterface := openflowtesting.NewMockClient(ctrl)
			if tc.expectedCalls != nil {
				tc.expectedCalls(testClientInterface.EXPECT())
			}
			c := &Controller{
				ofClient:   testClientInterface,
				ifaceStore: ifaceStore,
			}
			tc.ob = new(logInfo)
			gotErr := getNetworkPolicyInfo(pktIn, testPacket, c, tc.ob)
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
				pktLength:   "60",
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
				pktLength:   "60",
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

func BenchmarkLogDedupPacketAllow(b *testing.B) {
	// In the allow case, there is actually no buffering.
	auditLogger := &AuditLogger{
		bufferLength:     testBufferLength,
		clock:            clock.RealClock{},
		npLogger:         log.New(io.Discard, "", log.Ldate),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	ob, _ := newLogInfo(actionAllow)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auditLogger.LogDedupPacket(ob)
	}
}
