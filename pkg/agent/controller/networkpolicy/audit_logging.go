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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"antrea.io/ofnet/ofctrl"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/logdir"
)

const (
	logfileSubdir   string = "networkpolicy"
	logfileName     string = "np.log"
	nullPlaceholder        = "<nil>"
)

// AuditLogger is used for network policy audit logging.
// Includes a lumberjack logger and a map used for log deduplication.
type AuditLogger struct {
	bufferLength     time.Duration
	clock            clock.Clock // enable the use of a "virtual" clock for unit tests
	npLogger         *log.Logger
	logDeduplication logRecordDedupMap
}

type AuditLoggerOptions struct {
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

// logInfo will be set by retrieving info from packetin and register.
type logInfo struct {
	tableName    string // name of the table sending packetin
	npRef        string // Network Policy name reference
	ruleName     string // Network Policy rule name for Antrea-native policies
	direction    string // Direction of the Network Policy rule (Ingress / Egress)
	logLabel     string // Network Policy user-defined log label
	disposition  string // Allow/Drop of the rule sending packetin
	ofPriority   string // openflow priority of the flow sending packetin
	appliedToRef string // namespace and name of the Pod to which the Network Policy is applied
	srcIP        string // source IP of the traffic logged
	srcPort      string // source port of the traffic logged
	destIP       string // destination IP of the traffic logged
	destPort     string // destination port of the traffic logged
	pktLength    string // packet length of packetin
	protocolStr  string // protocol of the traffic logged
}

// logDedupRecord will be used as 1 sec buffer for log deduplication.
type logDedupRecord struct {
	count         int64            // record count of duplicate log
	initTime      time.Time        // initial time upon receiving packet log
	bufferTimerCh <-chan time.Time // 1 sec buffer for each log
}

// logRecordDedupMap includes a map of log buffers and a r/w mutex for accessing the map.
type logRecordDedupMap struct {
	logMutex sync.Mutex
	logMap   map[string]*logDedupRecord
}

// getLogKey returns the log record in logDeduplication map by logMsg.
func (l *AuditLogger) getLogKey(logMsg string) *logDedupRecord {
	l.logDeduplication.logMutex.Lock()
	defer l.logDeduplication.logMutex.Unlock()
	return l.logDeduplication.logMap[logMsg]
}

// logAfterTimer runs concurrently until buffer timer stops, then call terminateLogKey.
func (l *AuditLogger) logAfterTimer(logMsg string) {
	ch := l.getLogKey(logMsg).bufferTimerCh
	<-ch
	l.terminateLogKey(logMsg)
}

// terminateLogKey logs and deletes the log record in logDeduplication map by logMsg.
func (l *AuditLogger) terminateLogKey(logMsg string) {
	l.logDeduplication.logMutex.Lock()
	defer l.logDeduplication.logMutex.Unlock()
	logRecord := l.logDeduplication.logMap[logMsg]
	if logRecord.count == 1 {
		l.npLogger.Printf(logMsg)
	} else {
		l.npLogger.Printf("%s [%d packets in %s]", logMsg, logRecord.count, time.Since(logRecord.initTime))
	}
	delete(l.logDeduplication.logMap, logMsg)
}

// updateLogKey initiates record or increases the count in logDeduplication corresponding to given logMsg.
func (l *AuditLogger) updateLogKey(logMsg string, bufferLength time.Duration) bool {
	l.logDeduplication.logMutex.Lock()
	defer l.logDeduplication.logMutex.Unlock()
	_, exists := l.logDeduplication.logMap[logMsg]
	if exists {
		l.logDeduplication.logMap[logMsg].count++
	} else {
		record := logDedupRecord{1, l.clock.Now(), l.clock.After(bufferLength)}
		l.logDeduplication.logMap[logMsg] = &record
	}
	return exists
}

func buildLogMsg(ob *logInfo) string {
	return strings.Join([]string{
		ob.tableName,
		ob.npRef,
		ob.ruleName,
		ob.direction,
		ob.disposition,
		ob.ofPriority,
		ob.appliedToRef,
		ob.srcIP,
		ob.srcPort,
		ob.destIP,
		ob.destPort,
		ob.protocolStr,
		ob.pktLength,
		ob.logLabel,
	}, " ")
}

// LogDedupPacket logs information in ob based on disposition and duplication conditions.
func (l *AuditLogger) LogDedupPacket(ob *logInfo) {
	// Deduplicate non-Allow packet log.
	logMsg := buildLogMsg(ob)
	if ob.disposition == openflow.DispositionToString[openflow.DispositionAllow] {
		l.npLogger.Printf(logMsg)
	} else {
		// Increase count if duplicated within 1 sec, create buffer otherwise.
		exists := l.updateLogKey(logMsg, l.bufferLength)
		if !exists {
			// Go routine for logging when buffer timer stops.
			go l.logAfterTimer(logMsg)
		}
	}
}

// newAuditLogger is called while newing network policy agent controller.
// Customize AuditLogger specifically for audit logging through agent configuration.
func newAuditLogger(options *AuditLoggerOptions) (*AuditLogger, error) {
	logDir := filepath.Join(logdir.GetLogDir(), logfileSubdir)
	logFile := filepath.Join(logDir, logfileName)
	_, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	} else if err != nil {
		return nil, fmt.Errorf("received error while accessing network policy log directory: %v", err)
	}

	// Use lumberjack log file rotation.
	logOutput := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    options.MaxSize,
		MaxBackups: options.MaxBackups,
		MaxAge:     options.MaxAge,
		Compress:   options.Compress,
	}

	auditLogger := &AuditLogger{
		bufferLength:     time.Second,
		clock:            clock.RealClock{},
		npLogger:         log.New(logOutput, "", log.Ldate|log.Lmicroseconds),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	klog.InfoS("Initialized Antrea-native Policy Logger for audit logging", "logFile", logFile, "options", options)
	return auditLogger, nil
}

// getNetworkPolicyInfo fills in tableName, npName, ofPriority, disposition of logInfo ob.
func getNetworkPolicyInfo(pktIn *ofctrl.PacketIn, packet *binding.Packet, c *Controller, ob *logInfo) error {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	// Get table name.
	tableID := getPacketInTableID(pktIn)
	ob.tableName = openflow.GetFlowTableName(tableID)

	var localIP string
	// We use the tableID to determine the direction of the NP rule.
	// The advantage of this method is that it should work for all NP types.
	if isAntreaPolicyIngressTable(tableID) || tableID == openflow.IngressRuleTable.GetID() {
		ob.direction = "Ingress"
		localIP = packet.DestinationIP.String()
	} else if isAntreaPolicyEgressTable(tableID) || tableID == openflow.EgressRuleTable.GetID() {
		ob.direction = "Egress"
		localIP = packet.SourceIP.String()
	} else {
		// this case should not be possible
		klog.InfoS("Cannot determine direction of NetworkPolicy rule")
		ob.direction = nullPlaceholder
	}

	if localIP != "" {
		iface, ok := c.ifaceStore.GetInterfaceByIP(localIP)
		if ok && iface.Type == interfacestore.ContainerInterface {
			ob.appliedToRef = fmt.Sprintf("%s/%s", iface.ContainerInterfaceConfig.PodNamespace, iface.ContainerInterfaceConfig.PodName)
		}
	}
	if ob.appliedToRef == "" {
		klog.InfoS("Cannot determine namespace/name of appliedTo Pod", "ip", localIP)
		ob.appliedToRef = nullPlaceholder
	}

	// Get disposition Allow or Drop.
	match = getMatchRegField(matchers, openflow.APDispositionField)
	disposition, err := getInfoInReg(match, openflow.APDispositionField.GetRange().ToNXRange())
	if err != nil {
		return fmt.Errorf("received error while unloading disposition from reg: %v", err)
	}
	ob.disposition = openflow.DispositionToString[disposition]

	// Get layer 7 NetworkPolicy redirect action, if traffic is redirected, disposition log should be overwritten.
	if match = getMatchRegField(matchers, openflow.L7NPRegField); match != nil {
		l7NPRegVal, err := getInfoInReg(match, openflow.L7NPRegField.GetRange().ToNXRange())
		if err != nil {
			return fmt.Errorf("received error while unloading l7 NP redirect value from reg: %v", err)
		}
		if l7NPRegVal == openflow.DispositionL7NPRedirect {
			ob.disposition = "Redirect"
		}
	}

	// Get K8s default deny action, if traffic is default deny, no conjunction could be matched.
	if match = getMatchRegField(matchers, openflow.APDenyRegMark.GetField()); match != nil {
		apDenyRegVal, err := getInfoInReg(match, openflow.APDenyRegMark.GetField().GetRange().ToNXRange())
		if err != nil {
			return fmt.Errorf("received error while unloading deny mark from reg: %v", err)
		}
		isK8sDefaultDeny := (apDenyRegVal == 0) && (disposition == openflow.DispositionDrop || disposition == openflow.DispositionRej)
		if isK8sDefaultDeny {
			// For K8s NetworkPolicy implicit drop action, we cannot get Namespace/name.
			ob.npRef = string(v1beta2.K8sNetworkPolicy)
			fillLogInfoPlaceholders([]*string{&ob.ruleName, &ob.logLabel, &ob.ofPriority})
			return nil
		}
	}

	// Set match to corresponding conjunction ID field according to disposition.
	match = getMatch(matchers, tableID, disposition)

	// Get NetworkPolicy full name and OF priority of the conjunction.
	conjID, err := getInfoInReg(match, nil)
	if err != nil {
		return fmt.Errorf("received error while unloading conjunction id from reg: %v", err)
	}
	ok, npRef, ofPriority, ruleName, logLabel := c.ofClient.GetPolicyInfoFromConjunction(conjID)
	if !ok {
		return fmt.Errorf("networkpolicy not found for conjunction id: %v", conjID)
	}
	ob.npRef = npRef.ToString()
	ob.ofPriority = ofPriority
	ob.ruleName = ruleName
	ob.logLabel = logLabel
	// Fill in placeholders for Antrea-native policies without log labels,
	// K8s NetworkPolicies without rule names or log labels.
	fillLogInfoPlaceholders([]*string{&ob.ruleName, &ob.logLabel, &ob.ofPriority})
	return nil
}

// getPacketInfo fills in IP, packet length, protocol, port number of logInfo ob.
func getPacketInfo(packet *binding.Packet, ob *logInfo) {
	ob.srcIP = packet.SourceIP.String()
	ob.destIP = packet.DestinationIP.String()
	ob.pktLength = strconv.FormatUint(uint64(packet.IPLength), 10)
	ob.protocolStr = ip.IPProtocolNumberToString(packet.IPProto, "UnknownProtocol")
	if ob.protocolStr == "TCP" || ob.protocolStr == "UDP" {
		ob.srcPort = strconv.FormatUint(uint64(packet.SourcePort), 10)
		ob.destPort = strconv.FormatUint(uint64(packet.DestinationPort), 10)
	} else {
		// Placeholders for ICMP packets without port numbers.
		fillLogInfoPlaceholders([]*string{&ob.srcPort, &ob.destPort})
	}
}

func fillLogInfoPlaceholders(logItems []*string) {
	for i, v := range logItems {
		if *v == "" {
			*logItems[i] = nullPlaceholder
		}
	}
}

// logPacket retrieves information from openflow reg, controller cache, packet-in
// packet to log. Log is deduplicated for non-Allow packets from record in logDeduplication.
// Deduplication is safe guarded by logRecordDedupMap mutex.
func (c *Controller) logPacket(pktIn *ofctrl.PacketIn) error {
	ob := new(logInfo)
	packet, err := binding.ParsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("received error while parsing packetin: %v", err)
	}

	// Set Network Policy and packet info to log.
	err = getNetworkPolicyInfo(pktIn, packet, c, ob)
	if err != nil {
		return fmt.Errorf("received error while retrieving NetworkPolicy info: %v", err)
	}
	getPacketInfo(packet, ob)

	// Log the ob info to corresponding file w/ deduplication.
	c.auditLogger.LogDedupPacket(ob)
	return nil
}
