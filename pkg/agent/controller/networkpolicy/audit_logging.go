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
	"sync"
	"time"

	"antrea.io/ofnet/ofctrl"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/logdir"
)

const (
	logfileSubdir string = "networkpolicy"
	logfileName   string = "np.log"
)

type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (c realClock) Now() time.Time {
	return time.Now()
}

func (c realClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

// AntreaPolicyLogger is used for Antrea policy audit logging.
// Includes a lumberjack logger and a map used for log deduplication.
type AntreaPolicyLogger struct {
	bufferLength     time.Duration
	clock            Clock // enable the use of a "virtual" clock for unit tests
	anpLogger        *log.Logger
	logDeduplication logRecordDedupMap
}

// logInfo will be set by retrieving info from packetin and register.
type logInfo struct {
	tableName   string // name of the table sending packetin
	npRef       string // Network Policy name reference for Antrea NetworkPolicy
	disposition string // Allow/Drop of the rule sending packetin
	ofPriority  string // openflow priority of the flow sending packetin
	srcIP       string // source IP of the traffic logged
	srcPort     string // source port of the traffic logged
	destIP      string // destination IP of the traffic logged
	destPort    string // destination port of the traffic logged
	pktLength   uint16 // packet length of packetin
	protocolStr string // protocol of the traffic logged
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
func (l *AntreaPolicyLogger) getLogKey(logMsg string) *logDedupRecord {
	l.logDeduplication.logMutex.Lock()
	defer l.logDeduplication.logMutex.Unlock()
	return l.logDeduplication.logMap[logMsg]
}

// logAfterTimer runs concurrently until buffer timer stops, then call terminateLogKey.
func (l *AntreaPolicyLogger) logAfterTimer(logMsg string) {
	ch := l.getLogKey(logMsg).bufferTimerCh
	<-ch
	l.terminateLogKey(logMsg)
}

// terminateLogKey logs and deletes the log record in logDeduplication map by logMsg.
func (l *AntreaPolicyLogger) terminateLogKey(logMsg string) {
	l.logDeduplication.logMutex.Lock()
	defer l.logDeduplication.logMutex.Unlock()
	logRecord := l.logDeduplication.logMap[logMsg]
	if logRecord.count == 1 {
		l.anpLogger.Printf(logMsg)
	} else {
		l.anpLogger.Printf("%s [%d packets in %s]", logMsg, logRecord.count, time.Since(logRecord.initTime))
	}
	delete(l.logDeduplication.logMap, logMsg)
}

// updateLogKey initiates record or increases the count in logDeduplication corresponding to given logMsg.
func (l *AntreaPolicyLogger) updateLogKey(logMsg string, bufferLength time.Duration) bool {
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

// LogDedupPacket logs information in ob based on disposition and duplication conditions.
func (l *AntreaPolicyLogger) LogDedupPacket(ob *logInfo) {
	// Deduplicate non-Allow packet log.
	logMsg := fmt.Sprintf("%s %s %s %s %s %s %s %s %s %d", ob.tableName, ob.npRef, ob.disposition, ob.ofPriority, ob.srcIP, ob.srcPort, ob.destIP, ob.destPort, ob.protocolStr, ob.pktLength)
	if ob.disposition == openflow.DispositionToString[openflow.DispositionAllow] {
		l.anpLogger.Printf(logMsg)
	} else {
		// Increase count if duplicated within 1 sec, create buffer otherwise.
		exists := l.updateLogKey(logMsg, l.bufferLength)
		if !exists {
			// Go routine for logging when buffer timer stops.
			go l.logAfterTimer(logMsg)
		}
	}
}

// newAntreaPolicyLogger is called while newing Antrea network policy agent controller.
// Customize AntreaPolicyLogger specifically for Antrea Policies audit logging.
func newAntreaPolicyLogger() (*AntreaPolicyLogger, error) {
	logDir := filepath.Join(logdir.GetLogDir(), logfileSubdir)
	logFile := filepath.Join(logDir, logfileName)
	_, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	} else if err != nil {
		return nil, fmt.Errorf("received error while accessing Antrea network policy log directory: %v", err)
	}

	// Use lumberjack log file rotation.
	logOutput := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    500,  // allow max 500 megabytes for one log file
		MaxBackups: 3,    // allow max 3 old log file backups
		MaxAge:     28,   // allow max 28 days maintenance of old log files
		Compress:   true, // compress the old log files for backup
	}

	antreaPolicyLogger := &AntreaPolicyLogger{
		bufferLength:     time.Second,
		clock:            &realClock{},
		anpLogger:        log.New(logOutput, "", log.Ldate|log.Lmicroseconds),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	klog.InfoS("Initialized Antrea-native Policy Logger for audit logging", "logFile", logFile)
	return antreaPolicyLogger, nil
}

// getNetworkPolicyInfo fills in tableName, npName, ofPriority, disposition of logInfo ob.
func getNetworkPolicyInfo(pktIn *ofctrl.PacketIn, c *Controller, ob *logInfo) error {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	// Get table name.
	tableID := pktIn.TableId
	ob.tableName = openflow.GetFlowTableName(tableID)

	// Get disposition Allow or Drop.
	match = getMatchRegField(matchers, openflow.APDispositionField)
	info, err := getInfoInReg(match, openflow.APDispositionField.GetRange().ToNXRange())
	if err != nil {
		return fmt.Errorf("received error while unloading disposition from reg: %v", err)
	}
	ob.disposition = openflow.DispositionToString[info]

	// Set match to corresponding ingress/egress reg according to disposition.
	match = getMatch(matchers, tableID, info)

	// Get Network Policy full name and OF priority of the conjunction.
	info, err = getInfoInReg(match, nil)
	if err != nil {
		return fmt.Errorf("received error while unloading conjunction id from reg: %v", err)
	}
	ob.npRef, ob.ofPriority = c.ofClient.GetPolicyInfoFromConjunction(info)

	return nil
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
	err = getNetworkPolicyInfo(pktIn, c, ob)
	if err != nil {
		return fmt.Errorf("received error while retrieving NetworkPolicy info: %v", err)
	}
	ob.srcIP = packet.SourceIP.String()
	ob.destIP = packet.DestinationIP.String()
	ob.pktLength = packet.IPLength
	ob.protocolStr = ip.IPProtocolNumberToString(packet.IPProto, "UnknownProtocol")
	if ob.protocolStr == "TCP" || ob.protocolStr == "UDP" {
		ob.srcPort = strconv.Itoa(int(packet.SourcePort))
		ob.destPort = strconv.Itoa(int(packet.DestinationPort))
	} else {
		// Placeholders for ICMP packets without port numbers.
		ob.srcPort, ob.destPort = "<nil>", "<nil>"
	}

	// Log the ob info to corresponding file w/ deduplication.
	c.antreaPolicyLogger.LogDedupPacket(ob)
	return nil
}
