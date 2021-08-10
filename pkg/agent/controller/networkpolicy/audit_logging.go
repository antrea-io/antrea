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
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/util/logdir"
)

const (
	logfileSubdir string = "networkpolicy"
	logfileName   string = "np.log"
)

// AntreaPolicyLogger is used for Antrea policy audit logging.
// Includes a lumberjack logger and a map used for log deduplication.
type AntreaPolicyLogger struct {
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
	destIP      string // destination IP of the traffic logged
	pktLength   uint16 // packet length of packetin
	protocolStr string // protocol of the traffic logged
}

// logDedupRecord will be used as 1 sec buffer for log deduplication.
type logDedupRecord struct {
	count       int64       // record count of duplicate log
	initTime    time.Time   // initial time upon receiving packet log
	bufferTimer *time.Timer // 1 sec buffer for each log
}

// logRecordDedupMap includes a map of log buffers and a r/w mutex for accessing the map.
type logRecordDedupMap struct {
	logMutex sync.Mutex
	logMap   map[string]*logDedupRecord
}

// getLogKey returns the log record in logDeduplication map by logMsg.
func (a *AntreaPolicyLogger) getLogKey(logMsg string) *logDedupRecord {
	a.logDeduplication.logMutex.Lock()
	defer a.logDeduplication.logMutex.Unlock()
	return a.logDeduplication.logMap[logMsg]
}

// logAfterTimer runs concurrently until buffer timer stops, then call terminateLogKey.
func (a *AntreaPolicyLogger) logAfterTimer(logMsg string) {
	logRecordTimer := a.getLogKey(logMsg).bufferTimer
	<-logRecordTimer.C
	a.terminateLogKey(logMsg)
}

// terminateLogKey logs and deletes the log record in logDeduplication map by logMsg.
func (a *AntreaPolicyLogger) terminateLogKey(logMsg string) {
	a.logDeduplication.logMutex.Lock()
	defer a.logDeduplication.logMutex.Unlock()
	if a.logDeduplication.logMap[logMsg].count == 1 {
		a.anpLogger.Printf(logMsg)
	} else {
		a.anpLogger.Printf("%s [%d packets in %s]", logMsg, a.logDeduplication.logMap[logMsg].count, time.Since(a.logDeduplication.logMap[logMsg].initTime))
	}
	delete(a.logDeduplication.logMap, logMsg)
}

// updateLogKey initiates record or increases the count in logDeduplication corresponding to given logMsg.
func (a *AntreaPolicyLogger) updateLogKey(logMsg string, bufferLength time.Duration) bool {
	a.logDeduplication.logMutex.Lock()
	defer a.logDeduplication.logMutex.Unlock()
	_, exists := a.logDeduplication.logMap[logMsg]
	if exists {
		a.logDeduplication.logMap[logMsg].count++
	} else {
		record := logDedupRecord{1, time.Now(), time.NewTimer(bufferLength)}
		a.logDeduplication.logMap[logMsg] = &record
	}
	return exists
}

// logDedupPacket logs information in ob based on disposition and duplication conditions.
func (a *AntreaPolicyLogger) logDedupPacket(ob *logInfo, bufferLength time.Duration) {
	// Deduplicate non-Allow packet log.
	logMsg := fmt.Sprintf("%s %s %s %s SRC: %s DEST: %s %d %s", ob.tableName, ob.npRef, ob.disposition, ob.ofPriority, ob.srcIP, ob.destIP, ob.pktLength, ob.protocolStr)
	if ob.disposition == openflow.DispositionToString[openflow.DispositionAllow] {
		a.anpLogger.Printf(logMsg)
	} else {
		// Increase count if duplicated within 1 sec, create buffer otherwise.
		exists := a.updateLogKey(logMsg, bufferLength)
		if !exists {
			// Go routine for logging when buffer timer stops.
			go a.logAfterTimer(logMsg)
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

	cAntreaPolicyLogger := &AntreaPolicyLogger{
		anpLogger:        log.New(logOutput, "", log.Ldate|log.Lmicroseconds),
		logDeduplication: logRecordDedupMap{logMap: make(map[string]*logDedupRecord)},
	}
	klog.V(2).Infof("Initialized Antrea-native Policy Logger for audit logging with log file '%s'", logFile)
	return cAntreaPolicyLogger, nil
}
