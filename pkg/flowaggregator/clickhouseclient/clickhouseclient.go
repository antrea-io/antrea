// Copyright 2022 Antrea Authors
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

package clickhouseclient

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go"
	"github.com/gammazero/deque"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
)

const (
	maxQueueSize      = 1 << 19 // 524288. ~500MB assuming 1KB per record
	queueFlushTimeout = 10 * time.Second
	insertQuery       = `INSERT INTO flows (
                   flowStartSeconds,
                   flowEndSeconds,
                   flowEndSecondsFromSourceNode,
                   flowEndSecondsFromDestinationNode,
                   flowEndReason,
                   sourceIP,
                   destinationIP,
                   sourceTransportPort,
                   destinationTransportPort,
                   protocolIdentifier,
                   packetTotalCount,
                   octetTotalCount,
                   packetDeltaCount,
                   octetDeltaCount,
                   reversePacketTotalCount,
                   reverseOctetTotalCount,
                   reversePacketDeltaCount,
                   reverseOctetDeltaCount,
                   sourcePodName,
                   sourcePodNamespace,
                   sourceNodeName,
                   destinationPodName,
                   destinationPodNamespace,
                   destinationNodeName,
                   destinationClusterIP,
                   destinationServicePort,
                   destinationServicePortName,
                   ingressNetworkPolicyName,
                   ingressNetworkPolicyNamespace,
                   ingressNetworkPolicyRuleName,
                   ingressNetworkPolicyRuleAction,
                   ingressNetworkPolicyType,
                   egressNetworkPolicyName,
                   egressNetworkPolicyNamespace,
                   egressNetworkPolicyRuleName,
                   egressNetworkPolicyRuleAction,
                   egressNetworkPolicyType,
                   tcpState,
                   flowType,
                   sourcePodLabels,
                   destinationPodLabels,
                   throughput,
                   reverseThroughput,
                   throughputFromSourceNode,
                   throughputFromDestinationNode,
                   reverseThroughputFromSourceNode,
                   reverseThroughputFromDestinationNode,
                   clusterUUID)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
)

// PrepareClickHouseConnection is used for unit testing
var PrepareClickHouseConnection = prepareConnection

type stopPayload struct {
	flushQueue bool
}

type ClickHouseExportProcess struct {
	// db holds sql connection struct to clickhouse db.
	db *sql.DB
	// dsn is data source name used for connection to clickhouse db.
	dsn string
	// deque buffers flows records between batch commits.
	deque *deque.Deque
	// dequeMutex is for concurrency between adding and removing records from deque.
	dequeMutex sync.Mutex
	// queueSize is the max size of deque
	queueSize int
	// commitInterval is the interval between batch commits
	commitInterval time.Duration
	// stopCh is the channel to receive stop message
	stopCh chan stopPayload
	// exportWg is to ensure that all messages have been flushed from the queue when we stop
	exportWg sync.WaitGroup
	// commitTicker is a ticker, containing a channel used to trigger batchCommitAll() for every commitInterval period
	commitTicker         *time.Ticker
	exportProcessRunning bool
	// mutex protects configuration state from concurrent access
	mutex       sync.Mutex
	clusterUUID string
}

type ClickHouseInput struct {
	Username       string
	Password       string
	Database       string
	DatabaseURL    string
	Debug          bool
	Compress       *bool
	CommitInterval time.Duration
}

func (ci *ClickHouseInput) GetDataSourceName() (string, error) {
	if len(ci.DatabaseURL) == 0 || len(ci.Username) == 0 || len(ci.Password) == 0 {
		return "", fmt.Errorf("URL, Username or Password missing for clickhouse DSN")
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s?username=%s&password=%s", ci.DatabaseURL, ci.Username, ci.Password))

	if len(ci.Database) > 0 {
		sb.WriteString("&database=")
		sb.WriteString(ci.Database)
	}
	if ci.Debug {
		sb.WriteString("&debug=true")
	} else {
		sb.WriteString("&debug=false")
	}
	if *ci.Compress {
		sb.WriteString("&compress=true")
	} else {
		sb.WriteString("&compress=false")
	}

	return sb.String(), nil
}

func NewClickHouseClient(input ClickHouseInput, clusterUUID string) (*ClickHouseExportProcess, error) {
	dsn, connect, err := PrepareClickHouseConnection(input)
	if err != nil {
		return nil, err
	}

	chClient := &ClickHouseExportProcess{
		db:             connect,
		dsn:            dsn,
		deque:          deque.New(),
		queueSize:      maxQueueSize,
		commitInterval: input.CommitInterval,
		clusterUUID:    clusterUUID,
	}
	return chClient, nil
}

func (ch *ClickHouseExportProcess) CacheRecord(record ipfixentities.Record) {
	chRow := flowrecord.GetFlowRecord(record)

	ch.dequeMutex.Lock()
	defer ch.dequeMutex.Unlock()
	for ch.deque.Len() >= ch.queueSize {
		ch.deque.PopFront()
	}
	ch.deque.PushBack(chRow)
}

func (ch *ClickHouseExportProcess) Start() {
	ch.startExportProcess()
}

func (ch *ClickHouseExportProcess) Stop() {
	ch.stopExportProcess(true)
}

func (ch *ClickHouseExportProcess) startExportProcess() {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	if ch.exportProcessRunning {
		return
	}
	ch.exportProcessRunning = true
	ch.commitTicker = time.NewTicker(ch.commitInterval)
	ch.stopCh = make(chan stopPayload, 1)
	ch.exportWg.Add(1)
	go func() {
		defer ch.exportWg.Done()
		ch.flowRecordPeriodicCommit()
	}()
}

func (ch *ClickHouseExportProcess) stopExportProcess(flushQueue bool) {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	if !ch.exportProcessRunning {
		return
	}
	ch.exportProcessRunning = false
	defer ch.commitTicker.Stop()
	ch.stopCh <- stopPayload{
		flushQueue: flushQueue,
	}
	ch.exportWg.Wait()
}

func (ch *ClickHouseExportProcess) flowRecordPeriodicCommit() {
	klog.InfoS("Starting ClickHouse exporting process")
	ctx := context.Background()
	logTicker := time.NewTicker(time.Minute)
	defer logTicker.Stop()
	committedRec := 0
	for {
		select {
		case stop := <-ch.stopCh:
			klog.InfoS("Stopping ClickHouse exporting process")
			if !stop.flushQueue {
				return
			}
			ctx, cancelFn := context.WithTimeout(ctx, queueFlushTimeout)
			defer cancelFn()
			committed, err := ch.batchCommitAll(ctx)
			if err != nil {
				klog.ErrorS(err, "Error when doing batchCommitAll on stop")
			} else {
				committedRec += committed
				klog.V(4).InfoS("Total number of records committed to DB", "count", committedRec)
			}
			return
		case <-ch.commitTicker.C:
			committed, err := ch.batchCommitAll(ctx)
			if err == nil {
				committedRec += committed
			}
		case <-logTicker.C:
			klog.V(4).InfoS("Total number of records committed to DB", "count", committedRec)
			committedRec = 0
		}
	}
}

// batchCommitAll commits all flow records cached in local deque in one INSERT query.
// Returns the number of records successfully committed, and error if encountered.
// Cached records will be removed only after successful commit.
func (ch *ClickHouseExportProcess) batchCommitAll(ctx context.Context) (int, error) {
	ch.dequeMutex.Lock()
	currSize := ch.deque.Len()
	ch.dequeMutex.Unlock()
	if currSize == 0 {
		return 0, nil
	}

	var stmt *sql.Stmt

	// start new connection
	tx, err := ch.db.BeginTx(ctx, nil)
	if err == nil {
		stmt, err = tx.PrepareContext(ctx, insertQuery)
	}
	if err != nil {
		klog.ErrorS(err, "Error when preparing insert statement")
		_ = tx.Rollback()
		return 0, err
	}

	// populate items from deque
	ch.dequeMutex.Lock()
	// currSize could have increased due to CacheRecord being called in between.
	currSize = ch.deque.Len()
	recordsToExport := make([]*flowrecord.FlowRecord, 0, currSize)
	for i := 0; i < currSize; i++ {
		record, ok := ch.deque.PopFront().(*flowrecord.FlowRecord)
		if !ok {
			continue
		}
		recordsToExport = append(recordsToExport, record)
	}
	ch.dequeMutex.Unlock()

	for _, record := range recordsToExport {
		_, err := stmt.ExecContext(
			ctx,
			record.FlowStartSeconds,
			record.FlowEndSeconds,
			record.FlowEndSecondsFromSourceNode,
			record.FlowEndSecondsFromDestinationNode,
			record.FlowEndReason,
			record.SourceIP,
			record.DestinationIP,
			record.SourceTransportPort,
			record.DestinationTransportPort,
			record.ProtocolIdentifier,
			record.PacketTotalCount,
			record.OctetTotalCount,
			record.PacketDeltaCount,
			record.OctetDeltaCount,
			record.ReversePacketTotalCount,
			record.ReverseOctetTotalCount,
			record.ReversePacketDeltaCount,
			record.ReverseOctetDeltaCount,
			record.SourcePodName,
			record.SourcePodNamespace,
			record.SourceNodeName,
			record.DestinationPodName,
			record.DestinationPodNamespace,
			record.DestinationNodeName,
			record.DestinationClusterIP,
			record.DestinationServicePort,
			record.DestinationServicePortName,
			record.IngressNetworkPolicyName,
			record.IngressNetworkPolicyNamespace,
			record.IngressNetworkPolicyRuleName,
			record.IngressNetworkPolicyRuleAction,
			record.IngressNetworkPolicyType,
			record.EgressNetworkPolicyName,
			record.EgressNetworkPolicyNamespace,
			record.EgressNetworkPolicyRuleName,
			record.EgressNetworkPolicyRuleAction,
			record.EgressNetworkPolicyType,
			record.TcpState,
			record.FlowType,
			record.SourcePodLabels,
			record.DestinationPodLabels,
			record.Throughput,
			record.ReverseThroughput,
			record.ThroughputFromSourceNode,
			record.ThroughputFromDestinationNode,
			record.ReverseThroughputFromSourceNode,
			record.ReverseThroughputFromDestinationNode,
			ch.clusterUUID)

		if err != nil {
			klog.ErrorS(err, "Error when adding record")
			ch.pushRecordsToFrontOfQueue(recordsToExport)
			_ = tx.Rollback()
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		klog.ErrorS(err, "Error when committing record")
		ch.pushRecordsToFrontOfQueue(recordsToExport)
		return 0, err
	}

	return len(recordsToExport), nil
}

// pushRecordsToFrontOfQueue pushes records to the front of deque without exceeding its capacity.
// Items with lower index (older records) will be dropped first if deque is to be filled.
func (ch *ClickHouseExportProcess) pushRecordsToFrontOfQueue(records []*flowrecord.FlowRecord) {
	ch.dequeMutex.Lock()
	defer ch.dequeMutex.Unlock()

	for i := len(records) - 1; i >= 0; i-- {
		if ch.deque.Len() >= ch.queueSize {
			break
		}
		ch.deque.PushFront(records[i])
	}
}

func prepareConnection(input ClickHouseInput) (string, *sql.DB, error) {
	dsn, err := input.GetDataSourceName()
	if err != nil {
		return "", nil, fmt.Errorf("error when parsing ClickHouse DSN: %v", err)
	}
	connect, err := ConnectClickHouse(dsn)
	if err != nil {
		return "", nil, err
	}
	// Test open Transaction
	tx, err := connect.Begin()
	if err == nil {
		_, err = tx.Prepare(insertQuery)
	}
	if err != nil {
		return "", nil, fmt.Errorf("error when preparing insert statement, %v", err)
	}
	_ = tx.Commit()
	return dsn, connect, err
}

func (ch *ClickHouseExportProcess) GetDsnMap() map[string]string {
	parseURL := strings.Split(ch.dsn, "?")
	m := make(map[string]string)
	m["databaseURL"] = parseURL[0]
	for _, v := range strings.Split(parseURL[1], "&") {
		pair := strings.Split(v, "=")
		m[pair[0]] = pair[1]
	}
	return m
}

func (ch *ClickHouseExportProcess) UpdateCH(dsn string, connect *sql.DB) {
	ch.stopExportProcess(false) // do not flush the queue
	defer ch.startExportProcess()
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	ch.dsn = dsn
	ch.db = connect
}

func (ch *ClickHouseExportProcess) GetCommitInterval() time.Duration {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	return ch.commitInterval
}

func (ch *ClickHouseExportProcess) SetCommitInterval(commitInterval time.Duration) {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	ch.commitInterval = commitInterval
	if ch.commitTicker != nil {
		ch.commitTicker.Reset(ch.commitInterval)
	}
}

func (ch *ClickHouseExportProcess) GetDsn() string {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()
	return ch.dsn
}

func ConnectClickHouse(url string) (*sql.DB, error) {
	var connect *sql.DB
	var connErr error
	connRetryInterval := 1 * time.Second
	connTimeout := 10 * time.Second

	// Connect to ClickHouse in a loop
	if err := wait.PollImmediate(connRetryInterval, connTimeout, func() (bool, error) {
		// Open the database and ping it
		var err error
		connect, err = sql.Open("clickhouse", url)
		if err != nil {
			connErr = fmt.Errorf("error when opening DB connection: %v", err)
			return false, nil
		}
		if err := connect.Ping(); err != nil {
			if exception, ok := err.(*clickhouse.Exception); ok {
				connErr = fmt.Errorf("failed to ping ClickHouse: %v", exception.Message)
			} else {
				connErr = fmt.Errorf("failed to ping ClickHouse: %v", err)
			}
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse after %s: %v", connTimeout, connErr)
	}
	return connect, nil
}
