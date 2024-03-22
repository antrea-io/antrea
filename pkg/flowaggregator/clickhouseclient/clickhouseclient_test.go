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
	"database/sql/driver"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gammazero/deque"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
	flowrecordtesting "antrea.io/antrea/pkg/flowaggregator/flowrecord/testing"
	flowaggregatortesting "antrea.io/antrea/pkg/flowaggregator/testing"
)

func init() {
	registry.LoadRegistry()
}

var fakeClusterUUID = uuid.New().String()

func TestCacheRecord(t *testing.T) {
	ctrl := gomock.NewController(t)

	chExportProc := ClickHouseExportProcess{
		deque: deque.New(),
	}

	chExportProc.queueSize = 1
	// First call. only populate row.
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	chExportProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, chExportProc.deque.Len())
	assert.Equal(t, "10.10.0.79", chExportProc.deque.At(0).(*flowrecord.FlowRecord).SourceIP)

	// Second call. discard prev row and add new row.
	mockRecord = ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, false)
	chExportProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, chExportProc.deque.Len())
	assert.Equal(t, "2001:0:3238:dfe1:63::fefb", chExportProc.deque.At(0).(*flowrecord.FlowRecord).SourceIP)
}

func TestBatchCommitAll(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "error when opening a stub database connection")
	defer db.Close()

	chExportProc := ClickHouseExportProcess{
		db:          db,
		deque:       deque.New(),
		queueSize:   maxQueueSize,
		clusterUUID: fakeClusterUUID,
	}

	recordRow := flowrecordtesting.PrepareTestFlowRecord()

	chExportProc.deque.PushBack(recordRow)

	mock.ExpectBegin()
	mock.ExpectPrepare(insertQuery).ExpectExec().
		WithArgs(
			time.Unix(int64(1637706961), 0),
			time.Unix(int64(1637706973), 0),
			time.Unix(int64(1637706974), 0),
			time.Unix(int64(1637706975), 0),
			3,
			"10.10.0.79",
			"10.10.0.80",
			44752,
			5201,
			6,
			823188,
			30472817041,
			241333,
			8982624938,
			471111,
			24500996,
			136211,
			7083284,
			"perftest-a",
			"antrea-test",
			"k8s-node-control-plane",
			"perftest-b",
			"antrea-test-b",
			"k8s-node-control-plane-b",
			"10.10.1.10",
			5202,
			"perftest",
			"test-flow-aggregator-networkpolicy-ingress-allow",
			"antrea-test-ns",
			"test-flow-aggregator-networkpolicy-rule",
			2,
			1,
			"test-flow-aggregator-networkpolicy-egress-allow",
			"antrea-test-ns-e",
			"test-flow-aggregator-networkpolicy-rule-e",
			5,
			4,
			"TIME_WAIT",
			11,
			"{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}",
			"{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}",
			15902813472,
			12381344,
			15902813473,
			15902813474,
			12381345,
			12381346,
			fakeClusterUUID,
			"test-egress",
			"172.18.0.1",
			"http",
			"mockHttpString",
			"test-egress-node").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	count, err := chExportProc.batchCommitAll(context.Background())
	assert.NoError(t, err, "error occurred when committing record with mock sql db")
	assert.Equal(t, 1, count)
	assert.Equal(t, 0, chExportProc.deque.Len())
	assert.NoError(t, mock.ExpectationsWereMet(), "unfulfilled expectations for db sql operation")
}

func TestBatchCommitAllMultiRecord(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "error when opening a stub database connection")
	defer db.Close()

	chExportProc := ClickHouseExportProcess{
		db:        db,
		deque:     deque.New(),
		queueSize: maxQueueSize,
	}
	recordRow := flowrecord.FlowRecord{}
	fieldCount := reflect.TypeOf(recordRow).NumField() + 1
	argList := make([]driver.Value, fieldCount)
	for i := 0; i < len(argList); i++ {
		argList[i] = sqlmock.AnyArg()
	}

	mock.ExpectBegin()
	expected := mock.ExpectPrepare(insertQuery)
	for i := 0; i < 10; i++ {
		chExportProc.deque.PushBack(&recordRow)
		expected.ExpectExec().WithArgs(argList...).WillReturnResult(sqlmock.NewResult(int64(i), 1))
	}
	mock.ExpectCommit()

	count, err := chExportProc.batchCommitAll(context.Background())
	assert.NoError(t, err, "error occurred when committing record with mock sql db")
	assert.Equal(t, 10, count)
	assert.Equal(t, 0, chExportProc.deque.Len())
	assert.NoError(t, mock.ExpectationsWereMet(), "unfulfilled expectations for db sql operation")
}

func TestBatchCommitAllError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "error when opening a stub database connection")
	defer db.Close()

	chExportProc := ClickHouseExportProcess{
		db:        db,
		deque:     deque.New(),
		queueSize: maxQueueSize,
	}
	recordRow := flowrecord.FlowRecord{}
	chExportProc.deque.PushBack(&recordRow)
	fieldCount := reflect.TypeOf(recordRow).NumField() + 1
	argList := make([]driver.Value, fieldCount)
	for i := 0; i < len(argList); i++ {
		argList[i] = sqlmock.AnyArg()
	}

	mock.ExpectBegin()
	mock.ExpectPrepare(insertQuery).ExpectExec().WithArgs(argList...).WillReturnError(
		fmt.Errorf("mock error for sql stmt exec"))
	mock.ExpectRollback()

	count, err := chExportProc.batchCommitAll(context.Background())
	assert.Error(t, err, "expected error when SQL transaction error")
	assert.Equal(t, 0, count)
	assert.Equal(t, 1, chExportProc.deque.Len())
	assert.NoError(t, mock.ExpectationsWereMet(), "unfulfilled expectations for db sql operation")
}

func TestPushRecordsToFrontOfQueue(t *testing.T) {
	chExportProc := ClickHouseExportProcess{
		deque:     deque.New(),
		queueSize: 4,
	}

	// init deque [0]
	records := make([]*flowrecord.FlowRecord, 5)
	for i := 0; i < 5; i++ {
		records[i] = &flowrecord.FlowRecord{SourceTransportPort: uint16(i)}
	}
	chExportProc.deque.PushBack(records[0])

	// all records should be pushed to front of deque if cap allows.
	// deque before [0], cap: 4
	// pushfront([1,2])
	// expected deque: [1,2,0]
	pushbackRecords := records[1:3]
	chExportProc.pushRecordsToFrontOfQueue(pushbackRecords)
	assert.Equal(t, 3, chExportProc.deque.Len(), "deque size mismatch")
	assert.Equal(t, records[1], chExportProc.deque.At(0), "deque has wrong item at index 0")
	assert.Equal(t, records[2], chExportProc.deque.At(1), "deque has wrong item at index 1")
	assert.Equal(t, records[0], chExportProc.deque.At(2), "deque has wrong item at index 2")

	// only newest items should be pushed to front of deque if hitting capacity.
	// deque before [1,2,0], cap: 4
	// pushfront([3,4])
	// expected deque: [4,1,2,0]
	pushbackRecords = records[3:]
	chExportProc.pushRecordsToFrontOfQueue(pushbackRecords)
	assert.Equal(t, 4, chExportProc.deque.Len(), "deque size mismatch")
	assert.Equal(t, records[4], chExportProc.deque.At(0), "deque has wrong item at index 0")
	assert.Equal(t, records[1], chExportProc.deque.At(1), "deque has wrong item at index 1")
	assert.Equal(t, records[2], chExportProc.deque.At(2), "deque has wrong item at index 2")
	assert.Equal(t, records[0], chExportProc.deque.At(3), "deque has wrong item at index 3")
}

func TestFlushCacheOnStop(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "error when opening a stub database connection")
	defer db.Close()

	// something arbitrarily large
	const commitInterval = time.Hour

	chExportProc := ClickHouseExportProcess{
		db:        db,
		config:    ClickHouseConfig{CommitInterval: commitInterval},
		deque:     deque.New(),
		queueSize: maxQueueSize,
	}

	recordRow := flowrecordtesting.PrepareTestFlowRecord()
	chExportProc.deque.PushBack(recordRow)

	mock.ExpectBegin()
	mock.ExpectPrepare(insertQuery).ExpectExec().WillDelayFor(time.Second).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	chExportProc.Start()
	// this should block for about 1 second, which is the duration by which
	// we delay the SQL transaction.
	chExportProc.Stop()

	assert.NoError(t, mock.ExpectationsWereMet(), "unfulfilled expectations for db sql operation")
}

func TestUpdateCH(t *testing.T) {
	db1, mock1, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "error when opening a stub database connection")
	defer db1.Close()

	db2, mock2, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "error when opening a stub database connection")
	defer db2.Close()

	// something small for the sake of the test
	const commitInterval = 100 * time.Millisecond

	chExportProc := ClickHouseExportProcess{
		db:        db1,
		config:    ClickHouseConfig{CommitInterval: commitInterval},
		deque:     deque.New(),
		queueSize: maxQueueSize,
	}

	recordRow := flowrecordtesting.PrepareTestFlowRecord()
	func() {
		// commitTicker is ticking so the export process may be
		// accessing the queue at the same time.
		chExportProc.dequeMutex.Lock()
		defer chExportProc.dequeMutex.Unlock()
		chExportProc.deque.PushBack(recordRow)
	}()

	mock1.ExpectBegin()
	mock1.ExpectPrepare(insertQuery).ExpectExec().WillReturnResult(sqlmock.NewResult(0, 1))
	mock1.ExpectCommit()

	chExportProc.Start()
	defer chExportProc.Stop()

	require.Eventually(t, func() bool {
		err := mock1.ExpectationsWereMet()
		return err == nil
	}, time.Second, commitInterval, "timeout while waiting for first flow record to be committed (before DB connection update)")

	mock2.ExpectBegin()
	mock2.ExpectPrepare(insertQuery).ExpectExec().WillReturnResult(sqlmock.NewResult(0, 1))
	mock2.ExpectCommit()

	t.Logf("Calling UpdateCH to update DB connection")
	chExportProc.UpdateCH(ClickHouseConfig{CommitInterval: commitInterval}, db2)

	func() {
		chExportProc.dequeMutex.Lock()
		defer chExportProc.dequeMutex.Unlock()
		chExportProc.deque.PushBack(recordRow)
	}()

	require.Eventually(t, func() bool {
		err := mock2.ExpectationsWereMet()
		return err == nil
	}, time.Second, commitInterval, "timeout while waiting for second flow record to be committed (after DB connection update)")
}

func TestParseDatabaseURL(t *testing.T) {
	testcases := []struct {
		url               string
		expectedProto     clickhouse.Protocol
		expectedAddr      string
		expectedTLSEnable bool
		expectedErrMsg    string
	}{
		{
			url:            "abc://127.0.0.1:9000",
			expectedErrMsg: "connection over abc transport protocol is not supported",
		},
		{
			url:            "127.0.0.1:9000",
			expectedErrMsg: "failed to parse ClickHouse database URL",
		},
		{
			url:            "tcp://user:password@127.0.0.1:9000",
			expectedErrMsg: "invalid ClickHouse database URL",
		},
		{
			url:            "tcp://127.0.0.1:9000/path",
			expectedErrMsg: "invalid ClickHouse database URL",
		},
		{
			url:            "tcp://127.0.0.1:9000?key=value",
			expectedErrMsg: "invalid ClickHouse database URL",
		},
		{
			url:           "tcp://127.0.0.1:9000",
			expectedProto: clickhouse.Native,
			expectedAddr:  "127.0.0.1:9000",
		},
		{
			url:               "tls://127.0.0.1:9000",
			expectedProto:     clickhouse.Native,
			expectedAddr:      "127.0.0.1:9000",
			expectedTLSEnable: true,
		},
		{
			url:           "http://127.0.0.1:9000",
			expectedProto: clickhouse.HTTP,
			expectedAddr:  "127.0.0.1:9000",
		},
		{
			url:               "https://127.0.0.1:9000",
			expectedProto:     clickhouse.HTTP,
			expectedAddr:      "127.0.0.1:9000",
			expectedTLSEnable: true,
		},
	}
	for _, tc := range testcases {
		proto, addr, tlsEnable, err := parseDatabaseURL(tc.url)
		if tc.expectedErrMsg != "" {
			assert.Contains(t, err.Error(), tc.expectedErrMsg)
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.expectedProto, proto)
			assert.Equal(t, tc.expectedTLSEnable, tlsEnable)
			assert.Equal(t, tc.expectedAddr, addr)
		}
	}
}
