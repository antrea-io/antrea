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

package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const (
	// The storage percentage at which the monitor starts to delete old records. By default, if the storage usage is larger than 50%, it starts to delete the old records.
	threshold = 0.5
	// The percentage of records in ClickHouse that will be deleted when the storage grows above threshold.
	deletePercentage = 0.5
	// The monitor stops for 3 intervals after a deletion to wait for the ClickHouse MergeTree Engine to release memory.
	skipRoundsNum = 3
	// Connection to ClickHouse times out if it fails for 1 minute.
	connTimeout = time.Minute
	// Retry connection to ClickHouse every 10 seconds if it fails.
	connRetryInterval = 10 * time.Second
	// Query to ClickHouse time out if if it fails for 10 seconds.
	queryTimeout = 10 * time.Second
	// Retry query to ClickHouse every second if it fails.
	queryRetryInterval = 1 * time.Second
	// Time format for timeInserted
	timeFormat = "2006-01-02 15:04:05"
	// The monitor runs every minute.
	monitorExecInterval = 1 * time.Minute
)

var (
	// Storage size allocated for the ClickHouse in number of bytes
	allocatedSpace uint64
	// The name of the table to store the flow records
	tableName = os.Getenv("TABLE_NAME")
	// The names of the materialized views
	mvNames = strings.Split(os.Getenv("MV_NAMES"), " ")
	// The remaining number of rounds to be skipped
	remainingRoundsNum = 0
)

func main() {
	// Check environment variables
	allocatedSpaceStr := os.Getenv("STORAGE_SIZE")

	if len(tableName) == 0 || len(mvNames) == 0 || len(allocatedSpaceStr) == 0 {
		klog.ErrorS(nil, "Unable to load environment variables, TABLE_NAME, MV_NAMES and STORAGE_SIZE must be defined")
		return
	}
	var err error
	quantity, err := resource.ParseQuantity(allocatedSpaceStr)
	if err != nil {
		klog.ErrorS(err, "Error when parsing STORAGE_SIZE")
		return
	}
	allocatedSpace = uint64(quantity.Value())

	connect, err := connectLoop()
	if err != nil {
		klog.ErrorS(err, "Error when connecting to ClickHouse")
		os.Exit(1)
	}
	checkStorageCondition(connect)
	wait.Forever(func() {
		// The monitor stops working for several rounds after a deletion
		// as the release of memory space by the ClickHouse MergeTree engine requires time
		if remainingRoundsNum > 0 {
			klog.InfoS("Skip rounds after a successful deletion", "remaining number of rounds", remainingRoundsNum)
			remainingRoundsNum -= 1
		} else if remainingRoundsNum == 0 {
			monitorMemory(connect)
		} else {
			klog.ErrorS(nil, "Remaining rounds number to be skipped should be larger than or equal to 0", "number", remainingRoundsNum)
			os.Exit(1)
		}
	}, monitorExecInterval)
}

// Connects to ClickHouse in a loop
func connectLoop() (*sql.DB, error) {
	// ClickHouse configuration
	userName := os.Getenv("CLICKHOUSE_USERNAME")
	password := os.Getenv("CLICKHOUSE_PASSWORD")
	databaseURL := os.Getenv("DB_URL")
	if len(userName) == 0 || len(password) == 0 || len(databaseURL) == 0 {
		return nil, fmt.Errorf("unable to load environment variables, CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD and DB_URL must be defined")
	}
	var connect *sql.DB
	if err := wait.PollImmediate(connRetryInterval, connTimeout, func() (bool, error) {
		// Open the database and ping it
		dataSourceName := fmt.Sprintf("%s?debug=true&username=%s&password=%s", databaseURL, userName, password)
		var err error
		connect, err = sql.Open("clickhouse", dataSourceName)
		if err != nil {
			klog.ErrorS(err, "Failed to connect to ClickHouse")
			return false, nil
		}
		if err := connect.Ping(); err != nil {
			if exception, ok := err.(*clickhouse.Exception); ok {
				klog.ErrorS(nil, "Failed to ping ClickHouse", "message", exception.Message)
			} else {
				klog.ErrorS(err, "Failed to ping ClickHouse")
			}
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse after %s", connTimeout)
	}
	return connect, nil
}

// Check if ClickHouse shares storage space with other software
func checkStorageCondition(connect *sql.DB) {
	var (
		freeSpace  uint64
		usedSpace  uint64
		totalSpace uint64
	)
	getDiskUsage(connect, &freeSpace, &totalSpace)
	getClickHouseUsage(connect, &usedSpace)
	availablePercentage := float64(freeSpace+usedSpace) / float64(totalSpace)
	klog.InfoS("Low available percentage implies ClickHouse does not save data on a dedicated disk", "availablePercentage", availablePercentage)
}

func getDiskUsage(connect *sql.DB, freeSpace *uint64, totalSpace *uint64) {
	// Get free space from ClickHouse system table
	if err := wait.PollImmediate(queryRetryInterval, queryTimeout, func() (bool, error) {
		if err := connect.QueryRow("SELECT free_space, total_space FROM system.disks").Scan(freeSpace, totalSpace); err != nil {
			klog.ErrorS(err, "Failed to get the disk usage")
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		klog.ErrorS(err, "Failed to get the disk usage", "timeout", queryTimeout)
		return
	}
}

func getClickHouseUsage(connect *sql.DB, usedSpace *uint64) {
	// Get space usage from ClickHouse system table
	if err := wait.PollImmediate(queryRetryInterval, queryTimeout, func() (bool, error) {
		if err := connect.QueryRow("SELECT SUM(bytes) FROM system.parts").Scan(usedSpace); err != nil {
			klog.ErrorS(err, "Failed to get the used space size by the ClickHouse")
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		klog.ErrorS(err, "Failed to get the used space size by the ClickHouse", "timeout", queryTimeout)
		return
	}
}

// Checks the memory usage in the ClickHouse, and deletes records when it exceeds the threshold.
func monitorMemory(connect *sql.DB) {
	var (
		freeSpace  uint64
		usedSpace  uint64
		totalSpace uint64
	)
	getDiskUsage(connect, &freeSpace, &totalSpace)
	getClickHouseUsage(connect, &usedSpace)

	// Total space for ClickHouse is the smaller one of the user allocated space size and the actual space size on the disk
	if (freeSpace + usedSpace) < allocatedSpace {
		totalSpace = freeSpace + usedSpace
	} else {
		totalSpace = allocatedSpace
	}

	// Calculate the memory usage
	usagePercentage := float64(usedSpace) / float64(totalSpace)
	klog.InfoS("Memory usage", "total", totalSpace, "used", usedSpace, "percentage", usagePercentage)
	// Delete records when memory usage is larger than threshold
	if usagePercentage > threshold {
		timeBoundary, err := getTimeBoundary(connect)
		if err != nil {
			klog.ErrorS(err, "Failed to get timeInserted boundary")
			return
		}
		// Delete old data in the table storing records and related materialized views
		tables := append([]string{tableName}, mvNames...)
		for _, table := range tables {
			// Delete all records inserted earlier than an upper boundary of timeInserted
			command := fmt.Sprintf("ALTER TABLE %s DELETE WHERE timeInserted < toDateTime('%v')", table, timeBoundary.Format(timeFormat))
			if _, err := connect.Exec(command); err != nil {
				klog.ErrorS(err, "Failed to delete records from ClickHouse", "table", table)
				return
			}
		}
		klog.InfoS("Skip rounds after a successful deletion", "skipRoundsNum", skipRoundsNum)
		remainingRoundsNum = skipRoundsNum
	}
}

// Gets the timeInserted value of the latest row to be deleted.
func getTimeBoundary(connect *sql.DB) (time.Time, error) {
	var timeBoundary time.Time
	deleteRowNum, err := getDeleteRowNum(connect)
	if err != nil {
		return timeBoundary, err
	}
	command := fmt.Sprintf("SELECT timeInserted FROM %s LIMIT 1 OFFSET %d", tableName, deleteRowNum)
	if err := wait.PollImmediate(queryRetryInterval, queryTimeout, func() (bool, error) {
		if err := connect.QueryRow(command).Scan(&timeBoundary); err != nil {
			klog.ErrorS(err, "Failed to get timeInserted boundary", "table name", tableName)
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		return timeBoundary, fmt.Errorf("failed to get timeInserted boundary from %s: %v", tableName, err)
	}
	return timeBoundary, nil
}

// Calculates number of rows to be deleted depending on number of rows in the table and the percentage to be deleted.
func getDeleteRowNum(connect *sql.DB) (uint64, error) {
	var deleteRowNum, count uint64
	command := fmt.Sprintf("SELECT COUNT() FROM %s", tableName)
	if err := wait.PollImmediate(queryRetryInterval, queryTimeout, func() (bool, error) {
		if err := connect.QueryRow(command).Scan(&count); err != nil {
			klog.ErrorS(err, "Failed to get the number of records", "table name", tableName)
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		return deleteRowNum, fmt.Errorf("failed to get the number of records from %s: %v", tableName, err)
	}
	deleteRowNum = uint64(float64(count) * deletePercentage)
	return deleteRowNum, nil
}
