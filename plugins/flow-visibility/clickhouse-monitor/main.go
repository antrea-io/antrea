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
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	// Retry connection to ClickHouse every 5 seconds if it fails.
	connRetryInterval = 5 * time.Second
	// Query to ClickHouse time out if if it fails for 10 seconds.
	queryTimeout = 10 * time.Second
	// Retry query to ClickHouse every second if it fails.
	queryRetryInterval = 1 * time.Second
	// Time format for timeInserted
	timeFormat = "2006-01-02 15:04:05"
)

var (
	// The name of the table to store the flow records
	tableName = os.Getenv("TABLE_NAME")
	// The names of the materialized views
	mvNames = strings.Split(os.Getenv("MV_NAMES"), " ")
	// The namespace of the ClickHouse server
	namespace = os.Getenv("NAMESPACE")
	// The ClickHouse monitor label
	monitorLabel = os.Getenv("MONITOR_LABEL")
)

func main() {
	// Check environment variables
	if len(tableName) == 0 || len(mvNames) == 0 || len(namespace) == 0 || len(monitorLabel) == 0 {
		klog.ErrorS(nil, "Unable to load environment variables, TABLE_NAME, MV_NAMES, NAMESPACE and MONITOR_LABEL must be defined")
		return
	}
	// The monitor stops working for several rounds after a deletion
	// as the release of memory space by the ClickHouse MergeTree engine requires time
	if !skipRound() {
		connect, err := connectLoop()
		if err != nil {
			klog.ErrorS(err, "Error when connecting to ClickHouse")
			return
		}
		deleted := monitorMemory(connect)
		if deleted {
			klog.InfoS("Skip rounds after a successful deletion", "skipRoundsNum", skipRoundsNum)
		} else {
			klog.InfoS("Next round will not be skipped", "skipRoundsNum", 0)
		}
	}
}

// Checks the k8s log for the number of rounds to skip.
// Returns true when the monitor needs to skip more rounds and log the rest number of rounds to skip.
func skipRound() bool {
	logString, err := getPodLogs()
	if err != nil {
		klog.ErrorS(err, "Not find last monitor job")
		return false
	}
	// A sample log string looks like the following
	// [clickhouse]host(s)=clickhouse-clickhouse.flow-visibility.svc.cluster.local:9000, database=default, username=clickhouse_operator
	// ...
	// [clickhouse][connect=1][prepare] SELECT free_space, total_space FROM system.disks
	// [clickhouse][connect=1][send query] SELECT free_space, total_space FROM system.disks
	// ...
	// I0208 19:54:07.346630       1 main.go:213] "Memory usage" total=1979224064 used=11431936 percentage=0.005775968576744225
	// I0207 22:29:06.283450       1 main.go:71] "Next round will not be skipped" skipRoundsNum=0
	// ...

	// reads the number of rounds requires to be skipped
	logs := strings.Split(logString, "skipRoundsNum=")
	if len(logs) != 2 {
		klog.ErrorS(nil, "Error when finding number of rounds")
		return false
	}
	lines := strings.Split(logs[1], "\n")
	remainingRoundsNum, convErr := strconv.Atoi(lines[0])
	if convErr != nil {
		klog.ErrorS(convErr, "Error when finding last monitor job")
		return false
	}
	if remainingRoundsNum > 0 {
		klog.InfoS("Skip rounds after a successful deletion", "skipRoundsNum", remainingRoundsNum-1)
		return true
	}
	return false
}

// Gets pod logs from the ClickHouse monitor job
func getPodLogs() (string, error) {
	var logString string
	podLogOpts := corev1.PodLogOptions{}
	config, err := rest.InClusterConfig()
	listOptions := metav1.ListOptions{
		LabelSelector: monitorLabel,
	}
	if err != nil {
		return logString, fmt.Errorf("error when getting config: %v", err)
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return logString, fmt.Errorf("error when getting access to K8S: %v", err)
	}
	// gets ClickHouse monitor pod
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
	if err != nil {
		return logString, fmt.Errorf("failed to list ClickHouse monitor Pods: %v", err)
	}
	for _, pod := range pods.Items {
		// reads logs from the last successful pod
		if pod.Status.Phase == corev1.PodSucceeded {
			req := clientset.CoreV1().Pods(namespace).GetLogs(pod.Name, &podLogOpts)
			podLogs, err := req.Stream(context.TODO())
			if err != nil {
				return logString, fmt.Errorf("error when opening stream: %v", err)
			}
			defer podLogs.Close()

			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, podLogs)
			if err != nil {
				return logString, fmt.Errorf("error when copying information from podLogs to buf: %v", err)
			}
			logString := buf.String()
			return logString, nil
		}
	}
	return logString, fmt.Errorf("no successful monitor")
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

// Checks the memory usage in the ClickHouse, deletes records when it exceeds the threshold.
func monitorMemory(connect *sql.DB) bool {
	var (
		freeSpace  uint64
		totalSpace uint64
	)
	// Get memory usage from ClickHouse system table
	if err := wait.PollImmediate(queryRetryInterval, queryTimeout, func() (bool, error) {
		if err := connect.QueryRow("SELECT free_space, total_space FROM system.disks").Scan(&freeSpace, &totalSpace); err != nil {
			klog.ErrorS(err, "Failed to get memory usage for ClickHouse")
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		klog.ErrorS(err, "Failed to get memory usage for ClickHouse")
		return false
	}

	// Calculate the memory usage
	usagePercentage := float64(totalSpace-freeSpace) / float64(totalSpace)
	klog.InfoS("Memory usage", "total", totalSpace, "used", totalSpace-freeSpace, "percentage", usagePercentage)
	// Delete records when memory usage is larger than threshold
	if usagePercentage > threshold {
		timeBoundary, err := getTimeBoundary(connect)
		if err != nil {
			klog.ErrorS(err, "Failed to get timeInserted boundary")
			return false
		}
		// Delete old data in the table storing records and related materialized views
		tables := append([]string{tableName}, mvNames...)
		for _, table := range tables {
			// Delete all records inserted earlier than an upper boundary of timeInserted
			command := fmt.Sprintf("ALTER TABLE %s DELETE WHERE timeInserted < toDateTime('%v')", table, timeBoundary.Format(timeFormat))
			if _, err := connect.Exec(command); err != nil {
				klog.ErrorS(err, "Failed to delete records from ClickHouse", "table", table)
				return false
			}
		}
		return true
	}
	return false
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
