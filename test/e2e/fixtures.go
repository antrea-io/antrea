// Copyright 2019 Antrea Authors
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

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTest(tb testing.TB) (*TestData, error) {
	data := &TestData{}
	tb.Logf("Creating K8s clientset")
	// TODO: it is probably not needed to re-create the clientset in each test, maybe we could
	// just keep it in clusterInfo?
	if err := data.createClient(); err != nil {
		return nil, err
	}
	tb.Logf("Creating '%s' K8s Namespace", testNamespace)
	if err := data.createTestNamespace(); err != nil {
		return nil, err
	}
	tb.Logf("Applying Antrea YAML")
	if err := data.deployAntrea(); err != nil {
		return nil, err
	}
	tb.Logf("Waiting for all Antrea DaemonSet Pods")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		return nil, err
	}
	// TODO: CoreDNS keeps crashing at the moment, even when Antrea is running fine.
	// t.Logf("Checking CoreDNS deployment")
	// if err := data.checkCoreDNSPods(defaultTimeout); err != nil {
	// 	return nil, err
	// }
	return data, nil
}

func logsDirForTest(testName string) string {
	// a filepath-friendly timestamp format.
	const timeFormat = "Jan02-15-04-05"
	timeStamp := time.Now().Format(timeFormat)
	logsDir := filepath.Join(testOptions.logsExportDir, fmt.Sprintf("%s.%s", testName, timeStamp))
	return logsDir
}

func exportLogs(tb testing.TB, data *TestData) {
	if tb.Skipped() {
		return
	}
	// if test was successful and --logs-export-on-success was not provided, we do not export
	// any logs.
	if !tb.Failed() && !testOptions.logsExportOnSuccess {
		return
	}
	logsDir := logsDirForTest(tb.Name())
	tb.Logf("Exporting test logs to '%s'", logsDir)
	// remove directory if it already exists. This ensures that we start with an empty
	// directory. Given that we append a timestamp at the end of the path it is very unlikely to
	// happen.
	_ = os.RemoveAll(logsDir)
	if err := os.Mkdir(logsDir, 0700); err != nil {
		tb.Errorf("Error when creating logs directory '%s': %v", logsDir, err)
		return
	}

	// for now we just retrieve the logs for the Antrea Pods, but maybe we can find a good way to
	// retrieve the logs for the test Pods in the future (before deleting them) if it is useful
	// for debugging.

	// getPodWriter creates the file with name nodeName-podName-suffix. It returns nil if the
	// file cannot be created. File must be closed by the caller.
	getPodWriter := func(nodeName, podName, suffix string) *os.File {
		logFile := filepath.Join(logsDir, fmt.Sprintf("%s-%s-%s", nodeName, podName, suffix))
		f, err := os.Create(logFile)
		if err != nil {
			tb.Errorf("Error when creating log file '%s': '%v'", logFile, err)
			return nil
		}
		return f
	}

	// getNodeWriter creates the file with name nodeName-suffix. It returns nil if the file
	// cannot be created. File must be closed by the caller.
	getNodeWriter := func(nodeName, suffix string) *os.File {
		logFile := filepath.Join(logsDir, fmt.Sprintf("%s-%s", nodeName, suffix))
		f, err := os.Create(logFile)
		if err != nil {
			tb.Errorf("Error when creating log file '%s': '%v'", logFile, err)
			return nil
		}
		return f
	}

	// runKubectl runs the provided kubectl command on the master Node and returns the
	// output. It returns an empty string in case of error.
	runKubectl := func(cmd string) string {
		rc, stdout, _, err := RunCommandOnNode(masterNodeName(), cmd)
		if err != nil || rc != 0 {
			tb.Errorf("Error when running this kubectl command on master Node: %s", cmd)
			return ""
		}
		return stdout
	}

	// dump the logs for Antrea Pods to disk.
	data.forAllAntreaPods(func(nodeName, podName string) error {
		w := getPodWriter(nodeName, podName, "logs")
		if w == nil {
			return nil
		}
		defer w.Close()
		cmd := fmt.Sprintf("kubectl -n %s logs --all-containers %s", antreaNamespace, podName)
		stdout := runKubectl(cmd)
		if stdout == "" {
			return nil
		}
		w.WriteString(stdout)
		return nil
	})

	// dump the output of "kubectl describe" for Antrea pods to disk.
	data.forAllAntreaPods(func(nodeName, podName string) error {
		w := getPodWriter(nodeName, podName, "describe")
		if w == nil {
			return nil
		}
		defer w.Close()
		cmd := fmt.Sprintf("kubectl -n %s describe pod %s", antreaNamespace, podName)
		stdout := runKubectl(cmd)
		if stdout == "" {
			return nil
		}
		w.WriteString(stdout)
		return nil
	})

	// export kubelet logs with journalctl for each Node. If the Nodes do not use journalctl we
	// print a log message. If kubelet is not run with systemd, the log file will be empty.
	if err := forAllNodes(func(nodeName string) error {
		const numLines = 100
		// --no-pager ensures the command does not hang.
		cmd := fmt.Sprintf("journalctl -u kubelet -n %d --no-pager", numLines)
		rc, stdout, _, err := RunCommandOnNode(nodeName, cmd)
		if err != nil || rc != 0 {
			// return an error and skip subsequent Nodes
			return fmt.Errorf("error when running journalctl on Node '%s', is it available?", nodeName)
		}
		w := getNodeWriter(nodeName, "kubelet")
		if w == nil {
			// move on to the next Node
			return nil
		}
		defer w.Close()
		w.WriteString(stdout)
		return nil
	}); err != nil {
		tb.Logf("Error when exporting kubelet logs: %v", err)
	}
}

func teardownTest(tb testing.TB, data *TestData) {
	exportLogs(tb, data)
	tb.Logf("Deleting '%s' K8s Namespace", testNamespace)
	if err := data.deleteTestNamespace(defaultTimeout); err != nil {
		tb.Logf("Error when tearing down test: %v", err)
	}
}

func deletePodWrapper(tb testing.TB, data *TestData, name string) {
	tb.Logf("Deleting Pod '%s'", name)
	if err := data.deletePod(name); err != nil {
		tb.Logf("Error when deleting Pod: %v", err)
	}
}
