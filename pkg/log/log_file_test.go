// Copyright 2020 Antrea Authors
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

package log

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"k8s.io/klog/v2"
)

const oneMB = 1 * 1024 * 1024

var (
	klogDefaultMaxSize = klog.MaxSize
)

func getTestFlags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddFlags(flags)
	return flags
}

func restoreFlagDefaultValues() {
	// The flag values are stored as global variables in klog and the
	// initial values for the global variables are used as the flag default
	// values. As a consequence, simply re-initializing the klog flags is
	// not enough, as the default values are no longer the same after the
	// first call to Parse. We need to explicitly set the flags to the known
	// default values, which will in turn reset the corresponding klog
	// global variables.
	klogFlags.Set(logToStdErrFlag, "true")
	klogFlags.Set(logFileFlag, "")
	klogFlags.Set(logDirFlag, "")
	klogFlags.Set(maxSizeFlag, fmt.Sprintf("%d", klogDefaultMaxSize/oneMB))
	klogFlags.Set(maxNumFlag, "0")

	klog.MaxSize = klogDefaultMaxSize
	logFileMaxNum = 0
	logDir = ""
}

// Log ~100K bytes.
func testLogging() {
	// ~1K bytes per line.
	line := make([]byte, 1000)
	for i := 0; i < 1000; i++ {
		line[i] = byte('0' + i%10)
	}
	// Log 100 lines, ~100K bytes.
	for i := 0; i < 100; i++ {
		klog.Infof("%d: %s", i, string(line))
		klog.Warningf("%d: %s", i, string(line))
	}
	FlushLogs()
}

func TestKlogFileLimits(t *testing.T) {
	testLogDir, err := os.MkdirTemp("", "antrea-log-test")
	if err != nil {
		t.Errorf("Failed to create tmp log dir: %v", err)
		return
	}
	defer os.RemoveAll(testLogDir)

	testMaxNum := 2
	args := []string{"--logtostderr=false", "--log_dir=" + testLogDir, "--log_file_max_size=1",
		fmt.Sprintf("--log_file_max_num=%d", testMaxNum)}
	testFlags := getTestFlags()
	testFlags.Parse(args)
	InitLogs(testFlags)
	defer restoreFlagDefaultValues()

	// Should generate about 5 log files (100K * 40 / 1M), though it is hard
	// to accurately control log file size and number, because of log file
	// and line headers, and they can also be affected by the log flush time.
	for i := 0; i < 40; i++ {
		testLogging()
		time.Sleep(time.Millisecond * 100)
	}

	infoLogFileNum := 0
	warningLogFileNum := 0
	validateFn := func() {
		f, err := os.Open(testLogDir)
		if err != nil {
			t.Errorf("Failed to open log directory: %v", err)
			return
		}
		allFiles, err := f.Readdir(-1)
		if err != nil {
			t.Errorf("Failed to read log directory: %v", err)
			return
		}
		f.Close()

		infoLogFiles := []os.FileInfo{}
		warningLogFiles := []os.FileInfo{}
		for _, file := range allFiles {
			if !file.Mode().IsRegular() {
				// Skip dir, symbol link, etc.
				continue
			}
			if !strings.HasPrefix(file.Name(), executableName) {
				continue
			}
			if strings.Contains(file.Name(), ".log.INFO.") {
				infoLogFiles = append(infoLogFiles, file)
			} else if strings.Contains(file.Name(), ".log.WARNING.") {
				warningLogFiles = append(warningLogFiles, file)
			} else if strings.Contains(file.Name(), ".log.ERROR.") {
				// The test should not generate many error logs to
				// avoid too many messages in the test console logs.
			} else {
				continue
			}
			assert.LessOrEqualf(t, file.Size(), int64(oneMB), "log file size check: %s", file.Name())
			t.Logf("Log file %s, size %d", file.Name(), file.Size())
		}
		infoLogFileNum = len(infoLogFiles)
		warningLogFileNum = len(warningLogFiles)
	}

	validateFn()
	assert.Greater(t, infoLogFileNum, testMaxNum, "info log file number before checking")
	assert.Greater(t, warningLogFileNum, testMaxNum, "warning log file number before checking")
	t.Logf("INFO log file number: %d, WARNING log file number: %d", infoLogFileNum, warningLogFileNum)
	// Call checkLogFiles() to delete extra files.
	checkLogFiles()
	validateFn()
	assert.Equal(t, testMaxNum, infoLogFileNum, "info log file number after checking")
	assert.Equal(t, testMaxNum, warningLogFileNum, "warning log file number after checking")
}

func TestFlags(t *testing.T) {
	testcases := []struct {
		name    string
		args    []string
		maxSize uint64
		maxNum  uint16
		logDir  string
	}{
		{
			name:    "logtostderr",
			args:    []string{"--log_file_max_size=1", "--log_file_max_num=1"},
			maxSize: klogDefaultMaxSize,
			maxNum:  0,
			logDir:  "",
		},
		{
			name:    "single file",
			args:    []string{"--logtostderr=false", "--log_file=test.log", "--log_file_max_size=1", "--log_file_max_num=1"},
			maxSize: klogDefaultMaxSize,
			maxNum:  0,
			logDir:  "",
		},
		{
			name:    "maxnum only",
			args:    []string{"--logtostderr=false", "--log_dir=/var/log/test", "--log_file_max_num=1"},
			maxSize: klogDefaultMaxSize,
			maxNum:  1,
			logDir:  "/var/log/test",
		},
		{
			name:    "tmp dir",
			args:    []string{"--logtostderr=false", "--log_file_max_size=1", "--log_file_max_num=2"},
			maxSize: oneMB,
			maxNum:  2,
			logDir:  os.TempDir(),
		},
	}

	for _, test := range testcases {
		testFlags := getTestFlags()
		testFlags.Parse(test.args)
		InitLogs(testFlags)
		assert.Equal(t, test.maxSize, klog.MaxSize, test.name)
		assert.Equal(t, test.maxNum, logFileMaxNum, test.name)
		assert.Equal(t, test.logDir, logDir, test.name)
		restoreFlagDefaultValues()
	}
}
