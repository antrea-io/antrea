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

// Package log processes the klog flags, and enforces the maximum log file
// size and maximum log file number limits.
package log

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/wait"
	klogv1 "k8s.io/klog"
	klogv2 "k8s.io/klog/v2"
)

const (
	logToStdErrFlag = "logtostderr"
	logDirFlag      = "log_dir"
	logFileFlag     = "log_file"
	maxSizeFlag     = "log_file_max_size"
	maxNumFlag      = "log_file_max_num"

	// Check log file number every 10 mins.
	logFileCheckInterval = time.Minute * 10
	// Allowed maximum value for the maximum file size limit.
	maxMaxSizeMB = 1024 * 100

	// outputCallDepth is the stack depth where we can find the origin of this call
	outputCallDepth = 6
	// defaultPrefixLength log prefix that we have to strip out
	defaultPrefixLength = 53
)

var (
	maxNumArg     = uint16(0)
	logFileMaxNum = uint16(0)
	logDir        = ""

	executableName = filepath.Base(os.Args[0])
)

// klogWriter is used in SetOutputBySeverity call below to redirect
// any calls to klogv1 to end up in klogv2
type klogWriter struct{}

func (kw klogWriter) Write(p []byte) (n int, err error) {
	if len(p) < defaultPrefixLength {
		klogv2.InfoDepth(outputCallDepth, string(p))
		return len(p), nil
	}
	if p[0] == 'I' {
		klogv2.InfoDepth(outputCallDepth, string(p[defaultPrefixLength:]))
	} else if p[0] == 'W' {
		klogv2.WarningDepth(outputCallDepth, string(p[defaultPrefixLength:]))
	} else if p[0] == 'E' {
		klogv2.ErrorDepth(outputCallDepth, string(p[defaultPrefixLength:]))
	} else if p[0] == 'F' {
		klogv2.FatalDepth(outputCallDepth, string(p[defaultPrefixLength:]))
	} else {
		klogv2.InfoDepth(outputCallDepth, string(p[defaultPrefixLength:]))
	}
	return len(p), nil
}

func AddFlags(fs *pflag.FlagSet) {
	fs.Uint16Var(&maxNumArg, maxNumFlag, maxNumArg, "Maximum number of log files per severity level to be kept. Value 0 means unlimited.")
}

// InitLogFileLimits initializes log file maximum size and maximum number limits based on the
// command line flags.
// Also sets up klogv2 flags
func InitLogFileLimits(fs *pflag.FlagSet) {
	var err error
	var logToStdErr bool
	var logFile string
	var maxSize uint64
	var klogFlags flag.FlagSet

	logToStdErr, err = fs.GetBool(logToStdErrFlag)
	if err != nil {
		// Should not happen. Return for safety.
		return
	}

	logFile, err = fs.GetString(logFileFlag)
	if err != nil {
		return
	}

	maxSize, err = fs.GetUint64(maxSizeFlag)
	if err != nil {
		return
	}

	logDir, err = fs.GetString(logDirFlag)
	if err != nil {
		return
	}

	// Set up flags for klog v2. This is needed as "k8s.io/component-base/logs"
	// uses v1, so a version of the flags connected to klogv2 is needed.
	klogv2.InitFlags(&klogFlags)
	klogFlags.Set(logToStdErrFlag, strconv.FormatBool(logToStdErr))
	klogFlags.Set(logFileFlag, logFile)
	klogFlags.Set(maxSizeFlag, strconv.FormatUint(maxSize, 10))
	klogFlags.Set(logDirFlag, logDir)
	klogv1Redirect()

	if logToStdErr {
		// Logging to files is not enabled.
		return
	}

	if logFile != "" {
		klogFlags.Set(logFileFlag, logFile)
		// Log to a single file. klog will take care of the max size limit.
		return
	}

	if maxSize > maxMaxSizeMB {
		klogv2.Errorf("The specified log file max size %d is too big (maximum: %d), ignored", maxSize, maxMaxSizeMB)
	} else {
		maxSize = maxSize * 1024 * 1024

		// klogv2 does not respect the max file size specified by --log_file_max_size
		// when --log_file is not used. Here as a workaround, we directly set the
		// specified max size to klogv2.MaxSize.
		if klogv2.MaxSize != maxSize {
			klogv2.MaxSize = maxSize
			klogv2.Infof("Set log file max size to %d", maxSize)
		}
	}

	if maxNumArg > 0 {

		logFileMaxNum = maxNumArg
		if logDir == "" {
			// Log to the tmp dir.
			logDir = os.TempDir()
			klogFlags.Set(logDirFlag, logDir)
		}
	}
}

// StartLogFileNumberMonitor starts monitoring the log files to make sure the
// number of log files does not exceed the maximum limit, when the log file
// number limit is configured.
func StartLogFileNumberMonitor(stopCh <-chan struct{}) {
	if logFileMaxNum == 0 {
		// The maximum log file number limit is not configured.
		return
	}

	go func() {
		klogv2.Infof("Starting log file monitoring. Maximum log file number is %d", logFileMaxNum)
		wait.Until(checkLogFiles, logFileCheckInterval, stopCh)
	}()
}

// klogv1Redirect redirects klogv1 to klogv2.
// Pulled from: https://github.com/kubernetes/klog/blob/master/examples/coexist_klog_v1_and_v2/coexist_klog_v1_and_v2.go
// TODO: remove function once proxy is updated to use v2.
func klogv1Redirect() {
	var klogv1Flags flag.FlagSet
	klogv1.InitFlags(&klogv1Flags)
	klogv1Flags.Set("logtostderr", "false")
	klogv1Flags.Set("stderrthreshold", "FATAL")
	klogv1.SetOutputBySeverity("INFO", klogWriter{})
}

func checkLogFiles() {
	f, err := os.Open(logDir)
	if err != nil {
		klogv2.Errorf("Failed to open log directory %s: %v", logDir, err)
		return
	}
	allFiles, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		klogv2.Errorf("Failed to read log directory %s: %v", logDir, err)
		return
	}

	maxNum := int(logFileMaxNum)
	if len(allFiles) <= maxNum {
		return
	}

	infoLogFiles := []os.FileInfo{}
	warningLogFiles := []os.FileInfo{}
	errorLogFiles := []os.FileInfo{}
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
			errorLogFiles = append(errorLogFiles, file)
		}
	}

	checkFilesFn := func(files []os.FileInfo) {
		if len(files) <= maxNum {
			return
		}
		// Sort files by modification time.
		sort.Slice(files, func(i, j int) bool {
			return files[i].ModTime().After(files[j].ModTime())
		})
		// Remove the oldest files.
		for _, file := range files[maxNum:] {
			err := os.Remove(logDir + "/" + file.Name())
			if err != nil {
				klogv2.Errorf("Failed to delete log file %s: %v", file.Name(), err)
			} else {
				klogv2.Infof("Deleted log file %s", file.Name())
			}
		}
	}

	checkFilesFn(infoLogFiles)
	checkFilesFn(warningLogFiles)
	checkFilesFn(errorLogFiles)
}
