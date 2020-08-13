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
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/wait"
	_ "k8s.io/component-base/logs" // just making import explicit (already imported by k8s libraries)
	klogv1 "k8s.io/klog"
	"k8s.io/klog/v2"
)

const (
	logToStdErrFlag  = "logtostderr"
	logDirFlag       = "log_dir"
	logFileFlag      = "log_file"
	maxSizeFlag      = "log_file_max_size"
	maxNumFlag       = "log_file_max_num"
	logFlushFreqFlag = "log-flush-frequency"

	// Check log file number every 10 mins.
	logFileCheckInterval = time.Minute * 10
	// Allowed maximum value for the maximum file size limit.
	maxMaxSizeMB = 1024 * 100

	logFlushFreqDefault = 5 * time.Second
)

var (
	maxNumArg     = uint16(0)
	logFileMaxNum = uint16(0)
	logDir        = ""

	executableName = filepath.Base(os.Args[0])

	// Klogv2Flags is the flag set for klog (klogv2).
	Klogv2Flags flag.FlagSet

	logFlushFreq = logFlushFreqDefault
)

func init() {
	klog.InitFlags(&Klogv2Flags)
}

func AddFlags(fs *pflag.FlagSet) {
	fs.AddGoFlagSet(&Klogv2Flags)
	// mimics InitLogs in "k8s.io/component-base/logs"
	fs.DurationVar(&logFlushFreq, logFlushFreqFlag, logFlushFreqDefault, "Maximum number of seconds between log flushes")
	fs.Uint16Var(&maxNumArg, maxNumFlag, maxNumArg, "Maximum number of log files per severity level to be kept. Value 0 means unlimited.")
}

// InitLogFileLimits initializes log file maximum size and maximum number limits based on the
// command line flags.
func InitLogFileLimits(fs *pflag.FlagSet) {
	var err error
	var logToStdErr bool
	var logFile string
	var maxSize uint64

	logToStdErr, err = fs.GetBool(logToStdErrFlag)
	if err != nil {
		// Should not happen. Return for safety.
		return
	}
	if logToStdErr {
		// Logging to files is not enabled.
		return
	}

	logFile, err = fs.GetString(logFileFlag)
	if err != nil {
		return
	}
	if logFile != "" {
		// Log to a single file. klog will take care of the max size limit.
		return
	}

	// Max log file size in MB.
	maxSize, err = fs.GetUint64(maxSizeFlag)
	if err != nil {
		return
	}
	if maxSize > maxMaxSizeMB {
		klog.Errorf("The specified log file max size %d is too big (maximum: %d), ignored", maxSize, maxMaxSizeMB)
	} else {
		maxSize = maxSize * 1024 * 1024

		// klog does not respect the max file size specified by --log_file_max_size
		// when --log_file is not used. Here as a workaround, we directly set the
		// specified max size to klog.MaxSize.
		if klog.MaxSize != maxSize {
			klog.MaxSize = maxSize
			klog.Infof("Set log file max size to %d", maxSize)
		}
	}

	if maxNumArg > 0 {
		logDir, err = fs.GetString(logDirFlag)
		if err != nil {
			return
		}

		logFileMaxNum = maxNumArg
		if logDir == "" {
			// Log to the tmp dir.
			logDir = os.TempDir()
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
		klog.Infof("Starting log file monitoring. Maximum log file number is %d", logFileMaxNum)
		wait.Until(checkLogFiles, logFileCheckInterval, stopCh)
	}()
}

func checkLogFiles() {
	f, err := os.Open(logDir)
	if err != nil {
		klog.Errorf("Failed to open log directory %s: %v", logDir, err)
		return
	}
	allFiles, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		klog.Errorf("Failed to read log directory %s: %v", logDir, err)
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
				klog.Errorf("Failed to delete log file %s: %v", file.Name(), err)
			} else {
				klog.Infof("Deleted log file %s", file.Name())
			}
		}
	}

	checkFilesFn(infoLogFiles)
	checkFilesFn(warningLogFiles)
	checkFilesFn(errorLogFiles)
}

// Support code for klogv2 while klogv1 is still used in third_party and
// "k8s.io/component-base/logs", for the K8s Go version we depend on (v0.18.4).
// TODO: remove when they are upgraded to klogv2.

// klogWriter is used in the SetOutput call below to redirect any calls to
// klogv1 to end up in klogv2
type klogWriter struct{}

// determineCallDepth is meant to be called by Write and determines the depth of
// the call stack to reach the original location of the log call.
func determineCallDepth() int {
	// based on our knowledge of the code, there are either 5-6 frames we
	// care about, so 10 is large enough.
	pcs := make([]uintptr, 10)
	depth := 1
	// 1 would be the caller of Callers (determineCallDepth), 2 would be the
	// caller of determineCallDepth (Write), 3 would be the caller of Write
	// (thus in the klog package).
	if numEntries := runtime.Callers(3, pcs); numEntries > 0 {
		pcs = pcs[:numEntries]
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			// as soon as we get out of klog.go, we have reached the
			// actual location of the log call.
			if !strings.HasSuffix(frame.File, "/klog.go") {
				return depth
			}
			depth++
			if !more {
				return -1
			}
		}
	}
	return -1
}

func (kw klogWriter) Write(p []byte) (n int, err error) {
	// will be either 5 or 6 based on which version of the logging functions
	// is used (e.g. Info vs Infof).
	outputCallDepth := determineCallDepth()
	if outputCallDepth < 0 { // should not happen, but handle "gracefully"
		return 0, nil
	}

	// determine and strip klogv1 prefix.
	prefixIndex := bytes.IndexByte(p, ']')
	if prefixIndex == -1 || prefixIndex+2 >= len(p) {
		klog.InfoDepth(outputCallDepth, string(p))
		return len(p), nil
	}

	if p[0] == 'I' {
		klog.InfoDepth(outputCallDepth, string(p[prefixIndex+2:]))
	} else if p[0] == 'W' {
		klog.WarningDepth(outputCallDepth, string(p[prefixIndex+2:]))
	} else if p[0] == 'E' {
		klog.ErrorDepth(outputCallDepth, string(p[prefixIndex+2:]))
	} else if p[0] == 'F' {
		klog.FatalDepth(outputCallDepth, string(p[prefixIndex+2:]))
	} else {
		klog.InfoDepth(outputCallDepth, string(p[prefixIndex+2:]))
	}

	return len(p), nil
}

// setUpKlogV1Redirect sets up redirection from klogv1 to
// TODO: remove once components use klogv2 by default.
func setUpKlogV1Redirect() {
	// klogv1 initialization
	// these flag values will not affect klogv2
	var klogv1Flags flag.FlagSet
	klogv1.InitFlags(&klogv1Flags)
	klogv1Flags.Set("logtostderr", "false")
	klogv1Flags.Set("alsologtostderr", "false")
	klogv1Flags.Set("stderrthreshold", "FATAL")
	klogv1.SetOutput(klogWriter{})
}

// InitKlog intializes logging with klog.
// TODO: remove once components use klogv2 by default.
func InitKlog() {
	setUpKlogV1Redirect()

	// redirect standard "log" to klog
	klog.CopyStandardLogTo("INFO")

	// The default flush interval is 5 seconds.
	// We cannot use wait.Forever(klog.Flush, logFlushFreq) as any
	// user-provided value would be ignored. We have the same issue with
	// "k8s.io/component-base/logs" when calling IntLogs() before arguments
	// are parsed.
	go func() {
		for {
			time.Sleep(logFlushFreq)
			klog.Flush()
		}
	}()
}

func FlushKlog() {
	klog.Flush()
}
