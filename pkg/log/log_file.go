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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
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
)

var (
	maxNumArg     = uint16(0)
	logFileMaxNum = uint16(0)
	logDir        = ""

	executableName = filepath.Base(os.Args[0])
)

// initLogFileLimits initializes log file maximum size and maximum number limits based on the
// command line flags.
func initLogFileLimits(fs *pflag.FlagSet) {
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
	fatalLogFIles := []os.FileInfo{}

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
		} else if strings.Contains(file.Name(), ".log.FATAL.") {
			fatalLogFIles = append(fatalLogFIles, file)
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
	checkFilesFn(fatalLogFIles)
}
