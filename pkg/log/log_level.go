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

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

const logVerbosityFlag = "v"

type logLevelManager struct {
	// we use this to access the verbosity value at runtime
	flag *pflag.Flag
}

var logLevelMgr = &logLevelManager{}

func (m *logLevelManager) getCurrentLogLevel() string {
	if m.flag == nil {
		return "UNKNOWN"
	}
	return m.flag.Value.String()
}

func (m *logLevelManager) setLogLevel(level string) error {
	if m.flag == nil {
		return fmt.Errorf("verbosity flag is unknown")
	}
	oldLevel := m.getCurrentLogLevel()
	if oldLevel == level {
		return nil
	}

	var l klog.Level
	err := l.Set(level)
	if err != nil {
		return err
	}
	klog.InfoS("Changed log level", "from", oldLevel, "to", level)
	return nil

}

func initLogLevelManager(fs *pflag.FlagSet) {
	flag := fs.Lookup(logVerbosityFlag)
	if flag == nil {
		klog.ErrorS(nil, "Failed to lookup verbosity flag", "flag", logVerbosityFlag)
	}
	logLevelMgr.flag = flag
}

// GetCurrentLogLevel returns the current log verbosity level.
func GetCurrentLogLevel() string {
	return logLevelMgr.getCurrentLogLevel()
}

// SetLogLevel sets the log verbosity level. level must be a string
// representation of a decimal integer.
func SetLogLevel(level string) error {
	return logLevelMgr.setLogLevel(level)
}
