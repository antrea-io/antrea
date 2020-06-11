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

// +build windows

package support

import (
	"flag"
	"path"
)

const antreaWindowsWellKnownLogDir = `C:\k\antrea\logs`

// TODO: collect ovs logs once its log path is fixed.
func (d *agentDumper) DumpLog(basedir string) error {
	logDirFlag := flag.CommandLine.Lookup("log_dir")
	var logDir string
	if logDirFlag == nil {
		logDir = antreaWindowsWellKnownLogDir
	} else if len(logDirFlag.Value.String()) == 0 {
		logDir = logDirFlag.DefValue
	} else {
		logDir = logDirFlag.Value.String()
	}
	return fileCopy(d.fs, path.Join(basedir, "logs", "agent"), logDir, "rancher-wins-antrea-agent")
}

// TODO: maybe collect interfaces on Windows Node in future.
func (d *agentDumper) DumpHostNetworkInfo(basedir string) error {
	return nil
}
