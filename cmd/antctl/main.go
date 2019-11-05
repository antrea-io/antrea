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

package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/logs"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl"
)

var rootCmd = &cobra.Command{
	Use:   "antctl",
	Short: "antctl is the command line tool for Antrea",
	Long:  "antctl is the command line tool for Antrea that supports showing the current state of Antrea Controller and Agent.",
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	if err := antctl.Init(rootCmd); err != nil {
		klog.Fatalf("Failed to init antctl: %v", err)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
