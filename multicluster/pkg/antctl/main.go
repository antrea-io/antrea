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

package antctl

// file for have a root file in /multicluster in case affecting the main part
// this file will be deleted when merging to the main

import (
	"flag"
	"math/rand"
	"os"
	"path"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/logs"
)

var commandName = path.Base(os.Args[0])

var rootCmd = &cobra.Command{
	Use:   commandName,
	Short: commandName + " is the command line tool for Antrea",
	Long:  commandName + " is the command line tool for Antrea that supports showing status of ${component}",
}

func init() {
	// prevent any unexpected output at beginning
	flag.Set("logtostderr", "false")
	flag.Set("v", "0")
	pflag.CommandLine.MarkHidden("log-flush-frequency")
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	rand.Seed(time.Now().UTC().UnixNano())
	err := rootCmd.Execute()
	if err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}
