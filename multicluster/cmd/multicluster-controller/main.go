// Copyright 2021 Antrea Authors
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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/component-base/logs"
)

var (
	scheme = runtime.NewScheme()
	opts   = newOptions()
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	command := newControllerCommand()
	command.AddCommand(newLeaderCommand())
	command.AddCommand(newMemberCommand())

	if err := command.Execute(); err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}

func newControllerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "antrea-mc-controller",
		Long: "The Antrea MultiCluster Controller.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Error: must be run in leader or member mode")
		},
	}
	flags := cmd.PersistentFlags()
	opts.addFlags(flags)
	return cmd
}
