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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/version"
)

func main() {
	command := newFlowAggregatorCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newFlowAggregatorCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:  "flow-aggregator",
		Long: "The Flow Aggregator.",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			defer log.FlushLogs()
			configFile, err := cmd.Flags().GetString("config")
			if err != nil {
				klog.Fatalf("Error when finding the path of config: %v", err)
			}
			if err := run(configFile); err != nil {
				klog.Fatalf("Error running flow aggregator: %v", err)
			}
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}
	flags := cmd.Flags()
	flags.String("config", "", "The path to the configuration file")
	log.AddFlags(flags)
	return cmd
}
