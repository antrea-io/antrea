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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"flag"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/logs"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/log"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	command := newSimulatorCommand()
	if err := command.Execute(); err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}

func newSimulatorCommand() *cobra.Command {
	configFile := ""
	cmd := &cobra.Command{
		Use:  "antrea-agent-simulator",
		Long: "The Antrea agent simulator.",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogFileLimits(cmd.Flags())

			if err := run(configFile); err != nil {
				klog.Fatalf("Error running agent: %v", err)
			}
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}

	flags := cmd.Flags()
	log.AddFlags(flags)
	flags.StringVar(&configFile, "config", configFile, "The path to the configuration file")
	if configFile == "" {
		configFile = "/kubeconfig/kubelet.kubeconfig"
	}
	// Install log flags
	flags.AddGoFlagSet(flag.CommandLine)
	return cmd
}
