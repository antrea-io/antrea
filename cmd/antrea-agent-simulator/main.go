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

// The simulator binary is responsible to run simulated nodes for antrea agent.
// It watches NetworkPolicies, AddressGroups and AppliedToGroups from antrea
// controller and prints the events of these resources to log.
package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/version"
)

func main() {
	command := newSimulatorCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newSimulatorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "antrea-agent-simulator",
		Long: "The Antrea agent simulator.",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			defer log.FlushLogs()

			if err := run(); err != nil {
				klog.Fatalf("Error running agent: %v", err)
			}
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}

	flags := cmd.Flags()
	log.AddFlags(flags)

	return cmd
}
