//go:build linux
// +build linux

// Copyright 2025 Antrea Authors
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

	"antrea.io/antrea/v2/pkg/log"
	"antrea.io/antrea/v2/pkg/version"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func main() {
	command := newAntreaSysctlInitCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newAntreaSysctlInitCommand() *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:  "antrea-sysctl-init",
		Long: "Initialize Antrea-required sysctl config.",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			defer log.FlushLogs()

			if err := opts.validate(); err != nil {
				klog.Fatalf("Failed to validate: %v", err)
			}
			if err := run(opts); err != nil {
				klog.Fatalf("Error running sysctl init: %v", err)
			}
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}

	flags := cmd.Flags()
	opts.addFlags(flags)
	log.AddFlags(flags)
	return cmd
}
