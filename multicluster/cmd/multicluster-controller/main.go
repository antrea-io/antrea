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

	"antrea.io/antrea/pkg/log"
)

var (
	scheme = runtime.NewScheme()
	opts   = newOptions()
)

func main() {
	command := newControllerCommand()
	flags := command.PersistentFlags()
	opts.addFlags(flags)
	log.AddFlags(flags)
	command.AddCommand(newLeaderCommand())
	command.AddCommand(newMemberCommand())

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newControllerCommand() *cobra.Command {
	return &cobra.Command{
		Use:  "antrea-mc-controller",
		Long: "The Antrea Multi-cluster Controller.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Error: must be run in leader or member mode")
		},
	}
}
