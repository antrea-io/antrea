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

import (
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/runtime"
)

// commandList organizes commands definitions.
// It is the protocol for a pair of antctl client and server.
type commandList struct {
	definitions []commandDefinition
	rawCommands []rawCommand
	codec       serializer.CodecFactory
}

func (cl *commandList) applyPersistentFlagsToRoot(root *cobra.Command) {
	root.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")
	root.PersistentFlags().StringP("kubeconfig", "k", "", "absolute path to the kubeconfig file")
	root.PersistentFlags().DurationP("timeout", "t", 0, "time limit of the execution of the command")
	root.PersistentFlags().StringP("server", "s", "", "address and port of the API server, taking precedence over the default endpoint and the one set in kubeconfig")
}

// applyToRootCommand is the "internal" version of ApplyToRootCommand, used for testing
func (cl *commandList) applyToRootCommand(root *cobra.Command, client AntctlClient, out io.Writer) {
	for _, groupCommand := range groupCommands {
		root.AddCommand(groupCommand)
	}
	for i := range cl.definitions {
		def := &cl.definitions[i]
		if (runtime.Mode == runtime.ModeAgent && def.agentEndpoint == nil) ||
			(runtime.Mode == runtime.ModeController && def.controllerEndpoint == nil) {
			continue
		}
		def.applySubCommandToRoot(root, client, out)
		klog.Infof("Added command %s", def.use)
	}
	cl.applyPersistentFlagsToRoot(root)

	for _, cmd := range cl.rawCommands {
		if (runtime.Mode == runtime.ModeAgent && cmd.supportAgent) ||
			(runtime.Mode == runtime.ModeController && cmd.supportController) {
			root.AddCommand(cmd.cobraCommand)
		}
	}

	root.SilenceUsage = true
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		enableVerbose, err := root.PersistentFlags().GetBool("verbose")
		if err != nil {
			return err
		}
		err = flag.Set("logtostderr", fmt.Sprint(enableVerbose))
		if err != nil {
			return err
		}
		if enableVerbose {
			err := flag.Set("v", fmt.Sprint(math.MaxInt32))
			if err != nil {
				return err
			}
		}
		return nil
	}
	renderDescription(root)
}

// ApplyToRootCommand applies the commandList to the root cobra command, it applies
// each commandDefinition of it to the root command as a sub-command.
func (cl *commandList) ApplyToRootCommand(root *cobra.Command) {
	client := newClient(cl.codec)
	cl.applyToRootCommand(root, client, os.Stdout)
}

// validate checks the validation of the commandList.
func (cl *commandList) validate() []error {
	var errs []error
	if len(cl.definitions) == 0 {
		return []error{fmt.Errorf("no command found in the command list")}
	}
	for i, c := range cl.definitions {
		for _, err := range c.validate() {
			errs = append(errs, fmt.Errorf("#%d command<%s>: %w", i, c.use, err))
		}
	}
	return errs
}

// GetDebugCommands returns all commands supported by Controller or Agent that
// are used for debugging purpose.
func (cl *commandList) GetDebugCommands(mode string) [][]string {
	var allCommands [][]string
	for _, def := range cl.definitions {
		// TODO: incorporate query commands into e2e testing once proxy access is implemented
		if def.commandGroup == query {
			continue
		}
		if mode == runtime.ModeController && def.use == "log-level" {
			// log-level command does not support remote execution.
			continue
		}
		if mode == runtime.ModeAgent && def.agentEndpoint != nil ||
			mode == runtime.ModeController && def.controllerEndpoint != nil {
			var currentCommand []string
			if group, ok := groupCommands[def.commandGroup]; ok {
				currentCommand = append(currentCommand, group.Use)
			}
			currentCommand = append(currentCommand, def.use)
			allCommands = append(allCommands, currentCommand)
		}
	}
	for _, cmd := range cl.rawCommands {
		if cmd.cobraCommand.Use == "proxy" {
			// proxy will keep running until interrupted so it
			// cannot be used as is in e2e tests.
			continue
		}
		if mode == runtime.ModeController && cmd.supportController ||
			mode == runtime.ModeAgent && cmd.supportAgent {
			allCommands = append(allCommands, strings.Split(cmd.cobraCommand.Use, " ")[:1])
		}
	}
	return allCommands
}

// renderDescription replaces placeholders ${component} in Short and Long of a command
// to the determined component during runtime.
func renderDescription(command *cobra.Command) {
	command.Short = strings.ReplaceAll(command.Short, "${component}", runtime.Mode)
	command.Long = strings.ReplaceAll(command.Long, "${component}", runtime.Mode)
}
