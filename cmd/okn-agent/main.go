// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"flag"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

func main() {
	klog.InitFlags(flag.CommandLine)
	defer klog.Flush()

	command := newAgentCommand()

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newAgentCommand() *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:  "okn-agent",
		Long: "The OKN agent runs on each node.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.complete(args); err != nil {
				klog.Fatalf("Failed to complete: %v", err)
			}
			if err := opts.validate(args); err != nil {
				klog.Fatalf("Failed to validate: %v", err)
			}
			klog.Fatal(runAgent(opts))
		},
	}

	flags := cmd.Flags()
	opts.addFlags(flags)
	// Install log flags
	flags.AddGoFlagSet(flag.CommandLine)
	return cmd
}

func runAgent(o *Options) error {
	agent, err := newAgent(o.config)
	if err != nil {
		return err
	}
	return agent.run()
}
