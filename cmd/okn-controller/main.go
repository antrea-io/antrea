// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"flag"
	"os"

	"okn/pkg/version"

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

func main() {
	klog.InitFlags(flag.CommandLine)
	defer klog.Flush()

	command := newControllerCommand()

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newControllerCommand() *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:  "okn-controller",
		Long: "The OKN Controller.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.complete(args); err != nil {
				klog.Fatalf("Failed to complete: %v", err)
			}
			if err := opts.validate(args); err != nil {
				klog.Fatalf("Failed to validate: %v", err)
			}
			if err := run(opts); err != nil {
				klog.Fatalf("Error running controller: %v", err)
			}
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}

	flags := cmd.Flags()
	opts.addFlags(flags)
	// Install log flags
	flags.AddGoFlagSet(flag.CommandLine)
	return cmd
}
