// Copyright 2026 Antrea Authors
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
	"path"

	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/version"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var (
	// sysctlConfig contains Antrea-specific sysctl overrides required for correct operation of features such as Egress,
	// which rely on policy routing and therefore require rp_filter to be set to loose mode (2) on Antrea-managed interfaces.
	sysctlConfig = `
# Antrea-specific sysctl overrides. These settings are required for features that rely on policy routing
# (e.g. Antrea Egress).
net.ipv4.conf.antrea-ext*.rp_filter = 2
net.ipv4.conf.antrea-gw0.rp_filter = 2
`

	sysctlDir           *string
	antreaOverwriteFile *string

	defaultFS = afero.NewOsFs()
)

func main() {
	command := newAntreaSysctlInitCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func newAntreaSysctlInitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "antrea-sysctl-init",
		Long: "Init Antrea-required sysctl config.",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			defer log.FlushLogs()

			run()
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}

	flags := cmd.Flags()
	sysctlDir = flags.String("sysctl-conf-dir", "/host/etc/sysctl.d/", "The path to sysctl config directory")
	antreaOverwriteFile = flags.String("sysctl-config-file", "99-zzzz-antrea.conf", "Filename of the Antrea sysctl overwrites config file")

	log.AddFlags(flags)
	return cmd
}

func run() {
	info, err := os.Stat(*sysctlDir)
	if err != nil {
		klog.InfoS("Failed to stat sysctl configuration directory", "sysctlDir", *sysctlDir, "err", err)
		return
	}

	if !info.IsDir() {
		klog.InfoS("Sysctl configuration path is not a directory", "sysctlDir", *sysctlDir)
		return
	}

	filePath := path.Join(*sysctlDir, *antreaOverwriteFile)
	if err = afero.WriteFile(defaultFS, filePath, []byte(sysctlConfig), 0644); err != nil {
		klog.InfoS("Failed to write Antrea sysctl configuration", "filePath", filePath, "err", err)
		return
	}

	klog.InfoS("Successfully wrote Antrea sysctl configuration", "filePath", filePath)
}
