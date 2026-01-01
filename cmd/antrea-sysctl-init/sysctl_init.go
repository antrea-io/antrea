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
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"k8s.io/klog/v2"
	"k8s.io/utils/exec"
)

var (
	defaultFs   = afero.NewOsFs()
	defaultExec = exec.New()

	// Name of the Antrea-specific sysctl configuration file created or overwritten by the init container. This file contains
	// sysctl settings that apply only to the interfaces managed by Antrea.
	// On some Linux distributions, sysctl configuration files may be automatically re-applied to all existing interfaces
	// when an interface is added or updated. In such environments, a relatively high filename prefix is used to ensure the
	// Antrea-specific sysctl configuration file is applied after most default distribution- or administrator-provided sysctl
	// configuration files.
	defaultSysctlFile = "/host/etc/sysctl.d/99-zzzz-antrea.conf"
)

func run(opts *options) error {
	sysctlConfig := buildAntreaSysctlConfig(opts.hostGatewayName)

	if err := afero.WriteFile(defaultFs, defaultSysctlFile, []byte(sysctlConfig), 0644); err != nil {
		return fmt.Errorf("failed to write Antrea sysctl configuration %q: %w", defaultSysctlFile, err)
	}

	// Apply the sysctl settings immediately. This may return an error if per-interface sysctl keys
	// (e.g. net.ipv4.conf.antrea-gw0.rp_filter) refer to interfaces that do not yet exist at the time of execution.
	cmd := defaultExec.Command("/usr/sbin/sysctl", "-p", defaultSysctlFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		klog.InfoS(
			"sysctl returned a non-fatal error while applying Antrea sysctl configuration",
			"filePath", defaultSysctlFile,
			"output", string(output),
			"error", err,
		)
	}

	klog.InfoS("Successfully wrote and applied Antrea sysctl configuration", "filePath", defaultSysctlFile)

	return nil
}

// buildAntreaSysctlConfig generates the Antrea-specific sysctl configuration file which is required by feature Antrea
// Egress separate-subnet or hybrid mode. For these cases, Antrea Egress replies on policy routing, which requires
// the reverse path filtering (rp_filter) to be set to loose mode (2) on network interfaces managed by Antrea.
func buildAntreaSysctlConfig(hostGateway string) string {
	lines := []string{
		"# Antrea-specific sysctl overrides. These settings are required for features that rely on policy routing",
		"# (e.g. Antrea Egress).",
		"",
		"net.ipv4.conf.antrea-ext*.rp_filter = 2",
		fmt.Sprintf("net.ipv4.conf.%s.rp_filter = 2", hostGateway),
	}

	return strings.Join(lines, "\n") + "\n"
}
