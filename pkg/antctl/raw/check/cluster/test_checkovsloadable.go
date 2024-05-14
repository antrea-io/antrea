// Copyright 2024 Antrea Authors.
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

package cluster

import (
	"context"
	"fmt"
	"strings"

	"antrea.io/antrea/pkg/antctl/raw/check"
)

type checkOVSLoadable struct{}

func init() {
	RegisterTest("check-if-openvswitch-is-loadable", &checkOVSLoadable{})
}

func (c *checkOVSLoadable) Run(ctx context.Context, testContext *testContext) error {
	command := []string{
		"/bin/sh",
		"-c",
		"grep -q 'openvswitch.ko' /lib/modules/$(uname -r)/modules.builtin; echo $?",
	}
	stdout, stderr, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, testContext.testPod.Name, "", command)
	if err != nil {
		return fmt.Errorf("error executing command in Pod %s: %w", testContext.testPod.Name, err)
	}
	if strings.TrimSpace(stdout) == "0" {
		testContext.Log("The kernel module openvswitch is built-in")
	} else if strings.TrimSpace(stdout) == "1" {
		testContext.Log("The kernel module openvswitch is not built-in. Running modprobe command to load the module.")
		cmd := []string{"modprobe", "openvswitch"}
		_, stderr, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, testContext.testPod.Name, "", cmd)
		if err != nil {
			return fmt.Errorf("error executing modprobe command in Pod %s: %w", testContext.testPod.Name, err)
		} else if stderr != "" {
			return fmt.Errorf("failed to load the OVS kernel module: %s, try running 'modprobe openvswitch' on your Nodes", stderr)
		} else {
			testContext.Log("openvswitch kernel module loaded successfully")
		}
	} else {
		return fmt.Errorf("error encountered while checking if openvswitch module is built-in - stderr: %s", stderr)
	}
	return nil
}
