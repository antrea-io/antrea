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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/antctl/raw/check"
)

type checkOVSLoadable struct{}

func init() {
	RegisterTest("Check if the module openvswitch is loadable", &checkOVSLoadable{})
}

func (c *checkOVSLoadable) Run(ctx context.Context, testContext *testContext) error {
	pods, err := testContext.client.CoreV1().Pods(testContext.namespace).List(ctx, metav1.ListOptions{LabelSelector: "name=check-cluster"})
	if err != nil {
		return fmt.Errorf("failed to list Pods: %v", err)
	}
	command := []string{
		"/bin/sh",
		"-c",
		`path="/lib/modules/$(uname -r)/modules.builtin"; grep -q "openvswitch.ko" "$path"; echo $?`,
	}
	stdout, _, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, pods.Items[0].Name, "", command)
	if err != nil {
		return fmt.Errorf("error executing command in Pod %s: %v", pods.Items[0].Name, err)
	}
	if strings.TrimSpace(stdout) == "0" {
		testContext.Log("The kernel module openvswitch is built-in")
	} else if strings.TrimSpace(stdout) == "1" {
		testContext.Log("The kernel module openvswitch is not built-in. Running modprobe command to load the module.")
		cmd := []string{"modprobe", "openvswitch"}
		stdout, stderr, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, pods.Items[0].Name, "", cmd)
		if err != nil {
			return fmt.Errorf("error executing modprobe command in Pod %s: %v", pods.Items[0].Name, err)
		}
		if stderr != "" {
			testContext.Log("failed to load the OVS kernel module from the container, try running 'modprobe openvswitch' on your Nodes")
		}
		if stdout == "" {
			testContext.Log("openvswitch kernel module loaded successfully")
		}
	}
	return nil
}
