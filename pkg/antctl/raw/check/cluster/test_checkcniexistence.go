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
	"sort"
	"strings"

	"antrea.io/antrea/pkg/antctl/raw/check"
)

type checkCNIExistence struct{}

func init() {
	RegisterTest("check-cni-existence", &checkCNIExistence{})
}

func (t *checkCNIExistence) Run(ctx context.Context, testContext *testContext) error {
	command := []string{"ls", "-1", "/etc/cni/net.d"}
	output, _, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, testContext.testPod.Name, "", command)
	if err != nil {
		return fmt.Errorf("failed to execute command in Pod %s, error: %w", testContext.testPod.Name, err)
	}
	files := strings.Fields(output)
	if len(files) == 0 {
		testContext.Log("No files present in /etc/cni/net.d in Node %s", testContext.testPod.Spec.NodeName)
		return nil
	}
	sort.Strings(files)
	if files[0] < "10-antrea.conflist" {
		return newUncertainError("another CNI configuration file with higher priority than Antrea's CNI configuration file found: %s; this may be expected if networkPolicyOnly mode is enabled", files[0])
	} else if files[0] != "10-antrea.conflist" {
		testContext.Log("Another CNI configuration file found: %s with Antrea having higher precedence", files[0])
	} else {
		testContext.Log("Antrea's CNI configuration file already present: %s", files[0])
	}
	return nil
}
