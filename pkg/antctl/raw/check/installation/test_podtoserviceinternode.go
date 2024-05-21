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

package installation

import (
	"context"
	"fmt"
)

type PodToServiceInterNodeConnectivityTest struct{}

func init() {
	RegisterTest("pod-to-service-internode-connectivity", &PodToServiceInterNodeConnectivityTest{})
}

func (t *PodToServiceInterNodeConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	if testContext.echoOtherNodePod == nil {
		return newNotRunnableError("Inter-Node test requires multiple Nodes")
	}
	service := echoOtherNodeDeploymentName
	for _, clientPod := range testContext.clientPods {
		testContext.Log("Validating from Pod %s to Service %s in Namespace %s...", clientPod.Name, service, testContext.namespace)
		if err := testContext.runAgnhostConnect(ctx, clientPod.Name, "", service, 80); err != nil {
			return fmt.Errorf("client Pod %s was not able to communicate with Service %s: %w", clientPod.Name, service, err)
		}
		testContext.Log("client Pod %s was able to communicate with Service %s", clientPod.Name, service)
	}
	return nil
}
