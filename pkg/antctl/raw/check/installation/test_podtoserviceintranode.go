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

	"antrea.io/antrea/pkg/antctl/raw/check"
)

type PodToServiceIntraNodeConnectivityTest struct{}

func init() {
	RegisterTest("pod-to-service-intranode-connectivity", &PodToServiceIntraNodeConnectivityTest{})
}

func (t *PodToServiceIntraNodeConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	service := echoSameNodeDeploymentName
	for _, clientPod := range testContext.clientPods {
		testContext.Log("Validating from Pod %s to Service %s in Namespace %s...", clientPod.Name, service, testContext.namespace)
		_, _, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, clientPod.Name, "", agnhostConnectCommand(service, "80"))
		if err != nil {
			return fmt.Errorf("client Pod %s was not able to communicate with Service %s", clientPod.Name, service)
		}
		testContext.Log("client Pod %s was able to communicate with Service %s", clientPod.Name, service)
	}
	return nil
}
