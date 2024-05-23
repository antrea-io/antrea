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

type AllIngressDenyConnectivityTest struct{}

func init() {
	RegisterTest("all-ingress-deny-connectivity", &AllIngressDenyConnectivityTest{})
}

func (a AllIngressDenyConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	check.ApplyIngressAll(ctx, testContext.client, testContext.namespace)
	err := check.WaitForNetworkPolicyReady(ctx, testContext.client, testContext.namespace, "all-ingress-deny", testContext.clusterName)
	if err != nil {
		return err
	}
	services := []string{echoSameNodeDeploymentName, echoOtherNodeDeploymentName}
	for _, clientPod := range testContext.clientPods {
		for _, service := range services {
			if err := testContext.runAgnhostConnect(ctx, clientPod.Name, "", service, 80); err != nil {
				testContext.Log("Network policy is working as expected with Pod %s and Service %s", clientPod.Name, service)
			} else {
				return fmt.Errorf("Network policy is not working as expected with Pod %s and Service %s ", clientPod.Name, service)
			}
		}
	}
	check.WaitForNetworkPolicyTeardown(ctx, testContext.client, testContext.namespace, "all-ingress-deny", testContext.clusterName)
	return nil
}
