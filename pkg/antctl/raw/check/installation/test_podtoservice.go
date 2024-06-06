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
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

type PodToServiceConnectivityTest struct {
	service string
	preRun  func(ctx context.Context, testContext *testContext) error
}

func init() {
	RegisterTest("pod-to-service-intranode-connectivity", &PodToServiceConnectivityTest{
		service: echoSameNodeDeploymentName,
	})
	RegisterTest("pod-to-service-internode-connectivity", &PodToServiceConnectivityTest{
		service: echoOtherNodeDeploymentName,
		preRun: func(ctx context.Context, testContext *testContext) error {
			if testContext.echoOtherNodePod == nil {
				return newNotRunnableError("Inter-Node test requires multiple Nodes")
			}
			return nil
		},
	})
}

func (t *PodToServiceConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	if t.preRun != nil {
		if err := t.preRun(ctx, testContext); err != nil {
			return err
		}
	}
	for _, clientPod := range testContext.clientPods {
		testContext.Log("Validating from Pod %s to Service %s in Namespace %s...", clientPod.Name, t.service, testContext.namespace)
		// Service is realized asynchronously, retry a few times.
		if err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 2*time.Second, true, func(ctx context.Context) (bool, error) {
			if err := testContext.runAgnhostConnect(ctx, clientPod.Name, "", t.service, 80); err != nil {
				testContext.Log("Client Pod %s was not able to communicate with Service %s: %v, retrying...", clientPod.Name, t.service, err)
				return false, nil
			}
			return true, nil
		}); err != nil {
			return fmt.Errorf("client Pod %s was not able to communicate with Service %s: %w", clientPod.Name, t.service, err)
		}
		testContext.Log("Client Pod %s was able to communicate with Service %s", clientPod.Name, t.service)
	}
	return nil
}
