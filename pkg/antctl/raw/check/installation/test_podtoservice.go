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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type PodToServiceConnectivityTest struct {
	getService func(testContext *testContext) (*corev1.Service, error)
}

func init() {
	RegisterTest("pod-to-service-intranode-connectivity", &PodToServiceConnectivityTest{
		getService: func(testContext *testContext) (*corev1.Service, error) {
			return testContext.echoSameNodeService, nil
		},
	})
	RegisterTest("pod-to-service-internode-connectivity", &PodToServiceConnectivityTest{
		getService: func(testContext *testContext) (*corev1.Service, error) {
			if testContext.echoOtherNodeService == nil {
				return nil, newNotRunnableError("Inter-Node test requires multiple Nodes")
			}
			return testContext.echoOtherNodeService, nil
		},
	})
}

func (t *PodToServiceConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	service, err := t.getService(testContext)
	if err != nil {
		return err
	}
	for idx := range testContext.clientPods {
		clientPod := &testContext.clientPods[idx]
		testContext.Log("Validating from Pod %s to Service %s in Namespace %s...", clientPod.Name, service.Name, testContext.namespace)
		for _, clusterIP := range service.Spec.ClusterIPs {
			// Service is realized asynchronously, retry a few times.
			if err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 2*time.Second, true, func(ctx context.Context) (bool, error) {
				if err := testContext.tcpProbe(ctx, clientPod.Name, "", clusterIP, 80); err != nil {
					testContext.Log("Client Pod %s was not able to communicate with Service %s (%s): %v, retrying...", clientPod.Name, service.Name, clusterIP, err)
					return false, nil
				}
				testContext.Log("Client Pod %s was able to communicate with Service %s (%s)", clientPod.Name, service.Name, clusterIP)
				return true, nil
			}); err != nil {
				return fmt.Errorf("client Pod %s was not able to communicate with Service %s (%s): %w", clientPod.Name, service.Name, clusterIP, err)
			}
		}
	}
	return nil
}
