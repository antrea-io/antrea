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

type PodToPodIntraNodeConnectivityTest struct{}

func init() {
	RegisterTest("pod-to-pod-intranode-connectivity", &PodToPodIntraNodeConnectivityTest{})
}

func (t *PodToPodIntraNodeConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	for _, clientPod := range testContext.clientPods {
		srcPod := testContext.namespace + "/" + clientPod.Name
		dstPod := testContext.namespace + "/" + testContext.echoSameNodePod.Name
		for _, podIP := range testContext.echoSameNodePod.Status.PodIPs {
			echoIP := podIP.IP
			testContext.Log("Validating from Pod %s to Pod %s at IP %s...", srcPod, dstPod, echoIP)
			if err := testContext.tcpProbe(ctx, clientPod.Name, "", echoIP, 80); err != nil {
				return fmt.Errorf("client Pod %s was not able to communicate with echo Pod %s (%s): %w", clientPod.Name, testContext.echoSameNodePod.Name, echoIP, err)
			}
			testContext.Log("client Pod %s was able to communicate with echo Pod %s (%s)", clientPod.Name, testContext.echoSameNodePod.Name, echoIP)
		}
	}
	return nil
}
