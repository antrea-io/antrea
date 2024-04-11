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

type PodToPodConnectivityTest struct{}

func (t *PodToPodConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	for _, clientPod := range testContext.clientPods.Items {
		for echoName, echoIP := range testContext.echoPods {
			var (
				srcPod = testContext.namespace + "/" + clientPod.Name
				dstPod = testContext.namespace + "/" + echoName
			)
			testContext.Log("Validating from pod %s to pod %s...", srcPod, dstPod)
			_, _, err := testContext.client.ExecInPod(ctx, testContext.namespace, clientPod.Name, "", agnhostConnectCommand(echoIP+":80"))
			if err != nil {
				return fmt.Errorf("client pod %s was not able to communicate with echo pod %s (%s): %w", clientPod.Name, echoName, echoIP, err)
			}
			testContext.Log("client pod %s was able to communicate with echo pod %s (%s)", clientPod.Name, echoName, echoIP)
		}
	}
	return nil
}
