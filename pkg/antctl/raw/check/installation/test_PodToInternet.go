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

type PodtoInternetConnectivityTest struct{}

func (t *PodtoInternetConnectivityTest) Run(ctx context.Context, testContext *TestContext) error {
	for _, clientPod := range testContext.client.clientPods.Items {
		var (
			srcPod = testContext.client.namespace + "/" + clientPod.Name
		)
		testContext.client.Header("Validating connectivity from pod %s to the world (google.com)...", srcPod)
		_, err := testContext.client.client.ExecInPod(ctx, testContext.client.namespace, clientPod.Name, clientDeploymentName, agnhostConnectCommand("google.com:80"))
		if err != nil {
			return fmt.Errorf("pod %s was not able to connect to google.com: %w", srcPod, err)
		}
		testContext.client.Log("Pod %s was able to connect to google.com", srcPod)
	}
	return nil
}
