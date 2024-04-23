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

type PodToInternetConnectivityTest struct{}

func init() {
	RegisterTest("pod-to-internet-connectivity", &PodToInternetConnectivityTest{})
}

func (t *PodToInternetConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	for _, clientPod := range testContext.clientPods.Items {
		srcPod := testContext.namespace + "/" + clientPod.Name
		testContext.Log("Validating connectivity from pod %s to the world (google.com)...", srcPod)
		_, _, err := check.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, clientPod.Name, clientDeploymentName, agnhostConnectCommand("google.com:80"))
		if err != nil {
			return fmt.Errorf("pod %s was not able to connect to google.com: %w", srcPod, err)
		}
		testContext.Log("Pod %s was able to connect to google.com", srcPod)
	}
	return nil
}
