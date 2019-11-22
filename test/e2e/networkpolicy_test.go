// Copyright 2019 Antrea Authors
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

package e2e

import (
	"testing"
)

func TestTrafficWithPodSelector(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	workerNode := workerNodeName(1)
	podName := randPodName("test-pod-networkpolicy-")
	if err := data.createBusyboxPodOnNode(podName, workerNode); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, podName)
	if _, err := data.podWaitForIP(defaultTimeout, podName); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
	}

	nginxPodName := randPodName("test-pod-nginx-")
	if err = data.createNginxPodOnNode(nginxPodName, workerNode); err != nil {
		t.Fatalf("Error when creating nginx pod: %v", err)
	}
	defer deletePodWrapper(t, data, nginxPodName)
	if _, err := data.podWaitForIP(defaultTimeout, nginxPodName); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", nginxPodName, err)
	}

	svcName := randSvcName("test-svc-nginx")
	if err = data.createNginxService(nginxPodName, svcName); err != nil {
		t.Fatalf("Error when creating nginx service: %v", err)
	}
	defer func() {
		if err = data.deleteNginxService(svcName); err != nil {
			t.Fatalf("delete nginx service error: %v", err)
		}
	}()

	// pod can wget to service
	if err = data.runWgetCommandFromTestPod(podName, svcName); err != nil {
		t.Fatalf("Run wget error: %v", err)
	}

	networkPolicyName := "assign-nginx"
	createdPolicy, err := data.createNetworkPolicyForMatchLabelsWithNginx(networkPolicyName)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	if _, err := data.networkPolicyWaitForExisting(defaultTimeout, networkPolicyName); err != nil {
		t.Fatalf("Error when waiting for network policy to take effect: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(createdPolicy); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	// pod cannot wget to service
	if err = data.runWgetCommandFromTestPod(podName, svcName); err == nil {
		t.Fatalf("Errow when running wget, it should fail: %v", err)
	}
}
