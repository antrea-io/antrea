// Copyright 2020 Antrea Authors
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
	"flag"
	"testing"
)

var (
	upgradeToYML = flag.String("upgrade.toYML", "", "Path to new Antrea manifest (on master Node)")
	pruneAll     = flag.Bool("upgrade.pruneAll", false, "Prune all Antrea resources when upgrading")
)

func skipIfNotUpgradeTest(t *testing.T) {
	if *upgradeToYML == "" {
		t.Skipf("Skipping test as we are not testing for upgrade")
	}
}

// TestUpgrade tests that some basic functionalities are not broken when
// upgrading from one version of Antrea to another. At the moment it checks
// that:
//  * connectivity (intra and inter Node) is not broken
//  * namespaces can be deleted
//  * Pod deletion leads to correct resource cleanup
// To run the test, provide the -upgrade.toYML flag.
func TestUpgrade(t *testing.T) {
	skipIfNotUpgradeTest(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodeName := nodeName(0)
	podName := randName("test-pod-")

	t.Logf("Creating a busybox test Pod on '%s'", nodeName)
	if err := data.createBusyboxPodOnNode(podName, nodeName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, podName, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", podName)
	}

	namespace := randName("test-namespace-")

	t.Logf("Creating namespace '%s'", namespace)
	if err := data.createNamespace(namespace); err != nil {
		t.Fatalf("Error when creating namespace '%s'", namespace)
	}
	defer data.deleteNamespace(namespace, defaultTimeout)

	data.testPodConnectivitySameNode(t)
	data.testPodConnectivityDifferentNodes(t)

	if t.Failed() {
		t.FailNow()
	}

	t.Logf("Upgrading YAML to %s", *upgradeToYML)
	var extraOptions string
	if *pruneAll {
		extraOptions = "--prune -l app=antrea --prune-whitelist=apiregistration.k8s.io/v1/APIService"
	}
	data.deployAntreaCommon(*upgradeToYML, extraOptions)
	t.Logf("Waiting for all Antrea DaemonSet Pods")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		t.Fatalf("Error when restarting Antrea: %v", err)
	}
	// Restart CoreDNS Pods to avoid issues caused by disrupting the datapath (when restarting
	// Antrea Agent Pods).
	t.Logf("Restarting CoreDNS Pods")
	if err := data.restartCoreDNSPods(defaultTimeout); err != nil {
		t.Fatalf("Error when restarting CoreDNS Pods: %v", err)
	}

	data.testPodConnectivitySameNode(t)
	data.testPodConnectivityDifferentNodes(t)

	t.Logf("Deleting namespace '%s'", namespace)
	if err := data.deleteNamespace(namespace, defaultTimeout); err != nil {
		t.Errorf("Namespace deletion failed: %v", err)
	}

	data.testDeletePod(t, podName, nodeName)
}
