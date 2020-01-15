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
	"fmt"
	"testing"
)

const pingCount = 10

// runPingMesh runs a ping mesh between all the provided Pods after first retrieveing their IP
// addresses.
func (data *TestData) runPingMesh(t *testing.T, podNames []string) {
	t.Logf("Waiting for Pods to be ready and retrieving IPs")
	podIPs := make(map[string]string)
	for _, podName := range podNames {
		if podIP, err := data.podWaitForIP(defaultTimeout, podName); err != nil {
			t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
		} else {
			podIPs[podName] = podIP
		}
	}
	t.Logf("Retrieved all Pod IPs: %v", podIPs)

	t.Logf("Ping mesh test between all Pods")
	for _, podName1 := range podNames {
		for _, podName2 := range podNames {
			if podName1 == podName2 {
				continue
			}
			if err := data.runPingCommandFromTestPod(podName1, podIPs[podName2], pingCount); err != nil {
				t.Errorf("Ping '%s' -> '%s': ERROR (%v)", podName1, podName2, err)
			} else {
				t.Logf("Ping '%s' -> '%s': OK", podName1, podName2)
			}
		}
	}
}

// TestPodConnectivitySameNode checks that Pods running on the same Node can reach each other, by
// creating multiple Pods on the same Node and having them ping each other.
func TestPodConnectivitySameNode(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	numPods := 2 // can be increased
	podNames := make([]string, numPods)
	for idx := range podNames {
		podNames[idx] = randName(fmt.Sprintf("test-pod-%d-", idx))
	}
	workerNode := workerNodeName(1)

	t.Logf("Creating two busybox test Pods on '%s'", workerNode)
	for _, podName := range podNames {
		if err := data.createBusyboxPodOnNode(podName, workerNode); err != nil {
			t.Fatalf("Error when creating busybox test Pod: %v", err)
		}
		defer deletePodWrapper(t, data, podName)
	}

	data.runPingMesh(t, podNames)
}

// createPodsOnDifferentNodes creates numPods busybox test Pods and assign them to all the different
// Nodes in round-robin fashion, then returns the names of the created Pods as well as a function
// which will delete the Pods when called.
func createPodsOnDifferentNodes(t *testing.T, data *TestData, numPods int) (podNames []string, cleanup func()) {
	podNames = make([]string, 0, numPods)

	cleanup = func() {
		for _, podName := range podNames {
			deletePodWrapper(t, data, podName)
		}
	}

	for idx := 0; idx < numPods; idx++ {
		podName := randName(fmt.Sprintf("test-pod-%d-", idx))
		nodeName := nodeName(idx % clusterInfo.numNodes)
		t.Logf("Creating busybox test Pods '%s' on '%s'", podName, nodeName)
		if err := data.createBusyboxPodOnNode(podName, nodeName); err != nil {
			cleanup()
			t.Fatalf("Error when creating busybox test Pod: %v", err)
		}
		podNames = append(podNames, podName)
	}

	return podNames, cleanup
}

func (data *TestData) testPodConnectivityDifferentNodes(t *testing.T) {
	numPods := 2 // can be increased
	podNames, deletePods := createPodsOnDifferentNodes(t, data, numPods)
	defer deletePods()

	data.runPingMesh(t, podNames)
}

// TestPodConnectivityDifferentNodes checks that Pods running on different Nodes can reach each
// other, by creating multiple Pods across distinct Nodes and having them ping each other.
func TestPodConnectivityDifferentNodes(t *testing.T) {
	skipIfNumNodesLessThan(t, 2)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	data.testPodConnectivityDifferentNodes(t)
}

func (data *TestData) redeployAntrea(t *testing.T, enableIPSec bool) {
	var err error

	t.Logf("Deleting Antrea Agent DaemonSet")
	if err = data.deleteAntrea(defaultTimeout); err != nil {
		t.Fatalf("Error when deleting Antrea DaemonSet: %v", err)
	}

	t.Logf("Applying Antrea YAML")
	if enableIPSec {
		err = data.deployAntreaIPSec()
	} else {
		err = data.deployAntrea()
	}
	if err != nil {
		t.Fatalf("Error when applying Antrea YAML: %v", err)
	}

	t.Logf("Waiting for all Antrea DaemonSet Pods")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		t.Fatalf("Error when restarting Antrea: %v", err)
	}
	t.Logf("Checking CoreDNS deployment")
	if err := data.checkCoreDNSPods(defaultTimeout); err != nil {
		t.Fatalf("Error when checking CoreDNS deployment: %v", err)
	}
}

// TestPodConnectivityAfterAntreaRestart checks that restarting antrea-agent does not create
// connectivity issues between Pods.
func TestPodConnectivityAfterAntreaRestart(t *testing.T) {
	// See https://github.com/vmware-tanzu/antrea/issues/244
	skipIfProviderIs(t, "kind", "test may cause subsequent tests to fail in Kind clusters")
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	numPods := 2 // can be increased
	podNames, deletePods := createPodsOnDifferentNodes(t, data, numPods)
	defer deletePods()

	data.runPingMesh(t, podNames)

	data.redeployAntrea(t, false)

	data.runPingMesh(t, podNames)
}

// TestOVSRestart checks that when OVS restarts unexpectedly the Antrea agent takes care of
// replaying flows. More precisely this tests check that Pod connectivity is not broken after a
// restart.
func TestOVSRestart(t *testing.T) {
	skipIfProviderIs(t, "kind", "stopping OVS daemons create connectivity issues")
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	numPods := 2
	podNames := make([]string, numPods)
	for idx := range podNames {
		podNames[idx] = randName(fmt.Sprintf("test-pod-%d-", idx))
	}
	workerNode := workerNodeName(1)

	t.Logf("Creating two busybox test Pods on '%s'", workerNode)
	for _, podName := range podNames {
		if err := data.createBusyboxPodOnNode(podName, workerNode); err != nil {
			t.Fatalf("Error when creating busybox test Pod: %v", err)
		}
		defer deletePodWrapper(t, data, podName)
	}

	data.runPingMesh(t, podNames)

	var antreaPodName string
	if antreaPodName, err = data.getAntreaPodOnNode(workerNode); err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", workerNode, err)
	}
	t.Logf("The Antrea Pod for Node '%s' is '%s'", workerNode, antreaPodName)

	t.Logf("Restarting OVS daemons on Node '%s'", workerNode)
	// We cannot use "ovs-ctl restart" as it takes care of saving / restoring the flows, while
	// we are trying to test whether the Antrea agent takes care of replaying the flows after an
	// unscheduled restart.
	stopCmd := []string{"/usr/share/openvswitch/scripts/ovs-ctl", "stop"}
	if stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, stopCmd); err != nil {
		t.Fatalf("Error when stopping OVS with ovs-ctl: %v - stdout: %s - stderr: %s", err, stdout, stderr)
	}
	startCmd := []string{"/usr/share/openvswitch/scripts/ovs-ctl", "--system-id=random", "start", "--db-file=/var/run/openvswitch/conf.db"}
	if stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, startCmd); err != nil {
		t.Fatalf("Error when starting OVS with ovs-ctl: %v - stdout: %s - stderr: %s", err, stdout, stderr)
	}

	// This should give Antrea ~10s to restore flows, since we generate 10 "pings" with a 1s
	// interval.
	t.Logf("Running second ping mesh to check that flows have been restored")
	data.runPingMesh(t, podNames)
}
