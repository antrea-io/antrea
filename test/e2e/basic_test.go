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
	"strings"
	"testing"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

// TestDeploy is a "no-op" test that simply performs setup and teardown.
func TestDeploy(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
}

// TestPodAssignIP verifies that Antrea allocates IP addresses properly to new Pods. It does this by
// deploying a busybox Pod, then waiting for the K8s apiserver to report the new IP address for that
// Pod, and finally verifying that the IP address is in the Pod Network CIDR for the cluster.
func TestPodAssignIP(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	podName := randPodName("test-pod-")

	t.Logf("Creating a busybox test Pod")
	if err := data.createBusyboxPod(podName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, podName)

	t.Logf("Checking Pod networking")
	if podIP, err := data.podWaitForIP(defaultTimeout, podName); err != nil {
		t.Errorf("Error when waiting for Pod IP: %v", err)
	} else {
		t.Logf("Pod IP is '%s'", podIP)
		isValid, err := validatePodIP(clusterInfo.podNetworkCIDR, podIP)
		if err != nil {
			t.Errorf("Error when trying to validate Pod IP: %v", err)
		} else if !isValid {
			t.Errorf("Pod IP is not in the expected Pod Network CIDR")
		} else {
			t.Logf("Pod IP is valid!")
		}
	}
}

// TestDeletePod creates a Pod, then deletes it, and checks that the veth interface (in the Node
// network namespace) and the OVS port for the container get removed.
func TestDeletePod(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodeName := nodeName(0)
	podName := randPodName("test-pod-")

	t.Logf("Creating a busybox test Pod on '%s'", nodeName)
	if err := data.createBusyboxPodOnNode(podName, nodeName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, podName); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", podName)
	}

	ifName := util.GenerateContainerInterfaceName(podName, testNamespace)
	t.Logf("Host interface name for Pod is '%s'", ifName)

	var AntreaPodName string
	if AntreaPodName, err = data.getAntreaPodOnNode(nodeName); err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName, err)
	}
	t.Logf("The Antrea Pod for Node '%s' is '%s'", nodeName, AntreaPodName)

	doesInterfaceExist := func() bool {
		cmd := fmt.Sprintf("ip link show %s", ifName)
		if rc, _, _, err := RunCommandOnNode(nodeName, cmd); err != nil {
			t.Fatalf("Error when running ip command on Node '%s': %v", nodeName, err)
		} else {
			return rc == 0
		}
		return false
	}

	doesOVSPortExist := func() bool {
		cmd := []string{"ovs-vsctl", "port-to-br", ifName}
		if _, stderr, err := data.runCommandFromPod(AntreaNamespace, AntreaPodName, OVSContainerName, cmd); err == nil {
			return true
		} else if strings.Contains(stderr, "no port named") {
			return false
		} else {
			t.Fatalf("Error when running ovs-vsctl command on Pod '%s': %v", AntreaPodName, err)
		}
		return true
	}

	t.Logf("Checking that the veth interface and the OVS port exist")
	if !doesInterfaceExist() {
		t.Errorf("Interface '%s' does not exist on Node '%s'", ifName, nodeName)
	}
	if !doesOVSPortExist() {
		t.Errorf("OVS port '%s' does not exist on Node '%s'", ifName, nodeName)
	}

	t.Logf("Deleting Pod '%s'", podName)
	if err := data.deletePodAndWait(defaultTimeout, podName); err != nil {
		t.Fatalf("Error when deleting Pod: %v", err)
	}

	t.Logf("Checking that the veth interface and the OVS port no longer exist")
	if doesInterfaceExist() {
		t.Errorf("Interface '%s' still exists on Node '%s' after Pod deletion", ifName, nodeName)
	}
	if doesOVSPortExist() {
		t.Errorf("OVS port '%s' still exists on Node '%s' after Pod deletion", ifName, nodeName)
	}
}

// TestAntreaGracefulExit verifies that Antrea Pods can terminate gracefully.
func TestAntreaGracefulExit(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var gracePeriodSeconds int64 = 60
	t.Logf("Deleting one Antrea Pod")
	if timeToDelete, err := data.deleteAntreaAgentOnNode(nodeName(0), gracePeriodSeconds, defaultTimeout); err != nil {
		t.Fatalf("Error when deleting Antrea Pod: %v", err)
	} else if timeToDelete > 20*time.Second {
		t.Errorf("Antrea Pod took too long to delete: %v", timeToDelete)
	}
	// At the moment we only check that the Pod terminates in a reasonable amout of time (less
	// than the grace period), which means that all containers "honor" the SIGTERM signal.
	// TODO: ideally we would be able to also check the exit code but it may not be possible.
}

// TestIPAMRestart checks that when the Antrea agent is restarted the information about which IP
// address is already allocated is not lost. It does that by creating a first Pod and retrieving
// its IP address, restarting the Antrea agent, then creating a second Pod and retrieving its IP
// address. If the 2 IP addresses match, then it is an error. This is not a perfect test, as it
// assumes that IP addresses are assigned in-order and not randomly.
func TestIPAMRestart(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodeName := nodeName(0)
	podName1 := randPodName("test-pod-")
	podName2 := randPodName("test-pod-")
	pods := make([]string, 0, 2)
	var podIP1, podIP2 string

	defer func() {
		for _, pod := range pods {
			deletePodWrapper(t, data, pod)
		}
	}()

	createPodAndGetIP := func(podName string) (string, error) {
		t.Logf("Creating a busybox test Pod '%s' and waiting for IP", podName)
		if err := data.createBusyboxPodOnNode(podName, nodeName); err != nil {
			t.Fatalf("Error when creating busybox test Pod '%s': %v", podName, err)
			return "", err
		}
		pods = append(pods, podName)
		if podIP, err := data.podWaitForIP(defaultTimeout, podName); err != nil {
			return "", err
		} else {
			return podIP, nil
		}
	}

	if podIP1, err = createPodAndGetIP(podName1); err != nil {
		t.Fatalf("Failed to retrieve IP for Pod '%s': %v", podName1, err)
	}
	t.Logf("Pod '%s' has IP address %s", podName1, podIP1)

	t.Logf("Restarting antrea-agent on Node '%s'", nodeName)
	if _, err := data.deleteAntreaAgentOnNode(nodeName, 30 /* grace period in seconds */, defaultTimeout); err != nil {
		t.Fatalf("Error when restarting antrea-agent on Node '%s': %v", nodeName, err)
	}

	t.Logf("Checking that all Antrea DaemonSet Pods are running")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		t.Fatalf("Error when waiting for Antrea Pods: %v", err)
	}

	if podIP2, err = createPodAndGetIP(podName2); err != nil {
		t.Fatalf("Failed to retrieve IP for Pod '%s': %v", podName2, err)
	}
	t.Logf("Pod '%s' has IP address %s", podName2, podIP2)

	if podIP1 == podIP2 {
		t.Errorf("Pods '%s' and '%s' were assigned the same IP %s", podName1, podName2, podIP1)
	}
}
