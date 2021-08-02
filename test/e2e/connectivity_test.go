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
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/config"
)

const pingCount = 5

// TestConnectivity is the top-level test which contains all subtests for
// Connectivity related test cases so they can share setup, teardown.
func TestConnectivity(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testPodConnectivityOnSameNode", func(t *testing.T) {
		testPodConnectivityOnSameNode(t, data)
	})
	t.Run("testHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testHostPortPodConnectivity(t, data)
	})
	t.Run("testPodConnectivityDifferentNodes", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testPodConnectivityDifferentNodes(t, data)
	})
	t.Run("testPodConnectivityAfterAntreaRestart", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testPodConnectivityAfterAntreaRestart(t, data)
	})
	t.Run("testOVSRestartSameNode", func(t *testing.T) {
		skipIfProviderIs(t, "kind", "test not valid for the netdev datapath type")
		skipIfNotIPv4Cluster(t)
		skipIfHasWindowsNodes(t)
		testOVSRestartSameNode(t, data)
	})
	t.Run("testOVSFlowReplay", func(t *testing.T) {
		skipIfProviderIs(t, "kind", "stopping OVS daemons create connectivity issues")
		skipIfHasWindowsNodes(t)
		testOVSFlowReplay(t, data)
	})
	t.Run("testPingLargeMTU", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testPingLargeMTU(t, data)
	})
}

func waitForPodIPs(t *testing.T, data *TestData, podInfos []podInfo) map[string]*PodIPs {
	t.Logf("Waiting for Pods to be ready and retrieving IPs")
	podIPs := make(map[string]*PodIPs)
	for _, pi := range podInfos {
		podName := pi.name
		if podIP, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace); err != nil {
			t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
		} else {
			podIPs[podName] = podIP
		}
	}
	t.Logf("Retrieved all Pod IPs: %v", podIPs)
	return podIPs
}

// runPingMesh runs a ping mesh between all the provided Pods after first retrieving their IP
// addresses.
func (data *TestData) runPingMesh(t *testing.T, podInfos []podInfo, ctrname string) {
	podIPs := waitForPodIPs(t, data, podInfos)

	t.Logf("Ping mesh test between all Pods")
	for _, pi1 := range podInfos {
		for _, pi2 := range podInfos {
			if pi1.name == pi2.name {
				continue
			}
			if err := data.runPingCommandFromTestPod(pi1, testNamespace, podIPs[pi2.name], ctrname, pingCount, 0); err != nil {
				t.Errorf("Ping '%s' -> '%s': ERROR (%v)", pi1.name, pi2.name, err)
			} else {
				t.Logf("Ping '%s' -> '%s': OK", pi1.name, pi2.name)
			}
		}
	}
}

func (data *TestData) testPodConnectivitySameNode(t *testing.T) {
	numPods := 2 // can be increased
	podInfos := make([]podInfo, numPods)
	for idx := range podInfos {
		podInfos[idx].name = randName(fmt.Sprintf("test-pod-%d-", idx))
	}
	// If there are Windows Nodes, set workerNode to one of them.
	workerNode := workerNodeName(1)
	if len(clusterInfo.windowsNodes) != 0 {
		workerNode = workerNodeName(clusterInfo.windowsNodes[0])
	}

	t.Logf("Creating %d agnhost Pods on '%s'", numPods, workerNode)
	for i := range podInfos {
		podInfos[i].os = clusterInfo.nodesOS[workerNode]
		if err := data.createAgnhostPodOnNode(podInfos[i].name, testNamespace, workerNode); err != nil {
			t.Fatalf("Error when creating agnhost test Pod '%s': %v", podInfos[i], err)
		}
		defer deletePodWrapper(t, data, podInfos[i].name)
	}

	data.runPingMesh(t, podInfos, agnhostContainerName)
}

// testPodConnectivityOnSameNode checks that Pods running on the same Node can reach each other, by
// creating multiple Pods on the same Node and having them ping each other.
func testPodConnectivityOnSameNode(t *testing.T, data *TestData) {
	data.testPodConnectivitySameNode(t)
}

func (data *TestData) testHostPortPodConnectivity(t *testing.T) {
	// Create a server Pod with hostPort set to 80.
	hpPodName := randName("test-host-port-pod-")
	hpPodPort := int32(80)
	if err := data.createServerPod(hpPodName, testNamespace, "", hpPodPort, true, false); err != nil {
		t.Fatalf("Error when creating HostPort server Pod: %v", err)
	}
	defer deletePodWrapper(t, data, hpPodName)
	// Retrieve the IP Address of the Node on which the Pod is scheduled.
	hpPod, err := data.podWaitFor(defaultTimeout, hpPodName, testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		t.Fatalf("Error when waiting for Pod '%s': %v", hpPodName, err)
	}
	hpPodHostIP := hpPod.Status.HostIP
	// Create client Pod to test connectivity.
	clientName := randName("test-client-")
	if err := data.createBusyboxPodOnNode(clientName, testNamespace, ""); err != nil {
		t.Fatalf("Error when creating test client Pod: %v", err)
	}
	defer deletePodWrapper(t, data, clientName)
	if _, err := data.podWaitForIPs(defaultTimeout, clientName, testNamespace); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", clientName, err)
	}

	if err = data.runNetcatCommandFromTestPod(clientName, testNamespace, hpPodHostIP, hpPodPort); err != nil {
		t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(hpPodHostIP, fmt.Sprint(hpPodPort)))
	}
}

// testHostPortPodConnectivity checks that a Pod with hostPort set is reachable.
func testHostPortPodConnectivity(t *testing.T, data *TestData) {
	data.testHostPortPodConnectivity(t)
}

// createPodsOnDifferentNodes creates agnhost Pods through a DaemonSet. This function returns information of the created
// Pods as well as a function which will delete the Pods when called. Since Pods can be on Nodes of different OSes, podInfo
// slice instead of PodName slice is used to inform caller of correct commands and options. Linux and Windows Pods are
// alternating in this podInfo slice so that the test can cover different connectivity cases between different OSes.
func createPodsOnDifferentNodes(t *testing.T, data *TestData, tag string) (podInfos []podInfo, cleanup func() error) {
	dsName := "connectivity-test" + tag
	_, cleanup, err := data.createDaemonSet(dsName, testNamespace, agnhostContainerName, agnhostImage, []string{"sleep", "3600"}, nil)
	if err != nil {
		t.Fatalf("Error when creating DaemonSet '%s': %v", dsName, err)
	}
	if err := data.waitForDaemonSetPods(defaultTimeout, dsName, testNamespace); err != nil {
		t.Fatalf("Error when waiting for DaemonSet Pods to get IPs: %v", err)
	}

	piMap := map[string][]podInfo{"linux": {}, "windows": {}}
	pods, err := data.clientset.CoreV1().Pods(testNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "antrea-e2e=" + dsName,
	})
	if err != nil {
		t.Fatalf("Error when getting connectivity test Pods: %v", err)
	}

	for _, p := range pods.Items {
		os := clusterInfo.nodesOS[p.Spec.NodeName]
		piMap[os] = append(piMap[os], podInfo{p.Name, os})
	}
	var linIdx, winIdx int
	for linIdx != len(piMap["linux"]) && winIdx != len(piMap["windows"]) {
		podInfos = append(podInfos, piMap["linux"][linIdx])
		podInfos = append(podInfos, piMap["windows"][winIdx])
		linIdx++
		winIdx++
	}
	for ; linIdx != len(piMap["linux"]); linIdx++ {
		podInfos = append(podInfos, piMap["linux"][linIdx])
	}
	for ; winIdx != len(piMap["windows"]); winIdx++ {
		podInfos = append(podInfos, piMap["windows"][winIdx])
	}

	return podInfos, cleanup
}

func (data *TestData) testPodConnectivityDifferentNodes(t *testing.T) {
	numPods, maxPods := 2, 3
	encapMode, err := data.GetEncapMode()
	if err != nil {
		t.Errorf("Failed to retrieve encap mode: %v", err)
	}
	if encapMode == config.TrafficEncapModeHybrid {
		// To adequately test hybrid traffic across and within
		// subnet, all Nodes should have a Pod.
		numPods = maxPods
	}
	podInfos, deletePods := createPodsOnDifferentNodes(t, data, "differentnodes")
	defer deletePods()

	if len(podInfos) > maxPods {
		podInfos = podInfos[:maxPods]
	}
	data.runPingMesh(t, podInfos[:numPods], agnhostContainerName)
}

// testPodConnectivityDifferentNodes checks that Pods running on different Nodes can reach each
// other, by creating multiple Pods across distinct Nodes and having them ping each other.
func testPodConnectivityDifferentNodes(t *testing.T, data *TestData) {
	data.testPodConnectivityDifferentNodes(t)
}

func (data *TestData) redeployAntrea(t *testing.T, enableIPSec bool) {
	var err error
	// export logs before deleting Antrea
	if enableIPSec {
		exportLogs(t, data, "beforeRedeployWithIPsec", false)
	} else {
		exportLogs(t, data, "beforeRedploy", false)
	}
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

	// After redeploying Antrea with / without IPsec, we wait for watchForRestartsDuration and
	// count the number of container restarts. watchForRestartsDuration should be large enough
	// to detect issues, e.g. if there is an issue with the antrea-ipsec container.
	const watchForRestartsDuration = 20 * time.Second
	timer := time.NewTimer(watchForRestartsDuration)
	defer timer.Stop()

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

	<-timer.C
	containerRestarts, err := data.getAgentContainersRestartCount()
	if err != nil {
		t.Fatalf("Cannot retrieve number of container restarts across Agent Pods: %v", err)
	}
	if containerRestarts > 0 {
		t.Errorf("Unexpected container restarts (%d) after deploying new YAML", containerRestarts)
	}
}

// testPodConnectivityAfterAntreaRestart checks that restarting antrea-agent does not create
// connectivity issues between Pods.
func testPodConnectivityAfterAntreaRestart(t *testing.T, data *TestData) {
	numPods := 2 // can be increased
	podInfos, deletePods := createPodsOnDifferentNodes(t, data, "antrearestart")
	defer deletePods()

	data.runPingMesh(t, podInfos[:numPods], agnhostContainerName)

	data.redeployAntrea(t, false)

	data.runPingMesh(t, podInfos[:numPods], agnhostContainerName)
}

// testOVSRestartSameNode verifies that datapath flows are not removed when the Antrea Agent Pod is
// stopped gracefully (e.g. as part of a RollingUpdate). The test sends ARP requests every 1s and
// checks that there is no packet loss during the restart. This test does not apply to the userspace
// ndetdev datapath, since in this case the datapath functionality is implemented by the
// ovs-vswitchd daemon itself. When ovs-vswitchd restarts, datapath flows are flushed and it may
// take some time for the Agent to replay the flows. This will not impact this test, since we are
// just testing L2 connectivity betwwen 2 Pods on the same Node, and the default behavior of the
// br-int bridge is to implement normal L2 forwarding.
func testOVSRestartSameNode(t *testing.T, data *TestData) {
	workerNode := workerNodeName(1)
	t.Logf("Creating two busybox test Pods on '%s'", workerNode)
	podNames, podIPs, cleanupFn := createTestBusyboxPods(t, data, 2, testNamespace, workerNode)
	defer cleanupFn()

	resCh := make(chan error, 1)

	runArping := func() error {
		// we send arp pings for 25 seconds; this duration is a bit arbitrary and we assume
		// that restarting Antrea takes less than that time. Unfortunately, the arping
		// utility in busybox does not let us choose a smaller interval than 1 second.
		count := 25
		cmd := fmt.Sprintf("arping -c %d %s", count, podIPs[1].ipv4.String())
		stdout, stderr, err := data.runCommandFromPod(testNamespace, podNames[0], busyboxContainerName, strings.Fields(cmd))
		if err != nil {
			return fmt.Errorf("error when running arping command: %v - stdout: %s - stderr: %s", err, stdout, stderr)
		}
		// if the datapath flows have been flushed, there will be some unanswered ARP
		// requests.
		_, _, lossRate, err := parseArpingStdout(stdout)
		if err != nil {
			return err
		}
		t.Logf("Arping loss rate: %f%%", lossRate)
		if lossRate > 0 {
			t.Logf(stdout)
			return fmt.Errorf("arping loss rate is %f%%", lossRate)
		}
		return nil
	}
	go func() {
		resCh <- runArping()
	}()
	// make sure that by the time we delete the Antrea agent, at least one unicast ARP has been
	// sent (and cached in the OVS kernel datapath).
	time.Sleep(3 * time.Second)

	t.Logf("Restarting antrea-agent on Node '%s'", workerNode)
	if _, err := data.deleteAntreaAgentOnNode(workerNode, 30 /* grace period in seconds */, defaultTimeout); err != nil {
		t.Fatalf("Error when restarting antrea-agent on Node '%s': %v", workerNode, err)
	}

	if err := <-resCh; err != nil {
		t.Errorf("Arping test failed: %v", err)
	}
}

// testOVSFlowReplay checks that when OVS restarts unexpectedly the Antrea agent takes care of
// replaying flows. More precisely this test checks that we have the same number of flows and groups
// after deleting them and force-restarting the OVS daemons. We also make sure that Pod connectivity
// still works.
func testOVSFlowReplay(t *testing.T, data *TestData) {
	numPods := 2
	podInfos := make([]podInfo, numPods)
	for i := range podInfos {
		podInfos[i].name = randName(fmt.Sprintf("test-pod-%d-", i))
	}
	workerNode := workerNodeName(1)

	t.Logf("Creating %d busybox test Pods on '%s'", numPods, workerNode)
	for i := range podInfos {
		podInfos[i].os = clusterInfo.nodesOS[workerNode]
		if err := data.createBusyboxPodOnNode(podInfos[i].name, testNamespace, workerNode); err != nil {
			t.Fatalf("Error when creating busybox test Pod '%s': %v", podInfos[i].name, err)
		}
		defer deletePodWrapper(t, data, podInfos[i].name)
	}

	data.runPingMesh(t, podInfos, busyboxContainerName)

	var antreaPodName string
	var err error
	if antreaPodName, err = data.getAntreaPodOnNode(workerNode); err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", workerNode, err)
	}
	t.Logf("The Antrea Pod for Node '%s' is '%s'", workerNode, antreaPodName)

	countFlows := func() int {
		cmd := []string{"ovs-ofctl", "dump-flows", defaultBridgeName}
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		if err != nil {
			t.Fatalf("error when dumping flows: <%v>, err: <%v>", stderr, err)
		}
		count := strings.Count(stdout, "\n")
		t.Logf("Counted %d flow in OVS bridge '%s' for Node '%s'", count, defaultBridgeName, workerNode)
		return count
	}
	countGroups := func() int {
		cmd := []string{"ovs-ofctl", "dump-groups", defaultBridgeName}
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		if err != nil {
			t.Fatalf("error when dumping groups: <%v>, err: <%v>", stderr, err)
		}
		count := strings.Count(stdout, "\n")
		t.Logf("Counted %d group in OVS bridge '%s' for Node '%s'", count, defaultBridgeName, workerNode)
		return count
	}

	numFlows1, numGroups1 := countFlows(), countGroups()

	// This is necessary because "ovs-ctl restart" saves and restores OpenFlow flows for the
	// bridge. An alternative may be to kill the antrea-ovs container running on that Node.
	t.Logf("Deleting flows / groups and restarting OVS daemons on Node '%s'", workerNode)
	delFlowsAndGroups := func() {
		cmd := []string{"ovs-ofctl", "del-flows", defaultBridgeName}
		_, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		if err != nil {
			t.Fatalf("error when deleting flows: <%v>, err: <%v>", stderr, err)
		}
		cmd = []string{"ovs-ofctl", "del-groups", defaultBridgeName}
		_, stderr, err = data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		if err != nil {
			t.Fatalf("error when deleting groups: <%v>, err: <%v>", stderr, err)
		}
	}
	delFlowsAndGroups()
	restartCmd := []string{"/usr/share/openvswitch/scripts/ovs-ctl", "--system-id=random", "restart", "--db-file=/var/run/openvswitch/conf.db"}
	if stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, restartCmd); err != nil {
		t.Fatalf("Error when restarting OVS with ovs-ctl: %v - stdout: %s - stderr: %s", err, stdout, stderr)
	}

	// This should give Antrea ~10s to restore flows, since we generate 10 "pings" with a 1s
	// interval.
	t.Logf("Running second ping mesh to check that flows have been restored")
	data.runPingMesh(t, podInfos, busyboxContainerName)

	numFlows2, numGroups2 := countFlows(), countGroups()
	assert.Equal(t, numFlows1, numFlows2, "Mismatch in OVS flow count after flow replay")
	assert.Equal(t, numGroups1, numGroups2, "Mismatch in OVS group count after flow replay")
}

// testPingLargeMTU verifies that fragmented ICMP packets are handled correctly. Until OVS 2.12.0,
// the conntrack implementation of the OVS userspace datapath did not support v4/v6 fragmentation
// and this test was failing when Antrea was running on a Kind cluster.
func testPingLargeMTU(t *testing.T, data *TestData) {
	skipIfNumNodesLessThan(t, 2)

	podInfos, deletePods := createPodsOnDifferentNodes(t, data, "largemtu")
	defer deletePods()
	podIPs := waitForPodIPs(t, data, podInfos)

	pingSize := 2000
	t.Logf("Running ping with size %d between Pods %s and %s", pingSize, podInfos[0].name, podInfos[1].name)
	if err := data.runPingCommandFromTestPod(podInfos[0], testNamespace, podIPs[podInfos[1].name], agnhostContainerName, pingCount, pingSize); err != nil {
		t.Error(err)
	}
}
