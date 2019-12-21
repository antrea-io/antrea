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
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

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

	podName := randName("test-pod-")

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
	podName := randName("test-pod-")

	t.Logf("Creating a busybox test Pod on '%s'", nodeName)
	if err := data.createBusyboxPodOnNode(podName, nodeName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, podName); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", podName)
	}

	ifName := util.GenerateContainerInterfaceName(podName, testNamespace)
	t.Logf("Host interface name for Pod is '%s'", ifName)

	var antreaPodName string
	if antreaPodName, err = data.getAntreaPodOnNode(nodeName); err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName, err)
	}
	t.Logf("The Antrea Pod for Node '%s' is '%s'", nodeName, antreaPodName)

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
		exists, err := data.doesOVSPortExist(antreaPodName, ifName)
		if err != nil {
			t.Fatalf("Cannot determine if OVS port exists: %v", err)
		}
		return exists
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
	podName1 := randName("test-pod-")
	podName2 := randName("test-pod-")
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

// TestReconcileGatewayRoutesOnStartup checks that when the Antrea agent is restarted, the set of
// gateway routes is updated correctly, i.e. stale routes (for Nodes which are no longer in the
// cluster) are removed and missing routes are added.
func TestReconcileGatewayRoutesOnStartup(t *testing.T) {
	if clusterInfo.numNodes < 2 {
		t.Skipf("Skipping test as it requires 2 different nodes")
	}

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	type Route struct {
		peerPodCIDR *net.IPNet
		peerPodGW   net.IP
	}

	nodeName := nodeName(0)
	antreaPodName := func() string {
		antreaPodName, err := data.getAntreaPodOnNode(nodeName)
		if err != nil {
			t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName, err)
		}
		t.Logf("The Antrea Pod for Node '%s' is '%s'", nodeName, antreaPodName)
		return antreaPodName
	}

	getGatewayRoutes := func() (routes []Route, err error) {
		cmd := fmt.Sprintf("ip route list dev %s", antreaGWName)
		rc, stdout, _, err := RunCommandOnNode(nodeName, cmd)
		if err != nil {
			return nil, fmt.Errorf("error when running ip command on Node '%s': %v", nodeName, err)
		}
		if rc != 0 {
			return nil, fmt.Errorf("running ip command on Node '%s' returned error", nodeName)
		}
		re := regexp.MustCompile(`([^\s]+) via ([^\s]+)`)
		for _, line := range strings.Split(stdout, "\n") {
			var err error
			matches := re.FindStringSubmatch(line)
			if len(matches) == 0 {
				continue
			}
			route := Route{}
			if _, route.peerPodCIDR, err = net.ParseCIDR(matches[1]); err != nil {
				return nil, fmt.Errorf("%s is not a valid net CIDR", matches[1])
			}
			if route.peerPodGW = net.ParseIP(matches[2]); route.peerPodGW == nil {
				return nil, fmt.Errorf("%s is not a valid IP", matches[2])
			}
			routes = append(routes, route)
		}
		return routes, nil
	}

	t.Logf("Retrieving gateway routes on Node '%s'", nodeName)
	var routes []Route
	if err := wait.PollImmediate(1*time.Second, defaultTimeout, func() (found bool, err error) {
		routes, err = getGatewayRoutes()
		if err != nil {
			return false, err
		}
		if len(routes) < clusterInfo.numNodes-1 {
			// Not enough routes, keep trying
			return false, nil
		} else if len(routes) > clusterInfo.numNodes-1 {
			return false, fmt.Errorf("found too many gateway routes, expected %d but got %d", clusterInfo.numNodes-1, len(routes))
		}
		return true, nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Not enough gateway routes after %v", defaultTimeout)
	} else if err != nil {
		t.Fatalf("Error while waiting for gateway routes: %v", err)
	} else {
		t.Logf("Found all expected gateway routes")
	}

	routeToDelete := routes[0]
	// A dummy route
	routeToAdd := Route{}
	_, routeToAdd.peerPodCIDR, _ = net.ParseCIDR("99.99.99.0/24")
	routeToAdd.peerPodGW = net.ParseIP("99.99.99.1")

	// We run the ip command from the antrea-agent container for delete / add since they need to
	// be run as root and the antrea-agent container is privileged. If we used RunCommandOnNode,
	// we may need to use "sudo" for some providers (e.g. vagrant).
	deleteGatewayRoute := func(route Route) error {
		cmd := []string{"ip", "route", "del", route.peerPodCIDR.String()}
		_, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName(), agentContainerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running ip command on Node '%s': %v", nodeName, err)
		}
		return nil
	}

	addGatewayRoute := func(route Route) error {
		cmd := []string{"ip", "route", "add", route.peerPodCIDR.String(), "via", route.peerPodGW.String(), "dev", antreaGWName, "onlink"}
		_, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName(), agentContainerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running ip command on Node '%s': %v", nodeName, err)
		}
		return nil
	}

	t.Logf("Deleting one actual gateway route and adding a dummy one")
	if err := deleteGatewayRoute(routeToDelete); err != nil {
		t.Fatalf("Error when deleting route: %v", err)
	}
	if err := addGatewayRoute(routeToAdd); err != nil {
		t.Fatalf("Error when adding dummy route route: %v", err)
	}
	defer func() {
		// Cleanup the dummy route regardless of whether the test was a success or a
		// failure; ignore error (there will be an error if the test is a success since the
		// dummy route will no longer exist).
		_ = deleteGatewayRoute(routeToAdd)
	}()

	t.Logf("Restarting antrea-agent on Node '%s'", nodeName)
	if _, err := data.deleteAntreaAgentOnNode(nodeName, 30 /* grace period in seconds */, defaultTimeout); err != nil {
		t.Fatalf("Error when restarting antrea-agent on Node '%s': %v", nodeName, err)
	}

	t.Logf("Checking that all Antrea DaemonSet Pods are running")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		t.Fatalf("Error when waiting for Antrea Pods: %v", err)
	}

	// We expect the agent to delete the extra route we added and add back the route we deleted
	t.Logf("Waiting for gateway routes to converge")
	if err := wait.Poll(1*time.Second, defaultTimeout, func() (bool, error) {
		newRoutes, err := getGatewayRoutes()
		if err != nil {
			return false, err
		}
		if len(newRoutes) != len(routes) {
			return false, nil
		}
		for _, route := range newRoutes {
			if route.peerPodGW.Equal(routeToAdd.peerPodGW) {
				// The dummy route hasn't been deleted yet, keep trying
				return false, nil
			}
		}
		// At this stage we have confirmed that the dummy route has been deleted
		for _, route := range newRoutes {
			if route.peerPodGW.Equal(routeToDelete.peerPodGW) {
				// The deleted route was added back, success!
				return true, nil
			}
		}
		// We haven't found the deleted route, keep trying
		return false, nil
	}); err == wait.ErrWaitTimeout {
		t.Errorf("Gateway routes did not converge after %v", defaultTimeout)
	} else if err != nil {
		t.Fatalf("Error while waiting for gateway routes to converge: %v", err)
	} else {
		t.Logf("Gateway routes successfully converged")
	}
}
