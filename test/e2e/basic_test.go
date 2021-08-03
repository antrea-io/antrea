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
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/podinterface"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/clusteridentity"
)

// TestBasic is the top-level test which contains some subtests for
// basic test cases so they can share setup, teardown.
func TestBasic(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testPodAssignIP", func(t *testing.T) { testPodAssignIP(t, data) })
	t.Run("testDeletePod", func(t *testing.T) { testDeletePod(t, data) })
	t.Run("testAntreaGracefulExit", func(t *testing.T) { testAntreaGracefulExit(t, data) })
	t.Run("testIPAMRestart", func(t *testing.T) { testIPAMRestart(t, data) })
	t.Run("testDeletePreviousRoundFlowsOnStartup", func(t *testing.T) { testDeletePreviousRoundFlowsOnStartup(t, data) })
	t.Run("testGratuitousARP", func(t *testing.T) { testGratuitousARP(t, data) })
	t.Run("testClusterIdentity", func(t *testing.T) { testClusterIdentity(t, data) })
}

// testPodAssignIP verifies that Antrea allocates IP addresses properly to new Pods. It does this by
// deploying a busybox Pod, then waiting for the K8s apiserver to report the new IP address for that
// Pod, and finally verifying that the IP address is in the Pod Network CIDR for the cluster.
func testPodAssignIP(t *testing.T, data *TestData) {
	podName := randName("test-pod-")

	t.Logf("Creating a busybox test Pod")
	if err := data.createBusyboxPodOnNode(podName, testNamespace, ""); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, podName)

	t.Logf("Checking Pod networking")
	if podIPs, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace); err != nil {
		t.Errorf("Error when waiting for Pod IP: %v", err)
	} else {
		if clusterInfo.podV4NetworkCIDR != "" {
			checkPodIP(t, clusterInfo.podV4NetworkCIDR, podIPs.ipv4)
		}
		if clusterInfo.podV6NetworkCIDR != "" {
			checkPodIP(t, clusterInfo.podV6NetworkCIDR, podIPs.ipv6)
		}
	}
}

// checkPodIP verifies that the given IP is a valid address, and checks it is in the provided Pod Network CIDR.
func checkPodIP(t *testing.T, podNetworkCIDR string, podIP *net.IP) {
	t.Logf("Pod IP is '%s'", podIP.String())
	isValid, err := validatePodIP(podNetworkCIDR, *podIP)

	if err != nil {
		t.Errorf("Error when trying to validate Pod IP: %v", err)
	} else if !isValid {
		t.Errorf("Pod IP is not in the expected Pod Network CIDR")
	} else {
		t.Logf("Pod IP is valid!")
	}
}

func (data *TestData) testDeletePod(t *testing.T, podName string, nodeName string, isWindowsNode bool) {
	var antreaPodName string
	var err error
	if antreaPodName, err = data.getAntreaPodOnNode(nodeName); err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName, err)
	}
	t.Logf("The Antrea Pod for Node '%s' is '%s'", nodeName, antreaPodName)

	var stdout string
	if isWindowsNode {
		antctlCmd := fmt.Sprintf("C:/k/antrea/bin/antctl.exe get podinterface %s -n %s -o json", podName, testNamespace)
		envCmd := fmt.Sprintf("export POD_NAME=antrea-agent;export KUBERNETES_SERVICE_HOST=%s;export KUBERNETES_SERVICE_PORT=%d", clusterInfo.k8sServiceHost, clusterInfo.k8sServicePort)
		cmd := fmt.Sprintf("%s && %s", envCmd, antctlCmd)
		_, stdout, _, err = RunCommandOnNode(nodeName, cmd)
	} else {
		cmds := []string{"antctl", "get", "podinterface", podName, "-n", testNamespace, "-o", "json"}
		stdout, _, err = runAntctl(antreaPodName, cmds, data)
	}
	if err != nil {
		t.Fatalf("Error when running antctl: %v", err)
	}

	var podInterfaces []podinterface.Response
	if err := json.Unmarshal([]byte(stdout), &podInterfaces); err != nil {
		t.Fatalf("Error when querying the pod interface: %v", err)
	}
	if len(podInterfaces) != 1 {
		t.Fatalf("Expected 1 pod interface, got %d", len(podInterfaces))
	}
	ifName := podInterfaces[0].InterfaceName
	podIPs := podInterfaces[0].IPs
	t.Logf("Host interface name for Pod is '%s'", ifName)

	var doesInterfaceExist, doesOVSPortExist func() bool
	var doesIPAllocationExist func(podIP string) bool
	if isWindowsNode {
		doesInterfaceExist = func() bool {
			cmd := fmt.Sprintf("powershell 'Get-HnsEndpoint | Where-Object Name -EQ %s | Select-Object ID | Format-Table -HideTableHeaders'", ifName)
			_, stdout, _, err := RunCommandOnNode(nodeName, cmd)
			if err != nil {
				t.Fatalf("Error when querying HNSEndpoint with name %s: %s", ifName, err.Error())
			}
			return strings.TrimSpace(stdout) != ""
		}
		doesOVSPortExist = func() bool {
			exists, err := data.doesOVSPortExistOnWindows(nodeName, ifName)
			if err != nil {
				t.Fatalf("Cannot determine if OVS port exists: %v", err)
			}
			return exists
		}
		doesIPAllocationExist = func(podIP string) bool {
			cmd := fmt.Sprintf("powershell 'Test-Path /var/lib/cni/networks/antrea/%s'", podIP)
			_, stdout, _, err := RunCommandOnNode(nodeName, cmd)
			if err != nil {
				t.Fatalf("Error when querying IPAM result: %s", err.Error())
			}
			return strings.EqualFold(strings.TrimRight(stdout, "\r\n"), "true")
		}
	} else {
		doesInterfaceExist = func() bool {
			cmd := []string{"ip", "link", "show", ifName}
			stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
			if err != nil {
				if strings.Contains(stderr, "does not exist") {
					return false
				}
				t.Fatalf("Error when running ip command in Pod '%s': %v - stdout: %s - stderr: %s", antreaPodName, err, stdout, stderr)
			}
			return true
		}
		doesOVSPortExist = func() bool {
			exists, err := data.doesOVSPortExist(antreaPodName, ifName)
			if err != nil {
				t.Fatalf("Cannot determine if OVS port exists: %v", err)
			}
			return exists
		}
		doesIPAllocationExist = func(podIP string) bool {
			cmd := []string{"test", "-f", "/var/run/antrea/cni/networks/antrea/" + podIP}
			_, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
			return err == nil
		}
	}

	t.Logf("Checking that the veth interface and the OVS port exist")
	if !doesInterfaceExist() {
		t.Errorf("Interface '%s' does not exist on Node '%s'", ifName, nodeName)
	}
	if !doesOVSPortExist() {
		t.Errorf("OVS port '%s' does not exist on Node '%s'", ifName, nodeName)
	}
	for _, podIP := range podIPs {
		if !doesIPAllocationExist(podIP) {
			t.Errorf("IP allocation '%s' does not exist on Node '%s'", podIP, nodeName)
		}
	}

	t.Logf("Deleting Pod '%s'", podName)
	if err := data.deletePodAndWait(defaultTimeout, podName, testNamespace); err != nil {
		t.Fatalf("Error when deleting Pod: %v", err)
	}

	t.Logf("Checking that the veth interface and the OVS port no longer exist")
	if doesInterfaceExist() {
		t.Errorf("Interface '%s' still exists on Node '%s' after Pod deletion", ifName, nodeName)
	}
	if doesOVSPortExist() {
		t.Errorf("OVS port '%s' still exists on Node '%s' after Pod deletion", ifName, nodeName)
	}
	for _, podIP := range podIPs {
		if doesIPAllocationExist(podIP) {
			t.Errorf("IP allocation '%s' still exists on Node '%s'", podIP, nodeName)
		}
	}
}

// testDeletePod creates a Pod, then deletes it, and checks that the veth interface (in the Node
// network namespace) and the OVS port for the container get removed.
func testDeletePod(t *testing.T, data *TestData) {
	isWindows := false
	nodeIdx := 0

	if len(clusterInfo.windowsNodes) > 0 {
		isWindows = true
		nodeIdx = clusterInfo.windowsNodes[0]
	}

	nodeName := nodeName(nodeIdx)
	podName := randName("test-pod-")

	t.Logf("Creating an agnhost test Pod on '%s'", nodeName)
	if err := data.createAgnhostPodOnNode(podName, testNamespace, nodeName); err != nil {
		t.Fatalf("Error when creating agnhost test Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, podName, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", podName)
	}

	data.testDeletePod(t, podName, nodeName, isWindows)
}

// testAntreaGracefulExit verifies that Antrea Pods can terminate gracefully.
func testAntreaGracefulExit(t *testing.T, data *TestData) {
	var gracePeriodSeconds int64 = 60
	t.Logf("Deleting one Antrea Pod")
	maxDeleteTimeout := 20 * time.Second
	// When running Antrea instrumented binary to collect e2e coverage,
	// we need to set the maxDeleteTimeout to a larger value
	// since it needs to collect coverage data files
	if testOptions.enableCoverage {
		maxDeleteTimeout = 80 * time.Second
	}

	if timeToDelete, err := data.deleteAntreaAgentOnNode(nodeName(0), gracePeriodSeconds, defaultTimeout); err != nil {
		t.Fatalf("Error when deleting Antrea Pod: %v", err)
	} else if timeToDelete > maxDeleteTimeout {
		t.Errorf("Antrea Pod took too long to delete: %v", timeToDelete)
	}
	// At the moment we only check that the Pod terminates in a reasonable amount of time (less
	// than the grace period), which means that all containers "honor" the SIGTERM signal.
	// TODO: ideally we would be able to also check the exit code but it may not be possible.
}

// testIPAMRestart checks that when the Antrea agent is restarted the information about which IP
// address is already allocated is not lost. It does that by creating a first Pod and retrieving
// its IP address, restarting the Antrea agent, then creating a second Pod and retrieving its IP
// address. If the 2 IP addresses match, then it is an error. This is not a perfect test, as it
// assumes that IP addresses are assigned in-order and not randomly.
func testIPAMRestart(t *testing.T, data *TestData) {
	nodeName := nodeName(0)
	podName1 := randName("test-pod-")
	podName2 := randName("test-pod-")
	pods := make([]string, 0, 2)
	var podIP1, podIP2 *PodIPs
	var err error
	defer func() {
		for _, pod := range pods {
			deletePodWrapper(t, data, pod)
		}
	}()

	createPodAndGetIP := func(podName string) (*PodIPs, error) {
		t.Logf("Creating a busybox test Pod '%s' and waiting for IP", podName)
		if err := data.createBusyboxPodOnNode(podName, testNamespace, nodeName); err != nil {
			t.Fatalf("Error when creating busybox test Pod '%s': %v", podName, err)
			return nil, err
		}
		pods = append(pods, podName)
		if podIP, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace); err != nil {
			return nil, err
		} else {
			return podIP, nil
		}
	}

	if podIP1, err = createPodAndGetIP(podName1); err != nil {
		t.Fatalf("Failed to retrieve IP for Pod '%s': %v", podName1, err)
	}
	t.Logf("Pod '%s' has IP address %v", podName1, podIP1)

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
	t.Logf("Pod '%s' has IP addresses %v", podName2, podIP2)

	if podIP1.hasSameIP(podIP2) {
		t.Errorf("Pods '%s' and '%s' were assigned the same IP %v", podName1, podName2, podIP1)
	}
}

// TestReconcileGatewayRoutesOnStartup checks that when the Antrea agent is restarted, the set of
// gateway routes is updated correctly, i.e. stale routes (for Nodes which are no longer in the
// cluster) are removed and missing routes are added.
func TestReconcileGatewayRoutesOnStartup(t *testing.T) {
	skipIfNumNodesLessThan(t, 2)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		t.Logf("Running IPv4 test")
		testReconcileGatewayRoutesOnStartup(t, data, false)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		t.Logf("Running IPv6 test")
		testReconcileGatewayRoutesOnStartup(t, data, true)
	}
}

func testReconcileGatewayRoutesOnStartup(t *testing.T, data *TestData, isIPv6 bool) {
	encapMode, err := data.GetEncapMode()
	if err != nil {
		t.Fatalf(" failed to get encap mode, err %v", err)
	}

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

	antreaGWName, err := data.GetGatewayInterfaceName(antreaNamespace)
	if err != nil {
		t.Fatalf("Failed to detect gateway interface name from ConfigMap: %v", err)
	}

	getGatewayRoutes := func() (routes []Route, err error) {
		var cmd []string
		if !isIPv6 {
			cmd = []string{"ip", "route", "list", "dev", antreaGWName}
		} else {
			cmd = []string{"ip", "-6", "route", "list", "dev", antreaGWName}
		}
		podName := antreaPodName()
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, agentContainerName, cmd)
		if err != nil {
			return nil, fmt.Errorf("error when running ip command in Pod '%s': %v - stdout: %s - stderr: %s", podName, err, stdout, stderr)
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

	expectedRtNumMin, expectedRtNumMax := clusterInfo.numNodes-1, clusterInfo.numNodes-1
	if encapMode == config.TrafficEncapModeNoEncap {
		expectedRtNumMin, expectedRtNumMax = 0, 0

	} else if encapMode == config.TrafficEncapModeHybrid {
		expectedRtNumMin = 1
	}

	t.Logf("Retrieving gateway routes on Node '%s'", nodeName)
	var routes []Route
	if err := wait.PollImmediate(defaultInterval, defaultTimeout, func() (found bool, err error) {
		routes, err = getGatewayRoutes()
		if err != nil {
			return false, err
		}

		if len(routes) < expectedRtNumMin {
			// Not enough routes, keep trying
			return false, nil
		} else if len(routes) > expectedRtNumMax {
			return false, fmt.Errorf("found too many gateway routes, expected %d but got %d", expectedRtNumMax, len(routes))
		}
		return true, nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Not enough gateway routes after %v", defaultTimeout)
	} else if err != nil {
		t.Fatalf("Error while waiting for gateway routes: %v", err)
	} else {
		t.Logf("Found all expected gateway routes")
	}

	var routeToDelete *Route
	if encapMode.SupportsEncap() {
		routeToDelete = &routes[0]
	}
	// A dummy route
	routeToAdd := &Route{}
	if !isIPv6 {
		_, routeToAdd.peerPodCIDR, _ = net.ParseCIDR("99.99.99.0/24")
		routeToAdd.peerPodGW = net.ParseIP("99.99.99.1")
	} else {
		_, routeToAdd.peerPodCIDR, _ = net.ParseCIDR("fe80::0/112")
		routeToAdd.peerPodGW = net.ParseIP("fe80::1")
	}

	// We run the ip command from the antrea-agent container for delete / add since they need to
	// be run as root and the antrea-agent container is privileged. If we used RunCommandOnNode,
	// we may need to use "sudo" for some providers (e.g. vagrant).
	deleteGatewayRoute := func(route *Route) error {
		var cmd []string
		if !isIPv6 {
			cmd = []string{"ip", "route", "del", route.peerPodCIDR.String()}
		} else {
			cmd = []string{"ip", "-6", "route", "del", route.peerPodCIDR.String()}
		}
		_, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName(), agentContainerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running ip command on Node '%s': %v", nodeName, err)
		}
		return nil
	}

	addGatewayRoute := func(route *Route) error {
		var cmd []string
		if !isIPv6 {
			cmd = []string{"ip", "route", "add", route.peerPodCIDR.String(), "via", route.peerPodGW.String(), "dev", antreaGWName, "onlink"}
		} else {
			cmd = []string{"ip", "-6", "route", "add", route.peerPodCIDR.String(), "via", route.peerPodGW.String(), "dev", antreaGWName, "onlink"}
		}
		_, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName(), agentContainerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running ip command on Node '%s': %v", nodeName, err)
		}
		return nil
	}

	if routeToDelete != nil {
		t.Logf("Deleting one actual gateway route and adding a dummy one")
		if err := deleteGatewayRoute(routeToDelete); err != nil {
			t.Fatalf("Error when deleting route: %v", err)
		}
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
	if err := wait.Poll(defaultInterval, defaultTimeout, func() (bool, error) {
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
		if routeToDelete != nil {
			// At this stage we have confirmed that the dummy route has been deleted
			for _, route := range newRoutes {
				if route.peerPodGW.Equal(routeToDelete.peerPodGW) {
					// The deleted route was added back, success!
					return true, nil
				}
			}
		} else {
			return true, nil
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

func getRoundNumber(data *TestData, podName string) (uint64, error) {
	type transaction struct {
		Op      string   `json:"op"`
		Table   string   `json:"table"`
		Where   []string `json:"where"`
		Columns []string `json:"columns"`
	}

	query := []interface{}{
		"Open_vSwitch",
		transaction{
			Op:      "select",
			Table:   "Bridge",
			Where:   []string{},
			Columns: []string{"external_ids"},
		},
	}

	b, err := json.Marshal(query)
	if err != nil {
		return 0, fmt.Errorf("error when marshalling OVSDB query: %v", err)
	}
	cmd := []string{"ovsdb-client", "query", string(b)}
	stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, ovsContainerName, cmd)
	if err != nil {
		return 0, fmt.Errorf("cannot retrieve round number: stderr: <%v>, err: <%v>", stderr, err)
	}

	result := []struct {
		Rows []struct {
			ExternalIds []interface{} `json:"external_ids"`
		} `json:"rows"`
	}{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return 0, fmt.Errorf("error when unmarshalling OVSDB result: %v", err)
	}
	externalIds := result[0].Rows[0].ExternalIds[1].([]interface{})
	for _, externalID := range externalIds {
		externalIDArray := externalID.([]interface{})
		key := externalIDArray[0].(string)
		value := externalIDArray[1].(string)
		if key == "roundNum" {
			if roundNum, err := strconv.ParseUint(value, 10, 64); err != nil {
				return 0, fmt.Errorf("cannot convert roundNum to uint64: %v", err)
			} else {
				return roundNum, nil
			}
		}
	}

	return 0, fmt.Errorf("did not find roundNum in OVSDB result")
}

// testDeletePreviousRoundFlowsOnStartup checks that when the Antrea agent is restarted, flows from
// the previous "round" which are no longer needed (e.g. in case of changes to the cluster / to
// Network Policies) are removed correctly.
func testDeletePreviousRoundFlowsOnStartup(t *testing.T, data *TestData) {
	skipIfRunCoverage(t, "Stopping Agent does not work with Coverage")
	nodeName := nodeName(0)
	antreaPodName := func() string {
		antreaPodName, err := data.getAntreaPodOnNode(nodeName)
		if err != nil {
			t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName, err)
		}
		t.Logf("The Antrea Pod for Node '%s' is '%s'", nodeName, antreaPodName)
		return antreaPodName
	}

	podName := antreaPodName()

	roundNumber := func(podName string) uint64 {
		roundNum, err := getRoundNumber(data, podName)
		if err != nil {
			t.Fatalf("Unable to get agent round number: %v", err)
		}
		return roundNum
	}

	// get current round number
	roundNum1 := roundNumber(podName)
	t.Logf("Current round number is %d", roundNum1)

	t.Logf("Restarting agent and waiting for new round number")
	if _, err := data.deleteAntreaAgentOnNode(nodeName, 30 /* grace period in seconds */, defaultTimeout); err != nil {
		t.Fatalf("Error when restarting antrea-agent on Node '%s': %v", nodeName, err)
	}

	podName = antreaPodName() // pod name has changed

	waitForNextRoundNum := func(roundNum uint64) uint64 {
		var nextRoundNum uint64
		if err := wait.Poll(defaultInterval, defaultTimeout, func() (bool, error) {
			nextRoundNum = roundNumber(podName)
			if nextRoundNum != roundNum {
				return true, nil
			}
			return false, nil
		}); err != nil {
			t.Fatalf("Unable to retrieve new round number: %v", err)
		}
		t.Logf("New round number is %d", nextRoundNum)
		return nextRoundNum
	}

	roundNum2 := waitForNextRoundNum(roundNum1)

	// at this time, we now that stale flows have been cleaned-up and that the new round number
	// has been persisted and will not change again until the next restart

	cookieID, cookieMask := cookie.CookieMaskForRound(roundNum2)

	// add dummy flow with current round number
	addFlow := func() {
		cmd := []string{
			"ovs-ofctl", "add-flow", defaultBridgeName,
			fmt.Sprintf("table=0,cookie=%#x,priority=0,actions=drop", cookieID),
		}
		_, stderr, err := data.runCommandFromPod(antreaNamespace, podName, ovsContainerName, cmd)
		if err != nil {
			t.Fatalf("error when adding flow: <%v>, err: <%v>", stderr, err)
		}
	}
	t.Logf("Adding dummy flow")
	addFlow()

	// stopAgent stops the docker container, which should be re-created immediately by kubectl
	stopAgent := func() {
		cmd := []string{"kill", "1"}
		// ignore potential error as it is possible for the container to exit with code 137
		// if the container does not restart properly, we will know when we try to get the
		// new round number below.
		data.runCommandFromPod(antreaNamespace, podName, agentContainerName, cmd)
	}
	t.Logf("Restarting antrea-agent container on Node %s", nodeName)
	stopAgent()
	defer func() {
		// "cleanup": delete agent to ensure the restart count goes back to 0
		// this will also take care of deleting the flow in case of test failure
		if _, err := data.deleteAntreaAgentOnNode(nodeName, 30 /* grace period in seconds */, defaultTimeout); err != nil {
			t.Logf("Error when restarting antrea-agent on Node '%s': %v", nodeName, err)
		}
	}()

	// validate new round number
	waitForNextRoundNum(roundNum2)

	// check that the dummy flow has been removed
	// checkFlow returns true if the flow is present
	checkFlow := func() bool {
		cmd := []string{
			"ovs-ofctl", "dump-flows", defaultBridgeName,
			fmt.Sprintf("table=0,cookie=%#x/%#x", cookieID, cookieMask),
		}
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, ovsContainerName, cmd)
		if err != nil {
			t.Fatalf("error when dumping flows: <%v>, err: <%v>", stderr, err)
		}
		flows := strings.Split(stdout, "\n")[1:]
		return len(flows) > 1
	}

	smallTimeout := 5 * time.Second
	t.Logf("Checking that dummy flow is deleted within %v", smallTimeout)
	// In theory there should be no need to poll here because the agent only persists the new
	// round number after stale flows have been deleted, but it is probably better not to make
	// this assumption in an e2e test.
	if err := wait.PollImmediate(defaultInterval, smallTimeout, func() (bool, error) {
		return !checkFlow(), nil

	}); err != nil {
		t.Errorf("Flow was still present after timeout")
	}
}

// testGratuitousARP verifies that we receive 3 GARP packets after a Pod is up.
// There might be ARP packets other than GARP sent if there is any unintentional
// traffic. So we just check the number of ARP packets is greater than 3.
func testGratuitousARP(t *testing.T, data *TestData) {
	skipIfNotIPv4Cluster(t)
	podName := randName("test-pod-")
	nodeName := workerNodeName(1)

	t.Logf("Creating Pod '%s' on '%s'", podName, nodeName)
	if err := data.createBusyboxPodOnNode(podName, testNamespace, nodeName); err != nil {
		t.Fatalf("Error when creating Pod '%s': %v", podName, err)
	}
	defer deletePodWrapper(t, data, podName)

	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName, err)
	}

	podIP, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
	}

	// Sending GARP is an asynchronous operation. The last GARP is supposed to
	// be sent 100ms after processing CNI ADD request.
	time.Sleep(100 * time.Millisecond)

	cmd := []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=10,arp,arp_spa=%s", podIP.ipv4.String())}
	stdout, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
	if err != nil {
		t.Fatalf("Error when querying openflow: %v", err)
	}

	re := regexp.MustCompile(`n_packets=([0-9]+)`)
	matches := re.FindStringSubmatch(stdout)
	if len(matches) == 0 {
		t.Fatalf("cannot retrieve n_packets, unexpected output: %s", stdout)
	}
	arpPackets, _ := strconv.ParseUint(matches[1], 10, 32)
	if arpPackets < 3 {
		t.Errorf("Expected at least 3 ARP packets, got %d", arpPackets)
	}
	t.Logf("Got %d ARP packets after Pod was up", arpPackets)
}

// testClusterIdentity verifies that the antrea-cluster-identity ConfigMap is
// populated correctly by the Antrea Controller.
func testClusterIdentity(t *testing.T, data *TestData) {
	clusterIdentityProvider := clusteridentity.NewClusterIdentityProvider(
		antreaNamespace,
		clusteridentity.DefaultClusterIdentityConfigMapName,
		data.clientset,
	)

	const retryInterval = time.Second
	const timeout = 10 * time.Second
	var clusterUUID uuid.UUID
	err := wait.PollImmediate(retryInterval, timeout, func() (bool, error) {
		if clusterIdentity, _, err := clusterIdentityProvider.Get(); err != nil {
			return false, nil
		} else {
			clusterUUID = clusterIdentity.UUID
			t.Logf("Cluster UUID: %v", clusterUUID)
			return true, nil
		}
	})

	assert.NoError(t, err, "Failed to retrieve cluster identity information within %v", timeout)
	assert.NotEqual(t, uuid.Nil, clusterUUID)
}
