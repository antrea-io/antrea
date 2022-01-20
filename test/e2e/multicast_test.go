// Copyright 2021 Antrea Authors
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/features"
)

func skipIfMulticastDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.Multicast, true, false)
}

func TestMulticast(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotIPv4Cluster(t)
	skipIfMulticastDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodeMulticastInterfaces, err := computeMulticastInterfaces(t, data)
	if err != nil {
		t.Fatalf("Error computing multicast interfaces: %v", err)
	}
	t.Run("testMulticastBetweenPodsInTwoNodes", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testcases := []multicastTestcase{
			{
				name:            "testMulticastForLocalPods",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
				receiverConfigs: []multicastTestPodConfig{{0, false}},
				port:            3456,
				group:           net.ParseIP("224.3.4.5"),
			},
			{
				name:            "testMulticastForInterNodePods",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
				receiverConfigs: []multicastTestPodConfig{{1, false}},
				port:            3457,
				group:           net.ParseIP("224.3.4.6"),
			},
			{
				name:            "testMulticastTrafficFromExternal",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: true},
				receiverConfigs: []multicastTestPodConfig{{1, false}},
				port:            3458,
				group:           net.ParseIP("224.3.4.7"),
			},
			{
				name:            "testMulticastTrafficToExternal",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
				receiverConfigs: []multicastTestPodConfig{{1, true}},
				port:            3459,
				group:           net.ParseIP("224.3.4.8"),
			},
		}
		for _, mc := range testcases {
			mc := mc
			t.Run(mc.name, func(t *testing.T) {
				runTestMulticastBetweenPods(t, data, mc, nodeMulticastInterfaces)
			})
		}
	})
	t.Run("testMulticastBetweenPodsInThreeNodes", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 3)
		testcases := []multicastTestcase{
			{
				name:            "testMulticastMultipleReceiversOnSameNode",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
				receiverConfigs: []multicastTestPodConfig{{0, false}, {0, false}},
				port:            3460,
				group:           net.ParseIP("224.3.4.9"),
			},
			{
				name:            "testMulticastMultipleReceiversForInterNodePods",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
				receiverConfigs: []multicastTestPodConfig{{1, false}, {2, false}},
				port:            3461,
				group:           net.ParseIP("224.3.4.10"),
			},
			{
				name:            "testMulticastMultipleReceiversTrafficFromExternal",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: true},
				receiverConfigs: []multicastTestPodConfig{{1, false}, {2, true}},
				port:            3462,
				group:           net.ParseIP("224.3.4.11"),
			},
			{
				name:            "testMulticastMultipleReceiversTrafficToExternal",
				senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
				receiverConfigs: []multicastTestPodConfig{{1, true}, {2, false}},
				port:            3463,
				group:           net.ParseIP("224.3.4.12"),
			},
		}
		for _, mc := range testcases {
			mc := mc
			t.Run(mc.name, func(t *testing.T) {
				runTestMulticastBetweenPods(t, data, mc, nodeMulticastInterfaces)
			})
		}
	})
	t.Run("runTestMulticastForwardToMultipleInterfaces", func(t *testing.T) {
		multipleInterfacesFound := false
		var nodeIdx int
		for i, ifaces := range nodeMulticastInterfaces {
			if len(ifaces) >= 2 {
				multipleInterfacesFound = true
				nodeIdx = i
				break
			}
		}
		if !multipleInterfacesFound {
			t.Skip("Skipping test because none of the Nodes has more than one multicast enabled interface")
		}
		runTestMulticastForwardToMultipleInterfaces(t, data, nodeIdx, 3464, "224.3.4.13", nodeMulticastInterfaces[nodeIdx])
	})
}

type multicastTestPodConfig struct {
	nodeIdx       int
	isHostNetwork bool
}

type multicastTestcase struct {
	name            string
	senderConfig    multicastTestPodConfig
	receiverConfigs []multicastTestPodConfig
	port            int
	group           net.IP
}

func runTestMulticastForwardToMultipleInterfaces(t *testing.T, data *TestData, senderIdx int, senderPort int, senderGroup string, senderMulticastInterfaces []string) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	senderName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-sender-", nodeName(senderIdx), testNamespace, false)
	defer cleanupFunc()
	tcpdumpName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNetshootPodOnNode, "test-tcpdump-", nodeName(senderIdx), testNamespace, true)
	defer cleanupFunc()
	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("timeout 90s mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", senderPort, mcjoinWaitTimeout, senderGroup)}
	go func() {
		data.runCommandFromPod(testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
		// Check whether multicast interfaces can receive multicast traffic in the server side.
		// The check is needed for verifying external interfaces acting as multicast interfaces are able to forward multicast traffic.
		// If multicast traffic is sent from non-HostNetwork pods, all multicast interfaces in senders should receive multicast traffic.
		for _, multicastInterface := range senderMulticastInterfaces {
			tcpdumpReceiveMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("timeout 5s tcpdump -q -i %s -c 1 -W 90 host %s", multicastInterface, senderGroup)}
			_, stderr, err := data.runCommandFromPod(testNamespace, tcpdumpName, tcpdumpContainerName, tcpdumpReceiveMulticastCommand)
			if err != nil {
				return false, err
			}
			if !strings.Contains(stderr, "1 packet captured") {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Error waiting for capturing multicast traffic on all multicast interfaces: %v", err)
	}
}

func runTestMulticastBetweenPods(t *testing.T, data *TestData, mc multicastTestcase, nodeMulticastInterfaces [][]string) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	gatewayInterface, err := data.GetGatewayInterfaceName(antreaNamespace)
	failOnError(err, t)
	senderName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-sender-", nodeName(mc.senderConfig.nodeIdx), testNamespace, mc.senderConfig.isHostNetwork)
	defer cleanupFunc()
	receiverNames := make([]string, 0)
	for _, receiver := range mc.receiverConfigs {
		receiverName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-receiver-", nodeName(receiver.nodeIdx), testNamespace, receiver.isHostNetwork)
		receiverNames = append(receiverNames, receiverName)
		defer cleanupFunc()
	}
	var wg sync.WaitGroup
	for _, receiverName := range receiverNames {
		r := receiverName
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The following command joins a multicast group and sets the timeout to 100 seconds(-W 100) before exit.
			// The command will return after receiving 1 packet(-c 1).
			receiveMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -c 1 -o -p %d -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
			res, _, err := data.runCommandFromPod(testNamespace, r, mcjoinContainerName, receiveMulticastCommand)
			failOnError(err, t)
			assert.Contains(t, res, "Total: 1 packets")
		}()
	}
	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
	go func() {
		data.runCommandFromPod(testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
		// Sender pods should add an outbound multicast route except running as HostNetwork.
		_, mrouteResult, _, err := RunCommandOnNode(nodeName(mc.senderConfig.nodeIdx), fmt.Sprintf("ip mroute show to %s iif %s | grep '%s'", mc.group.String(), gatewayInterface, strings.Join(nodeMulticastInterfaces[mc.senderConfig.nodeIdx], " ")))
		if err != nil {
			return false, err
		}
		if !mc.senderConfig.isHostNetwork {
			if len(mrouteResult) == 0 {
				return false, nil
			}
		} else {
			if len(mrouteResult) != 0 {
				return false, nil
			}
		}
		// Check inbound multicast route and whether multicast interfaces has joined the multicast group.
		for _, receiver := range mc.receiverConfigs {
			for _, receiverMulticastInterface := range nodeMulticastInterfaces[receiver.nodeIdx] {
				_, mRouteResult, _, err := RunCommandOnNode(nodeName(receiver.nodeIdx), fmt.Sprintf("ip mroute show to %s iif %s ", mc.group.String(), receiverMulticastInterface))
				if err != nil {
					return false, err
				}
				// If multicast traffic is sent from non-HostNetwork pods and senders-receivers are located in different nodes,
				// the receivers should configure corresponding inbound multicast routes.
				if mc.senderConfig.nodeIdx != receiver.nodeIdx && !receiver.isHostNetwork {
					if len(mRouteResult) == 0 {
						return false, nil
					}
				} else {
					if len(mRouteResult) != 0 {
						return false, nil
					}
				}
				_, mAddrResult, _, err := RunCommandOnNode(nodeName(receiver.nodeIdx), fmt.Sprintf("ip maddr show %s | grep %s", receiverMulticastInterface, mc.group.String()))
				if err != nil {
					return false, err
				}
				// The receivers should also join multicast group.
				// Note that in HostNetwork mode, the "join multicast" action is taken by mcjoin,
				// which will not persist after mcjoin exits.
				if !receiver.isHostNetwork {
					if len(mAddrResult) == 0 {
						return false, nil
					}
				} else {
					if len(mAddrResult) != 0 {
						return false, nil
					}
				}
			}
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Error waiting for multicast routes and stats: %v", err)
	}
	wg.Wait()
}

// computeMulticastInterfaces computes multicastInterfaces for each node.
// It returns [][]string with its index as node index and value as multicastInterfaces for this node.
func computeMulticastInterfaces(t *testing.T, data *TestData) ([][]string, error) {
	multicastInterfaces, err := data.GetMulticastInterfaces(antreaNamespace)
	if err != nil {
		return nil, err
	}
	transportInterface, err := GetTransportInterface()
	if err != nil {
		t.Fatalf("Error getting transport interfaces: %v", err)
	}
	nodeMulticastInterfaces := make([][]string, 0, len(clusterInfo.nodes))
	for nodeIdx := range clusterInfo.nodes {
		_, localInterfacesStr, _, err := RunCommandOnNode(nodeName(nodeIdx), "ls /sys/class/net")
		if err != nil {
			return nil, err
		}
		// The final multicast interfaces used for the node is calculated by (localInterfacesSet intersects multicastInterfaceSet adds transportInterface).
		localInterfacesSet := sets.NewString(strings.Split(strings.TrimSpace(localInterfacesStr), "\n")...)
		multicastInterfaceSet := sets.NewString(multicastInterfaces...)
		externalMulticastInterfaces := localInterfacesSet.Intersection(multicastInterfaceSet)
		currNodeMulticastInterfaces := externalMulticastInterfaces.Insert(transportInterface).List()
		t.Logf("Multicast interfaces for node index %d is %+v", nodeIdx, currNodeMulticastInterfaces)
		nodeMulticastInterfaces = append(nodeMulticastInterfaces, currNodeMulticastInterfaces)
	}
	return nodeMulticastInterfaces, nil
}
