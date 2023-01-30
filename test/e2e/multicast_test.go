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
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	agentconfig "antrea.io/antrea/cmd/antrea-agent/app/config"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/multicast"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

func skipIfMulticastDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.Multicast, true, false)
}

var igmpQueryType = int32(0x11)

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
	t.Run("testMulticastWithNoEncap", func(t *testing.T) {
		skipIfEncapModeIsNot(t, data, config.TrafficEncapModeNoEncap)
		runMulticastTestCases(t, data, nodeMulticastInterfaces, true)
	})
	t.Run("testMulticastWithEncap", func(t *testing.T) {
		ac := func(config *agentconfig.AgentConfig) {
			config.TrafficEncapMode = "encap"
		}
		if err := data.mutateAntreaConfigMap(nil, ac, true, true); err != nil {
			t.Fatalf("Failed to deploy cluster with encap mode: %v", err)
		}
		runMulticastTestCases(t, data, nodeMulticastInterfaces, false)
	})
}

func runMulticastTestCases(t *testing.T, data *TestData, nodeMulticastInterfaces map[int][]string, checkReceiverRoute bool) {
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
				t.Parallel()
				runTestMulticastBetweenPods(t, data, mc, nodeMulticastInterfaces, checkReceiverRoute)
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
				t.Parallel()
				runTestMulticastBetweenPods(t, data, mc, nodeMulticastInterfaces, checkReceiverRoute)
			})
		}
	})
	t.Run("testMulticastForwardToMultipleInterfaces", func(t *testing.T) {
		// Skip this case with encap mode because iptables masquerade is configured, and it leads the multicast packet
		// sent from Pod are not able to forwarded to more than one network interface on the host.
		skipIfEncapModeIsNot(t, data, config.TrafficEncapModeNoEncap)
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
		testMulticastForwardToMultipleInterfaces(t, data, nodeIdx, 3464, "224.3.4.13", nodeMulticastInterfaces[nodeIdx])
	})
	t.Run("testMulticaststats", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testcases := []multicastStatsTestcase{
			{
				name: "testMulticastNetworkPolicyStats",
				senderConfigs: []senderConfigs{
					{nodeName: nodeName(0), name: "test1-sender-1", IPs: []string{"225.20.2.2", "225.20.2.3"}, sendSessions: 10},
				},
				multicastANPConfigs: []ANPConfigs{
					{
						name:         "anp1-multicast",
						appliedToPod: "test1-sender-1",
						ruleConfigs: []ruleConfig{
							{name: "allow-multicast-traffic", address: "225.20.2.3", action: crdv1alpha1.RuleActionAllow},
							{name: "drop-multicast-traffic", address: "225.20.2.2", action: crdv1alpha1.RuleActionDrop},
						},
					},
				},
				antctlResults: map[string]multicast.PodTrafficStats{
					"test1-sender-1": {Inbound: 0, Outbound: 10},
				},
				multicastANPStatsResult: map[string]map[string]int64{
					"anp1-multicast": {"allow-multicast-traffic": 10, "drop-multicast-traffic": 10},
				},
			},
			{
				name: "testIGMPNetworkPolicyStats",
				receiverConfigs: []receiverConfigs{
					{nodeName: nodeName(1), name: "test2-receiver-1", IPs: []string{"225.20.3.2", "225.20.3.3"}},
				},
				igmpANPConfigs: []ANPConfigs{
					{
						name:         "anp1-igmp",
						appliedToPod: "test2-receiver-1",
						ruleConfigs: []ruleConfig{
							{name: "allow-igmp-report", address: "225.20.3.3", action: crdv1alpha1.RuleActionAllow},
							{name: "drop-igmp-report", address: "225.20.3.2", action: crdv1alpha1.RuleActionDrop},
						},
					},
				},
				antctlResults: map[string]multicast.PodTrafficStats{
					"test2-receiver-1": {Inbound: 0, Outbound: 0},
				},
				igmpStatsResult: map[string]sets.String{
					"anp1-igmp": sets.NewString("allow-igmp-report", "drop-igmp-report"),
				},
				multicastGroupsResult: map[string]sets.String{
					"225.20.3.3": sets.NewString("test2-receiver-1"),
				},
			},
			{
				name: "testMulticastStatsWithMixedANPs",
				senderConfigs: []senderConfigs{
					{nodeName: nodeName(0), name: "test3-sender-1", IPs: []string{"225.20.1.2", "225.20.1.3"}, sendSessions: 10},
					{nodeName: nodeName(1), name: "test3-sender-2", IPs: []string{"225.20.1.2", "225.20.1.3"}, sendSessions: 10},
				},
				receiverConfigs: []receiverConfigs{
					{nodeName: nodeName(1), name: "test3-receiver-1", IPs: []string{"225.20.1.2", "225.20.1.3"}},
					{nodeName: nodeName(0), name: "test3-receiver-2", IPs: []string{"225.20.1.2", "225.20.1.3"}},
				},
				multicastANPConfigs: []ANPConfigs{
					{
						name:         "anp1-mixed",
						appliedToPod: "test3-sender-1",
						ruleConfigs: []ruleConfig{
							{name: "allow-multicast-traffic", address: "225.20.1.3", action: crdv1alpha1.RuleActionAllow},
							{name: "drop-multicast-traffic", address: "225.20.1.2", action: crdv1alpha1.RuleActionDrop},
						},
					},
				},
				igmpANPConfigs: []ANPConfigs{
					{
						name:         "anp2-mixed",
						appliedToPod: "test3-receiver-1",
						ruleConfigs: []ruleConfig{
							{name: "allow-igmp-report", address: "225.20.1.2", action: crdv1alpha1.RuleActionAllow},
							{name: "drop-igmp-report", address: "225.20.1.3", action: crdv1alpha1.RuleActionDrop},
						},
					},
					{
						name:         "anp3-mixed",
						appliedToPod: "test3-receiver-1",
						ruleConfigs:  []ruleConfig{{name: "allow-igmp-query", igmpType: &igmpQueryType, address: "224.0.0.1", action: crdv1alpha1.RuleActionAllow}},
					},
				},
				antctlResults: map[string]multicast.PodTrafficStats{
					"test3-sender-1":   {Inbound: 0, Outbound: 10},
					"test3-sender-2":   {Inbound: 0, Outbound: 20},
					"test3-receiver-1": {Inbound: 10, Outbound: 0},
					"test3-receiver-2": {Inbound: 30, Outbound: 0},
				},
				multicastANPStatsResult: map[string]map[string]int64{
					"anp1-mixed": {"allow-multicast-traffic": 10, "drop-multicast-traffic": 10},
				},
				igmpStatsResult: map[string]sets.String{
					"anp2-mixed": sets.NewString("allow-igmp-report", "drop-igmp-report"),
					"anp3-mixed": sets.NewString("allow-igmp-query"),
				},
				multicastGroupsResult: map[string]sets.String{
					"225.20.1.2": sets.NewString("test3-receiver-2", "test3-receiver-1"),
					"225.20.1.3": sets.NewString("test3-receiver-2"),
				},
			},
		}
		for _, mc := range testcases {
			mc := mc
			t.Run(mc.name, func(t *testing.T) {
				testMulticastStatsWithSendersReceivers(t, data, mc)
			})
		}
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

type multicastStatsTestcase struct {
	name                    string
	senderConfigs           []senderConfigs
	receiverConfigs         []receiverConfigs
	multicastANPConfigs     []ANPConfigs
	igmpANPConfigs          []ANPConfigs
	antctlResults           map[string]multicast.PodTrafficStats
	multicastANPStatsResult map[string]map[string]int64
	igmpStatsResult         map[string]sets.String
	multicastGroupsResult   map[string]sets.String
}

type senderConfigs struct {
	name         string
	nodeName     string
	IPs          []string
	sendSessions int
}

type receiverConfigs struct {
	name     string
	nodeName string
	IPs      []string
}

type ANPConfigs struct {
	name         string
	appliedToPod string
	ruleConfigs  []ruleConfig
}

type ruleConfig struct {
	name     string
	address  string
	igmpType *int32
	action   crdv1alpha1.RuleAction
}

// testMulticastStatsWithSendersReceivers tests multiple multicast senders and receivers cases with specified AntreaNetworkPolicies which may drop/allow IGMP or Multicast traffic.
// It checks the results of all the multicaststats-related commands, including kubectl get multicastgroups, antctl get podmulticaststats and kubectl get antreanetworkpolicystats.
func testMulticastStatsWithSendersReceivers(t *testing.T, data *TestData, mc multicastStatsTestcase) {
	mcjoinWaitTimeout := defaultTimeout / time.Second

	for _, senderConfig := range mc.senderConfigs {
		_, _, cleanupFunc := createAndWaitForPodWithExactName(t, data, data.createMcJoinPodOnNode, senderConfig.name, senderConfig.nodeName, data.testNamespace, false)
		defer cleanupFunc()
	}

	for _, receiverConfig := range mc.receiverConfigs {
		_, _, cleanupFunc := createAndWaitForPodWithExactName(t, data, data.createMcJoinPodOnNode, receiverConfig.name, receiverConfig.nodeName, data.testNamespace, false)
		defer cleanupFunc()
	}

	var err error
	k8sUtils, _ = NewKubernetesUtils(data)
	p10 := float64(10)

	for _, anp := range mc.multicastANPConfigs {
		np := &crdv1alpha1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: anp.name, Labels: map[string]string{"antrea-e2e": anp.name}},
			Spec: crdv1alpha1.NetworkPolicySpec{
				Priority: p10,
				AppliedTo: []crdv1alpha1.AppliedTo{
					{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": anp.appliedToPod}}},
				},
				Egress: []crdv1alpha1.Rule{},
			},
		}
		for i := range anp.ruleConfigs {
			np.Spec.Egress = append(np.Spec.Egress, crdv1alpha1.Rule{
				To: []crdv1alpha1.NetworkPolicyPeer{
					{
						IPBlock: &crdv1alpha1.IPBlock{
							CIDR: fmt.Sprintf("%s/32", anp.ruleConfigs[i].address),
						},
					},
				},
				Action: &anp.ruleConfigs[i].action,
				Name:   anp.ruleConfigs[i].name,
			})
		}
		if _, err = k8sUtils.CreateOrUpdateANP(np); err != nil {
			t.Fatalf("Creating ANP %s failed: %v", np.Name, err)
		}
		err = data.waitForANPRealized(t, data.testNamespace, np.Name, policyRealizedTimeout)
		if err != nil {
			t.Fatalf("Error when waiting for ANP %s to be realized: %v", np.Name, err)
		}
		defer data.DeleteANP(data.testNamespace, anp.name)
	}

	for _, anp := range mc.igmpANPConfigs {
		np := &crdv1alpha1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: anp.name, Labels: map[string]string{"antrea-e2e": anp.name}},
			Spec: crdv1alpha1.NetworkPolicySpec{
				Priority: p10,
				AppliedTo: []crdv1alpha1.AppliedTo{
					{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": anp.appliedToPod}}},
				},
				Egress:  []crdv1alpha1.Rule{},
				Ingress: []crdv1alpha1.Rule{},
			},
		}
		for i := range anp.ruleConfigs {
			rule := crdv1alpha1.Rule{
				From: []crdv1alpha1.NetworkPolicyPeer{},
				Protocols: []crdv1alpha1.NetworkPolicyProtocol{
					{
						IGMP: &crdv1alpha1.IGMPProtocol{IGMPType: anp.ruleConfigs[i].igmpType, GroupAddress: anp.ruleConfigs[i].address},
					},
				},
				Action: &anp.ruleConfigs[i].action,
				Name:   anp.ruleConfigs[i].name,
			}
			if anp.ruleConfigs[i].igmpType != nil && *anp.ruleConfigs[i].igmpType == igmpQueryType {
				np.Spec.Ingress = append(np.Spec.Ingress, rule)
			} else {
				np.Spec.Egress = append(np.Spec.Egress, rule)
			}
		}
		if _, err = k8sUtils.CreateOrUpdateANP(np); err != nil {
			t.Fatalf("Creating ANP %s failed: %v", np.Name, err)
		}
		err = data.waitForANPRealized(t, data.testNamespace, np.Name, policyRealizedTimeout)
		if err != nil {
			t.Fatalf("Error when waiting for ANP %s released: %v", np.Name, err)
		}
		defer data.DeleteANP(data.testNamespace, anp.name)
	}

	for _, receiverConfig := range mc.receiverConfigs {
		for _, addr := range receiverConfig.IPs {
			go func(receiver, addr string) {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -o -p %d -W %d %s", 2234, mcjoinWaitTimeout, addr)}
				data.RunCommandFromPod(data.testNamespace, receiver, mcjoinContainerName, cmd)
			}(receiverConfig.name, addr)
		}
	}

	time.Sleep(5 * time.Second)

	var wg sync.WaitGroup

	for _, senderConfig := range mc.senderConfigs {
		for _, addr := range senderConfig.IPs {
			wg.Add(1)
			go func(sender, addr string, sessions int) {
				defer wg.Done()
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -f 500 -o -p %d -s -t 30 -c %d -W %d %s", 2234, sessions, mcjoinWaitTimeout, addr)}
				data.RunCommandFromPod(data.testNamespace, sender, mcjoinContainerName, cmd)
			}(senderConfig.name, addr, senderConfig.sendSessions)
		}
	}
	wg.Wait()

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
		for _, senderConfig := range mc.senderConfigs {
			stats := mc.antctlResults[senderConfig.name]
			t.Logf("Checking antctl get podmulticaststats result for %s", senderConfig.name)
			antreaPod, err := data.getAntreaPodOnNode(senderConfig.nodeName)
			if err != nil {
				t.Fatalf("Error getting getAntreaPodOnNode for %s", senderConfig.name)
			}
			matches, err := checkAntctlResult(t, data, antreaPod, senderConfig.name, stats.Inbound, stats.Outbound)
			if err != nil || !matches {
				return false, err
			}
		}
		groupAddresses := sets.NewString()
		for _, receiverConfig := range mc.receiverConfigs {
			groupAddresses.Insert(receiverConfig.IPs...)
			stats := mc.antctlResults[receiverConfig.name]
			t.Logf("Checking antctl get podmulticaststats result for %s", receiverConfig.name)
			antreaPod, err := data.getAntreaPodOnNode(receiverConfig.nodeName)
			if err != nil {
				t.Fatalf("Error getting getAntreaPodOnNode for %s", receiverConfig.name)
			}
			matches, err := checkAntctlResult(t, data, antreaPod, receiverConfig.name, stats.Inbound, stats.Outbound)
			if err != nil || !matches {
				return false, err
			}
		}
		for _, anp := range mc.igmpANPConfigs {
			stats, err := data.crdClient.StatsV1alpha1().AntreaNetworkPolicyStats(data.testNamespace).Get(context.TODO(), anp.name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			t.Logf("Got AntreaNetworkPolicy stats: %v", stats)
			expectedRuleNames, exist := mc.igmpStatsResult[anp.name]
			if !exist || len(expectedRuleNames) == 0 {
				if len(stats.RuleTrafficStats) > 0 {
					return false, nil
				}
			} else {
				ruleNames := sets.NewString()
				for _, ruleName := range stats.RuleTrafficStats {
					ruleNames.Insert(ruleName.Name)
				}
				if !ruleNames.Equal(expectedRuleNames) {
					return false, nil
				}
			}
		}
		for _, anp := range mc.multicastANPConfigs {
			stats, err := data.crdClient.StatsV1alpha1().AntreaNetworkPolicyStats(data.testNamespace).Get(context.TODO(), anp.name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			t.Logf("Got AntreaNetworkPolicy stats: %v", stats)
			if len(stats.RuleTrafficStats) != len(mc.multicastANPStatsResult[anp.name]) {
				return false, nil
			}
			for _, rule := range stats.RuleTrafficStats {
				pktCount := mc.multicastANPStatsResult[anp.name][rule.Name]
				if pktCount != rule.TrafficStats.Packets {
					return false, nil
				}
			}
		}
		for _, group := range groupAddresses.List() {
			multicastGroup, err := data.crdClient.StatsV1alpha1().MulticastGroups().Get(context.TODO(), group, metav1.GetOptions{})
			if err != nil && !errors.IsNotFound(err) {
				t.Logf("Got multicastGroup error %v", err)
				return false, err
			}
			expectedPodNames, exist := mc.multicastGroupsResult[group]
			if err != nil {
				t.Logf("Got multicastGroup error %v", err)
				if exist && len(expectedPodNames) > 0 {
					return false, nil
				}
			} else {
				t.Logf("Got multicast group information for group %s: %v", group, multicastGroup)
				podsNames := sets.NewString()
				for _, pod := range multicastGroup.Pods {
					podsNames.Insert(pod.Name)
				}
				if !podsNames.Equal(expectedPodNames) {
					return false, nil
				}
			}
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Test failed: %v", err)
	}
}

func testMulticastForwardToMultipleInterfaces(t *testing.T, data *TestData, senderIdx int, senderPort int, senderGroup string, senderMulticastInterfaces []string) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	senderName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-sender-", nodeName(senderIdx), data.testNamespace, false)
	defer cleanupFunc()
	tcpdumpName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNetshootPodOnNode, "test-tcpdump-", nodeName(senderIdx), data.testNamespace, true)
	defer cleanupFunc()
	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("timeout 90s mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", senderPort, mcjoinWaitTimeout, senderGroup)}
	go func() {
		data.RunCommandFromPod(data.testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
		// Check whether multicast interfaces can receive multicast traffic in the server side.
		// The check is needed for verifying external interfaces acting as multicast interfaces are able to forward multicast traffic.
		// If multicast traffic is sent from non-HostNetwork pods, all multicast interfaces in senders should receive multicast traffic.
		for _, multicastInterface := range senderMulticastInterfaces {
			tcpdumpReceiveMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("timeout 5s tcpdump -q -i %s -c 1 -W 90 host %s", multicastInterface, senderGroup)}
			_, stderr, err := data.RunCommandFromPod(data.testNamespace, tcpdumpName, tcpdumpContainerName, tcpdumpReceiveMulticastCommand)
			if err != nil {
				return false, err
			}
			if !strings.Contains(stderr, "1 packet captured") {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Error when waiting for capturing multicast traffic on all multicast interfaces: %v", err)
	}
}

func runTestMulticastBetweenPods(t *testing.T, data *TestData, mc multicastTestcase, nodeMulticastInterfaces map[int][]string, checkReceiverRoute bool) {
	currentEncapMode, _ := data.GetEncapMode()
	if requiresExternalHostSupport(mc) && currentEncapMode == config.TrafficEncapModeEncap {
		t.Skipf("Multicast does not support using hostNetwork Pod to simulate the external host with encap mode, skip the case")
	}
	mcjoinWaitTimeout := defaultTimeout / time.Second
	gatewayInterface, err := data.GetGatewayInterfaceName(antreaNamespace)
	failOnError(err, t)
	senderName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-sender-", nodeName(mc.senderConfig.nodeIdx), data.testNamespace, mc.senderConfig.isHostNetwork)
	defer cleanupFunc()
	var wg sync.WaitGroup
	_, cleanupFuncs := setupReceivers(t, data, mc, mcjoinWaitTimeout, &wg)
	for _, cleanupFunc := range cleanupFuncs {
		defer cleanupFunc()
	}

	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
	go func() {
		data.RunCommandFromPod(data.testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()

	readyReceivers := sets.NewInt()
	senderReady := false
	if err := wait.Poll(3*time.Second, defaultTimeout, func() (bool, error) {
		if !senderReady {
			// Sender pods should add an outbound multicast route except running as HostNetwork.
			_, mrouteResult, _, err := data.RunCommandOnNode(nodeName(mc.senderConfig.nodeIdx), fmt.Sprintf("ip mroute show to %s iif %s | grep '%s'", mc.group.String(), gatewayInterface, strings.Join(nodeMulticastInterfaces[mc.senderConfig.nodeIdx], " ")))
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
			senderReady = true
		}

		// Check inbound multicast route and whether multicast interfaces has joined the multicast group.
		for _, receiver := range mc.receiverConfigs {
			if readyReceivers.Has(receiver.nodeIdx) {
				continue
			}
			for _, receiverMulticastInterface := range nodeMulticastInterfaces[receiver.nodeIdx] {
				if checkReceiverRoute {
					_, mRouteResult, _, err := data.RunCommandOnNode(nodeName(receiver.nodeIdx), fmt.Sprintf("ip mroute show to %s iif %s ", mc.group.String(), receiverMulticastInterface))
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
				}
				_, mAddrResult, _, err := data.RunCommandOnNode(nodeName(receiver.nodeIdx), fmt.Sprintf("ip maddr show %s | grep %s", receiverMulticastInterface, mc.group.String()))
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
			readyReceivers = readyReceivers.Insert(receiver.nodeIdx)
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Error when waiting for multicast routes and statistics: %v", err)
	}
	wg.Wait()
}

func setupReceivers(t *testing.T, data *TestData, mc multicastTestcase, mcjoinWaitTimeout time.Duration, wg *sync.WaitGroup) ([]string, []func()) {
	receiverNames := make([]string, 0)
	cleanupFuncs := []func(){}
	for _, receiver := range mc.receiverConfigs {
		receiverName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-receiver-", nodeName(receiver.nodeIdx), data.testNamespace, receiver.isHostNetwork)
		receiverNames = append(receiverNames, receiverName)
		cleanupFuncs = append(cleanupFuncs, cleanupFunc)
	}

	for _, receiverName := range receiverNames {
		r := receiverName
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The following command joins a multicast group and sets the timeout to 100 seconds(-W 100) before exit.
			// The command will return after receiving 10 packet(-c 10).
			receiveMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -c 10 -o -p %d -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
			res, _, err := data.RunCommandFromPod(data.testNamespace, r, mcjoinContainerName, receiveMulticastCommand)
			failOnError(err, t)
			assert.Contains(t, res, "Total: 10 packets")
		}()
	}
	return receiverNames, cleanupFuncs
}

// computeMulticastInterfaces computes multicastInterfaces for each node.
// It returns [][]string with its index as node index and value as multicastInterfaces for this node.
func computeMulticastInterfaces(t *testing.T, data *TestData) (map[int][]string, error) {
	multicastInterfaces, err := data.GetMulticastInterfaces(antreaNamespace)
	if err != nil {
		return nil, err
	}
	transportInterface, err := GetTransportInterface(data)
	if err != nil {
		t.Fatalf("Error getting transport interfaces: %v", err)
	}
	nodeMulticastInterfaces := make(map[int][]string)
	for nodeIdx := range clusterInfo.nodes {
		_, localInterfacesStr, _, err := data.RunCommandOnNode(nodeName(nodeIdx), "ls /sys/class/net")
		if err != nil {
			return nil, err
		}
		// The final multicast interfaces used for the node is calculated by (localInterfacesSet intersects multicastInterfaceSet adds transportInterface).
		localInterfacesSet := sets.NewString(strings.Split(strings.TrimSpace(localInterfacesStr), "\n")...)
		multicastInterfaceSet := sets.NewString(multicastInterfaces...)
		externalMulticastInterfaces := localInterfacesSet.Intersection(multicastInterfaceSet)
		currNodeMulticastInterfaces := externalMulticastInterfaces.Insert(transportInterface).List()
		t.Logf("Multicast interfaces for node index %d is %+v", nodeIdx, currNodeMulticastInterfaces)
		nodeMulticastInterfaces[nodeIdx] = currNodeMulticastInterfaces
	}
	return nodeMulticastInterfaces, nil
}

func checkAntctlResult(t *testing.T, data *TestData, antreaPodName, containerPodName string, inbound, outbound uint64) (bool, error) {
	antctlCmds := []string{"antctl", "get", "podmulticaststats"}
	stdout, stderr, err := runAntctl(antreaPodName, antctlCmds, data)
	if err != nil {
		t.Errorf("Error when executing antctl get podmulticaststats, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
		return false, err
	}
	t.Logf("The result of running antctl get podmulticaststats in %s is stdout: %s, stderr: %s, err: %v", antreaPodName, stdout, stderr, err)
	match, _ := regexp.MatchString(fmt.Sprintf("%s[[:space:]]+%s[[:space:]]+%d[[:space:]]+%d", data.testNamespace, containerPodName, inbound, outbound), strings.TrimSpace(stdout))
	return match, nil
}

func requiresExternalHostSupport(mc multicastTestcase) bool {
	if mc.senderConfig.isHostNetwork {
		return true
	}
	for _, receiver := range mc.receiverConfigs {
		if receiver.isHostNetwork {
			return true
		}
	}
	return false
}
