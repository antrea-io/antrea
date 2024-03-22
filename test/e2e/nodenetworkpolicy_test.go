// Copyright 2024 Antrea Authors
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	. "antrea.io/antrea/test/e2e/utils"
)

const labelNodeHostname = "kubernetes.io/hostname"

func initializeAntreaNodeNetworkPolicy(t *testing.T, data *TestData, toHostNetworkPod bool) {
	p80 = 80
	p81 = 81
	p8080 = 8080
	p8081 = 8081
	p8082 = 8082
	p8085 = 8085
	podsPerNamespace = []string{"a"}
	suffix := randName("")
	namespaces = make(map[string]TestNamespaceMeta)
	for _, ns := range []string{"x", "y", "z"} {
		namespaces[ns] = TestNamespaceMeta{
			Name: ns + "-" + suffix,
		}
	}
	nodes = make(map[string]string)
	nodes["x"] = controlPlaneNodeName()
	nodes["y"] = workerNodeName(1)
	hostNetworks := make(map[string]bool)
	hostNetworks["x"] = true
	if toHostNetworkPod {
		hostNetworks["y"] = true
	} else {
		hostNetworks["y"] = false
		nodes["z"] = workerNodeName(1)
		hostNetworks["z"] = false
	}
	allPods = []Pod{}

	for _, podName := range podsPerNamespace {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns.Name, podName))
		}
	}

	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, podsPerNamespace, true, nodes, hostNetworks)
	failOnError(err, t)
	podIPs = ips
}

func skipIfNodeNetworkPolicyDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.NodeNetworkPolicy, true, false)
}

func TestAntreaNodeNetworkPolicy(t *testing.T) {
	skipIfAntreaPolicyDisabled(t)
	skipIfNodeNetworkPolicyDisabled(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	initializeAntreaNodeNetworkPolicy(t, data, true)

	t.Run("Case=ACNPAllowNoDefaultIsolationTCP", func(t *testing.T) { testNodeACNPAllowNoDefaultIsolation(t, ProtocolTCP) })
	t.Run("Case=ACNPAllowNoDefaultIsolationUDP", func(t *testing.T) { testNodeACNPAllowNoDefaultIsolation(t, ProtocolUDP) })
	t.Run("Case=ACNPAllowNoDefaultIsolationSCTP", func(t *testing.T) { testNodeACNPAllowNoDefaultIsolation(t, ProtocolSCTP) })
	t.Run("Case=ACNPDropEgress", func(t *testing.T) { testNodeACNPDropEgress(t, ProtocolTCP) })
	t.Run("Case=ACNPDropEgressUDP", func(t *testing.T) { testNodeACNPDropEgress(t, ProtocolUDP) })
	t.Run("Case=ACNPDropEgressSCTP", func(t *testing.T) { testNodeACNPDropEgress(t, ProtocolSCTP) })
	t.Run("Case=ACNPDropIngress", func(t *testing.T) { testNodeACNPDropIngress(t, ProtocolTCP) })
	t.Run("Case=ACNPDropIngressUDP", func(t *testing.T) { testNodeACNPDropIngress(t, ProtocolUDP) })
	t.Run("Case=ACNPDropIngressSCTP", func(t *testing.T) { testNodeACNPDropIngress(t, ProtocolSCTP) })
	t.Run("Case=ACNPPortRange", func(t *testing.T) { testNodeACNPPortRange(t) })
	t.Run("Case=ACNPSourcePort", func(t *testing.T) { testNodeACNPSourcePort(t) })
	t.Run("Case=ACNPRejectEgress", func(t *testing.T) { testNodeACNPRejectEgress(t, ProtocolTCP) })
	t.Run("Case=ACNPRejectEgressUDP", func(t *testing.T) { testNodeACNPRejectEgress(t, ProtocolUDP) })
	t.Run("Case=ACNPRejectEgressSCTP", func(t *testing.T) { testNodeACNPRejectEgress(t, ProtocolSCTP) })
	t.Run("Case=ACNPRejectIngress", func(t *testing.T) { testNodeACNPRejectIngress(t, ProtocolTCP) })
	t.Run("Case=ACNPRejectIngressUDP", func(t *testing.T) { testNodeACNPRejectIngress(t, ProtocolUDP) })
	t.Run("Case=ACNPNoEffectOnOtherProtocols", func(t *testing.T) { testNodeACNPNoEffectOnOtherProtocols(t) })
	t.Run("Case=ACNPPriorityOverride", func(t *testing.T) { testNodeACNPPriorityOverride(t) })
	t.Run("Case=ACNPTierOverride", func(t *testing.T) { testNodeACNPTierOverride(t) })
	t.Run("Case=ACNPCustomTiers", func(t *testing.T) { testNodeACNPCustomTiers(t) })
	t.Run("Case=ACNPPriorityConflictingRule", func(t *testing.T) { testNodeACNPPriorityConflictingRule(t) })

	k8sUtils.Cleanup(namespaces)

	initializeAntreaNodeNetworkPolicy(t, data, false)

	t.Run("Case=ACNPNamespaceIsolation", func(t *testing.T) { testNodeACNPNamespaceIsolation(t) })
	t.Run("Case=ACNPClusterGroupUpdate", func(t *testing.T) { testNodeACNPClusterGroupUpdate(t) })
	t.Run("Case=ACNPClusterGroupRefRuleIPBlocks", func(t *testing.T) { testNodeACNPClusterGroupRefRuleIPBlocks(t) })
	t.Run("Case=ACNPNestedClusterGroup", func(t *testing.T) { testNodeACNPNestedClusterGroupCreateAndUpdate(t, data) })
	t.Run("Case=ACNPNestedIPBlockClusterGroup", func(t *testing.T) { testNodeACNPNestedIPBlockClusterGroupCreateAndUpdate(t) })

	k8sUtils.Cleanup(namespaces)
}

// testNodeACNPAllowNoDefaultIsolation tests that no default isolation rules are created for ACNPs applied to Node.
func testNodeACNPAllowNoDefaultIsolation(t *testing.T, protocol AntreaPolicyProtocol) {
	if protocol == ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-allow-x-from-y-ingress").
		SetPriority(1.1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder1.AddIngress(protocol, &p81, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-allow-x-to-y-egress").
		SetPriority(1.1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder2.AddEgress(protocol, &p81, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	testStep := []*TestStep{
		{
			Name:          "Port 81",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder1.Get(), builder2.Get()},
			Ports:         []int32{81},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow No Default Isolation", testStep},
	}
	executeTests(t, testCase)
}

// testNodeACNPDropEgress tests that an ACNP applied to Node is able to drop egress traffic from Node x to Node y.
func testNodeACNPDropEgress(t *testing.T, protocol AntreaPolicyProtocol) {
	if protocol == ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	if protocol == ProtocolUDP {
		// For UDP, when action `Reject` or `Drop` is specified in an egress rule, agnhost got the unexpected message immediately
		// like the follows.
		//   UNKNOWN: write udp 172.18.0.3:58150->172.18.0.2:80: write: operation not permitted
		//   UNKNOWN: write udp 172.18.0.3:58150->172.18.0.2:80: write: operation not permitted
		//   UNKNOWN: write udp 172.18.0.3:58150->172.18.0.2:80: write: operation not permitted
		t.Skip("Skipping test as dropping UDP egress traffic doesn't return the expected stdout or stderr message")
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-drop-x-to-y-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From Node:x to Node:y", testStep},
	}
	executeTests(t, testCase)
}

// testNodeACNPDropIngress tests that an ACNP applied to Node is able to drop ingress traffic from Node y to Node x.
func testNodeACNPDropIngress(t *testing.T, protocol AntreaPolicyProtocol) {
	if protocol == ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-drop-x-from-y-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Ingress From Node:y to Node:x", testStep},
	}
	executeTests(t, testCase)
}

// testACNPPortRange tests the port range in an ACNP applied to Node can work.
func testNodeACNPPortRange(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-drop-x-to-y-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddEgress(ProtocolTCP, &p8080, nil, &p8082, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "acnp-port-range", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	testSteps := []*TestStep{
		{
			Name:          fmt.Sprintf("ACNP Drop Ports 8080:8082"),
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{8080, 8081, 8082},
			Protocol:      ProtocolTCP,
		},
	}

	testCase := []*TestCase{
		{"ACNP Drop Egress From Node:x to Node:y with a portRange", testSteps},
	}
	executeTests(t, testCase)
}

// testNodeACNPSourcePort tests ACNP applied to Node source port filtering. The agnhost image used in E2E tests uses
// ephemeral ports to initiate TCP connections, which should be 32768–60999 by default  (https://en.wikipedia.org/wiki/Ephemeral_port).
// This test retrieves the port range from the client Pod and uses it in sourcePort and sourceEndPort of an ACNP rule to
// verify that packets can be matched by source port.
func testNodeACNPSourcePort(t *testing.T) {
	portStart, portEnd, err := k8sUtils.getTCPv4SourcePortRangeFromPod(getNS("x"), "a")
	failOnError(err, t)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-source-port").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddIngressForSrcPort(ProtocolTCP, nil, nil, &portStart, &portEnd, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, false, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-source-port").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder2.AddIngressForSrcPort(ProtocolTCP, &p80, nil, &portStart, &portEnd, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, false, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-source-port").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder3.AddIngressForSrcPort(ProtocolTCP, &p80, &p81, &portStart, &portEnd, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, false, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)
	// After adding the dst port constraint of port 80, traffic on port 81 should not be affected.
	updatedReachability := NewReachability(allPods, Connected)

	testSteps := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "Port 81",
			Reachability:  updatedReachability,
			TestResources: []metav1.Object{builder2.Get()},
			Ports:         []int32{81},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "Port range 80-81",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder3.Get()},
			Ports:         []int32{80, 81},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Node:y to Node:x based on source port", testSteps},
	}
	executeTests(t, testCase)
}

// testNodeACNPRejectEgress tests that an ACNP applied to Node is able to reject egress traffic from Node x to Node y.
func testNodeACNPRejectEgress(t *testing.T, protocol AntreaPolicyProtocol) {
	if protocol == ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	if protocol == ProtocolUDP {
		// For UDP, when action `Reject` or `Drop` is specified in an egress rule, agnhost got the unexpected message immediately
		// like the follows.
		//   UNKNOWN: write udp 172.18.0.3:58150->172.18.0.2:80: write: operation not permitted
		//   UNKNOWN: write udp 172.18.0.3:58150->172.18.0.2:80: write: operation not permitted
		//   UNKNOWN: write udp 172.18.0.3:58150->172.18.0.2:80: write: operation not permitted
		t.Skip("Skipping test as dropping UDP egress traffic doesn't return the expected stdout or stderr message")
	}

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-x-to-y-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	reachability := NewReachability(allPods, Connected)

	expectedResult := Rejected
	// For SCTP, when action `Rejected` is specified in an egress rule, it behaves identical to action `Dropped`.
	if protocol == ProtocolSCTP {
		expectedResult = Dropped
	}
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), expectedResult)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{"ACNP Reject Egress From Node:x to Node:y", testStep},
	}
	executeTests(t, testCase)
}

// testNodeACNPRejectIngress tests that an ACNP applied Node to is able to reject ingress traffic from Node y to Node x.
func testNodeACNPRejectIngress(t *testing.T, protocol AntreaPolicyProtocol) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-x-from-y-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("y", "a"), getPod("x", "a"), Rejected)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{"ACNP Reject ingress from Node:y to Node:x", testStep},
	}
	executeTests(t, testCase)
}

// testNodeACNPNoEffectOnOtherProtocols tests that an ACNP applied Node which drops TCP traffic won't affect other protocols (e.g. UDP).
func testNodeACNPNoEffectOnOtherProtocols(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-drop-x-from-y-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability1 := NewReachability(allPods, Connected)
	reachability1.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)

	reachability2 := NewReachability(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability1,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "Port 80",
			Reachability:  reachability2,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolUDP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Ingress From Node:y to Node:x TCP Not UDP", testStep},
	}
	executeTests(t, testCase)
}

// testNodeACNPPriorityOverride tests priority overriding in three ACNPs applied to Node. Those three ACNPs are synced in
// a specific order to test priority reassignment, and each controls a smaller set of traffic patterns as priority increases.
func testNodeACNPPriorityOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-priority1").
		SetPriority(1.001).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// Highest priority. Drops traffic from y to x.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority2").
		SetPriority(1.002).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// Medium priority. Allows traffic from y to x.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-priority3").
		SetPriority(1.003).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// Lowest priority. Drops traffic from y to x.
	builder3.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)

	testStepTwoACNP := []*TestStep{
		{
			Name:          "Two Policies with different priorities",
			Reachability:  reachabilityTwoACNPs,
			TestResources: []metav1.Object{builder3.Get(), builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	// Create the Policies in specific order to make sure that priority re-assignments work as expected.
	testStepAll := []*TestStep{
		{
			Name:          "All three Policies",
			Reachability:  reachabilityAllACNPs,
			TestResources: []metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP PriorityOverride Intermediate", testStepTwoACNP},
		{"ACNP PriorityOverride All", testStepAll},
	}
	executeTests(t, testCase)
}

// testNodeACNPTierOverride tests tier priority overriding in three ACNPs applied to Node. Each ACNP controls a smaller
// set of traffic patterns as tier priority increases.
func testNodeACNPTierOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-emergency").
		SetTier("emergency").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// Highest priority tier. Drops traffic from y to x.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-securityops").
		SetTier("securityops").
		SetPriority(10).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	// Medium priority tier. Allows traffic from y to x.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-tier-application").
		SetTier("application").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	// Lowest priority tier. Drops traffic from y to x.
	builder3.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)

	testStepTwoACNP := []*TestStep{
		{
			Name:          "Two Policies in different tiers",
			Reachability:  reachabilityTwoACNPs,
			TestResources: []metav1.Object{builder3.Get(), builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testStepAll := []*TestStep{
		{
			Name:          "All three Policies in different tiers",
			Reachability:  reachabilityAllACNPs,
			TestResources: []metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP TierOverride Intermediate", testStepTwoACNP},
		{"ACNP TierOverride All", testStepAll},
	}
	executeTests(t, testCase)
}

// testNodeACNPCustomTiers tests tier priority overriding in two ACNPs applied to Node with custom created tiers. Each ACNP
// controls a smaller set of traffic patterns as tier priority increases.
func testNodeACNPCustomTiers(t *testing.T) {
	k8sUtils.DeleteTier("high-priority")
	k8sUtils.DeleteTier("low-priority")
	// Create two custom tiers with tier priority immediately next to each other.
	_, err := k8sUtils.CreateTier("high-priority", 245)
	failOnError(err, t)
	_, err = k8sUtils.CreateTier("low-priority", 246)
	failOnError(err, t)

	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-high").
		SetTier("high-priority").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// Medium priority tier. Allows traffic from y to x.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-low").
		SetTier("low-priority").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// Lowest priority tier. Drops traffic from y to x.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachabilityOneACNP := NewReachability(allPods, Connected)
	reachabilityOneACNP.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)
	testStepOneACNP := []*TestStep{
		{
			Name:          "One Policy",
			Reachability:  reachabilityOneACNP,
			TestResources: []metav1.Object{builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	testStepTwoACNP := []*TestStep{
		{
			Name:          "Two Policies in different tiers",
			Reachability:  reachabilityTwoACNPs,
			TestResources: []metav1.Object{builder2.Get(), builder1.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Custom Tier priority with one policy", testStepOneACNP},
		{"ACNP Custom Tier priority with two policies", testStepTwoACNP},
	}
	executeTests(t, testCase)
	// Cleanup customized tiers. ACNPs created in those tiers need to be deleted first.
	failOnError(k8sUtils.CleanACNPs(), t)
	failOnError(k8sUtils.DeleteTier("high-priority"), t)
	failOnError(k8sUtils.DeleteTier("low-priority"), t)
	time.Sleep(networkPolicyDelay)
}

// testNodeACNPPriorityConflictingRule tests that if there are two ACNPs applied to Node in the cluster with rules that
// conflicts with each other, the ACNP with higher priority will prevail.
func testNodeACNPPriorityConflictingRule(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-drop").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(2).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	// The following ingress rule will take no effect as it is exactly the same as ingress rule of cnp-drop,
	// but cnp-allow has lower priority.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{labelNodeHostname: nodes["y"]}, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.Expect(getPod("y", "a"), getPod("x", "a"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Both ACNP",
			Reachability:  reachabilityBothACNP,
			TestResources: []metav1.Object{builder1.Get(), builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Priority Conflicting Rule", testStep},
	}
	executeTests(t, testCase)
}

func testNodeACNPNamespaceIsolation(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("test-acnp-ns-isolation").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder1.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("y")}, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability1 := NewReachability(allPods, Connected)
	reachability1.ExpectEgressToNamespace(getPod("x", "a"), getNS("y"), Dropped)
	testStep1 := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability1,
		TestResources: []metav1.Object{builder1.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testCase := []*TestCase{
		{"ACNP Namespace isolation for namespace y", []*TestStep{testStep1}},
	}
	executeTests(t, testCase)
}

func testNodeACNPClusterGroupUpdate(t *testing.T) {
	cgName := "cg-ns-z-then-y"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": getNS("z")}, nil)
	// Update CG NS selector to group Pods from Namespace Y
	updatedCgBuilder := &ClusterGroupSpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("y"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{cgBuilder.Get(), builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "Port 80 - update",
			Reachability:  updatedReachability,
			TestResources: []metav1.Object{updatedCgBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From Node:x to ClusterGroup with NS:z updated to ClusterGroup with NS:y", testStep},
	}
	executeTests(t, testCase)
}

func testNodeACNPClusterGroupRefRuleIPBlocks(t *testing.T) {
	podYAIP, _ := podIPs[getNS("y")+"/a"]
	podZAIP, _ := podIPs[getNS("z")+"/a"]
	// There are three situations of a Pod's IP(s):
	// 1. Only one IPv4 address.
	// 2. Only one IPv6 address.
	// 3. One IPv4 and one IPv6 address, and we don't know the order in list.
	// We need to add all IP(s) of Pods as CIDR to IPBlock.
	genCIDR := func(ip string) string {
		if strings.Contains(ip, ".") {
			return ip + "/32"
		}
		return ip + "/128"
	}
	var ipBlock1, ipBlock2 []crdv1beta1.IPBlock
	for i := 0; i < len(podYAIP); i++ {
		ipBlock1 = append(ipBlock1, crdv1beta1.IPBlock{CIDR: genCIDR(podYAIP[i])})
		ipBlock2 = append(ipBlock2, crdv1beta1.IPBlock{CIDR: genCIDR(podZAIP[i])})
	}

	cgName := "cg-ipblocks-pod-in-ns-y"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetIPBlocks(ipBlock1)
	cgName2 := "cg-ipblock-pod-in-ns-z"
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cgName2).
		SetIPBlocks(ipBlock2)

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-x-to-yz-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName2, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("x", "a"), getPod("z", "a"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get(), cgBuilder.Get(), cgBuilder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From Node x to Pod y/a and z/a to ClusterGroup with ipBlocks", testStep},
	}
	executeTests(t, testCase)
}

func testNodeACNPNestedClusterGroupCreateAndUpdate(t *testing.T, data *TestData) {
	cg1Name := "cg-1"
	cgBuilder1 := &ClusterGroupSpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil)
	cgNestedName := "cg-nested"
	cgBuilderNested := &ClusterGroupSpecBuilder{}
	cgBuilderNested = cgBuilderNested.SetName(cgNestedName).SetChildGroups([]string{cg1Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-nested-cg").SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}}).
		AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil, crdv1beta1.RuleActionDrop, cgNestedName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("y"), Dropped)
	testStep1 := &TestStep{
		Name:         "Port 80",
		Reachability: reachability,
		// Note in this testcase the ClusterGroup is created after the ACNP
		TestResources: []metav1.Object{builder.Get(), cgBuilder1.Get(), cgBuilderNested.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	cg2Name := "cg-2"
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetNamespaceSelector(map[string]string{"ns": getNS("z")}, nil)
	cgBuilderNested = cgBuilderNested.SetChildGroups([]string{cg2Name})
	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	testStep2 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{cgBuilder2.Get(), cgBuilderNested.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testSteps := []*TestStep{testStep1, testStep2}
	testCase := []*TestCase{
		{"ACNP nested ClusterGroup create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testNodeACNPNestedIPBlockClusterGroupCreateAndUpdate(t *testing.T) {
	podYAIP, _ := podIPs[getPodName("y", "a")]
	podZAIP, _ := podIPs[getPodName("z", "a")]
	genCIDR := func(ip string) string {
		switch IPFamily(ip) {
		case "v4":
			return ip + "/32"
		case "v6":
			return ip + "/128"
		default:
			return ""
		}
	}
	cg1Name, cg2Name := "cg-y", "cg-z"
	cgParentName := "cg-parent"
	var ipBlockYA, ipBlockZA []crdv1beta1.IPBlock
	for i := 0; i < len(podYAIP); i++ {
		ipBlockYA = append(ipBlockYA, crdv1beta1.IPBlock{CIDR: genCIDR(podYAIP[i])})
		ipBlockZA = append(ipBlockZA, crdv1beta1.IPBlock{CIDR: genCIDR(podZAIP[i])})
	}
	cgBuilder1 := &ClusterGroupSpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetIPBlocks(ipBlockYA)
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetIPBlocks(ipBlockZA)
	cgParent := &ClusterGroupSpecBuilder{}
	cgParent = cgParent.SetName(cgParentName).SetChildGroups([]string{cg1Name, cg2Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-x-to-yz-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NodeSelector: map[string]string{labelNodeHostname: nodes["x"]}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgParentName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("x", "a"), getPod("z", "a"), Dropped)
	testStep := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get(), cgBuilder1.Get(), cgBuilder2.Get(), cgParent.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	cgParent = cgParent.SetChildGroups([]string{cg1Name})

	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	testStep2 := &TestStep{
		Name:          "Port 80, updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{cgParent.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testCase := []*TestCase{
		{"ACNP Drop Ingress From Node x to Pod y/a and z/a with nested ClusterGroup with ipBlocks", []*TestStep{testStep, testStep2}},
	}
	executeTests(t, testCase)
}
