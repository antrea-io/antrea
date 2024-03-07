// Copyright 2023 Antrea Authors
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	annotation "antrea.io/antrea/pkg/ipam"
	e2eutils "antrea.io/antrea/test/e2e/utils"
)

// initializeAntreaIPAM must be called after Namespace in antreaIPAMNamespaces created
func initializeAntreaIPAM(t *testing.T, data *TestData) {
	podsPerNamespace = []string{"a", "b", "c"}
	namespaces = make(map[string]TestNamespaceMeta)
	regularNamespaces := make(map[string]TestNamespaceMeta)
	suffix := randName("")
	namespaces["x"] = TestNamespaceMeta{
		Name: "antrea-x-" + suffix,
	}
	regularNamespaces["x"] = namespaces["x"]
	// This function "initializeAntreaIPAM" will be used more than once, and variable "allPods" is global.
	// It should be empty every time when "initializeAntreaIPAM" is performed, otherwise there will be unexpected
	// results.
	allPods = []Pod{}
	podsByNamespace = make(map[string][]Pod)
	for _, ns := range antreaIPAMNamespaces {
		namespaces[ns] = TestNamespaceMeta{Name: ns}
	}
	for _, podName := range podsPerNamespace {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns.Name, podName))
			podsByNamespace[ns.Name] = append(podsByNamespace[ns.Name], NewPod(ns.Name, podName))
		}
	}

	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	_, err = k8sUtils.Bootstrap(regularNamespaces, podsPerNamespace, true, nil, nil)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, podsPerNamespace, false, nil, nil)
	failOnError(err, t)
	podIPs = ips
}

func TestAntreaIPAMAntreaPolicy(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	for _, namespace := range antreaIPAMNamespaces {
		ipPool, err := createIPPool(t, data, namespace)
		if err != nil {
			t.Fatalf("Creating IPPool failed, err=%+v", err)
		}
		defer deleteIPPoolWrapper(t, data, ipPool.Name)
		annotations := map[string]string{}
		annotations[annotation.AntreaIPAMAnnotationKey] = ipPool.Name
		err = data.createNamespaceWithAnnotations(namespace, annotations)
		if err != nil {
			t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
		}
		defer deleteAntreaIPAMNamespace(t, data, namespace)
	}
	initializeAntreaIPAM(t, data)

	t.Run("TestGroupNoK8sNP", func(t *testing.T) {
		// testcases below do not depend on underlying default-deny K8s NetworkPolicies.
		t.Run("Case=ACNPAllowNoDefaultIsolationTCP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, e2eutils.ProtocolTCP) })
		t.Run("Case=ACNPAllowNoDefaultIsolationUDP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, e2eutils.ProtocolUDP) })
		t.Run("Case=ACNPAllowNoDefaultIsolationSCTP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, e2eutils.ProtocolSCTP) })
		t.Run("Case=ACNPEgressDrop", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolTCP, Dropped, false) })
		t.Run("Case=ACNPEgressDropUDP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolUDP, Dropped, false) })
		t.Run("Case=ACNPEgressDropSCTP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolSCTP, Dropped, false) })
		t.Run("Case=ACNPIngressDrop", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolTCP, Dropped, true) })
		t.Run("Case=ACNPIngressDropUDP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolUDP, Dropped, true) })
		t.Run("Case=ACNPIngressDropSCTP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolSCTP, Dropped, true) })

		t.Run("Case=ACNPEgressReject", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolTCP, Rejected, false) })
		t.Run("Case=ACNPEgressRejectUDP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolUDP, Rejected, false) })
		t.Run("Case=ACNPIngressReject", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolTCP, Rejected, true) })
		t.Run("Case=ACNPIngressRejectUDP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolUDP, Rejected, true) })

		t.Run("Case=RejectServiceTrafficAntreaIPAMToAntreaIPAM", func(t *testing.T) {
			testRejectServiceTraffic(t, data, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
		})
		t.Run("Case=RejectServiceTrafficAntreaIPAMVLAN11ToAntreaIPAMVLAN11", func(t *testing.T) {
			testRejectServiceTraffic(t, data, testAntreaIPAMNamespace11, testAntreaIPAMNamespace11)
		})
		t.Run("Case=RejectServiceTrafficRegularToAntreaIPAM", func(t *testing.T) { testRejectServiceTraffic(t, data, data.testNamespace, testAntreaIPAMNamespace) })
		t.Run("Case=RejectServiceTrafficRegularToAntreaIPAMVLAN11", func(t *testing.T) { testRejectServiceTraffic(t, data, data.testNamespace, testAntreaIPAMNamespace11) })
		t.Run("Case=RejectServiceTrafficAntreaIPAMToAntreaIPAMVLAN11", func(t *testing.T) {
			testRejectServiceTraffic(t, data, testAntreaIPAMNamespace, testAntreaIPAMNamespace11)
		})
		t.Run("Case=RejectServiceTrafficAntreaIPAMToRegular", func(t *testing.T) { testRejectServiceTraffic(t, data, testAntreaIPAMNamespace, data.testNamespace) })
		t.Run("Case=RejectServiceTrafficAntreaIPAMVLAN11ToRegular", func(t *testing.T) { testRejectServiceTraffic(t, data, testAntreaIPAMNamespace11, data.testNamespace) })
		t.Run("Case=RejectServiceTrafficAntreaIPAMVLAN11ToAntreaIPAM", func(t *testing.T) {
			testRejectServiceTraffic(t, data, testAntreaIPAMNamespace11, testAntreaIPAMNamespace)
		})
		t.Run("Case=RejectServiceTrafficAntreaIPAMVLAN11ToAntreaIPAMVLAN12", func(t *testing.T) {
			testRejectServiceTraffic(t, data, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12)
		})

		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMToAntreaIPAM", func(t *testing.T) {
			testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
		})
		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMVLAN11ToAntreaIPAMVLAN11", func(t *testing.T) {
			testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace11, testAntreaIPAMNamespace11)
		})
		t.Run("Case=RejectNoInfiniteLoopRegularToAntreaIPAM", func(t *testing.T) { testRejectNoInfiniteLoop(t, data, data.testNamespace, testAntreaIPAMNamespace) })
		t.Run("Case=RejectNoInfiniteLoopRegularToAntreaIPAMVLAN11", func(t *testing.T) { testRejectNoInfiniteLoop(t, data, data.testNamespace, testAntreaIPAMNamespace11) })
		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMToAntreaIPAMVLAN11", func(t *testing.T) {
			testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace, testAntreaIPAMNamespace11)
		})
		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMToRegular", func(t *testing.T) { testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace, data.testNamespace) })
		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMVLAN11ToRegular", func(t *testing.T) { testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace11, data.testNamespace) })
		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMVLAN11ToAntreaIPAM", func(t *testing.T) {
			testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace11, testAntreaIPAMNamespace)
		})
		t.Run("Case=RejectNoInfiniteLoopAntreaIPAMVLAN11ToAntreaIPAMVLAN12", func(t *testing.T) {
			testRejectNoInfiniteLoop(t, data, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12)
		})

		t.Run("Case=ACNPAntreaIPAMNodePortServiceSupport", func(t *testing.T) { testACNPNodePortServiceSupport(t, data, testAntreaIPAMNamespace) })
		t.Run("Case=ACNPAntreaIPAMVLAN11NodePortServiceSupport", func(t *testing.T) { testACNPNodePortServiceSupport(t, data, testAntreaIPAMNamespace11) })
		t.Run("Case=ACNPAntreaIPAMMulticast", func(t *testing.T) { testMulticastNP(t, data, testAntreaIPAMNamespace) })
	})
	// print results for reachability tests
	printResults()

	k8sUtils.Cleanup(namespaces)
}

func testAntreaIPAMACNP(t *testing.T, protocol e2eutils.AntreaPolicyProtocol, action PodConnectivityMark, isIngress bool) {
	if protocol == e2eutils.ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	var ruleAction crdv1beta1.RuleAction
	switch action {
	case Dropped:
		ruleAction = crdv1beta1.RuleActionDrop
	case Rejected:
		ruleAction = crdv1beta1.RuleActionReject
	default:
		ruleAction = crdv1beta1.RuleActionAllow
	}
	builder := &e2eutils.ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(fmt.Sprintf("acnp-%s-a", strings.ToLower(string(ruleAction)))).
		SetPriority(1.0).
		SetAppliedToGroup([]e2eutils.ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder2 := &e2eutils.ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName(fmt.Sprintf("acnp-%s-b", strings.ToLower(string(ruleAction)))).
		SetPriority(1.0).
		SetAppliedToGroup([]e2eutils.ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder3 := &e2eutils.ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName(fmt.Sprintf("acnp-%s-c", strings.ToLower(string(ruleAction)))).
		SetPriority(1.0).
		SetAppliedToGroup([]e2eutils.ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "c"}}})
	if isIngress {
		builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
			nil, nil, nil, nil, nil, nil, ruleAction, "", "", nil)
		builder2.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
			nil, nil, nil, nil, nil, nil, ruleAction, "", "", nil)
		builder3.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
			nil, nil, nil, nil, nil, nil, ruleAction, "", "", nil)
	} else {
		builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
			nil, nil, nil, nil, nil, nil, ruleAction, "", "", nil)
		builder2.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
			nil, nil, nil, nil, nil, nil, ruleAction, "", "", nil)
		builder3.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
			nil, nil, nil, nil, nil, nil, ruleAction, "", "", nil)
	}

	reachability := NewReachability(allPods, action)
	reachability.ExpectSelf(allPods, Connected)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get(), builder2.Get(), builder3.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{fmt.Sprintf("ACNP %s for all Pods, ingress=%v", string(ruleAction), isIngress), testStep},
	}
	executeTests(t, testCase)
}
