// Copyright 2022 Antrea Authors
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
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"testing"

	annotation "antrea.io/antrea/pkg/ipam"
	e2eutils "antrea.io/antrea/test/e2e/utils"
)

var (
	antreaIPAMAntreaPolicyNamespaces = []string{testAntreaIPAMNamespaceX, testAntreaIPAMNamespaceX11, testAntreaIPAMNamespaceX12}
)

// initializeAntreaIPAM must be called after namespace in antreaIPAMAntreaPolicyNamespaces created
func initializeAntreaIPAM(t *testing.T, data *TestData) {
	p80 = 80
	p81 = 81
	p8080 = 8080
	p8081 = 8081
	p8082 = 8082
	p8085 = 8085
	pods = []string{"a", "b", "c"}
	namespaces = make(map[string]string)
	regularNamespaces := make(map[string]string)
	suffix := randName("")
	namespaces["x"] = "x-" + suffix
	regularNamespaces["x"] = namespaces["x"]
	// This function "initializeAntreaIPAM" will be used more than once, and variable "allPods" is global.
	// It should be empty every time when "initializeAntreaIPAM" is performed, otherwise there will be unexpected
	// results.
	allPods = []Pod{}
	podsByNamespace = make(map[string][]Pod)

	for _, ns := range antreaIPAMAntreaPolicyNamespaces {
		namespaces[ns] = ns
	}

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
			podsByNamespace[ns] = append(podsByNamespace[ns], NewPod(ns, podName))
		}
	}

	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	_, err = k8sUtils.Bootstrap(regularNamespaces, pods, true)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, pods, false)
	failOnError(err, t)
	podIPs = *ips
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
	for _, namespace := range antreaIPAMAntreaPolicyNamespaces {
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
		t.Run("Case=ACNPDrop", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolTCP, Dropped) })
		t.Run("Case=ACNPDropUDP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolUDP, Dropped) })
		t.Run("Case=ACNPDropSCTP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolSCTP, Dropped) })
		t.Run("Case=ACNPReject", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolTCP, Rejected) })
		t.Run("Case=ACNPRejectUDP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolUDP, Rejected) })
		t.Run("Case=ACNPRejectSCTP", func(t *testing.T) { testAntreaIPAMACNP(t, e2eutils.ProtocolSCTP, Rejected) })
		//t.Run("Case=RejectServiceTraffic", func(t *testing.T) { testRejectServiceTraffic(t, data) })
		//t.Run("Case=RejectNoInfiniteLoop", func(t *testing.T) { testRejectNoInfiniteLoop(t, data) })
	})
	// print results for reachability tests
	printResults()

	k8sUtils.Cleanup(namespaces)
}

func testAntreaIPAMACNP(t *testing.T, protocol e2eutils.AntreaPolicyProtocol, action PodConnectivityMark) {
	if protocol == e2eutils.ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	var ruleAction crdv1alpha1.RuleAction
	switch action {
	case Dropped:
		ruleAction = crdv1alpha1.RuleActionDrop
	case Rejected:
		ruleAction = crdv1alpha1.RuleActionReject
	default:
		ruleAction = crdv1alpha1.RuleActionAllow
	}
	builder := &e2eutils.ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(fmt.Sprintf("acnp-%s-a-to-b-egress-c-to-a-ingress", strings.ToLower(string(ruleAction)))).
		SetPriority(1.0).
		SetAppliedToGroup([]e2eutils.ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil,
		nil, nil, false, nil, ruleAction, "", "", nil)
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil,
		nil, nil, false, nil, ruleAction, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	for _, srcNamespace := range namespaces {
		for _, dstNamespace := range namespaces {
			reachability.Expect(Pod(srcNamespace+"/a"), Pod(dstNamespace+"/b"), action)
			reachability.Expect(Pod(srcNamespace+"/c"), Pod(dstNamespace+"/a"), action)
		}
	}
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			protocol,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{fmt.Sprintf("ACNP %s Egress From All Pod:a to Pod:b and Ingress From All Pod:c to Pod:a", string(ruleAction)), testStep},
	}
	executeTests(t, testCase)
}
