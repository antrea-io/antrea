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

package netpol_conformance

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreaTestFramework "antrea.io/antrea/test/e2e"
	antreaTestUtil "antrea.io/antrea/test/e2e/utils"
)

var (
	allPods    []antreaTestFramework.Pod
	k8sUtils   *antreaTestFramework.KubernetesUtils
	namespaces map[string]string
	p80        int32
)

// testANNPDropIngressEgress tests that an ANNP is able to drop ingress traffic
// from X/B to Y/A and drop egress traffic from Y/A to Z/C for the provided protocol.
func testANNPDropIngressEgress(t *testing.T, protocol antreaTestUtil.AntreaPolicyProtocol) {
	if protocol == antreaTestUtil.ProtocolSCTP {
		antreaTestFramework.SkipIfIPv6Cluster(t)
	}
	builder := &antreaTestUtil.AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "annp-deny-xb-to-ya-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]antreaTestUtil.ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": namespaces["z"]}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")

	reachability := antreaTestFramework.NewReachability(allPods, antreaTestFramework.Connected)
	reachability.Expect(antreaTestFramework.Pod(namespaces["x"]+"/b"), antreaTestFramework.Pod(namespaces["y"]+"/a"), antreaTestFramework.Dropped)
	reachability.Expect(antreaTestFramework.Pod(namespaces["y"]+"/a"), antreaTestFramework.Pod(namespaces["z"]+"/c"), antreaTestFramework.Dropped)
	testStep := []*antreaTestFramework.TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
			Duration:      0,
			CustomProbes:  nil,
		},
	}
	testCase := []*antreaTestFramework.TestCase{
		{Name: "ANNP Drop Ingress From X/B to Y/A And Egress From Y/A to Z/C", Steps: testStep},
	}
	antreaTestFramework.ExecuteTests(t, testCase)
}

// testANNPMultipleAppliedTo tests traffic from X/B to Y/A and Y/C will be dropped,
// after applying Antrea NetworkPolicy that applies to multiple AppliedTos.
func testANNPMultipleAppliedTo(t *testing.T, protocol antreaTestUtil.AntreaPolicyProtocol) {
	if protocol == antreaTestUtil.ProtocolSCTP {
		antreaTestFramework.SkipIfIPv6Cluster(t)
	}
	builder := &antreaTestUtil.AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "np-multiple-appliedto").SetPriority(1.0)
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, []antreaTestUtil.ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}, crdv1beta1.RuleActionDrop, "", "")
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, []antreaTestUtil.ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "c"}}}, crdv1beta1.RuleActionDrop, "", "")

	reachability := antreaTestFramework.NewReachability(allPods, antreaTestFramework.Connected)
	reachability.Expect(antreaTestFramework.Pod(namespaces["x"]+"/b"), antreaTestFramework.Pod(namespaces["y"]+"/a"), antreaTestFramework.Dropped)
	reachability.Expect(antreaTestFramework.Pod(namespaces["x"]+"/b"), antreaTestFramework.Pod(namespaces["y"]+"/c"), antreaTestFramework.Dropped)
	testStep := []*antreaTestFramework.TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      protocol,
			Duration:      0,
			CustomProbes:  nil,
		},
	}
	testCase := []*antreaTestFramework.TestCase{
		{Name: "ANNP Drop Ingress From X/B to Y/A", Steps: testStep},
	}
	antreaTestFramework.ExecuteTests(t, testCase)
}

func TestAntreaNetworkPolicyConformance(t *testing.T) {
	data, err := antreaTestFramework.SetupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer antreaTestFramework.TeardownTest(t, data)

	antreaTestFramework.InitializeTestbed(t, data)
	getTestbedInfo()

	t.Run("AntreaNetworkPolicyConformance", func(t *testing.T) {
		t.Run("Case=ANNPDropIngressEgressTCP", func(t *testing.T) { testANNPDropIngressEgress(t, antreaTestUtil.ProtocolTCP) })
		t.Run("Case=ANNPDropIngressEgressUDP", func(t *testing.T) { testANNPDropIngressEgress(t, antreaTestUtil.ProtocolUDP) })
		t.Run("Case=ANNPDropIngressEgressSCTP", func(t *testing.T) { testANNPDropIngressEgress(t, antreaTestUtil.ProtocolSCTP) })
		t.Run("Case=ANNPMultipleAppliedToTCP", func(t *testing.T) { testANNPMultipleAppliedTo(t, antreaTestUtil.ProtocolTCP) })
		t.Run("Case=ANNPMultipleAppliedToUDP", func(t *testing.T) { testANNPMultipleAppliedTo(t, antreaTestUtil.ProtocolUDP) })
		t.Run("Case=ANNPMultipleAppliedToSCTP", func(t *testing.T) { testANNPMultipleAppliedTo(t, antreaTestUtil.ProtocolSCTP) })
	})

	antreaTestFramework.PrintResults()

	k8sUtils.Cleanup(namespaces)
}

func getTestbedInfo() {
	p80 = 80
	k8sUtils = antreaTestFramework.GetTestbedK8sUtils()
	_, namespaces = antreaTestFramework.GetTestbedNamespaces()
	allPods, _, _ = antreaTestFramework.GetTestbedPods()
}
