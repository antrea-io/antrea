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
	"strings"
	"testing"
	"time"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	antreaTestFramework "antrea.io/antrea/test/e2e"
	antreaTestUtil "antrea.io/antrea/test/e2e/utils"
)

var (
	allPods                                     []antreaTestFramework.Pod
	podsByNamespace                             map[string][]antreaTestFramework.Pod
	k8sUtils                                    *antreaTestFramework.KubernetesUtils
	allTestList                                 []*antreaTestFramework.TestCase
	pods                                        []string
	namespaces                                  map[string]string
	podIPs                                      map[string][]string
	p80, p81, p8080, p8081, p8082, p8085, p6443 int32
)

// Verification of deleting/creating resources timed out.
const timeout = 10 * time.Second

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
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			protocol,
			0,
			nil,
		},
	}
	testCase := []*antreaTestFramework.TestCase{
		{"ANNP Drop Ingress From X/B to Y/A And Egress From Y/A to Z/C", testStep},
	}
	executeTests(t, testCase)
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
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			protocol,
			0,
			nil,
		},
	}
	testCase := []*antreaTestFramework.TestCase{
		{"ANNP Drop Ingress From X/B to Y/A", testStep},
	}
	executeTests(t, testCase)
}

func TestAntreaNetworkPolicyConformance(t *testing.T) {
	data, err := antreaTestFramework.SetupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer antreaTestFramework.TeardownTest(t, data)

	initialize(t, data)

	t.Run("AntreaNetworkPolicyConformance", func(t *testing.T) {
		t.Run("Case=ANNPDropIngressEgressTCP", func(t *testing.T) { testANNPDropIngressEgress(t, antreaTestUtil.ProtocolTCP) })
		t.Run("Case=ANNPDropIngressEgressUDP", func(t *testing.T) { testANNPDropIngressEgress(t, antreaTestUtil.ProtocolUDP) })
		t.Run("Case=ANNPDropIngressEgressSCTP", func(t *testing.T) { testANNPDropIngressEgress(t, antreaTestUtil.ProtocolSCTP) })
		t.Run("Case=ANNPMultipleAppliedToTCP", func(t *testing.T) { testANNPMultipleAppliedTo(t, antreaTestUtil.ProtocolTCP) })
		t.Run("Case=ANNPMultipleAppliedToUDP", func(t *testing.T) { testANNPMultipleAppliedTo(t, antreaTestUtil.ProtocolUDP) })
		t.Run("Case=ANNPMultipleAppliedToSCTP", func(t *testing.T) { testANNPMultipleAppliedTo(t, antreaTestUtil.ProtocolSCTP) })
	})

	k8sUtils.Cleanup(namespaces)
}

func initialize(t *testing.T, data *antreaTestFramework.TestData) {
	p80 = 80
	p81 = 81
	p8080 = 8080
	p8081 = 8081
	p8082 = 8082
	p8085 = 8085
	pods = []string{"a", "b", "c"}
	namespaces = make(map[string]string)
	suffix := antreaTestFramework.RandName("")
	namespaces["x"] = "x-" + suffix
	namespaces["y"] = "y-" + suffix
	namespaces["z"] = "z-" + suffix
	// This function "initialize" will be used more than once, and variable "allPods" is global.
	// It should be empty every time when "initialize" is performed, otherwise there will be unexpected
	// results.
	allPods = []antreaTestFramework.Pod{}
	podsByNamespace = make(map[string][]antreaTestFramework.Pod)

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, antreaTestFramework.NewPod(ns, podName))
			podsByNamespace[ns] = append(podsByNamespace[ns], antreaTestFramework.NewPod(ns, podName))
		}
	}

	var err error
	// k8sUtils is a global var
	k8sUtils, err = antreaTestFramework.NewKubernetesUtils(data)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, pods, true)
	failOnError(err, t)
	podIPs = ips
}

func failOnError(err error, t *testing.T) {
	if err != nil {
		log.Errorf("%+v", err)
		k8sUtils.Cleanup(namespaces)
		t.Fatalf("test failed: %v", err)
	}
}

func waitForResourceReady(t *testing.T, timeout time.Duration, obj metav1.Object) error {
	switch p := obj.(type) {
	case *crdv1beta1.ClusterNetworkPolicy:
		return k8sUtils.TestData.WaitForACNPCreationAndRealization(t, p.Name, timeout)
	case *crdv1beta1.NetworkPolicy:
		return k8sUtils.TestData.WaitForANNPCreationAndRealization(t, p.Namespace, p.Name, timeout)
	case *v1net.NetworkPolicy:
		time.Sleep(100 * time.Millisecond)
	case *v1.Service:
		// The minInterval of AntreaProxy's BoundedFrequencyRunner is 1s, which means a Service may be handled after 1s.
		time.Sleep(1 * time.Second)
	case *crdv1beta1.Tier:
	case *crdv1beta1.ClusterGroup:
	case *crdv1beta1.Group:
	}
	return nil
}

func waitForResourcesReady(t *testing.T, timeout time.Duration, objs ...metav1.Object) error {
	resultCh := make(chan error, len(objs))
	for _, obj := range objs {
		go func(o metav1.Object) {
			resultCh <- waitForResourceReady(t, timeout, o)
		}(obj)
	}

	for i := 0; i < len(objs); i++ {
		if err := <-resultCh; err != nil {
			return err
		}
	}
	return nil
}

// applyTestStepResources creates in the resources of a testStep in specified order.
// The ordering can be used to test different scenarios, like creating an ACNP before
// creating its referred ClusterGroup, and vice versa.
func applyTestStepResources(t *testing.T, step *antreaTestFramework.TestStep) {
	for _, r := range step.TestResources {
		switch o := r.(type) {
		case *crdv1beta1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateANNP(o)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(o)
			failOnError(err, t)
		case *crdv1beta1.Group:
			_, err := k8sUtils.CreateOrUpdateGroup(o)
			failOnError(err, t)
		case *v1.Service:
			_, err := k8sUtils.CreateOrUpdateService(o)
			failOnError(err, t)
		}

	}
	failOnError(waitForResourcesReady(t, timeout, step.TestResources...), t)
}

func cleanupTestCaseResources(t *testing.T, c *antreaTestFramework.TestCase) {
	// TestSteps in a TestCase may first create and then update the same resource.
	// Use sets to avoid duplicates.
	annpsToDelete, npsToDelete := sets.Set[string]{}, sets.Set[string]{}
	svcsToDelete, v1a3GroupsToDelete := sets.Set[string]{}, sets.Set[string]{}
	for _, step := range c.Steps {
		for _, r := range step.TestResources {
			switch o := r.(type) {
			case *crdv1beta1.NetworkPolicy:
				annpsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *crdv1beta1.Group:
				v1a3GroupsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}
	for annp := range annpsToDelete {
		namespace := strings.Split(annp, "/")[0]
		name := strings.Split(annp, "/")[1]
		failOnError(k8sUtils.DeleteANNP(namespace, name), t)
	}
	for np := range npsToDelete {
		namespace := strings.Split(np, "/")[0]
		name := strings.Split(np, "/")[1]
		failOnError(k8sUtils.DeleteNetworkPolicy(namespace, name), t)
	}
	for grp := range v1a3GroupsToDelete {
		namespace := strings.Split(grp, "/")[0]
		name := strings.Split(grp, "/")[1]
		failOnError(k8sUtils.DeleteGroup(namespace, name), t)
	}
	for svc := range svcsToDelete {
		namespace := strings.Split(svc, "/")[0]
		name := strings.Split(svc, "/")[1]
		failOnError(k8sUtils.DeleteService(namespace, name), t)
	}
}

// executeTests runs all the tests in testList and prints results
func executeTests(t *testing.T, testList []*antreaTestFramework.TestCase) {
	for _, testCase := range testList {
		log.Infof("running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			applyTestStepResources(t, step)

			reachability := step.Reachability
			if reachability != nil {
				start := time.Now()
				k8sUtils.Validate(allPods, reachability, step.Ports, step.Protocol)
				step.Duration = time.Now().Sub(start)

				_, wrong, _ := step.Reachability.Summary()
				if wrong != 0 {
					t.Errorf("Failure -- %d wrong results", wrong)
					reachability.PrintSummary(true, true, true)
				}
			}
		}
		log.Debug("Cleaning-up all policies and groups created by this Testcase")
		cleanupTestCaseResources(t, testCase)
	}
	allTestList = append(allTestList, testList...)
}
