// Copyright 2020 Antrea Authors
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
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/apis"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/features"
	. "antrea.io/antrea/test/e2e/utils"
)

// common for all tests.
var (
	p80              int32 = 80
	p81              int32 = 81
	p6443            int32 = 6443
	p8080            int32 = 8080
	p8081            int32 = 8081
	p8082            int32 = 8082
	p8085            int32 = 8085
	allPods          []Pod
	podsByNamespace  map[string][]Pod
	k8sUtils         *KubernetesUtils
	allTestList      []*TestCase
	podsPerNamespace []string
	namespaces       map[string]TestNamespaceMeta
	podIPs           map[string][]string
	nodes            map[string]string
	selfNamespace    *crdv1beta1.PeerNamespaces
)

const (
	// Provide enough time for policies to be enforced & deleted by the CNI plugin.
	networkPolicyDelay = 2000 * time.Millisecond
	// Timeout when waiting for a policy status to be updated and for the
	// policy to be considered realized.
	policyRealizedTimeout = 5 * time.Second
	// Verification of deleting/creating resources timed out.
	timeout = 10 * time.Second
	// audit log directory on Antrea Agent
	logDir          = "/var/log/antrea/networkpolicy/"
	logfileName     = "np.log"
	defaultTierName = "application"
)

func failOnError(err error, t *testing.T) {
	if err != nil {
		log.Errorf("%+v", err)
		k8sUtils.Cleanup(namespaces)
		t.Fatalf("test failed: %v", err)
	}
}

// podToAddrTestStep is a single unit of testing the connectivity from a Pod to an
// arbitrary destination address.
type podToAddrTestStep struct {
	clientPod            Pod
	destAddr             string
	destPort             int32
	expectedConnectivity PodConnectivityMark
}

// Util function to get the runtime name of a test Namespace.
func getNS(ns string) string {
	return namespaces[ns].Name
}

// Util function to get the runtime Pod struct of a test Pod.
func getPod(ns, po string) Pod {
	return Pod(namespaces[ns].Name + "/" + po)
}

// Util function to get the runtime Pod name of a test Pod.
func getPodName(ns, po string) string {
	return namespaces[ns].Name + "/" + po
}

func initialize(t *testing.T, data *TestData, customNamespaces map[string]TestNamespaceMeta) {
	selfNamespace = &crdv1beta1.PeerNamespaces{
		Match: crdv1beta1.NamespaceMatchSelf,
	}
	namespaces = make(map[string]TestNamespaceMeta)
	if customNamespaces != nil {
		namespaces = customNamespaces
	} else {
		suffix := randName("")
		for _, ns := range []string{"x", "y", "z"} {
			namespaces[ns] = TestNamespaceMeta{
				Name: ns + "-" + suffix,
			}
		}
	}
	// This function "initialize" will be used more than once, and variable "allPods" is global.
	// It should be empty every time when "initialize" is performed, otherwise there will be unexpected
	// results.
	allPods = []Pod{}
	podsByNamespace = make(map[string][]Pod)
	podsPerNamespace = []string{"a", "b", "c"}
	for _, podName := range podsPerNamespace {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns.Name, podName))
			podsByNamespace[ns.Name] = append(podsByNamespace[ns.Name], NewPod(ns.Name, podName))
		}
	}
	skipIfAntreaPolicyDisabled(t)

	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, podsPerNamespace, true, nil, nil)
	failOnError(err, t)
	podIPs = ips
}

func skipIfAntreaPolicyDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.AntreaPolicy, true, true)
}

func applyDefaultDenyToAllNamespaces(k8s *KubernetesUtils, namespaces map[string]TestNamespaceMeta) error {
	if err := k8s.CleanNetworkPolicies(namespaces); err != nil {
		return err
	}
	for _, ns := range namespaces {
		builder := &NetworkPolicySpecBuilder{}
		builder = builder.SetName(ns.Name, "default-deny-namespace")
		builder.SetTypeIngress()
		if _, err := k8s.CreateOrUpdateNetworkPolicy(builder.Get()); err != nil {
			return err
		}
	}
	time.Sleep(networkPolicyDelay)
	r := NewReachability(allPods, Dropped)
	k8s.Validate(allPods, r, []int32{p80}, ProtocolTCP)
	_, wrong, _ := r.Summary()
	if wrong != 0 {
		return fmt.Errorf("error when creating default deny k8s NetworkPolicies")
	}
	return nil
}

func cleanupDefaultDenyNPs(k8s *KubernetesUtils, namespaces map[string]TestNamespaceMeta) error {
	if err := k8s.CleanNetworkPolicies(namespaces); err != nil {
		return err
	}
	time.Sleep(networkPolicyDelay * 2)
	r := NewReachability(allPods, Connected)
	k8s.Validate(allPods, r, []int32{p80}, ProtocolTCP)
	_, wrong, _ := r.Summary()
	if wrong != 0 {
		return fmt.Errorf("error when cleaning default deny k8s NetworkPolicies")
	}
	return nil
}

func testMutateACNPNoTier(t *testing.T) {
	invalidNpErr := fmt.Errorf("ACNP tier not mutated to default tier")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-tier").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0)
	acnp := builder.Get()
	acnp, err := k8sUtils.CreateOrUpdateACNP(acnp)
	if err != nil {
		failOnError(fmt.Errorf("ACNP create failed %v", err), t)
	}
	if acnp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanACNPs(), t)
}

func testMutateANNPNoTier(t *testing.T) {
	invalidNpErr := fmt.Errorf("ANNP tier not mutated to default tier")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-no-tier").
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0)
	annp := builder.Get()
	annp, err := k8sUtils.CreateOrUpdateANNP(annp)
	if err != nil {
		failOnError(fmt.Errorf("ANNP create failed %v", err), t)
	}
	if annp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanANNPs([]string{annp.Namespace}), t)
}

func testCreateValidationInvalidACNP(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with non-exist tier accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-non-exist-tier").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(1.0).
		SetTier("no-exist")
	acnp := builder.Get()
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testUpdateValidationInvalidACNP(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy appliedTo set in both spec and rules accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-applied-to-update").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(1.0)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	acnp := builder.Get()
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP acnp-applied-to-update failed: %v", err), t)
	}
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil,
		nil, nil, nil, nil, nil, []ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}}, crdv1beta1.RuleActionAllow, "", "", nil)
	acnp = builder.Get()
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above update of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.DeleteACNP(acnp.Name), t)
}

func testCreateValidationInvalidANNP(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy with non-exist tier accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-no-priority").
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(1.0).
		SetTier("non-exist")
	annp := builder.Get()
	log.Debugf("creating ANNP %v", annp.Name)
	if _, err := k8sUtils.CreateOrUpdateANNP(annp); err == nil {
		// Above creation of ANNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testUpdateValidationInvalidANNP(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy appliedTo set in both spec and rules accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-applied-to-update").
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(1.0)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "")

	annp := builder.Get()
	if _, err := k8sUtils.CreateOrUpdateANNP(annp); err != nil {
		failOnError(fmt.Errorf("create ANNP annp-applied-to-update failed: %v", err), t)
	}
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil,
		nil, nil, nil, []ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}}, crdv1beta1.RuleActionAllow, "", "")
	annp = builder.Get()
	if _, err := k8sUtils.CreateOrUpdateANNP(annp); err == nil {
		// Above update of ANNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.DeleteANNP(annp.Namespace, annp.Name), t)
}

func testDeleteValidationReferencedTier(t *testing.T) {
	invalidErr := fmt.Errorf("reserved Tier deleted")
	if err := k8sUtils.DeleteTier("emergency"); err == nil {
		// Above deletion of reserved Tier must fail.
		failOnError(invalidErr, t)
	}
}

func testUpdateValidationInvalidTier(t *testing.T) {
	invalidErr := fmt.Errorf("Tier priority updated")
	oldTier, err := k8sUtils.CreateTier("prio-updated-tier", 21)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier prio-updated-tier: %v", err), t)
	}
	// Update this tier with new priority
	newTier := crdv1beta1.Tier{
		ObjectMeta: oldTier.ObjectMeta,
		Spec:       oldTier.Spec,
	}
	// Attempt to update Tier's priority
	newTier.Spec.Priority = 31
	// Above update of Tier must fail as it is an invalid case.
	if _, err = k8sUtils.UpdateTier(&newTier); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteTier(oldTier.Name), t)
}

func testCreateValidationInvalidTier(t *testing.T) {
	invalidErr := fmt.Errorf("Tiers created with overlapping priorities")
	tr, err := k8sUtils.CreateTier("tier-prio-20", 20)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-prio-20: %v", err), t)
	}
	// Attempt to create Tier with same priority.
	if _, err = k8sUtils.CreateTier("another-tier-prio-20", 20); err == nil {
		// Above creation of Tier must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteTier(tr.Name), t)
}

func testCreateValidationInvalidCG(t *testing.T) {
	invalidErr := fmt.Errorf("ClusterGroup using podSelecter and serviceReference together created")
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName("cg-mix-peer").
		SetPodSelector(map[string]string{"pod": "a"}, nil).
		SetServiceReference("svc", getNS("x"))
	cg := cgBuilder.Get()
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of ClusterGroup must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testUpdateValidationInvalidCG(t *testing.T) {
	invalidErr := fmt.Errorf("ClusterGroup using podSelecter and serviceReference together updated")
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName("cg-mix-peer-update").
		SetPodSelector(map[string]string{"pod": "a"}, nil)
	cg := cgBuilder.Get()
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err != nil {
		failOnError(fmt.Errorf("create ClusterGroup %s failed: %v", cg.Name, err), t)
	}
	cgBuilder.SetServiceReference("svc", getNS("x"))
	cg = cgBuilder.Get()
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above update of ClusterGroup must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteCG(cg.Name), t)
}

func testCreateValidationInvalidGroup(t *testing.T) {
	invalidErr := fmt.Errorf("Group using podSelecter and serviceReference together created")
	gBuilder := &GroupSpecBuilder{}
	gBuilder = gBuilder.SetName("g-mix-peer").SetNamespace(getNS("x")).
		SetPodSelector(map[string]string{"pod": "a"}, nil).
		SetServiceReference("svc", getNS("x"))
	g := gBuilder.Get()
	if _, err := k8sUtils.CreateOrUpdateGroup(g); err == nil {
		// Above creation of Group must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testUpdateValidationInvalidGroup(t *testing.T) {
	invalidErr := fmt.Errorf("Group using podSelecter and serviceReference together updated")
	gBuilder := &GroupSpecBuilder{}
	gBuilder = gBuilder.SetName("g-mix-peer").SetNamespace(getNS("x")).
		SetPodSelector(map[string]string{"pod": "a"}, nil)
	g := gBuilder.Get()
	if _, err := k8sUtils.CreateOrUpdateGroup(g); err != nil {
		failOnError(fmt.Errorf("create Group %s/%s failed: %v", g.Namespace, g.Name, err), t)
	}
	gBuilder.SetServiceReference("svc", getNS("x"))
	g = gBuilder.Get()
	if _, err := k8sUtils.CreateOrUpdateGroup(g); err == nil {
		// Above update of Group must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteGroup(g.Namespace, g.Name), t)
}

// testACNPAllowXBtoA tests traffic from X/B to pods with label A, after applying the default deny
// k8s NetworkPolicies in all namespaces and ACNP to allow X/B to A.
func testACNPAllowXBtoA(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-allow-xb-to-a").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Dropped)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Connected)
	reachability.Expect(getPod("x", "b"), getPod("z", "a"), Connected)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow X/B to A", testStep},
	}
	executeTests(t, testCase)
}

// testACNPSourcePort tests ACNP source port filtering. The agnhost image used in E2E tests uses
// ephemeral ports to initiate TCP connections, which should be 32768–60999 by default
// (https://en.wikipedia.org/wiki/Ephemeral_port). This test retrieves the port range from
// the client Pod and uses it in sourcePort and sourceEndPort of an ACNP rule to verify that
// packets can be matched by source port.
func testACNPSourcePort(t *testing.T) {
	portStart, portEnd, err := k8sUtils.getTCPv4SourcePortRangeFromPod(getNS("x"), "a")
	failOnError(err, t)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-source-port").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngressForSrcPort(ProtocolTCP, nil, nil, &portStart, &portEnd, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, false, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-source-port").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder2.AddIngressForSrcPort(ProtocolTCP, &p80, nil, &portStart, &portEnd, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, false, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-source-port").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder3.AddIngressForSrcPort(ProtocolTCP, &p80, &p81, &portStart, &portEnd, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, false, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(getNS("x")+"/b"), Pod(getNS("x")+"/a"), Dropped)
	reachability.Expect(Pod(getNS("x")+"/b"), Pod(getNS("y")+"/a"), Dropped)
	reachability.Expect(Pod(getNS("x")+"/b"), Pod(getNS("z")+"/a"), Dropped)
	// After adding the dst port constraint of port 80, traffic on port 81 should not be affected.
	updatedReachability := NewReachability(allPods, Connected)

	testSteps := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
			nil,
			nil,
		},
		{
			"Port 81",
			updatedReachability,
			[]metav1.Object{builder2.Get()},
			[]int32{81},
			ProtocolTCP,
			0,
			nil,
			nil,
			nil,
		},
		{
			"Port range 80-81",
			reachability,
			[]metav1.Object{builder3.Get()},
			[]int32{80, 81},
			ProtocolTCP,
			0,
			nil,
			nil,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop X/B to A based on source port", testSteps},
	}
	executeTests(t, testCase)
}

// testACNPAllowXBtoYA tests traffic from X/B to Y/A on named port 81, after applying the default deny
// k8s NetworkPolicies in all namespaces and ACNP to allow X/B to Y/A.
func testACNPAllowXBtoYA(t *testing.T) {
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-allow-xb-to-ya").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("y")}}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Dropped)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Connected)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:          "NamedPort 81",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{81},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow X/B to Y/A", testStep},
	}
	executeTests(t, testCase)
}

// testACNPPriorityOverrideDefaultDeny tests priority override in ACNP. It applies a higher priority ACNP to drop
// traffic from namespace Z to X/A, and in the meantime applies a lower priority ACNP to allow traffic from Z to X.
// It is tested with default deny k8s NetworkPolicies in all namespaces.
func testACNPPriorityOverrideDefaultDeny(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-priority2").
		SetPriority(2).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority1").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	// Ingress from ns:z to x/a will be dropped since acnp-priority1 has higher precedence.
	reachabilityBothACNP := NewReachability(allPods, Dropped)
	reachabilityBothACNP.Expect(getPod("z", "a"), getPod("x", "b"), Connected)
	reachabilityBothACNP.Expect(getPod("z", "a"), getPod("x", "c"), Connected)
	reachabilityBothACNP.Expect(getPod("z", "b"), getPod("x", "b"), Connected)
	reachabilityBothACNP.Expect(getPod("z", "b"), getPod("x", "c"), Connected)
	reachabilityBothACNP.Expect(getPod("z", "c"), getPod("x", "b"), Connected)
	reachabilityBothACNP.Expect(getPod("z", "c"), getPod("x", "c"), Connected)
	reachabilityBothACNP.ExpectSelf(allPods, Connected)

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
		{"ACNP PriorityOverride Default Deny", testStep},
	}
	executeTests(t, testCase)
}

// testACNPAllowNoDefaultIsolation tests that no default isolation rules are created for Policies.
func testACNPAllowNoDefaultIsolation(t *testing.T, protocol AntreaPolicyProtocol) {
	if protocol == ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-allow-x-ingress-y-egress-z").
		SetPriority(1.1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder.AddIngress(protocol, &p81, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("y")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)
	builder.AddEgress(protocol, &p81, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	testStep := []*TestStep{
		{
			Name:          "Port 81",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{81},
			Protocol:      protocol,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow No Default Isolation", testStep},
	}
	executeTests(t, testCase)
}

// testACNPDropEgress tests that an ACNP is able to drop egress traffic from pods labelled A to namespace Z.
func testACNPDropEgress(t *testing.T, protocol AntreaPolicyProtocol) {
	if protocol == ProtocolSCTP {
		// SCTP testing is failing on our IPv6 CI testbeds at the moment. This seems to be
		// related to an issue with ESX networking for SCTPv6 traffic when the Pods are on
		// different Node VMs which are themselves on different ESX hosts. We are
		// investigating the issue and disabling the tests for IPv6 clusters in the
		// meantime.
		skipIfIPv6Cluster(t)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Dropped)
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
		{"ACNP Drop Egress From All Pod:a to NS:z", testStep},
	}
	executeTests(t, testCase)
}

// testACNPDropIngressInSelectedNamespace tests that an ACNP is able to drop all ingress traffic towards a specific Namespace.
// The ACNP is created by selecting the Namespace as an appliedTo, and adding an ingress rule with Drop action and
// no `From` (which translate to drop ingress from everywhere).
func testACNPDropIngressInSelectedNamespace(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-ingress-to-x").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		crdv1beta1.RuleActionDrop, "", "drop-all-ingress", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectAllIngress(getPod("x", "a"), Dropped)
	reachability.ExpectAllIngress(getPod("x", "b"), Dropped)
	reachability.ExpectAllIngress(getPod("x", "c"), Dropped)
	reachability.ExpectSelf(allPods, Connected)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop all Ingress to Namespace x", testStep},
	}
	executeTests(t, testCase)
}

// testACNPNoEffectOnOtherProtocols tests that an ACNP which drops TCP traffic won't affect other protocols (e.g. UDP).
func testACNPNoEffectOnOtherProtocols(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability1 := NewReachability(allPods, Connected)
	reachability1.Expect(getPod("z", "a"), getPod("x", "a"), Dropped)
	reachability1.Expect(getPod("z", "b"), getPod("x", "a"), Dropped)
	reachability1.Expect(getPod("z", "c"), getPod("x", "a"), Dropped)
	reachability1.Expect(getPod("z", "a"), getPod("y", "a"), Dropped)
	reachability1.Expect(getPod("z", "b"), getPod("y", "a"), Dropped)
	reachability1.Expect(getPod("z", "c"), getPod("y", "a"), Dropped)
	reachability1.Expect(getPod("z", "b"), getPod("z", "a"), Dropped)
	reachability1.Expect(getPod("z", "c"), getPod("z", "a"), Dropped)

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
		{"ACNP Drop Ingress From All Pod:a to NS:z TCP Not UDP", testStep},
	}
	executeTests(t, testCase)
}

// testACNPAppliedToDenyXBtoCGWithYA tests traffic from X/B to ClusterGroup Y/A on named port 81 is dropped.
func testACNPAppliedToDenyXBtoCGWithYA(t *testing.T) {
	cgName := "cg-pods-ya"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil).
		SetPodSelector(map[string]string{"pod": "a"}, nil)
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-ya-from-xb").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:         "NamedPort 81",
			Reachability: reachability,
			// Note in this testcase the ClusterGroup is created after the ACNP
			TestResources: []metav1.Object{builder.Get(), cgBuilder.Get()},
			Ports:         []int32{81},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Deny ClusterGroup Y/A from X/B", testStep},
	}
	executeTests(t, testCase)
}

// testACNPIngressRuleDenyCGWithXBtoYA tests traffic from ClusterGroup with X/B to Y/A on named port 81 is dropped.
func testACNPIngressRuleDenyCGWithXBtoYA(t *testing.T) {
	cgName := "cg-pods-xb"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": getNS("x")}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-xb-to-ya").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("y")}}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:          "NamedPort 81",
			Reachability:  reachability,
			TestResources: []metav1.Object{cgBuilder.Get(), builder.Get()},
			Ports:         []int32{81},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Deny ClusterGroup X/B to Y/A", testStep},
	}
	executeTests(t, testCase)
}

// testACNPAppliedToRuleCGWithPodsAToNsZ tests that an ACNP is able to drop egress traffic from CG with pods labelled A namespace Z.
func testACNPAppliedToRuleCGWithPodsAToNsZ(t *testing.T) {
	cgName := "cg-pods-a"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetPodSelector(map[string]string{"pod": "a"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-a-to-z").
		SetPriority(1.0)
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, []ACNPAppliedToSpec{{Group: cgName}}, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Dropped)
	testStep := []*TestStep{
		{
			Name:         "Port 80",
			Reachability: reachability,
			// Note in this testcase the ClusterGroup is created after the ACNP
			TestResources: []metav1.Object{builder.Get(), cgBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From ClusterGroup with All Pod:a to NS:z", testStep},
	}
	executeTests(t, testCase)
}

// testACNPEgressRulePodsAToCGWithNsZ tests that an ACNP is able to drop egress traffic from pods labelled A to a CG with namespace Z.
func testACNPEgressRulePodsAToCGWithNsZ(t *testing.T) {
	cgName := "cg-ns-z"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": getNS("z")}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Dropped)
	testStep := []*TestStep{
		{
			Name:         "Port 80",
			Reachability: reachability,
			// Note in this testcase the ClusterGroup is created after the ACNP
			TestResources: []metav1.Object{builder.Get(), cgBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to ClusterGroup with NS:z", testStep},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupUpdateAppliedTo(t *testing.T) {
	cgName := "cg-pods-a-then-c"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetPodSelector(map[string]string{"pod": "a"}, nil)
	// Update CG Pod selector to group Pods C
	updatedCgBuilder := &ClusterGroupSpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName).SetPodSelector(map[string]string{"pod": "c"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(getPod("x", "c"), getNS("z"), Dropped)
	updatedReachability.ExpectEgressToNamespace(getPod("y", "c"), getNS("z"), Dropped)
	updatedReachability.Expect(getPod("z", "c"), getPod("z", "a"), Dropped)
	updatedReachability.Expect(getPod("z", "c"), getPod("z", "b"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "CG Pods A",
			Reachability:  reachability,
			TestResources: []metav1.Object{cgBuilder.Get(), builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "CG Pods C - update",
			Reachability:  updatedReachability,
			TestResources: []metav1.Object{updatedCgBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From CG Pod:a to NS:z updated to ClusterGroup with Pod:c", testStep},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupUpdate(t *testing.T) {
	cgName := "cg-ns-z-then-y"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": getNS("z")}, nil)
	// Update CG NS selector to group Pods from Namespace Y
	updatedCgBuilder := &ClusterGroupSpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("y"), Dropped)
	updatedReachability.ExpectEgressToNamespace(getPod("z", "a"), getNS("y"), Dropped)
	updatedReachability.Expect(getPod("y", "a"), getPod("y", "b"), Dropped)
	updatedReachability.Expect(getPod("y", "a"), getPod("y", "c"), Dropped)
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
		{"ACNP Drop Egress From All Pod:a to ClusterGroup with NS:z updated to ClusterGroup with NS:y", testStep},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupAppliedToPodAdd(t *testing.T, data *TestData) {
	cgName := "cg-pod-custom-pod-zj"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": getNS("z")}, nil).
		SetPodSelector(map[string]string{"pod": "j"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-zj-to-xj-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "j"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("z"), "j"),
				Labels: map[string]string{"pod": "j"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("x"), "j"),
				Labels: map[string]string{"pod": "j"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			TestResources: []metav1.Object{cgBuilder.Get(), builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
			CustomProbes:  cp,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From ClusterGroup with Pod: z/j to Pod: x/j for Pod ADD events", testStep},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPClusterGroupRefRulePodAdd(t *testing.T, data *TestData) {
	cgName := "cg-pod-custom-pod-zk"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": getNS("z")}, nil).
		SetPodSelector(map[string]string{"pod": "k"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-xk-to-cg-with-zk-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "k"},
				NSSelector:  map[string]string{"ns": getNS("x")},
			},
		})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("x"), "k"),
				Labels: map[string]string{"pod": "k"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("z"), "k"),
				Labels: map[string]string{"pod": "k"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep := []*TestStep{
		{
			Name: "Port 80",
			// Note in this testcase the ClusterGroup is created after the ACNP
			TestResources: []metav1.Object{builder.Get(), cgBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
			CustomProbes:  cp,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From Pod: x/k to ClusterGroup with Pod: z/k for Pod ADD event", testStep},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPClusterGroupRefRuleIPBlocks(t *testing.T) {
	podXAIP, _ := podIPs[getPodName("x", "a")]
	podXBIP, _ := podIPs[getPodName("x", "b")]
	podXCIP, _ := podIPs[getPodName("x", "c")]
	podZAIP, _ := podIPs[getPodName("z", "a")]
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
	for i := 0; i < len(podXAIP); i++ {
		ipBlock1 = append(ipBlock1, crdv1beta1.IPBlock{CIDR: genCIDR(podXAIP[i])})
		ipBlock1 = append(ipBlock1, crdv1beta1.IPBlock{CIDR: genCIDR(podXBIP[i])})
		ipBlock1 = append(ipBlock1, crdv1beta1.IPBlock{CIDR: genCIDR(podXCIP[i])})
		ipBlock2 = append(ipBlock2, crdv1beta1.IPBlock{CIDR: genCIDR(podZAIP[i])})
	}

	cgName := "cg-ipblocks-pod-in-ns-x"
	cgBuilder := &ClusterGroupSpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetIPBlocks(ipBlock1)
	cgName2 := "cg-ipblock-pod-za"
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cgName2).
		SetIPBlocks(ipBlock2)

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-x-ips-ingress-for-ya").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "a"},
				NSSelector:  map[string]string{"ns": getNS("y")},
			},
		})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName, "", nil)
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgName2, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("x", "c"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("y", "a"), Dropped)
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
		{"ACNP Drop Ingress From x to Pod y/a to ClusterGroup with ipBlocks", testStep},
	}
	executeTests(t, testCase)
}

// testANNPEgressRulePodsAToGrpWithPodsC tests that an ANNP is able to drop egress traffic from x/a to x/c.
func testANNPEgressRulePodsAToGrpWithPodsC(t *testing.T) {
	grpName := "grp-xc"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "c"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-xa-to-grp-xc-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("x", "c"), Dropped)
	testStep := []*TestStep{
		{
			Name:         "Port 80",
			Reachability: reachability,
			// Note in this testcase the Group is created after the ANNP
			TestResources: []metav1.Object{builder.Get(), grpBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop Egress From All Pod:x/a to Group with Pod:x/c", testStep},
	}
	executeTests(t, testCase)
}

// testANNPIngressRuleDenyGrpWithXCtoXA tests traffic from Group with X/B to X/A on named port 81 is dropped.
func testANNPIngressRuleDenyGrpWithXCtoXA(t *testing.T) {
	grpName := "grp-pods-xb"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "b"}, nil)
	port81Name := "serve-81"
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-grp-with-xb-to-xa").
		SetPriority(2.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:          "NamedPort 81",
			Reachability:  reachability,
			TestResources: []metav1.Object{grpBuilder.Get(), builder.Get()},
			Ports:         []int32{81},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Deny Group X/B to X/A", testStep},
	}
	executeTests(t, testCase)
}

func testANNPGroupUpdate(t *testing.T) {
	grpName := "grp-pod-xc-then-pod-xb"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "c"}, nil)
	// Update Group Pod selector from X/C to X/B
	updatedGrpBuilder := &GroupSpecBuilder{}
	updatedGrpBuilder = updatedGrpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "b"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-xa-to-grp-with-xc-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("x", "c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.Expect(getPod("x", "a"), getPod("x", "b"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{grpBuilder.Get(), builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "Port 80 - update",
			Reachability:  updatedReachability,
			TestResources: []metav1.Object{updatedGrpBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop Egress From All Pod:x/a to Group with Pod:x/c updated to Group with Pod:x/b", testStep},
	}
	executeTests(t, testCase)
}

// testANNPAppliedToDenyXBtoGrpWithXA tests traffic from X/B to Group X/A on named port 81 is dropped.
func testANNPAppliedToDenyXBtoGrpWithXA(t *testing.T) {
	grpName := "grp-pods-ya"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "a"}, nil)
	port81Name := "serve-81"
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-grp-with-xa-from-xb").
		SetPriority(2.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grpName}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			Name:         "NamedPort 81",
			Reachability: reachability,
			// Note in this testcase the Group is created after the ANNP
			TestResources: []metav1.Object{builder.Get(), grpBuilder.Get()},
			Ports:         []int32{81},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Deny Group X/A from X/B", testStep},
	}
	executeTests(t, testCase)
}

// testANNPAppliedToRuleGrpWithPodsAToPodsC tests that an ANNP is able to drop egress traffic from GRP with pods labelled A to pods C.
func testANNPAppliedToRuleGrpWithPodsAToPodsC(t *testing.T) {
	grpName := "grp-pods-a"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "a"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-grp-with-a-to-c").
		SetPriority(1.0)
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil, nil,
		nil, nil, nil, []ANNPAppliedToSpec{{Group: grpName}}, crdv1beta1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("x", "c"), Dropped)
	testStep := []*TestStep{
		{
			Name:         "Port 80",
			Reachability: reachability,
			// Note in this testcase the Group is created after the ANNP
			TestResources: []metav1.Object{builder.Get(), grpBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop Egress From Group with All Pod:a to Pod:c", testStep},
	}
	executeTests(t, testCase)
}

func testANNPGroupUpdateAppliedTo(t *testing.T) {
	grpName := "grp-pods-xa-then-xb"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "a"}, nil)
	// Update GRP Pod selector to group Pods x/b
	updatedGrpBuilder := &GroupSpecBuilder{}
	updatedGrpBuilder = updatedGrpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "b"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-grp-xc-to-xa-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grpName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("x", "c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.Expect(getPod("x", "b"), getPod("x", "c"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "GRP Pods X/C",
			Reachability:  reachability,
			TestResources: []metav1.Object{grpBuilder.Get(), builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
		{
			Name:          "GRP Pods X/B - update",
			Reachability:  updatedReachability,
			TestResources: []metav1.Object{updatedGrpBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop Egress From Pod:x/c to Group Pod:x/a updated to Group with Pod:x/b", testStep},
	}
	executeTests(t, testCase)
}

func testANNPGroupAppliedToPodAdd(t *testing.T, data *TestData) {
	grpName := "grp-pod-custom-pod-xj"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "j"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-grp-with-xj-to-xd-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grpName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "d"}, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("x"), "j"),
				Labels: map[string]string{"pod": "j"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("x"), "d"),
				Labels: map[string]string{"pod": "d"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			TestResources: []metav1.Object{grpBuilder.Get(), builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
			CustomProbes:  cp,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop Egress From Group with Pod: x/j to Pod: x/d for Pod ADD events", testStep},
	}
	executeTestsWithData(t, testCase, data)
}

func testANNPGroupServiceRefPodAdd(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", getNS("x"), 80, 80, map[string]string{"app": "b"}, nil)

	grp1Name, grp2Name := "grp-svc1", "grp-svc2"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc2")

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-grp-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grp1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grp2Name, "")

	svc1PodName := randName("test-pod-svc1-")
	svc2PodName := randName("test-pod-svc2-")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("x"), svc2PodName),
				Labels: map[string]string{"pod": svc2PodName, "app": "b"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("x"), svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "a"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	testStep := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability,
		TestResources: []metav1.Object{svc1, svc2, grpBuilder1.Get(), grpBuilder2.Get(), builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
		CustomProbes:  cp,
	}

	testSteps := []*TestStep{testStep}
	testCase := []*TestCase{
		{"ANNP Group Service Reference add pod", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testANNPGroupServiceRefDelete(t *testing.T) {
	svc1 := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", getNS("x"), 80, 80, map[string]string{"app": "b"}, nil)
	k8sUtils.CreateOrUpdateService(svc1)
	failOnError(waitForResourceReady(t, timeout, svc1), t)
	k8sUtils.CreateOrUpdateService(svc2)
	failOnError(waitForResourceReady(t, timeout, svc2), t)

	grp1Name, grp2Name := "grp-svc1", "grp-svc2"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc2")
	grp1 := grpBuilder1.Get()
	k8sUtils.CreateOrUpdateGroup(grp1)
	failOnError(waitForResourceReady(t, timeout, grp1), t)
	grp2 := grpBuilder2.Get()
	k8sUtils.CreateOrUpdateGroup(grp2)
	failOnError(waitForResourceReady(t, timeout, grp2), t)

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-grp-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grp1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grp2Name, "")
	annp := builder.Get()
	k8sUtils.CreateOrUpdateANNP(annp)
	failOnError(waitForResourceReady(t, timeout, annp), t)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ := reachability.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}
	// Delete services, pods should be connected.
	failOnError(k8sUtils.DeleteService(svc1.Namespace, svc1.Name), t)
	failOnError(k8sUtils.DeleteService(svc2.Namespace, svc2.Name), t)
	time.Sleep(defaultInterval)
	reachability2 := NewReachability(allPods, Connected)
	k8sUtils.Validate(allPods, reachability2, []int32{80}, ProtocolTCP)
	_, wrong, _ = reachability2.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability2.PrintSummary(true, true, true)
	}
	// Cleanup test resources.
	failOnError(k8sUtils.DeleteANNP(builder.Namespace, builder.Name), t)
}

func testANNPGroupServiceRefCreateAndUpdate(t *testing.T) {
	svc1 := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", getNS("x"), 80, 80, map[string]string{"app": "b"}, nil)

	grp1Name, grp2Name := "grp-svc1", "grp-svc2"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc2")

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-grp-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grp1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grp2Name, "")

	// Pods backing svc1 (label pod=a) in Namespace x should not allow ingress from Pods backing svc2 (label pod=b) in Namespace x.
	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	testStep1 := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{svc1, svc2, grpBuilder1.Get(), grpBuilder2.Get(), builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	// Test update selector of Service referred in grp-svc1, and update serviceReference of grp-svc2.
	svc1Updated := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "b"}, nil)
	svc3 := k8sUtils.BuildService("svc3", getNS("x"), 80, 80, map[string]string{"app": "c"}, nil)
	grpBuilder2Updated := grpBuilder2.SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc3")

	// Pods backing svc1 (label pod=b) in namespace x should not allow ingress from Pods backing svc3 (label pod=d) in namespace x.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(getPod("x", "c"), getPod("x", "b"), Dropped)
	testStep2 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{svc1Updated, svc3, grpBuilder1.Get(), grpBuilder2Updated.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testSteps := []*TestStep{testStep1, testStep2}
	testCase := []*TestCase{
		{"ANNP Group Service Reference create and update", testSteps},
	}
	executeTests(t, testCase)
}

func testANNPGroupRefRuleIPBlocks(t *testing.T) {
	podXBIP, _ := podIPs[getPodName("x", "b")]
	podXCIP, _ := podIPs[getPodName("x", "c")]
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
	var ipBlock []crdv1beta1.IPBlock
	for i := 0; i < len(podXBIP); i++ {
		ipBlock = append(ipBlock, crdv1beta1.IPBlock{CIDR: genCIDR(podXBIP[i])})
		ipBlock = append(ipBlock, crdv1beta1.IPBlock{CIDR: genCIDR(podXCIP[i])})
	}

	grpName := "grp-ipblocks-pod-xb-xc"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(getNS("x")).SetIPBlocks(ipBlock)

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-deny-xb-xc-ips-ingress-for-xa").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	reachability.Expect(getPod("x", "c"), getPod("x", "a"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get(), grpBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop Ingress From Group with ipBlocks to Pod: x/a", testStep},
	}
	executeTests(t, testCase)
}

func testANNPNestedGroupCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "a"}, nil)
	svc1PodName := randName("test-pod-svc1-")
	grp1Name, grp2Name, grp3Name := "grp-svc-x-a", "grp-select-x-b", "grp-select-x-c"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(getNS("x")).SetServiceReference(getNS("x"), "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "b"}, nil)
	grpBuilder3 := &GroupSpecBuilder{}
	grpBuilder3 = grpBuilder3.SetName(grp3Name).SetNamespace(getNS("x")).SetPodSelector(map[string]string{"pod": "c"}, nil)
	grpNestedName := "grp-nested"
	grpBuilderNested := &GroupSpecBuilder{}
	grpBuilderNested = grpBuilderNested.SetName(grpNestedName).SetNamespace(getNS("x")).SetChildGroups([]string{grp1Name, grp3Name})

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("x"), "annp-nested-grp").SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{}}).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil, nil, nil, crdv1beta1.RuleActionDrop, grpNestedName, "")

	// Pods in Namespace x should not allow traffic from Pods backing svc1 (label pod=a) in Namespace x.
	// Note that in this testStep grp3 will not be created yet, so even though grp-nested selects grp1 and
	// grp3 as childGroups, only members of grp1 will be included as this time.
	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("x"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep1 := &TestStep{
		Name:         "Port 80",
		Reachability: reachability,
		// Note in this testcase the Group is created after the ANNP
		TestResources: []metav1.Object{builder.Get(), svc1, grpBuilder1.Get(), grpBuilderNested.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	// Test update "grp-nested" to include "grp-select-x-b" as well.
	grpBuilderNested = grpBuilderNested.SetChildGroups([]string{grp1Name, grp2Name, grp3Name})
	// In addition to x/a, all traffic from x/b to Namespace x should also be denied.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(getPod("x", "a"), getNS("x"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("x", "b"), getNS("x"), Dropped)
	reachability2.ExpectSelf(allPods, Connected)
	// New member in grp-svc-x-a should be reflected in grp-nested as well.
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("x"), svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("x"), "test-add-pod-ns-x"),
				Labels: map[string]string{"pod": "test-add-pod-ns-x"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep2 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{grpBuilder2.Get(), grpBuilderNested.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
		CustomProbes:  cp,
	}

	// In this testStep grp3 is created. It's members should reflect in grp-nested
	// and as a result, all traffic from x/c to Namespace x should be denied as well.
	reachability3 := NewReachability(allPods, Connected)
	reachability3.ExpectEgressToNamespace(getPod("x", "a"), getNS("x"), Dropped)
	reachability3.ExpectEgressToNamespace(getPod("x", "b"), getNS("x"), Dropped)
	reachability3.ExpectEgressToNamespace(getPod("x", "c"), getNS("x"), Dropped)
	reachability3.ExpectSelf(allPods, Connected)
	testStep3 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability3,
		TestResources: []metav1.Object{grpBuilder3.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ANNP nested Group create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

// testBaselineNamespaceIsolation tests that an ACNP in the baseline Tier is able to enforce default namespace isolation,
// which can be later overridden by developer K8s NetworkPolicies.
func testBaselineNamespaceIsolation(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	nsExpOtherThanX := metav1.LabelSelectorRequirement{
		Key:      "ns",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{getNS("x")},
	}
	builder = builder.SetName("acnp-baseline-isolate-ns-x").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, []metav1.LabelSelectorRequirement{nsExpOtherThanX}, nil,
		nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	// create a K8s NetworkPolicy for Pods in namespace x to allow ingress traffic from Pods in the same namespace,
	// as well as from the y/a Pod. It should open up ingress from y/a since it's evaluated before the baseline tier.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(getNS("x"), "allow-ns-x-and-y-a").
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			nil, map[string]string{"ns": getNS("x")}, nil, nil).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "a"}, map[string]string{"ns": getNS("y")}, nil, nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("y", "b"), getPod("x", "a"), Dropped)
	reachability.Expect(getPod("y", "c"), getPod("x", "a"), Dropped)
	reachability.ExpectIngressFromNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("y", "b"), getPod("x", "b"), Dropped)
	reachability.Expect(getPod("y", "c"), getPod("x", "b"), Dropped)
	reachability.ExpectIngressFromNamespace(getPod("x", "b"), getNS("z"), Dropped)
	reachability.Expect(getPod("y", "b"), getPod("x", "c"), Dropped)
	reachability.Expect(getPod("y", "c"), getPod("x", "c"), Dropped)
	reachability.ExpectIngressFromNamespace(getPod("x", "c"), getNS("z"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get(), k8sNPBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP baseline tier namespace isolation", testStep},
	}
	executeTests(t, testCase)
	// Cleanup the K8s NetworkPolicy created for this test.
	failOnError(k8sUtils.CleanNetworkPolicies(map[string]TestNamespaceMeta{"x": {Name: getNS("x")}}), t)
	time.Sleep(networkPolicyDelay)
}

// testACNPPriorityOverride tests priority overriding in three ACNPs. Those three ACNPs are applied in a specific order to
// test priority reassignment, and each controls a smaller set of traffic patterns as priority increases.
func testACNPPriorityOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-priority1").
		SetPriority(1.001).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	// Highest priority. Drops traffic from z/b to x/a.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority2").
		SetPriority(1.002).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	// Medium priority. Allows traffic from z to x/a.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-priority3").
		SetPriority(1.003).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	// Lowest priority. Drops traffic from z to x.
	builder3.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(getPod("z", "a"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "a"), getPod("x", "c"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "b"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "b"), getPod("x", "c"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "c"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "c"), getPod("x", "c"), Dropped)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(getPod("z", "a"), getPod("x", "b"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "a"), getPod("x", "c"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "b"), getPod("x", "a"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "b"), getPod("x", "b"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "b"), getPod("x", "c"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "c"), getPod("x", "b"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "c"), getPod("x", "c"), Dropped)

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

// testACNPTierOverride tests tier priority overriding in three ACNPs. Each ACNP controls a smaller set of traffic patterns
// as tier priority increases.
func testACNPTierOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-emergency").
		SetTier("emergency").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	// Highest priority tier. Drops traffic from z/b to x/a.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-securityops").
		SetTier("securityops").
		SetPriority(10).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-tier-application").
		SetTier("application").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	// Lowest priority tier. Drops traffic from z to x.
	builder3.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(getPod("z", "a"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "a"), getPod("x", "c"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "b"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "b"), getPod("x", "c"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "c"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "c"), getPod("x", "c"), Dropped)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(getPod("z", "a"), getPod("x", "b"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "a"), getPod("x", "c"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "b"), getPod("x", "a"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "b"), getPod("x", "b"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "b"), getPod("x", "c"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "c"), getPod("x", "b"), Dropped)
	reachabilityAllACNPs.Expect(getPod("z", "c"), getPod("x", "c"), Dropped)

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

// testACNPTierOverride tests tier priority overriding in three ACNPs with custom created tiers. Each ACNP controls a
// smaller set of traffic patterns as tier priority increases.
func testACNPCustomTiers(t *testing.T) {
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-low").
		SetTier("low-priority").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	// Lowest priority tier. Drops traffic from z to x.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(getPod("z", "a"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "a"), getPod("x", "c"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "b"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "b"), getPod("x", "c"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "c"), getPod("x", "b"), Dropped)
	reachabilityTwoACNPs.Expect(getPod("z", "c"), getPod("x", "c"), Dropped)
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
		{"ACNP Custom Tier priority", testStepTwoACNP},
	}
	executeTests(t, testCase)
	// Cleanup customized tiers. ACNPs created in those tiers need to be deleted first.
	failOnError(k8sUtils.CleanACNPs(), t)
	failOnError(k8sUtils.DeleteTier("high-priority"), t)
	failOnError(k8sUtils.DeleteTier("low-priority"), t)
}

// testACNPPriorityConflictingRule tests that if there are two Policies in the cluster with rules that conflicts with
// each other, the ACNP with higher priority will prevail.
func testACNPPriorityConflictingRule(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-drop").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(2).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	// The following ingress rule will take no effect as it is exactly the same as ingress rule of cnp-drop,
	// but cnp-allow has lower priority.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.ExpectEgressToNamespace(getPod("z", "a"), getNS("x"), Dropped)
	reachabilityBothACNP.ExpectEgressToNamespace(getPod("z", "b"), getNS("x"), Dropped)
	reachabilityBothACNP.ExpectEgressToNamespace(getPod("z", "c"), getNS("x"), Dropped)
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

// testACNPRulePriority tests that if there are two rules in the cluster that conflicts with each other, the rule with
// higher precedence will prevail.
func testACNPRulePriority(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	// acnp-deny will apply to all pods in namespace x
	builder1 = builder1.SetName("acnp-deny").
		SetPriority(5).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("y")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)
	// This rule should take no effect as it will be overridden by the first rule of cnp-allow
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	// acnp-allow will also apply to all pods in namespace x
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(5).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}})
	builder2.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)
	// This rule should take no effect as it will be overridden by the first rule of cnp-drop
	builder2.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("y")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)

	// Only egress from pods in namespace x to namespace y should be denied
	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.ExpectIngressFromNamespace(getPod("y", "a"), getNS("x"), Dropped)
	reachabilityBothACNP.ExpectIngressFromNamespace(getPod("y", "b"), getNS("x"), Dropped)
	reachabilityBothACNP.ExpectIngressFromNamespace(getPod("y", "c"), getNS("x"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Both ACNP",
			Reachability:  reachabilityBothACNP,
			TestResources: []metav1.Object{builder2.Get(), builder1.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Rule Priority", testStep},
	}
	executeTests(t, testCase)
}

// testACNPPortRange tests the port range in an ACNP can work.
func testACNPPortRange(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p8080, nil, &p8082, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "acnp-port-range", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Dropped)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Dropped)
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
		{"ACNP Drop Egress From All Pod:a to NS:z with a portRange", testSteps},
	}
	executeTests(t, testCase)
}

// testACNPRejectEgress tests that an ACNP is able to reject egress traffic from pods labelled A to namespace Z.
func testACNPRejectEgress(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Rejected)
	reachability.ExpectEgressToNamespace(getPod("y", "a"), getNS("z"), Rejected)
	reachability.Expect(getPod("z", "a"), getPod("z", "b"), Rejected)
	reachability.Expect(getPod("z", "a"), getPod("z", "c"), Rejected)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ACNP Reject egress From All Pod:a to NS:z", testStep},
	}
	executeTests(t, testCase)
}

// testACNPRejectIngress tests that an ACNP is able to reject ingress traffic from pods labelled A to namespace Z.
func testACNPRejectIngress(t *testing.T, protocol AntreaPolicyProtocol) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-a-from-z-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectIngressFromNamespace(getPod("x", "a"), getNS("z"), Rejected)
	reachability.ExpectIngressFromNamespace(getPod("y", "a"), getNS("z"), Rejected)
	reachability.Expect(getPod("z", "b"), getPod("z", "a"), Rejected)
	reachability.Expect(getPod("z", "c"), getPod("z", "a"), Rejected)
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
		{"ACNP Reject ingress from NS:z to All Pod:a", testStep},
	}
	executeTests(t, testCase)
}

func testRejectServiceTraffic(t *testing.T, data *TestData, clientNamespace, serverNamespace string) {
	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, clientNamespace, nodeName(0), false))
	defer data.DeletePodAndWait(defaultTimeout, clientName, clientNamespace)
	_, err := data.podWaitForIPs(defaultTimeout, clientName, clientNamespace)
	require.NoError(t, err)

	svc1, cleanup1 := data.createAgnhostServiceAndBackendPods(t, "s1", serverNamespace, nodeName(0), v1.ServiceTypeClusterIP)
	defer cleanup1()

	svc2, cleanup2 := data.createAgnhostServiceAndBackendPods(t, "s2", serverNamespace, nodeName(1), v1.ServiceTypeClusterIP)
	defer cleanup2()

	testcases := []podToAddrTestStep{
		{
			Pod(clientNamespace + "/agnhost-client"),
			svc1.Spec.ClusterIP,
			80,
			Rejected,
		},
		{
			Pod(clientNamespace + "/agnhost-client"),
			svc2.Spec.ClusterIP,
			80,
			Rejected,
		},
	}

	// Test egress.
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-reject-egress-svc-traffic").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": "agnhost-client"}}})
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": "s1"}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": "s2"}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	acnpEgress := builder1.Get()
	k8sUtils.CreateOrUpdateACNP(acnpEgress)
	failOnError(waitForResourcesReady(t, timeout, acnpEgress, svc1, svc2), t)

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder1.Name), t)

	// Test ingress.
	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-reject-ingress-svc-traffic").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: svc1.Spec.Selector}, {PodSelector: svc2.Spec.Selector}})
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": "agnhost-client"}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	acnpIngress := builder2.Get()
	k8sUtils.CreateOrUpdateACNP(acnpIngress)
	failOnError(waitForResourceReady(t, timeout, acnpIngress), t)

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder2.Name), t)
}

// RejectNoInfiniteLoop tests that a reject action in both traffic directions won't cause an infinite rejection loop.
func testRejectNoInfiniteLoop(t *testing.T, data *TestData, clientNamespace, serverNamespace string) {
	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, clientNamespace, nodeName(0), false))
	defer data.DeletePodAndWait(defaultTimeout, clientName, clientNamespace)
	_, err := data.podWaitForIPs(defaultTimeout, clientName, clientNamespace)
	require.NoError(t, err)

	_, server0IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server", nodeName(0), serverNamespace, false)
	defer cleanupFunc()

	_, server1IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server", nodeName(1), serverNamespace, false)
	defer cleanupFunc()

	var testcases []podToAddrTestStep
	if clusterInfo.podV4NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(clientNamespace + "/agnhost-client"),
				server0IP.IPv4.String(),
				80,
				Rejected,
			},
			{
				Pod(clientNamespace + "/agnhost-client"),
				server1IP.IPv4.String(),
				80,
				Rejected,
			},
		}...)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(clientNamespace + "/agnhost-client"),
				server0IP.IPv6.String(),
				80,
				Rejected,
			},
			{
				Pod(clientNamespace + "/agnhost-client"),
				server1IP.IPv6.String(),
				80,
				Rejected,
			},
		}...)
	}

	runTestsWithACNP := func(acnp *crdv1beta1.ClusterNetworkPolicy, testcases []podToAddrTestStep) {
		k8sUtils.CreateOrUpdateACNP(acnp)
		failOnError(waitForResourceReady(t, timeout, acnp), t)

		for _, tc := range testcases {
			log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
			connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
			if err != nil {
				t.Errorf("Failure -- could not complete probe: %v", err)
			}
			if connectivity != tc.expectedConnectivity {
				t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
					tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
			}
		}
		failOnError(k8sUtils.DeleteACNP(acnp.Name), t)
	}

	// Test client and server reject traffic that ingress from each other.
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-reject-ingress-double-dir").
		SetPriority(1.0)
	builder1.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, nil, nil, nil, []ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}}, crdv1beta1.RuleActionReject, "", "", nil)
	builder1.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, nil, nil, nil, []ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}, crdv1beta1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder1.Get(), testcases)

	// Test client and server reject traffic that egress to each other.
	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-reject-egress-double-dir").
		SetPriority(1.0)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, nil, nil, nil, []ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}}, crdv1beta1.RuleActionReject, "", "", nil)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, nil, nil, nil, []ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}, crdv1beta1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder2.Get(), testcases)

	// Test server reject traffic that egress to client and ingress from client.
	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-reject-server-double-dir").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	builder3.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)
	builder3.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder3.Get(), testcases)

	// Test client reject traffic that egress to server and ingress from server.
	builder4 := &ClusterNetworkPolicySpecBuilder{}
	builder4 = builder4.SetName("acnp-reject-client-double-dir").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}})
	builder4.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)
	builder4.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder4.Get(), testcases)
}

// testANNPPortRange tests the port range in a ANNP can work.
func testANNPPortRange(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("y"), "annp-deny-yb-to-xc-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(ProtocolTCP, &p8080, nil, &p8082, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "annp-port-range")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("y", "b"), getPod("x", "c"), Dropped)

	var testSteps []*TestStep
	testSteps = append(testSteps, &TestStep{
		Name:          fmt.Sprintf("ANNP Drop Ports 8080:8082"),
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get()},
		Ports:         []int32{8080, 8081, 8082},
		Protocol:      ProtocolTCP,
	})

	testCase := []*TestCase{
		{"ANNP Drop Egress y/b to x/c with a portRange", testSteps},
	}
	executeTests(t, testCase)
}

// testANNPBasic tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea NetworkPolicy
// that specifies that. Also it tests that a K8s NetworkPolicy with same appliedTo will not affect its behavior.
func testANNPBasic(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("y"), "np-same-name").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	// build a K8s NetworkPolicy that has the same appliedTo but allows all traffic.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(getNS("y"), "np-same-name").
		SetPodSelector(map[string]string{"pod": "a"})
	k8sNPBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
		nil, nil, nil, nil)
	testStep2 := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get(), k8sNPBuilder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP Drop X/B to Y/A", testStep},
		{"With K8s NetworkPolicy of the same name", testStep2},
	}
	executeTests(t, testCase)
}

// testANNPUpdate tests traffic from X/B to Y/A on port 80 will be dropped, and
// update on the Antrea NetworkPolicy allows traffic from X/B to Y/A on port 80.
func testANNPUpdate(t *testing.T, data *TestData) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("y"), "np-before-update").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	annp, err := k8sUtils.CreateOrUpdateANNP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForANNPRealized(t, annp.Namespace, annp.Name, policyRealizedTimeout), t)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ := reachability.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	updatedBuilder := &AntreaNetworkPolicySpecBuilder{}
	updatedBuilder = updatedBuilder.SetName(getNS("y"), "np-before-update").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	updatedBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "")
	updatedReachability := NewReachability(allPods, Connected)
	annp, err = k8sUtils.CreateOrUpdateANNP(updatedBuilder.Get())
	failOnError(err, t)
	failOnError(data.waitForANNPRealized(t, annp.Namespace, annp.Name, policyRealizedTimeout), t)
	k8sUtils.Validate(allPods, updatedReachability, []int32{80}, ProtocolTCP)
	_, wrong, _ = reachability.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}
	failOnError(k8sUtils.DeleteANNP(annp.Namespace, annp.Name), t)
}

// testANNPMultipleAppliedTo tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea
// NetworkPolicy that applies to multiple AppliedTos, one of which doesn't select any Pod. It also ensures the Policy is
// updated correctly when one of its AppliedToGroup starts and stops selecting Pods.
func testANNPMultipleAppliedTo(t *testing.T, data *TestData, singleRule bool) {
	tempLabel := randName("temp-")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("y"), "np-multiple-appliedto").SetPriority(1.0)
	// Make it apply to an extra dummy AppliedTo to ensure it handles multiple AppliedToGroups correctly.
	// See https://github.com/antrea-io/antrea/issues/2083.
	if singleRule {
		builder.SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}, {PodSelector: map[string]string{tempLabel: ""}}})
		builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
			nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "")
	} else {
		builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
			nil, nil, nil, []ANNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}, crdv1beta1.RuleActionDrop, "", "")
		builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
			nil, nil, nil, []ANNPAppliedToSpec{{PodSelector: map[string]string{tempLabel: ""}}}, crdv1beta1.RuleActionDrop, "", "")
	}

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)

	annp, err := k8sUtils.CreateOrUpdateANNP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForANNPRealized(t, annp.Namespace, annp.Name, policyRealizedTimeout), t)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ := reachability.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	t.Logf("Making the Policy apply to y/c by labeling it with the temporary label that matches the dummy AppliedTo")
	podYC, err := k8sUtils.GetPodByLabel(getNS("y"), "c")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace y with label 'pod=c': %v", err)
	}
	podYC.Labels[tempLabel] = ""
	podYC, err = k8sUtils.clientset.CoreV1().Pods(podYC.Namespace).Update(context.TODO(), podYC, metav1.UpdateOptions{})
	assert.NoError(t, err)
	reachability = NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("x", "b"), getPod("y", "c"), Dropped)
	time.Sleep(networkPolicyDelay)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ = reachability.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	t.Logf("Making the Policy not apply to y/c by removing the temporary label")
	delete(podYC.Labels, tempLabel)
	_, err = k8sUtils.clientset.CoreV1().Pods(podYC.Namespace).Update(context.TODO(), podYC, metav1.UpdateOptions{})
	assert.NoError(t, err)
	reachability = NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	time.Sleep(networkPolicyDelay)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ = reachability.Summary()
	if wrong != 0 {
		t.Errorf("Failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	failOnError(k8sUtils.DeleteANNP(builder.Namespace, builder.Name), t)
}

// auditLogMatcher is used to validate that audit logs are as expected. It converts input parameters
// provided by test cases into regexes that are used to match the content of the audit logs file.
type auditLogMatcher struct {
	npRef       string
	ruleName    string
	direction   string
	disposition string
	logLabel    string
	priorityRe  string

	matchers []*regexp.Regexp
}

func NewAuditLogMatcher(npRef, ruleName, direction, disposition string) *auditLogMatcher {
	priorityRe := `[0-9]+`
	if npRef == "K8sNetworkPolicy" {
		// K8s NP default drop (isolated behavior): there is no priority
		priorityRe = "<nil>"
	}
	return &auditLogMatcher{
		npRef:       npRef,
		ruleName:    ruleName,
		direction:   direction,
		disposition: disposition,
		logLabel:    "<nil>",
		priorityRe:  priorityRe,
		matchers:    make([]*regexp.Regexp, 0),
	}
}

func (m *auditLogMatcher) WithLogLabel(logLabel string) *auditLogMatcher {
	m.logLabel = logLabel
	return m
}

func (m *auditLogMatcher) add(appliedToRef, srcIP, destIP string, destPort int32) {
	re := regexp.MustCompile(strings.Join([]string{
		m.npRef,
		m.ruleName,
		m.direction,
		m.disposition,
		m.priorityRe,
		appliedToRef,
		srcIP,
		`[0-9]+`, // srcPort
		destIP,
		strconv.Itoa(int(destPort)),
		"TCP",    // all AuditLogging tests use TCP
		`[0-9]+`, // pktLength
		m.logLabel,
	}, " "))
	m.matchers = append(m.matchers, re)
}

func (m *auditLogMatcher) AddProbe(appliedToRef, ns1, pod1, ns2, pod2 string, destPort int32) {
	srcIPs, _ := podIPs[fmt.Sprintf("%s/%s", ns1, pod1)]
	destIPs, _ := podIPs[fmt.Sprintf("%s/%s", ns2, pod2)]
	for _, srcIP := range srcIPs {
		for _, destIP := range destIPs {
			// only look for an entry in the audit log file if srcIP and dstIP are of the same family
			if IPFamily(srcIP) != IPFamily(destIP) {
				continue
			}
			m.add(appliedToRef, srcIP, destIP, destPort)
		}
	}
}

func (m *auditLogMatcher) AddProbeAddr(appliedToRef, ns, pod, destIP string, destPort int32) {
	srcIPs, _ := podIPs[fmt.Sprintf("%s/%s", ns, pod)]
	for _, srcIP := range srcIPs {
		// only look for an entry in the audit log file if srcIP and dstIP are of the same family
		if IPFamily(srcIP) != IPFamily(destIP) {
			continue
		}
		m.add(appliedToRef, srcIP, destIP, destPort)
	}
}

func (m *auditLogMatcher) Matchers() []*regexp.Regexp {
	return m.matchers
}

// testAuditLoggingBasic tests that audit logs are generated when egress drop applied
func testAuditLoggingBasic(t *testing.T, data *TestData) {
	npName := "test-log-acnp-deny"
	ruleName := "DropToZ"
	logLabel := "testLogLabel"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(npName).
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", ruleName, nil)
	builder.AddEgressLogging(logLabel)
	npRef := fmt.Sprintf("AntreaClusterNetworkPolicy:%s", npName)

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForACNPRealized(t, acnp.Name, policyRealizedTimeout), t)

	podXA, err := k8sUtils.GetPodByLabel(getNS("x"), "a")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace x with label 'pod=a': %v", err)
	}

	matcher := NewAuditLogMatcher(npRef, ruleName, "Egress", "Drop").WithLogLabel(logLabel)
	appliedToRef := fmt.Sprintf("%s/%s", podXA.Namespace, podXA.Name)

	// generate some traffic that will be dropped by test-log-acnp-deny
	var wg sync.WaitGroup
	oneProbe := func(ns1, pod1, ns2, pod2 string) {
		matcher.AddProbe(appliedToRef, ns1, pod1, ns2, pod2, p80)
		wg.Add(1)
		go func() {
			defer wg.Done()
			k8sUtils.Probe(ns1, pod1, ns2, pod2, p80, ProtocolTCP, nil, nil)
		}()
	}
	oneProbe(getNS("x"), "a", getNS("z"), "a")
	oneProbe(getNS("x"), "a", getNS("z"), "b")
	oneProbe(getNS("x"), "a", getNS("z"), "c")
	wg.Wait()

	// nodeName is guaranteed to be set at this stage, since the framework waits for all Pods to be in Running phase
	nodeName := podXA.Spec.NodeName
	checkAuditLoggingResult(t, data, nodeName, npRef, matcher.Matchers())

	failOnError(k8sUtils.CleanACNPs(), t)
}

// testAuditLoggingEnableK8s tests that audit logs are generated when K8s NP is applied
// tests both Allow traffic by K8s NP and Drop traffic by implicit K8s policy drop
func testAuditLoggingEnableK8s(t *testing.T, data *TestData) {
	failOnError(data.updateNamespaceWithAnnotations(getNS("x"), map[string]string{networkpolicy.EnableNPLoggingAnnotationKey: "true"}), t)
	// Add a K8s namespaced NetworkPolicy in ns x that allow ingress traffic from
	// Pod x/b to x/a which default denies other ingress including from Pod x/c to x/a
	npName := "allow-x-b-to-x-a"
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(getNS("x"), npName).
		SetPodSelector(map[string]string{"pod": "a"}).
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "b"}, nil, nil, nil)
	npRef := fmt.Sprintf("K8sNetworkPolicy:%s/%s", getNS("x"), npName)

	knp, err := k8sUtils.CreateOrUpdateNetworkPolicy(k8sNPBuilder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, knp), t)

	podXA, err := k8sUtils.GetPodByLabel(getNS("x"), "a")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace x with label 'pod=a': %v", err)
	}

	// matcher1 is for connections allowed by the K8s NP
	matcher1 := NewAuditLogMatcher(npRef, "<nil>", "Ingress", "Allow")
	// matcher2 is for connections dropped by the isolated behavior of the K8s NP
	matcher2 := NewAuditLogMatcher("K8sNetworkPolicy", "<nil>", "Ingress", "Drop")

	appliedToRef := fmt.Sprintf("%s/%s", podXA.Namespace, podXA.Name)

	// generate some traffic that will be dropped by implicit K8s policy drop
	var wg sync.WaitGroup
	oneProbe := func(ns1, pod1, ns2, pod2 string, matcher *auditLogMatcher) {
		matcher.AddProbe(appliedToRef, ns1, pod1, ns2, pod2, p80)
		wg.Add(1)
		go func() {
			defer wg.Done()
			k8sUtils.Probe(ns1, pod1, ns2, pod2, p80, ProtocolTCP, nil, nil)
		}()
	}
	oneProbe(getNS("x"), "b", getNS("x"), "a", matcher1)
	oneProbe(getNS("x"), "c", getNS("x"), "a", matcher2)
	wg.Wait()

	// nodeName is guaranteed to be set at this stage, since the framework waits for all Pods to be in Running phase
	nodeName := podXA.Spec.NodeName
	checkAuditLoggingResult(t, data, nodeName, "K8sNetworkPolicy", append(matcher1.Matchers(), matcher2.Matchers()...))

	failOnError(k8sUtils.DeleteNetworkPolicy(getNS("x"), "allow-x-b-to-x-a"), t)
	failOnError(data.UpdateNamespace(getNS("x"), func(namespace *v1.Namespace) {
		delete(namespace.Annotations, networkpolicy.EnableNPLoggingAnnotationKey)
	}), t)
}

// testAuditLoggingK8sService tests that audit logs are generated for K8s Service access
// tests both Allow traffic by K8s NP and Drop traffic by implicit K8s policy drop
func testAuditLoggingK8sService(t *testing.T, data *TestData) {
	failOnError(data.updateNamespaceWithAnnotations(getNS("x"), map[string]string{networkpolicy.EnableNPLoggingAnnotationKey: "true"}), t)

	// Create and expose nginx service on the same node as pod x/a
	podXA, err := k8sUtils.GetPodByLabel(getNS("x"), "a")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace x with label 'pod=a': %v", err)
	}
	serverNode := podXA.Spec.NodeName
	serviceName := "nginx"
	serverPodName, serverIP, nginxCleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", serverNode, getNS("x"), false)
	defer nginxCleanupFunc()
	serverPort := int32(80)
	ipFamily := v1.IPv4Protocol
	if IPFamily(podIPs[getPodName("x", "a")][0]) == "v6" {
		ipFamily = v1.IPv6Protocol
	}
	service, err := data.CreateService(serviceName, getNS("x"), serverPort, serverPort, map[string]string{"app": "nginx"}, false, false, v1.ServiceTypeClusterIP, &ipFamily)
	if err != nil {
		t.Fatalf("Error when creating nginx service: %v", err)
	}
	defer k8sUtils.DeleteService(service.Namespace, service.Name)

	// Add a K8s namespaced NetworkPolicy in ns x that allow ingress traffic from
	// Pod x/a to service nginx which default denies other ingress including from Pod x/b to service nginx
	npName := "allow-xa-to-service"
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(getNS("x"), npName).
		SetPodSelector(map[string]string{"app": serviceName}).
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "a"}, nil, nil, nil)
	npRef := fmt.Sprintf("K8sNetworkPolicy:%s/%s", getNS("x"), npName)

	knp, err := k8sUtils.CreateOrUpdateNetworkPolicy(k8sNPBuilder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, knp), t)

	// matcher1 is for connections allowed by the K8s NP
	matcher1 := NewAuditLogMatcher(npRef, "<nil>", "Ingress", "Allow")
	// matcher2 is for connections dropped by the isolated behavior of the K8s NP
	matcher2 := NewAuditLogMatcher("K8sNetworkPolicy", "<nil>", "Ingress", "Drop")

	appliedToRef := fmt.Sprintf("%s/%s", getNS("x"), serverPodName)

	// generate some traffic that wget the nginx service
	var wg sync.WaitGroup
	oneProbe := func(ns, pod string, matcher *auditLogMatcher) {
		for _, ip := range serverIP.IPStrings {
			ip := ip
			matcher.AddProbeAddr(appliedToRef, ns, pod, ip, serverPort)
			wg.Add(1)
			go func() {
				defer wg.Done()
				k8sUtils.ProbeAddr(ns, "pod", pod, ip, serverPort, ProtocolTCP, nil)
			}()
		}
	}
	oneProbe(getNS("x"), "a", matcher1)
	oneProbe(getNS("x"), "b", matcher2)
	wg.Wait()

	checkAuditLoggingResult(t, data, serverNode, "K8sNetworkPolicy", append(matcher1.Matchers(), matcher2.Matchers()...))

	failOnError(k8sUtils.DeleteNetworkPolicy(getNS("x"), npName), t)
	failOnError(data.UpdateNamespace(getNS("x"), func(namespace *v1.Namespace) {
		delete(namespace.Annotations, networkpolicy.EnableNPLoggingAnnotationKey)
	}), t)
}

func testAppliedToPerRule(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(getNS("y"), "np1").SetPriority(1.0)
	annpATGrp1 := ANNPAppliedToSpec{PodSelector: map[string]string{"pod": "a"}, PodSelectorMatchExp: nil}
	annpATGrp2 := ANNPAppliedToSpec{PodSelector: map[string]string{"pod": "b"}, PodSelectorMatchExp: nil}
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, []ANNPAppliedToSpec{annpATGrp1}, crdv1beta1.RuleActionDrop, "", "")
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("z")}, nil,
		nil, nil, nil, []ANNPAppliedToSpec{annpATGrp2}, crdv1beta1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("z", "b"), getPod("y", "b"), Dropped)
	testStep := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability,
			TestResources: []metav1.Object{builder.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp1").SetPriority(1.0)
	cnpATGrp1 := ACNPAppliedToSpec{PodSelector: map[string]string{"pod": "a"}, PodSelectorMatchExp: nil}
	cnpATGrp2 := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"}, NSSelector: map[string]string{"ns": getNS("y")},
		PodSelectorMatchExp: nil, NSSelectorMatchExp: nil}
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, nil, []ACNPAppliedToSpec{cnpATGrp1}, crdv1beta1.RuleActionDrop, "", "", nil)
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("z")},
		nil, nil, nil, nil, []ACNPAppliedToSpec{cnpATGrp2}, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(getPod("x", "b"), getPod("x", "a"), Dropped)
	reachability2.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	reachability2.Expect(getPod("x", "b"), getPod("z", "a"), Dropped)
	reachability2.Expect(getPod("z", "b"), getPod("y", "b"), Dropped)
	testStep2 := []*TestStep{
		{
			Name:          "Port 80",
			Reachability:  reachability2,
			TestResources: []metav1.Object{builder2.Get()},
			Ports:         []int32{80},
			Protocol:      ProtocolTCP,
		},
	}
	testCase := []*TestCase{
		{"ANNP AppliedTo per rule", testStep},
		{"ACNP AppliedTo per rule", testStep2},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupServiceRefCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", getNS("y"), 80, 80, map[string]string{"app": "b"}, nil)

	cg1Name, cg2Name := "cg-svc1", "cg-svc2"
	cgBuilder1 := &ClusterGroupSpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference(getNS("x"), "svc1")
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetServiceReference(getNS("y"), "svc2")

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-cg-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cg1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cg2Name, "", nil)

	// Pods backing svc1 (label pod=a) in Namespace x should not allow ingress from Pods backing svc2 (label pod=b) in Namespace y.
	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("y", "b"), getPod("x", "a"), Dropped)
	testStep1 := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{svc1, svc2, cgBuilder1.Get(), cgBuilder2.Get(), builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	// Test update selector of Service referred in cg-svc1, and update serviceReference of cg-svc2.
	svc1Updated := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "b"}, nil)
	svc3 := k8sUtils.BuildService("svc3", getNS("y"), 80, 80, map[string]string{"app": "a"}, nil)
	svc1PodName := randName("test-pod-svc1-")
	svc3PodName := randName("test-pod-svc3-")
	cgBuilder2Updated := cgBuilder2.SetServiceReference(getNS("y"), "svc3")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("y"), svc3PodName),
				Labels: map[string]string{"pod": svc3PodName, "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("x"), svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "b"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}

	// Pods backing svc1 (label pod=b) in namespace x should not allow ingress from Pods backing svc3 (label pod=a) in namespace y.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(getPod("y", "a"), getPod("x", "b"), Dropped)
	testStep2 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{svc1Updated, svc3, cgBuilder1.Get(), cgBuilder2Updated.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
		CustomProbes:  cp,
	}

	builderUpdated := &ClusterNetworkPolicySpecBuilder{}
	builderUpdated = builderUpdated.SetName("cnp-cg-svc-ref").SetPriority(1.0)
	builderUpdated.SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": getNS("x")}}})
	builderUpdated.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("y")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	// Pod x/a should not allow ingress from y/b per the updated ACNP spec.
	testStep3 := &TestStep{
		Name:          "Port 80 ACNP spec updated to selector",
		Reachability:  reachability,
		TestResources: []metav1.Object{builderUpdated.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ACNP ClusterGroup Service Reference create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPNestedClusterGroupCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", getNS("x"), 80, 80, map[string]string{"app": "a"}, nil)
	svc1PodName := randName("test-pod-svc1-")
	cg1Name, cg2Name, cg3Name := "cg-svc-x-a", "cg-select-y-b", "cg-select-y-c"
	cgBuilder1 := &ClusterGroupSpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference(getNS("x"), "svc1")
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).
		SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
	cgBuilder3 := &ClusterGroupSpecBuilder{}
	cgBuilder3 = cgBuilder3.SetName(cg3Name).
		SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil).
		SetPodSelector(map[string]string{"pod": "c"}, nil)
	cgNestedName := "cg-nested"
	cgBuilderNested := &ClusterGroupSpecBuilder{}
	cgBuilderNested = cgBuilderNested.SetName(cgNestedName).SetChildGroups([]string{cg1Name, cg3Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-nested-cg").SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("z")}}}).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgNestedName, "", nil)

	// Pods in Namespace z should not allow traffic from Pods backing svc1 (label pod=a) in Namespace x.
	// Note that in this testStep cg3 will not be created yet, so even though cg-nested selects cg1 and
	// cg3 as childGroups, only members of cg1 will be included as this time.
	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)

	testStep1 := &TestStep{
		Name:         "Port 80",
		Reachability: reachability,
		// Note in this testcase the ClusterGroup is created after the ACNP
		TestResources: []metav1.Object{builder.Get(), svc1, cgBuilder1.Get(), cgBuilderNested.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	// Test update "cg-nested" to include "cg-select-y-b" as well.
	cgBuilderNested = cgBuilderNested.SetChildGroups([]string{cg1Name, cg2Name, cg3Name})
	// In addition to x/a, all traffic from y/b to Namespace z should also be denied.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("y", "b"), getNS("z"), Dropped)
	// New member in cg-svc-x-a should be reflected in cg-nested as well.
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(getNS("x"), svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(getNS("z"), "test-add-pod-ns-z"),
				Labels: map[string]string{"pod": "test-add-pod-ns-z"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep2 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{cgBuilder2.Get(), cgBuilderNested.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
		CustomProbes:  cp,
	}

	// In this testStep cg3 is created. It's members should reflect in cg-nested
	// and as a result, all traffic from y/c to Namespace z should be denied as well.
	reachability3 := NewReachability(allPods, Connected)
	reachability3.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability3.ExpectEgressToNamespace(getPod("y", "b"), getNS("z"), Dropped)
	reachability3.ExpectEgressToNamespace(getPod("y", "c"), getNS("z"), Dropped)
	testStep3 := &TestStep{
		Name:          "Port 80 updated",
		Reachability:  reachability3,
		TestResources: []metav1.Object{cgBuilder3.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ACNP nested ClusterGroup create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPNestedIPBlockClusterGroupCreateAndUpdate(t *testing.T) {
	podXAIP, _ := podIPs[getPodName("x", "a")]
	podXBIP, _ := podIPs[getPodName("x", "b")]
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
	cg1Name, cg2Name, cg3Name := "cg-x-a-ipb", "cg-x-b-ipb", "cg-select-x-c"
	cgParentName := "cg-parent"
	var ipBlockXA, ipBlockXB []crdv1beta1.IPBlock
	for i := 0; i < len(podXAIP); i++ {
		ipBlockXA = append(ipBlockXA, crdv1beta1.IPBlock{CIDR: genCIDR(podXAIP[i])})
		ipBlockXB = append(ipBlockXB, crdv1beta1.IPBlock{CIDR: genCIDR(podXBIP[i])})
	}
	cgBuilder1 := &ClusterGroupSpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetIPBlocks(ipBlockXA)
	cgBuilder2 := &ClusterGroupSpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetIPBlocks(ipBlockXB)
	cgParent := &ClusterGroupSpecBuilder{}
	cgParent = cgParent.SetName(cgParentName).SetChildGroups([]string{cg1Name, cg2Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-x-ips-ingress-for-ya").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "a"},
				NSSelector:  map[string]string{"ns": getNS("y")},
			},
		})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, cgParentName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	reachability.Expect(getPod("x", "b"), getPod("y", "a"), Dropped)
	testStep := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get(), cgBuilder1.Get(), cgBuilder2.Get(), cgParent.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	cgBuilder3 := &ClusterGroupSpecBuilder{}
	cgBuilder3 = cgBuilder3.SetName(cg3Name).
		SetNamespaceSelector(map[string]string{"ns": getNS("x")}, nil).
		SetPodSelector(map[string]string{"pod": "c"}, nil)
	updatedCGParent := &ClusterGroupSpecBuilder{}
	updatedCGParent = updatedCGParent.SetName(cgParentName).SetChildGroups([]string{cg1Name, cg3Name})

	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(getPod("x", "a"), getPod("y", "a"), Dropped)
	reachability2.Expect(getPod("x", "c"), getPod("y", "a"), Dropped)
	testStep2 := &TestStep{
		Name:          "Port 80, updated",
		Reachability:  reachability2,
		TestResources: []metav1.Object{cgBuilder3.Get(), updatedCGParent.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testCase := []*TestCase{
		{"ACNP Drop Ingress From x to Pod y/a with nested ClusterGroup with ipBlocks", []*TestStep{testStep, testStep2}},
	}
	executeTests(t, testCase)
}

func testACNPNamespaceIsolation(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-ns-isolation").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	// deny ingress traffic except from own namespace, which is always allowed.
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, selfNamespace, nil, crdv1beta1.RuleActionAllow, "", "", nil)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Dropped)
	reachability.ExpectAllSelfNamespace(Connected)
	testStep1 := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("test-acnp-ns-isolation-applied-to-per-rule").
		SetTier("baseline").
		SetPriority(1.0)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		selfNamespace, []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}}, crdv1beta1.RuleActionAllow, "", "", nil)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil, nil,
		nil, []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}}, crdv1beta1.RuleActionDrop, "", "", nil)

	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(getPod("x", "a"), getNS("y"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("x", "a"), getNS("z"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("x", "b"), getNS("y"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("x", "b"), getNS("z"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("x", "c"), getNS("y"), Dropped)
	reachability2.ExpectEgressToNamespace(getPod("x", "c"), getNS("z"), Dropped)
	testStep2 := &TestStep{
		Name:          "Port 80",
		Reachability:  reachability2,
		TestResources: []metav1.Object{builder2.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testCase := []*TestCase{
		{"ACNP Namespace isolation for all namespaces", []*TestStep{testStep1}},
		{"ACNP Namespace isolation for namespace x", []*TestStep{testStep2}},
	}
	executeTests(t, testCase)
}

func testACNPStrictNamespacesIsolation(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-strict-ns-isolation").
		SetTier("securityops").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		selfNamespace, nil, crdv1beta1.RuleActionPass, "", "", nil)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)
	// deny ingress traffic except from own namespace, which is delegated to Namespace owners (who can create K8s
	// NetworkPolicies to regulate intra-Namespace traffic)
	reachability := NewReachability(allPods, Dropped)
	reachability.ExpectAllSelfNamespace(Connected)
	testStep1 := &TestStep{
		Name:          "Namespace isolation, Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	// Add a K8s namespaced NetworkPolicy in ns x that isolates all Pods in that namespace.
	builder2 := &NetworkPolicySpecBuilder{}
	builder2 = builder2.SetName(getNS("x"), "default-deny-in-namespace-x")
	builder2.SetTypeIngress()
	reachability2 := NewReachability(allPods, Dropped)
	reachability2.ExpectAllSelfNamespace(Connected)
	reachability2.ExpectSelfNamespace(getNS("x"), Dropped)
	reachability2.ExpectSelf(allPods, Connected)
	testStep2 := &TestStep{
		Name:          "Namespace isolation with K8s NP, Port 80",
		Reachability:  reachability2,
		TestResources: []metav1.Object{builder2.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	testCase := []*TestCase{
		{"ACNP strict Namespace isolation for all Namespaces", []*TestStep{testStep1, testStep2}},
	}
	executeTests(t, testCase)
}

func testACNPStrictNamespacesIsolationByLabels(t *testing.T) {
	samePurposeTierLabels := &crdv1beta1.PeerNamespaces{
		SameLabels: []string{"purpose", "tier"},
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-strict-ns-isolation-by-labels").
		SetTier("securityops").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		samePurposeTierLabels, nil, crdv1beta1.RuleActionPass, "", "", nil)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)
	// prod1 and prod2 Namespaces should be able to connect to each other. The same goes for dev1 and
	// dev2 Namespaces. However, any prod Namespace should not be able to connect to any dev Namespace
	// due to different "tier" label values. For the "no-tier" Namespace, the first ingress rule will
	// have no effect because the Namespace does not have a "tier" label. So every Pod in that Namespace
	// will be isolated according to the second rule of the ACNP.
	reachability := NewReachability(allPods, Dropped)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("prod1"), getNS("prod2"), Connected)
	reachability.ExpectNamespaceEgressToNamespace(getNS("prod1"), getNS("prod2"), Connected)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("prod2"), getNS("prod1"), Connected)
	reachability.ExpectNamespaceEgressToNamespace(getNS("prod2"), getNS("prod1"), Connected)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("dev1"), getNS("dev2"), Connected)
	reachability.ExpectNamespaceEgressToNamespace(getNS("dev1"), getNS("dev2"), Connected)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("dev2"), getNS("dev1"), Connected)
	reachability.ExpectNamespaceEgressToNamespace(getNS("dev2"), getNS("dev1"), Connected)
	reachability.ExpectAllSelfNamespace(Connected)
	reachability.ExpectSelfNamespace(getNS("no-tier"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := &TestStep{
		Name:          "Namespace isolation by label, Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}
	testCase := []*TestCase{
		{"ACNP strict Namespace isolation by Namespace purpose and tier labels", []*TestStep{testStep}},
	}
	executeTests(t, testCase)
}

func testACNPStrictNamespacesIsolationBySingleLabel(t *testing.T, data *TestData) {
	samePurposeTierLabels := &crdv1beta1.PeerNamespaces{
		SameLabels: []string{"purpose"},
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-strict-ns-isolation-by-single-purpose-label").
		SetTier("securityops").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		samePurposeTierLabels, nil, crdv1beta1.RuleActionPass, "", "", nil)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)
	// Namespaces are split into two logical groups, purpose=test (prod1,2 and dev1,2) and purpose=test-exclusion
	// (no-tier). The two groups of Namespace should not be able to connect to each other.
	reachability := NewReachability(allPods, Connected)
	reachability.ExpectNamespaceEgressToNamespace(getNS("prod1"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceEgressToNamespace(getNS("prod2"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceEgressToNamespace(getNS("dev1"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceEgressToNamespace(getNS("dev2"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("prod1"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("prod2"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("dev1"), getNS("no-tier"), Dropped)
	reachability.ExpectNamespaceIngressFromNamespace(getNS("dev2"), getNS("no-tier"), Dropped)

	testStep := &TestStep{
		Name:          "Namespace isolation by single label, Port 80",
		Reachability:  reachability,
		TestResources: []metav1.Object{builder.Get()},
		Ports:         []int32{80},
		Protocol:      ProtocolTCP,
	}

	labelNoTierNS := func() {
		nsReturned, err := data.clientset.CoreV1().Namespaces().Get(context.TODO(), getNS("no-tier"), metav1.GetOptions{})
		if err != nil {
			t.Errorf("failed to get the Namespace that has no tier label")
		}
		nsReturned.Labels = map[string]string{
			"purpose": "test",
		}
		log.Infof("Updating no-tier Namespace purpose label")
		if _, err = data.clientset.CoreV1().Namespaces().Update(context.TODO(), nsReturned, metav1.UpdateOptions{}); err != nil {
			t.Errorf("failed to update the no-tier Namespace with purpose=test label")
		}
	}
	revertLabel := func() {
		nsReturned, err := data.clientset.CoreV1().Namespaces().Get(context.TODO(), getNS("no-tier"), metav1.GetOptions{})
		if err != nil {
			t.Errorf("failed to get the no-tier Namespace")
		}
		nsReturned.Labels = map[string]string{
			"purpose": "test-exclusion",
		}
		if _, err = data.clientset.CoreV1().Namespaces().Update(context.TODO(), nsReturned, metav1.UpdateOptions{}); err != nil {
			t.Errorf("failed to revert the purpose label for the no-tier Namespace")
		}
	}
	newReachability := NewReachability(allPods, Connected)
	testSetp2 := &TestStep{
		Name:           "Namespace isolation after Namespace label update, Port 80",
		Reachability:   newReachability,
		Ports:          []int32{80},
		Protocol:       ProtocolTCP,
		CustomSetup:    labelNoTierNS,
		CustomTeardown: revertLabel,
	}
	testCase := []*TestCase{
		{"ACNP strict Namespace isolation by Namespace purpose label", []*TestStep{testStep, testSetp2}},
	}
	executeTestsWithData(t, testCase, data)
}

func testFQDNPolicy(t *testing.T) {
	// The ipv6-only test env doesn't have IPv6 access to the web.
	skipIfNotIPv4Cluster(t)
	// It is convenient to have higher log verbosity for FQDN tests for troubleshooting failures.
	logLevel := log.GetLevel()
	log.SetLevel(log.TraceLevel)
	defer log.SetLevel(logLevel)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-fqdn").
		SetTier("application").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	// The DNS server of e2e testbeds may reply large DNS response with a long list of AUTHORITY SECTION and ADDITIONAL
	// SECTION, which causes the response to be truncated and the clients to retry over TCP. However, antrea-agent only
	// inspects DNS UDP packets, the DNS resolution result will be missed by it if the clients uses DNS over TCP. And if
	// the IP got from DNS/TCP response is different from the IP got from the first DNS/UDP response, the following
	// application traffic will bypass FQDN NetworkPolicy.
	// So we changed the target domain from google.com to github.com, which has a more stable DNS resolution result. The
	// change could be reverted once we support inspecting DNS/TCP traffic.
	// See https://github.com/antrea-io/antrea/issues/4130 for more details.
	builder.AddFQDNRule("*github.com", ProtocolTCP, nil, nil, nil, "r1", nil, crdv1beta1.RuleActionReject)
	builder.AddFQDNRule("wayfair.com", ProtocolTCP, nil, nil, nil, "r2", nil, crdv1beta1.RuleActionDrop)
	// Test upper-case FQDN.
	builder.AddFQDNRule("Stackoverflow.com", ProtocolTCP, nil, nil, nil, "r3", nil, crdv1beta1.RuleActionDrop)

	// All client Pods below are randomly chosen from test Namespaces.
	testcases := []podToAddrTestStep{
		{
			getPod("x", "a"),
			"docs.github.com",
			80,
			Rejected,
		},
		{
			getPod("x", "b"),
			"api.github.com",
			80,
			Rejected,
		},
		{
			getPod("y", "a"),
			"wayfair.com",
			80,
			Dropped,
		},
		{
			getPod("y", "b"),
			"stackoverflow.com",
			80,
			Dropped,
		},
		{
			getPod("z", "a"),
			"facebook.com",
			80,
			Connected,
		},
	}
	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, acnp), t)
	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

// testFQDNPolicyInClusterService uses in-cluster headless Services to test FQDN
// policies, to avoid having a dependency on external connectivity. The reason we
// use headless Service is that FQDN will use the IP from DNS A/AAAA records to
// implement flows in the egress policy table. For a non-headless Service, the DNS
// Name resolves to the ClusterIP for the Service. But when traffic arrives to the
// egress table, the dstIP has already been DNATed to the Endpoints IP by
// AntreaProxy Service Load-Balancing, and the policies are not enforced correctly.
// For a headless Service, the Endpoints IP will be directly returned by the DNS
// server. In this case, FQDN based policies can be enforced successfully.
func testFQDNPolicyInClusterService(t *testing.T) {
	logLevel := log.GetLevel()
	log.SetLevel(log.TraceLevel)
	defer log.SetLevel(logLevel)
	var services []*v1.Service
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4Svc := k8sUtils.BuildService("ipv4-svc", getNS("x"), 80, 80, map[string]string{"pod": "a"}, nil)
		ipv4Svc.Spec.ClusterIP = "None"
		ipv4Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv4Protocol}
		services = append(services, ipv4Svc)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Svc := k8sUtils.BuildService("ipv6-svc", getNS("x"), 80, 80, map[string]string{"pod": "b"}, nil)
		ipv6Svc.Spec.ClusterIP = "None"
		ipv6Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv6Protocol}
		services = append(services, ipv6Svc)
	}

	for _, service := range services {
		k8sUtils.CreateOrUpdateService(service)
		failOnError(waitForResourceReady(t, timeout, service), t)
	}

	svcDNSName := func(service *v1.Service) string {
		return fmt.Sprintf("%s.%s.svc.cluster.local", service.Name, service.Namespace)
	}

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-fqdn-cluster-svc").
		SetTier("application").
		SetPriority(1.0)
	for idx, service := range services {
		builder.AddFQDNRule(svcDNSName(service), ProtocolTCP, nil, nil, nil, fmt.Sprintf("r%d", idx*2), []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("y")}, PodSelector: map[string]string{"pod": "b"}}}, crdv1beta1.RuleActionReject)
		builder.AddFQDNRule(svcDNSName(service), ProtocolTCP, nil, nil, nil, fmt.Sprintf("r%d", idx*2+1), []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("z")}, PodSelector: map[string]string{"pod": "c"}}}, crdv1beta1.RuleActionDrop)
	}
	acnp := builder.Get()
	k8sUtils.CreateOrUpdateACNP(acnp)
	failOnError(waitForResourceReady(t, timeout, acnp), t)

	var testcases []podToAddrTestStep
	for _, service := range services {
		eachServiceCases := []podToAddrTestStep{
			{
				getPod("y", "b"),
				// To indicate the server Name is a FQDN, end it with a dot. Then DNS resolver won't attempt to append
				// domain names (e.g. svc.cluster.local, cluster.local) when resolving it, making it get resolution
				// result more quickly.
				svcDNSName(service) + ".",
				80,
				Rejected,
			},
			{
				getPod("z", "c"),
				svcDNSName(service) + ".",
				80,
				Dropped,
			},
			{
				getPod("x", "c"),
				svcDNSName(service) + ".",
				80,
				Connected,
			},
		}
		testcases = append(testcases, eachServiceCases...)
	}

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	for _, service := range services {
		failOnError(k8sUtils.DeleteService(service.Namespace, service.Name), t)
	}
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

// testFQDNPolicyTCP
func testFQDNPolicyTCP(t *testing.T) {
	// The ipv6-only test env doesn't have IPv6 access to the web.
	skipIfNotIPv4Cluster(t)
	// It is convenient to have higher log verbosity for FQDN tests for troubleshooting failures.
	logLevel := log.GetLevel()
	log.SetLevel(log.TraceLevel)
	defer log.SetLevel(logLevel)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-fqdn-tcp").
		SetTier("application").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	builder.AddFQDNRule("github.com", ProtocolTCP, nil, nil, nil, "", nil, crdv1beta1.RuleActionDrop)
	testcases := []podToAddrTestStep{
		{
			getPod("y", "a"),
			"github.com",
			80,
			Dropped,
		},
	}
	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, acnp), t)
	for _, tc := range testcases {
		destIP, err := k8sUtils.digDNS(tc.clientPod.PodName(), tc.clientPod.Namespace(), tc.destAddr, true)
		if err != nil {
			t.Errorf("Failure -- could not complete dig: %v", err)
			continue
		}
		log.Tracef("Probing: %s -> %s(%s)", tc.clientPod.PodName(), tc.destAddr, destIP)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), destIP, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testToServices(t *testing.T, data *TestData) {
	skipIfProxyDisabled(t, data)
	var services []*v1.Service
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4Svc := k8sUtils.BuildService("ipv4-svc", getNS("x"), 81, 81, map[string]string{"pod": "a"}, nil)
		ipv4Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv4Protocol}
		services = append(services, ipv4Svc)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Svc := k8sUtils.BuildService("ipv6-svc", getNS("x"), 80, 80, map[string]string{"pod": "a"}, nil)
		ipv6Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv6Protocol}
		services = append(services, ipv6Svc)
	}

	var svcRefs []crdv1beta1.PeerService
	var builtSvcs []*v1.Service
	for _, service := range services {
		builtSvc, _ := k8sUtils.CreateOrUpdateService(service)
		failOnError(waitForResourceReady(t, timeout, service), t)
		svcRefs = append(svcRefs, crdv1beta1.PeerService{
			Name:      service.Name,
			Namespace: service.Namespace,
		})
		builtSvcs = append(builtSvcs, builtSvc)
	}

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-to-services").
		SetTier("application").
		SetPriority(1.0)
	builder.AddToServicesRule(svcRefs, "x-to-svc", []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}}, crdv1beta1.RuleActionDrop)
	builder.AddToServicesRule(svcRefs, "y-to-svc", []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("y")}}}, crdv1beta1.RuleActionDrop)
	time.Sleep(networkPolicyDelay)

	acnp := builder.Get()
	k8sUtils.CreateOrUpdateACNP(acnp)
	failOnError(waitForResourceReady(t, timeout, acnp), t)

	var testcases []podToAddrTestStep
	for _, service := range builtSvcs {
		eachServiceCases := []podToAddrTestStep{
			{
				getPod("x", "a"),
				service.Spec.ClusterIP,
				service.Spec.Ports[0].Port,
				Dropped,
			},
			{
				getPod("y", "b"),
				service.Spec.ClusterIP,
				service.Spec.Ports[0].Port,
				Dropped,
			},
			{
				Pod(getNS("z") + "/c"),
				service.Spec.ClusterIP,
				service.Spec.Ports[0].Port,
				Connected,
			},
		}
		testcases = append(testcases, eachServiceCases...)
	}

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
	for _, service := range services {
		failOnError(k8sUtils.DeleteService(service.Namespace, service.Name), t)
	}
}

func testServiceAccountSelector(t *testing.T, data *TestData) {
	k8sUtils.CreateOrUpdateServiceAccount(k8sUtils.BuildServiceAccount("test-sa", getNS("x"), nil))
	defer k8sUtils.DeleteServiceAccount(getNS("x"), "test-sa")

	serverName, serverIP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server", controlPlaneNodeName(), data.testNamespace, false)
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPodWithServiceAccount(t, data, data.createAgnhostPodWithSAOnNode, "client", controlPlaneNodeName(), getNS("x"), false, "test-sa")
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPodWithServiceAccount(t, data, data.createAgnhostPodWithSAOnNode, "client", controlPlaneNodeName(), getNS("x"), false, "default")
	defer cleanupFunc()

	sa := &crdv1beta1.NamespacedName{
		Name:      "test-sa",
		Namespace: getNS("x"),
	}

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-service-account").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": serverName}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", sa)

	acnp := builder.Get()
	_, err := k8sUtils.CreateOrUpdateACNP(acnp)
	if err != nil {
		log.Infof("err %s", err.Error())
	}
	failOnError(waitForResourceReady(t, timeout, acnp), t)

	var testcases []podToAddrTestStep
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4Testcases := []podToAddrTestStep{
			{
				getPod("x", client0Name),
				serverIP.IPv4.String(),
				80,
				Dropped,
			},
			{
				getPod("x", client1Name),
				serverIP.IPv4.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv4Testcases...)
	}

	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Testcases := []podToAddrTestStep{
			{
				getPod("x", client0Name),
				serverIP.IPv6.String(),
				80,
				Dropped,
			},
			{
				getPod("x", client1Name),
				serverIP.IPv6.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv6Testcases...)
	}

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPNodeSelectorEgress(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-drop-egress-control-plane").
		SetPriority(1.0)
	nodeSelector := metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/hostname": controlPlaneNodeName()}}
	builder.AddNodeSelectorRule(&nodeSelector, ProtocolTCP, &p6443, "egress-control-plane-drop",
		[]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}, PodSelector: map[string]string{"pod": "a"}}},
		crdv1beta1.RuleActionDrop, true)

	var testcases []podToAddrTestStep
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4Testcases := []podToAddrTestStep{
			{
				getPod("x", "a"),
				controlPlaneNodeIPv4(),
				6443,
				Dropped,
			},
			{
				getPod("x", "b"),
				controlPlaneNodeIPv4(),
				6443,
				Connected,
			},
		}
		testcases = append(testcases, ipv4Testcases...)
	}

	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Testcases := []podToAddrTestStep{
			{
				getPod("x", "a"),
				controlPlaneNodeIPv6(),
				6443,
				Dropped,
			},
			{
				getPod("x", "b"),
				controlPlaneNodeIPv6(),
				6443,
				Connected,
			},
		}
		testcases = append(testcases, ipv6Testcases...)
	}
	_, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	time.Sleep(networkPolicyDelay)
	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPNodeSelectorIngress(t *testing.T, data *TestData) {
	_, serverIP0, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server0", nodeName(1), getNS("x"), false)
	defer cleanupFunc()

	_, serverIP1, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server1", nodeName(1), getNS("y"), false)
	defer cleanupFunc()

	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, getNS("z"), controlPlaneNodeName(), true))
	defer data.DeletePodAndWait(defaultTimeout, clientName, getNS("z"))
	_, err := data.podWaitForIPs(defaultTimeout, clientName, getNS("z"))
	require.NoError(t, err)

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-drop-ingress-from-control-plane").
		SetPriority(1.0)
	nodeSelector := metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/hostname": controlPlaneNodeName()}}
	builder.AddNodeSelectorRule(&nodeSelector, ProtocolTCP, &p80, "ingress-control-plane-drop",
		[]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": getNS("x")}}},
		crdv1beta1.RuleActionDrop, false)

	testcases := []podToAddrTestStep{}
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4TestCases := []podToAddrTestStep{
			{
				getPod("z", clientName),
				serverIP0.IPv4.String(),
				80,
				Dropped,
			},
			{
				getPod("z", clientName),
				serverIP1.IPv4.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv4TestCases...)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6TestCases := []podToAddrTestStep{
			{
				getPod("z", clientName),
				serverIP0.IPv6.String(),
				80,
				Dropped,
			},
			{
				getPod("z", clientName),
				serverIP1.IPv6.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv6TestCases...)
	}

	_, err = k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	time.Sleep(networkPolicyDelay)
	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPICMPSupport(t *testing.T, data *TestData) {
	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createToolboxPodOnNode, "client", nodeName(1), data.testNamespace, false)
	defer cleanupFunc()

	server0Name, server0IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server0", nodeName(0), data.testNamespace, false)
	defer cleanupFunc()

	server1Name, server1IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server1", nodeName(1), data.testNamespace, false)
	defer cleanupFunc()

	icmpType := int32(8)
	icmpCode := int32(0)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-icmp").
		SetPriority(1.0).SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}})
	builder.AddEgress(ProtocolICMP, nil, nil, nil, &icmpType, &icmpCode, nil, nil, nil, map[string]string{"antrea-e2e": server0Name}, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)
	builder.AddEgress(ProtocolICMP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": server1Name}, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionDrop, "", "", nil)

	testcases := []podToAddrTestStep{}
	if clusterInfo.podV4NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server0IP.IPv4.String(),
				-1,
				Rejected,
			},
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server1IP.IPv4.String(),
				-1,
				Dropped,
			},
		}...)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server0IP.IPv6.String(),
				-1,
				Rejected,
			},
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server1IP.IPv6.String(),
				-1,
				Dropped,
			},
		}...)
	}

	_, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	time.Sleep(networkPolicyDelay)
	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolICMP, &tc.expectedConnectivity)
		if err != nil {
			t.Errorf("Failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("Failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPNodePortServiceSupport(t *testing.T, data *TestData, serverNamespace string) {
	skipIfProxyAllDisabled(t, data)

	// Create a NodePort Service.
	ipProtocol := v1.IPv4Protocol
	var nodePort int32
	nodePortSvc, err := data.createNginxNodePortService("test-nodeport-svc", serverNamespace, false, false, &ipProtocol)
	failOnError(err, t)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			nodePort = port.NodePort
			break
		}
	}

	backendPodName := "test-nodeport-backend-pod"
	require.NoError(t, data.createNginxPodOnNode(backendPodName, serverNamespace, nodeName(0), false))
	if err := data.podWaitForRunning(defaultTimeout, backendPodName, serverNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", backendPodName)
	}
	defer deletePodWrapper(t, data, serverNamespace, backendPodName)

	// Create another netns to fake an external network on the host network Pod.
	cmd, testNetns := getCommandInFakeExternalNetwork("sleep 3600", 24, "1.1.1.1", "1.1.1.254")
	clientNames := []string{"client0", "client1"}
	for idx, clientName := range clientNames {
		if err := NewPodBuilder(clientName, data.testNamespace, agnhostImage).OnNode(nodeName(idx)).WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data); err != nil {
			t.Fatalf("Failed to create client Pod: %v", err)
		}
		defer data.DeletePodAndWait(defaultTimeout, clientName, data.testNamespace)
		err = data.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
		failOnError(err, t)
	}

	cidr := "1.1.1.1/24"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-nodeport-svc").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				Service: &crdv1beta1.NamespacedName{
					Name:      nodePortSvc.Name,
					Namespace: nodePortSvc.Namespace,
				},
			},
		})
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, &cidr, nil, nil, nil,
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, acnp), t)
	for idx, clientName := range clientNames {
		log.Tracef("Probing: 1.1.1.1 -> %s:%d", nodeIP(idx), nodePort)
		// Connect to NodePort in the fake external network.
		cmd := ProbeCommand(fmt.Sprintf("%s:%d", nodeIP(idx), nodePort), "tcp", fmt.Sprintf("ip netns exec %s", testNetns))
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientName, agnhostContainerName, cmd)
		connectivity := Connected
		if err != nil || stderr != "" {
			// log this error as trace since may be an expected failure
			log.Tracef("1.1.1.1 -> %s:%d: error when running command: err - %v /// stdout - %s /// stderr - %s", nodeIP(idx), nodePort, err, stdout, stderr)
			// If err != nil and stderr == "", then it means this probe failed because of
			// the command instead of connectivity. For example, container name doesn't exist.
			if stderr == "" {
				connectivity = Error
			}
			connectivity = DecideProbeResult(stderr, 3)
		}
		if connectivity != Rejected {
			t.Errorf("Failure -- wrong results for probe: Source 1.1.1.1 --> Dest %s:%d connectivity: %v, expected: Rej", nodeIP(idx), nodePort, connectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPIGMPQueryAllow(t *testing.T, data *TestData, testNamespace string) {
	testACNPIGMPQuery(t, data, "test-acnp-igmp-query-allow", "testMulticastIGMPQueryAllow", "224.3.4.13", crdv1beta1.RuleActionAllow, testNamespace)
}

func testACNPIGMPQueryDrop(t *testing.T, data *TestData, testNamespace string) {
	testACNPIGMPQuery(t, data, "test-acnp-igmp-query-drop", "testMulticastIGMPQueryDrop", "224.3.4.14", crdv1beta1.RuleActionDrop, testNamespace)
}

func testACNPIGMPQuery(t *testing.T, data *TestData, acnpName, caseName, groupAddress string, action crdv1beta1.RuleAction, testNamespace string) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	mc := multicastTestcase{
		name:            caseName,
		senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
		receiverConfigs: []multicastTestPodConfig{{1, false}},
		port:            3457,
		group:           net.ParseIP(groupAddress),
	}
	senderName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-sender-", nodeName(mc.senderConfig.nodeIdx), testNamespace, mc.senderConfig.isHostNetwork)
	defer cleanupFunc()
	var wg sync.WaitGroup
	receiverNames, cleanupFuncs := setupReceivers(t, data, mc, mcjoinWaitTimeout, testNamespace, &wg)
	for _, cleanupFunc := range cleanupFuncs {
		defer cleanupFunc()
	}
	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
	go func() {
		data.RunCommandFromPod(testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()

	tcpdumpName, _, cleanupFunc := createAndWaitForPod(t, data, data.createToolboxPodOnNode, "test-tcpdump-", nodeName(mc.receiverConfigs[0].nodeIdx), data.testNamespace, true)
	defer cleanupFunc()

	queryGroupAddress := "224.0.0.1"
	cmd, err := generatePacketCaptureCmd(t, data, 15, queryGroupAddress, nodeName(mc.receiverConfigs[0].nodeIdx), receiverNames[0], testNamespace)
	if err != nil {
		t.Fatalf("failed to call generateConnCheckCmd: %v", err)
	}

	// check if IGMP can be sent to Pod
	if err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		captured, err := checkPacketCaptureResult(t, data, tcpdumpName, cmd)
		if captured {
			return true, nil
		}
		return false, err
	}); err != nil {
		t.Fatalf("Error waiting for multicast routes and stats: %v", err)
	}
	t.Logf("waitting for multicast receivers to be ready")
	wg.Wait()
	label := "igmp-query"
	_, err = k8sUtils.LabelPod(testNamespace, receiverNames[0], "antrea-e2e", label)
	if err != nil {
		t.Fatalf("failed to label pod %s: err=%v", receiverNames[0], err)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(acnpName).SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": label}}})

	// create acnp with ingress rule for IGMP query
	igmpType := crdv1beta1.IGMPQuery
	builder.AddIngress(ProtocolIGMP, nil, nil, nil, nil, nil, &igmpType, &queryGroupAddress, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, action, "", "", nil)
	acnp := builder.Get()
	_, err = k8sUtils.CreateOrUpdateACNP(acnp)
	defer data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("failed to create acnp %v: %v", acnpName, err)
	}

	// check if IGMP is dropped or not based on rule action
	captured, err := checkPacketCaptureResult(t, data, tcpdumpName, cmd)
	if action == crdv1beta1.RuleActionAllow {
		if !captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v ", *acnp, err)
		}
	} else {
		if captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v", *acnp, err)
		}
	}
}

func testACNPMulticastEgressAllow(t *testing.T, data *TestData, testNamespace string) {
	testACNPMulticastEgress(t, data, "test-acnp-multicast-egress-allow", "testMulticastEgressAllowTraffic", "224.3.4.15", crdv1beta1.RuleActionAllow, testNamespace)
}

func testACNPMulticastEgressDrop(t *testing.T, data *TestData, testNamespace string) {
	testACNPMulticastEgress(t, data, "test-acnp-multicast-egress-drop", "testMulticastEgressDropTrafficFor", "224.3.4.16", crdv1beta1.RuleActionDrop, testNamespace)
}

func testACNPMulticastEgress(t *testing.T, data *TestData, acnpName, caseName, groupAddress string, action crdv1beta1.RuleAction, testNamespace string) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	mc := multicastTestcase{
		name:            caseName,
		senderConfig:    multicastTestPodConfig{nodeIdx: 0, isHostNetwork: false},
		receiverConfigs: []multicastTestPodConfig{{1, false}},
		port:            3457,
		group:           net.ParseIP(groupAddress),
	}
	senderName, _, cleanupFunc := createAndWaitForPod(t, data, data.createMcJoinPodOnNode, "test-sender-", nodeName(mc.senderConfig.nodeIdx), testNamespace, mc.senderConfig.isHostNetwork)
	defer cleanupFunc()
	var wg sync.WaitGroup
	receiverNames, cleanupFuncs := setupReceivers(t, data, mc, mcjoinWaitTimeout, testNamespace, &wg)
	for _, cleanupFunc := range cleanupFuncs {
		defer cleanupFunc()
	}

	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
	go func() {
		data.RunCommandFromPod(testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()
	// check if receiver can receive multicast packet
	tcpdumpName, _, cleanupFunc := createAndWaitForPod(t, data, data.createToolboxPodOnNode, "test-tcpdump-", nodeName(mc.receiverConfigs[0].nodeIdx), data.testNamespace, true)
	defer cleanupFunc()
	cmd, err := generatePacketCaptureCmd(t, data, 5, mc.group.String(), nodeName(mc.receiverConfigs[0].nodeIdx), receiverNames[0], testNamespace)
	if err != nil {
		t.Fatalf("failed to call generateConnCheckCmd: %v", err)
	}

	if err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		captured, err := checkPacketCaptureResult(t, data, tcpdumpName, cmd)
		if captured {
			return true, nil
		}
		return false, err
	}); err != nil {
		t.Fatalf("Error waiting for multicast routes and stats: %v", err)
	}
	wg.Wait()
	label := "multicast-egress"
	_, err = k8sUtils.LabelPod(testNamespace, senderName, "antrea-e2e", label)
	if err != nil {
		t.Fatalf("failed to label pod %s: err=%v", senderName, err)
	}
	// create acnp with egress rule for multicast traffic
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(acnpName).SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": label}}})
	cidr := mc.group.String() + "/32"
	builder.AddEgress(ProtocolUDP, nil, nil, nil, nil, nil, nil, nil, &cidr, nil, nil, nil,
		nil, nil, nil, nil, nil, action, "", "", nil)
	acnp := builder.Get()
	_, err = k8sUtils.CreateOrUpdateACNP(acnp)
	if err != nil {
		t.Fatalf("failed to create acnp %v: %v", acnpName, err)
	}
	defer data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})

	captured, err := checkPacketCaptureResult(t, data, tcpdumpName, cmd)
	if action == crdv1beta1.RuleActionAllow {
		if !captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v", *acnp, err)
		}
	} else if action == crdv1beta1.RuleActionDrop {
		if captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v", *acnp, err)
		}
	}
}

// the matchers parameter is a list of regular expressions which will be matched against the
// contents of the audit logs. The call will "succeed" if all matches are successful.
func checkAuditLoggingResult(t *testing.T, data *TestData, nodeName, logLocator string, matchers []*regexp.Regexp) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		t.Errorf("Error occurred when trying to get the Antrea Agent Pod running on Node %s: %v", nodeName, err)
	}
	cmd := []string{"cat", logDir + logfileName}

	if err := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
		if err != nil || stderr != "" {
			// file may not exist yet
			t.Logf("Error when printing the audit log file, err: %v, stderr: %v", err, stderr)
			return false, nil
		}
		if !strings.Contains(stdout, logLocator) {
			t.Logf("Audit log file does not contain entries for '%s' yet", logLocator)
			return false, nil
		}

		var numEntries int
		for _, re := range matchers {
			t.Logf("Checking for expected entry: %s", re.String())
			if re.MatchString(stdout) {
				numEntries += 1
			} else {
				t.Logf("Audit log does not contain expected entry: %s", re.String())
			}
		}
		if numEntries != len(matchers) {
			t.Logf("Missing entries in audit log: expected %d but found %d", len(matchers), numEntries)
			return false, nil
		}
		return true, nil
	}); err != nil {
		t.Errorf("Error when polling audit log files for required entries: %v", err)
	}
}

func generatePacketCaptureCmd(t *testing.T, data *TestData, timeout int, hostIP, nodeName, podName string, testNamespace string) (string, error) {
	agentPodName := getAntreaPodName(t, data, nodeName)
	cmds := []string{"antctl", "get", "podinterface", podName, "-n", testNamespace, "-o", "json"}
	stdout, stderr, err := runAntctl(agentPodName, cmds, data)
	var podInterfaceInfo []apis.PodInterfaceResponse
	if err := json.Unmarshal([]byte(stdout), &podInterfaceInfo); err != nil {
		return "", err
	}
	t.Logf("%s returned: stdout %v, stderr : %v", cmds, stdout, stderr)
	if err != nil {
		return "", err
	}
	// Set "--preserve-status" to get the exit code of "tcpdump" as opposed to "timeout".
	cmd := fmt.Sprintf("timeout --preserve-status %ds tcpdump -q -i %s -c 1 -W 90 host %s", timeout, podInterfaceInfo[0].InterfaceName, hostIP)
	return cmd, nil
}

func checkPacketCaptureResult(t *testing.T, data *TestData, tcpdumpName, cmd string) (captured bool, err error) {
	stdout, stderr := "", ""
	stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, tcpdumpName, toolboxContainerName, []string{"/bin/sh", "-c", cmd})
	t.Logf("%s returned: stdout %v, stderr : %v", cmd, stdout, stderr)
	if err != nil {
		return false, err
	}
	if strings.Contains(stderr, "0 packets captured") {
		return false, nil
	}
	return true, nil
}

// executeTests runs all the tests in testList and prints results
func executeTests(t *testing.T, testList []*TestCase) {
	executeTestsWithData(t, testList, nil)
}

func executeTestsWithData(t *testing.T, testList []*TestCase, data *TestData) {
	for _, testCase := range testList {
		log.Infof("running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			applyTestStepResources(t, step)
			if step.CustomSetup != nil {
				step.CustomSetup()
			}
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
			if len(step.CustomProbes) > 0 && data == nil {
				t.Errorf("test case %s with custom probe must set test data", testCase.Name)
				continue
			}
			for _, p := range step.CustomProbes {
				doProbe(t, data, p, step.Protocol)
			}
			if step.CustomTeardown != nil {
				step.CustomTeardown()
			}
		}
		log.Debug("Cleaning-up all policies and groups created by this Testcase")
		cleanupTestCaseResources(t, testCase)
	}
	allTestList = append(allTestList, testList...)
}

func doProbe(t *testing.T, data *TestData, p *CustomProbe, protocol AntreaPolicyProtocol) {
	// Bootstrap Pods
	_, _, srcPodCleanupFunc := createAndWaitForPodWithLabels(t, data, data.createServerPodWithLabels, p.SourcePod.Pod.PodName(), p.SourcePod.Pod.Namespace(), p.Port, p.SourcePod.Labels)
	defer srcPodCleanupFunc()
	_, _, dstPodCleanupFunc := createAndWaitForPodWithLabels(t, data, data.createServerPodWithLabels, p.DestPod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.Port, p.DestPod.Labels)
	defer dstPodCleanupFunc()
	log.Tracef("Probing: %s -> %s", p.SourcePod.Pod.PodName(), p.DestPod.Pod.PodName())
	connectivity, err := k8sUtils.Probe(p.SourcePod.Pod.Namespace(), p.SourcePod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.DestPod.Pod.PodName(), p.Port, protocol, nil, &p.ExpectConnectivity)
	if err != nil {
		t.Errorf("Failure -- could not complete probe: %v", err)
	}
	if connectivity != p.ExpectConnectivity {
		t.Errorf("Failure -- wrong results for custom probe: Source %s/%s --> Dest %s/%s connectivity: %v, expected: %v",
			p.SourcePod.Pod.Namespace(), p.SourcePod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.DestPod.Pod.PodName(), connectivity, p.ExpectConnectivity)
	}
}

// applyTestStepResources creates in the resources of a testStep in specified order.
// The ordering can be used to test different scenarios, like creating an ACNP before
// creating its referred ClusterGroup, and vice versa.
func applyTestStepResources(t *testing.T, step *TestStep) {
	for _, r := range step.TestResources {
		switch o := r.(type) {
		case *crdv1beta1.ClusterNetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateACNP(o)
			failOnError(err, t)
		case *crdv1beta1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateANNP(o)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(o)
			failOnError(err, t)
		case *crdv1beta1.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateCG(o)
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

func cleanupTestCaseResources(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same resource.
	// Use sets to avoid duplicates.
	acnpsToDelete, annpsToDelete, npsToDelete := sets.Set[string]{}, sets.Set[string]{}, sets.Set[string]{}
	svcsToDelete, v1a3ClusterGroupsToDelete, v1a3GroupsToDelete := sets.Set[string]{}, sets.Set[string]{}, sets.Set[string]{}
	for _, step := range c.Steps {
		for _, r := range step.TestResources {
			switch o := r.(type) {
			case *crdv1beta1.ClusterNetworkPolicy:
				acnpsToDelete.Insert(o.Name)
			case *crdv1beta1.NetworkPolicy:
				annpsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *crdv1beta1.ClusterGroup:
				v1a3ClusterGroupsToDelete.Insert(o.Name)
			case *crdv1beta1.Group:
				v1a3GroupsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}
	for acnp := range acnpsToDelete {
		failOnError(k8sUtils.DeleteACNP(acnp), t)
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
	for cg := range v1a3ClusterGroupsToDelete {
		failOnError(k8sUtils.DeleteCG(cg), t)
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

// printResults summarizes test results for all the testcases
func printResults() {
	fmt.Printf("\n---------------- Test Results ------------------\n")
	failCount := 0
	for _, testCase := range allTestList {
		fmt.Printf("Test %s:\n", testCase.Name)
		testFailed := false
		for _, step := range testCase.Steps {
			if step.Reachability == nil {
				continue
			}
			_, wrong, comparison := step.Reachability.Summary()
			var result string
			if wrong == 0 {
				result = "success"
			} else {
				result = fmt.Sprintf("failure -- %d wrong results", wrong)
				testFailed = true
			}
			fmt.Printf("\tStep %s on port %d, duration %d seconds, result: %s\n",
				step.Name, step.Ports, int(step.Duration.Seconds()), result)
			if wrong != 0 {
				fmt.Printf("\n%s\n", comparison.PrettyPrint("\t\t"))
			}
		}
		if testFailed {
			failCount++
		}
	}
	fmt.Printf("=== TEST FAILURES: %d/%d ===\n\n", failCount, len(allTestList))
}

func waitForResourceReady(t *testing.T, timeout time.Duration, obj metav1.Object) error {
	defer timeCost()("ready")
	switch p := obj.(type) {
	case *crdv1beta1.ClusterNetworkPolicy:
		return k8sUtils.waitForACNPRealized(t, p.Name, timeout)
	case *crdv1beta1.NetworkPolicy:
		return k8sUtils.waitForANNPRealized(t, p.Namespace, p.Name, timeout)
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

// TestAntreaPolicy is the top-level test which contains all subtests for
// AntreaPolicy related test cases so that they can share setup and teardown.
func TestAntreaPolicy(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	initialize(t, data, nil)

	// This test group only provides one case for each CR, including ACNP, ANNP, Tier,
	// ClusterGroup and Group to make sure the corresponding validation webhooks is
	// called. And for all specific cases/branches inside the validation webhook, we
	// just use UTs to cover them to reduce the pressure on E2E tests.
	t.Run("TestGroupValidationWebhook", func(t *testing.T) {
		// For creation.
		t.Run("Case=CreateInvalidACNP", func(t *testing.T) { testCreateValidationInvalidACNP(t) })
		t.Run("Case=CreateInvalidANNP", func(t *testing.T) { testCreateValidationInvalidANNP(t) })
		t.Run("Case=CreateInvalidTier", func(t *testing.T) { testCreateValidationInvalidTier(t) })
		t.Run("Case=CreateInvalidClusterGroup", func(t *testing.T) { testCreateValidationInvalidCG(t) })
		t.Run("Case=CreateInvalidGroup", func(t *testing.T) { testCreateValidationInvalidGroup(t) })

		// For update.
		t.Run("Case=UpdateInvalidACNP", func(t *testing.T) { testUpdateValidationInvalidACNP(t) })
		t.Run("Case=UpdateInvalidANNP", func(t *testing.T) { testUpdateValidationInvalidANNP(t) })
		t.Run("Case=UpdateInvalidTier", func(t *testing.T) { testUpdateValidationInvalidTier(t) })
		t.Run("Case=UpdateInvalidClusterGroup", func(t *testing.T) { testUpdateValidationInvalidCG(t) })
		t.Run("Case=UpdateInvalidGroup", func(t *testing.T) { testUpdateValidationInvalidGroup(t) })

		// For deletion. ACNP, ANNP, ClusterGroup and Group don't have deletion validation.
		t.Run("Case=DeleteReferencedTier", func(t *testing.T) { testDeleteValidationReferencedTier(t) })
	})

	// This test group only provides one case for each CR, including ACNP and ANNP to
	// make sure the corresponding mutation webhooks is called. And for all specific
	// cases/branches inside the mutation webhook, we just use UTs to cover them to
	// reduce the pressure on E2E tests.
	t.Run("TestGroupMutationWebhook", func(t *testing.T) {
		t.Run("Case=MutateACNPNoTier", func(t *testing.T) { testMutateACNPNoTier(t) })
		t.Run("Case=MutateANNPNoTier", func(t *testing.T) { testMutateANNPNoTier(t) })
	})

	t.Run("TestGroupDefaultDENY", func(t *testing.T) {
		// testcases below require default-deny k8s NetworkPolicies to work
		applyDefaultDenyToAllNamespaces(k8sUtils, namespaces)
		t.Run("Case=ACNPAllowXBtoA", func(t *testing.T) { testACNPAllowXBtoA(t) })
		t.Run("Case=ACNPAllowXBtoYA", func(t *testing.T) { testACNPAllowXBtoYA(t) })
		t.Run("Case=ACNPPriorityOverrideDefaultDeny", func(t *testing.T) { testACNPPriorityOverrideDefaultDeny(t) })
		cleanupDefaultDenyNPs(k8sUtils, namespaces)
	})

	t.Run("TestGroupNoK8sNP", func(t *testing.T) {
		// testcases below do not depend on underlying default-deny K8s NetworkPolicies.
		t.Run("Case=ACNPAllowNoDefaultIsolationTCP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, ProtocolTCP) })
		t.Run("Case=ACNPAllowNoDefaultIsolationUDP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, ProtocolUDP) })
		t.Run("Case=ACNPAllowNoDefaultIsolationSCTP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, ProtocolSCTP) })
		t.Run("Case=ACNPDropEgress", func(t *testing.T) { testACNPDropEgress(t, ProtocolTCP) })
		t.Run("Case=ACNPDropEgressUDP", func(t *testing.T) { testACNPDropEgress(t, ProtocolUDP) })
		t.Run("Case=ACNPDropEgressSCTP", func(t *testing.T) { testACNPDropEgress(t, ProtocolSCTP) })
		t.Run("Case=ACNPDropIngressInNamespace", func(t *testing.T) { testACNPDropIngressInSelectedNamespace(t) })
		t.Run("Case=ACNPPortRange", func(t *testing.T) { testACNPPortRange(t) })
		t.Run("Case=ACNPSourcePort", func(t *testing.T) { testACNPSourcePort(t) })
		t.Run("Case=ACNPRejectEgress", func(t *testing.T) { testACNPRejectEgress(t) })
		t.Run("Case=ACNPRejectIngress", func(t *testing.T) { testACNPRejectIngress(t, ProtocolTCP) })
		t.Run("Case=ACNPRejectIngressUDP", func(t *testing.T) { testACNPRejectIngress(t, ProtocolUDP) })
		t.Run("Case=RejectServiceTraffic", func(t *testing.T) { testRejectServiceTraffic(t, data, data.testNamespace, data.testNamespace) })
		t.Run("Case=RejectNoInfiniteLoop", func(t *testing.T) { testRejectNoInfiniteLoop(t, data, data.testNamespace, data.testNamespace) })
		t.Run("Case=ACNPNoEffectOnOtherProtocols", func(t *testing.T) { testACNPNoEffectOnOtherProtocols(t) })
		t.Run("Case=ACNPBaselinePolicy", func(t *testing.T) { testBaselineNamespaceIsolation(t) })
		t.Run("Case=ACNPPriorityOverride", func(t *testing.T) { testACNPPriorityOverride(t) })
		t.Run("Case=ACNPTierOverride", func(t *testing.T) { testACNPTierOverride(t) })
		t.Run("Case=ACNPCustomTiers", func(t *testing.T) { testACNPCustomTiers(t) })
		t.Run("Case=ACNPPriorityConflictingRule", func(t *testing.T) { testACNPPriorityConflictingRule(t) })
		t.Run("Case=ACNPRulePriority", func(t *testing.T) { testACNPRulePriority(t) })
		t.Run("Case=ANNPPortRange", func(t *testing.T) { testANNPPortRange(t) })
		t.Run("Case=ANNPBasic", func(t *testing.T) { testANNPBasic(t) })
		t.Run("Case=ANNPUpdate", func(t *testing.T) { testANNPUpdate(t, data) })
		t.Run("Case=testANNPMultipleAppliedToSingleRule", func(t *testing.T) { testANNPMultipleAppliedTo(t, data, true) })
		t.Run("Case=testANNPMultipleAppliedToMultipleRules", func(t *testing.T) { testANNPMultipleAppliedTo(t, data, false) })
		t.Run("Case=AppliedToPerRule", func(t *testing.T) { testAppliedToPerRule(t) })
		t.Run("Case=ACNPNamespaceIsolation", func(t *testing.T) { testACNPNamespaceIsolation(t) })
		t.Run("Case=ACNPStrictNamespaceIsolation", func(t *testing.T) { testACNPStrictNamespacesIsolation(t) })
		t.Run("Case=ACNPClusterGroupEgressRulePodsAToCGWithNsZ", func(t *testing.T) { testACNPEgressRulePodsAToCGWithNsZ(t) })
		t.Run("Case=ACNPClusterGroupUpdate", func(t *testing.T) { testACNPClusterGroupUpdate(t) })
		t.Run("Case=ACNPClusterGroupAppliedToDenyXBToCGWithYA", func(t *testing.T) { testACNPAppliedToDenyXBtoCGWithYA(t) })
		t.Run("Case=ACNPClusterGroupAppliedToRuleCGWithPodsAToNsZ", func(t *testing.T) { testACNPAppliedToRuleCGWithPodsAToNsZ(t) })
		t.Run("Case=ACNPClusterGroupUpdateAppliedTo", func(t *testing.T) { testACNPClusterGroupUpdateAppliedTo(t) })
		t.Run("Case=ACNPClusterGroupAppliedToPodAdd", func(t *testing.T) { testACNPClusterGroupAppliedToPodAdd(t, data) })
		t.Run("Case=ACNPClusterGroupRefRulePodAdd", func(t *testing.T) { testACNPClusterGroupRefRulePodAdd(t, data) })
		t.Run("Case=ACNPClusterGroupRefRuleIPBlocks", func(t *testing.T) { testACNPClusterGroupRefRuleIPBlocks(t) })
		t.Run("Case=ACNPClusterGroupIngressRuleDenyCGWithXBtoYA", func(t *testing.T) { testACNPIngressRuleDenyCGWithXBtoYA(t) })
		t.Run("Case=ACNPClusterGroupServiceRef", func(t *testing.T) { testACNPClusterGroupServiceRefCreateAndUpdate(t, data) })
		t.Run("Case=ACNPNestedClusterGroup", func(t *testing.T) { testACNPNestedClusterGroupCreateAndUpdate(t, data) })
		t.Run("Case=ACNPNestedIPBlockClusterGroup", func(t *testing.T) { testACNPNestedIPBlockClusterGroupCreateAndUpdate(t) })
		t.Run("Case=ANNPGroupEgressRulePodsAToGrpWithPodsC", func(t *testing.T) { testANNPEgressRulePodsAToGrpWithPodsC(t) })
		t.Run("Case=ANNPIngressRuleDenyGrpWithXCtoXA", func(t *testing.T) { testANNPIngressRuleDenyGrpWithXCtoXA(t) })
		t.Run("Case=ANNPGroupUpdate", func(t *testing.T) { testANNPGroupUpdate(t) })
		t.Run("Case=ANNPGroupAppliedToDenyXBToGrpWithXA", func(t *testing.T) { testANNPAppliedToDenyXBtoGrpWithXA(t) })
		t.Run("Case=ANNPGroupAppliedToRuleGrpWithPodsAToPodsC", func(t *testing.T) { testANNPAppliedToRuleGrpWithPodsAToPodsC(t) })
		t.Run("Case=ANNPGroupUpdateAppliedTo", func(t *testing.T) { testANNPGroupUpdateAppliedTo(t) })
		t.Run("Case=ANNPGroupAppliedToPodAdd", func(t *testing.T) { testANNPGroupAppliedToPodAdd(t, data) })
		t.Run("Case=ANNPGroupServiceRefPodAdd", func(t *testing.T) { testANNPGroupServiceRefPodAdd(t, data) })
		t.Run("Case=ANNPGroupServiceRefDelete", func(t *testing.T) { testANNPGroupServiceRefDelete(t) })
		t.Run("Case=ANNPGroupServiceRef", func(t *testing.T) { testANNPGroupServiceRefCreateAndUpdate(t) })
		t.Run("Case=ANNPGroupRefRuleIPBlocks", func(t *testing.T) { testANNPGroupRefRuleIPBlocks(t) })
		t.Run("Case=ANNPNestedGroup", func(t *testing.T) { testANNPNestedGroupCreateAndUpdate(t, data) })
		t.Run("Case=ACNPFQDNPolicy", func(t *testing.T) { testFQDNPolicy(t) })
		t.Run("Case=ACNPFQDNPolicyInCluster", func(t *testing.T) { testFQDNPolicyInClusterService(t) })
		t.Run("Case=ACNPFQDNPolicyTCP", func(t *testing.T) { testFQDNPolicyTCP(t) })
		t.Run("Case=ACNPToServices", func(t *testing.T) { testToServices(t, data) })
		t.Run("Case=ACNPServiceAccountSelector", func(t *testing.T) { testServiceAccountSelector(t, data) })
		t.Run("Case=ACNPNodeSelectorEgress", func(t *testing.T) { testACNPNodeSelectorEgress(t) })
		t.Run("Case=ACNPNodeSelectorIngress", func(t *testing.T) { testACNPNodeSelectorIngress(t, data) })
		t.Run("Case=ACNPICMPSupport", func(t *testing.T) { testACNPICMPSupport(t, data) })
		t.Run("Case=ACNPNodePortServiceSupport", func(t *testing.T) { testACNPNodePortServiceSupport(t, data, data.testNamespace) })
	})
	// print results for reachability tests
	printResults()

	t.Run("TestGroupAuditLogging", func(t *testing.T) {
		t.Run("Case=AuditLoggingBasic", func(t *testing.T) { testAuditLoggingBasic(t, data) })
		t.Run("Case=AuditLoggingEnableK8s", func(t *testing.T) { testAuditLoggingEnableK8s(t, data) })
		t.Run("Case=AuditLoggingK8sService", func(t *testing.T) { testAuditLoggingK8sService(t, data) })
	})

	t.Run("TestMulticastNP", func(t *testing.T) {
		skipIfMulticastDisabled(t, data)
		testMulticastNP(t, data, data.testNamespace)
	})
	k8sUtils.Cleanup(namespaces)
}

func testMulticastNP(t *testing.T, data *TestData, testNamespace string) {
	t.Run("Case=MulticastNPIGMPQueryAllow", func(t *testing.T) { testACNPIGMPQueryAllow(t, data, testNamespace) })
	t.Run("Case=MulticastNPIGMPQueryDrop", func(t *testing.T) { testACNPIGMPQueryDrop(t, data, testNamespace) })
	t.Run("Case=MulticastNPPolicyEgressAllow", func(t *testing.T) { testACNPMulticastEgressAllow(t, data, testNamespace) })
	t.Run("Case=MulticastNPPolicyEgressDrop", func(t *testing.T) { testACNPMulticastEgressDrop(t, data, testNamespace) })
}

func TestAntreaPolicyExtendedNamespaces(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	extendedNamespaces := make(map[string]TestNamespaceMeta)
	suffix := randName("")
	// two "prod" Namespaces labeled purpose=test and tier=prod.
	// two "dev" Namespaces labeled purpose=test and tier=dev.
	// one "no-tier-label" Namespace labeled purpose=test.
	for i := 1; i <= 2; i++ {
		prodNS := TestNamespaceMeta{
			Name: "prod" + strconv.Itoa(i) + "-" + suffix,
			Labels: map[string]string{
				"purpose": "test",
				"tier":    "prod",
			},
		}
		extendedNamespaces["prod"+strconv.Itoa(i)] = prodNS
		devNS := TestNamespaceMeta{
			Name: "dev" + strconv.Itoa(i) + "-" + suffix,
			Labels: map[string]string{
				"purpose": "test",
				"tier":    "dev",
			},
		}
		extendedNamespaces["dev"+strconv.Itoa(i)] = devNS
	}
	extendedNamespaces["no-tier"] = TestNamespaceMeta{
		Name: "no-tier-" + suffix,
		Labels: map[string]string{
			"purpose": "test-exclusion",
		},
	}
	initialize(t, data, extendedNamespaces)

	t.Run("TestGroupACNPNamespaceLabelSelections", func(t *testing.T) {
		t.Run("Case=ACNPStrictNamespacesIsolationByLabels", func(t *testing.T) { testACNPStrictNamespacesIsolationByLabels(t) })
		t.Run("Case=ACNPStrictNamespacesIsolationBySingleLabel", func(t *testing.T) { testACNPStrictNamespacesIsolationBySingleLabel(t, data) })
	})
	k8sUtils.Cleanup(namespaces)
}

func TestAntreaPolicyStatus(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	_, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-0", controlPlaneNodeName(), data.testNamespace, false)
	defer cleanupFunc()
	_, _, cleanupFunc = createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-1", workerNodeName(1), data.testNamespace, false)
	defer cleanupFunc()

	annpBuilder := &AntreaNetworkPolicySpecBuilder{}
	annpBuilder = annpBuilder.SetName(data.testNamespace, "annp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	annpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "")
	annp := annpBuilder.Get()
	log.Debugf("creating ANNP %v", annp.Name)
	_, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Create(context.TODO(), annp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Delete(context.TODO(), annp.Name, metav1.DeleteOptions{})

	acnpBuilder := &ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("acnp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	acnpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, map[string]string{"ns": getNS("x")},
		nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)
	acnp := acnpBuilder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	_, err = data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Create(context.TODO(), acnp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})

	expectedStatus := crdv1beta1.NetworkPolicyStatus{
		Phase:                crdv1beta1.NetworkPolicyRealized,
		ObservedGeneration:   1,
		CurrentNodesRealized: 2,
		DesiredNodesRealized: 2,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	}
	checkANNPStatus(t, data, annp, expectedStatus)
	checkACNPStatus(t, data, acnp, expectedStatus)
}

func TestAntreaPolicyStatusWithAppliedToPerRule(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	server0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-0", controlPlaneNodeName(), data.testNamespace, false)
	defer cleanupFunc()
	server1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-1", workerNodeName(1), data.testNamespace, false)
	defer cleanupFunc()

	annpBuilder := &AntreaNetworkPolicySpecBuilder{}
	annpBuilder = annpBuilder.SetName(data.testNamespace, "annp-applied-to-per-rule").
		SetPriority(1.0)
	annpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, []ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": server0Name}}}, crdv1beta1.RuleActionAllow, "", "")
	annpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": getNS("x")}, nil,
		nil, nil, nil, []ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": server1Name}}}, crdv1beta1.RuleActionAllow, "", "")
	annp := annpBuilder.Get()
	log.Debugf("creating ANNP %v", annp.Name)
	annp, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Create(context.TODO(), annp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Delete(context.TODO(), annp.Name, metav1.DeleteOptions{})

	annp = checkANNPStatus(t, data, annp, crdv1beta1.NetworkPolicyStatus{
		Phase:                crdv1beta1.NetworkPolicyRealized,
		ObservedGeneration:   1,
		CurrentNodesRealized: 2,
		DesiredNodesRealized: 2,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	})

	// Remove the second ingress rule.
	annp.Spec.Ingress = annp.Spec.Ingress[0:1]
	_, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Update(context.TODO(), annp, metav1.UpdateOptions{})
	assert.NoError(t, err)
	annp = checkANNPStatus(t, data, annp, crdv1beta1.NetworkPolicyStatus{
		Phase:                crdv1beta1.NetworkPolicyRealized,
		ObservedGeneration:   2,
		CurrentNodesRealized: 1,
		DesiredNodesRealized: 1,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	})

	// Add a non-existing group.
	// Although nothing will be changed in datapath, the policy's status should be realized with the latest generation.
	annp.Spec.Ingress[0].AppliedTo = append(annp.Spec.Ingress[0].AppliedTo, crdv1beta1.AppliedTo{Group: "foo"})
	_, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Update(context.TODO(), annp, metav1.UpdateOptions{})
	assert.NoError(t, err)
	annp = checkANNPStatus(t, data, annp, crdv1beta1.NetworkPolicyStatus{
		Phase:                crdv1beta1.NetworkPolicyRealized,
		ObservedGeneration:   3,
		CurrentNodesRealized: 1,
		DesiredNodesRealized: 1,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	})

	// Delete the non-existing group.
	// Although nothing will be changed in datapath, the policy's status should be realized with the latest generation.
	annp.Spec.Ingress[0].AppliedTo = annp.Spec.Ingress[0].AppliedTo[0:1]
	_, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Update(context.TODO(), annp, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkANNPStatus(t, data, annp, crdv1beta1.NetworkPolicyStatus{
		Phase:                crdv1beta1.NetworkPolicyRealized,
		ObservedGeneration:   4,
		CurrentNodesRealized: 1,
		DesiredNodesRealized: 1,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	})
}

func TestAntreaPolicyStatusWithAppliedToUnsupportedGroup(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	initialize(t, data, nil)

	testNamespace := getNS("x")
	// Build a Group with namespaceSelector selecting namespaces outside testNamespace.
	grpName := "grp-with-ns-selector"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(testNamespace).
		SetPodSelector(map[string]string{"pod": "b"}, nil).
		SetNamespaceSelector(map[string]string{"ns": getNS("y")}, nil)
	grp, err := k8sUtils.CreateOrUpdateGroup(grpBuilder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, grp), t)
	// Build a Group with the unsupported Group as child Group.
	grpNestedName := "grp-nested"
	grpBuilderNested := &GroupSpecBuilder{}
	grpBuilderNested = grpBuilderNested.SetName(grpNestedName).SetNamespace(testNamespace).SetChildGroups([]string{grpName})
	grp, err = k8sUtils.CreateOrUpdateGroup(grpBuilderNested.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, grp), t)

	annpBuilder := &AntreaNetworkPolicySpecBuilder{}
	annpBuilder = annpBuilder.SetName(testNamespace, "annp-applied-to-unsupported-group").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grpName}})
	annp, err := k8sUtils.CreateOrUpdateANNP(annpBuilder.Get())
	failOnError(err, t)
	expectedStatus := crdv1beta1.NetworkPolicyStatus{
		Phase:                crdv1beta1.NetworkPolicyPending,
		ObservedGeneration:   1,
		CurrentNodesRealized: 0,
		DesiredNodesRealized: 0,
		Conditions: []crdv1beta1.NetworkPolicyCondition{
			{
				Type:               crdv1beta1.NetworkPolicyConditionRealizable,
				Status:             metav1.ConditionFalse,
				LastTransitionTime: metav1.Now(),
				Reason:             "NetworkPolicyAppliedToUnsupportedGroup",
				Message:            fmt.Sprintf("Group %s/%s with Pods in other Namespaces can not be used as AppliedTo", testNamespace, grpName),
			},
		},
	}
	checkANNPStatus(t, data, annp, expectedStatus)

	annpBuilder2 := &AntreaNetworkPolicySpecBuilder{}
	annpBuilder2 = annpBuilder2.SetName(testNamespace, "annp-applied-to-unsupported-child-group").
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{Group: grpNestedName}})
	annp2, err := k8sUtils.CreateOrUpdateANNP(annpBuilder2.Get())
	failOnError(err, t)
	expectedStatus.Conditions[0].Message = fmt.Sprintf("Group %s/%s with Pods in other Namespaces can not be used as AppliedTo", testNamespace, grpNestedName)
	checkANNPStatus(t, data, annp2, expectedStatus)

	failOnError(k8sUtils.DeleteANNP(annp.Namespace, annp.Name), t)
	failOnError(k8sUtils.DeleteANNP(annp2.Namespace, annp2.Name), t)
	failOnError(k8sUtils.DeleteGroup(testNamespace, grpName), t)
	failOnError(k8sUtils.DeleteGroup(testNamespace, grpNestedName), t)
	k8sUtils.Cleanup(namespaces)
}

func checkANNPStatus(t *testing.T, data *TestData, annp *crdv1beta1.NetworkPolicy, expectedStatus crdv1beta1.NetworkPolicyStatus) *crdv1beta1.NetworkPolicy {
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, policyRealizedTimeout, false, func(ctx context.Context) (bool, error) {
		var err error
		annp, err = data.crdClient.CrdV1beta1().NetworkPolicies(annp.Namespace).Get(context.TODO(), annp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return networkpolicy.NetworkPolicyStatusEqual(annp.Status, expectedStatus), nil
	})
	assert.NoError(t, err, "Antrea NetworkPolicy failed to reach expected status")
	return annp
}

func checkACNPStatus(t *testing.T, data *TestData, acnp *crdv1beta1.ClusterNetworkPolicy, expectedStatus crdv1beta1.NetworkPolicyStatus) *crdv1beta1.ClusterNetworkPolicy {
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, policyRealizedTimeout, false, func(ctx context.Context) (bool, error) {
		var err error
		acnp, err = data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Get(context.TODO(), acnp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return networkpolicy.NetworkPolicyStatusEqual(acnp.Status, expectedStatus), nil
	})
	assert.NoError(t, err, "Antrea ClusterNetworkPolicy failed to reach expected status")
	return acnp
}

// waitForANNPRealized waits until an ANNP is realized and returns, or times out. A policy is
// considered realized when its Status has been updated so that the ObservedGeneration matches the
// resource's Generation and the Phase is set to Realized.
func (data *TestData) waitForANNPRealized(t *testing.T, namespace string, name string, timeout time.Duration) error {
	t.Logf("Waiting for ANNP '%s/%s' to be realized", namespace, name)
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		annp, err := data.crdClient.CrdV1beta1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return annp.Status.ObservedGeneration == annp.Generation && annp.Status.Phase == crdv1beta1.NetworkPolicyRealized, nil
	}); err != nil {
		return fmt.Errorf("error when waiting for ANNP '%s/%s' to be realized: %v", namespace, name, err)
	}
	return nil
}

// waitForACNPRealized waits until an ACNP is realized and returns, or times out. A policy is
// considered realized when its Status has been updated so that the ObservedGeneration matches the
// resource's Generation and the Phase is set to Realized.
func (data *TestData) waitForACNPRealized(t *testing.T, name string, timeout time.Duration) error {
	t.Logf("Waiting for ACNP '%s' to be realized", name)
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		acnp, err := data.crdClient.CrdV1beta1().ClusterNetworkPolicies().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return acnp.Status.ObservedGeneration == acnp.Generation && acnp.Status.Phase == crdv1beta1.NetworkPolicyRealized, nil
	}); err != nil {
		return fmt.Errorf("error when waiting for ACNP '%s' to be realized: %v", name, err)
	}
	return nil
}

// TestAntreaPolicyStats is the top-level test which contains all subtests for
// AntreaPolicyStats related test cases so they can share setup, teardown.
func TestAntreaPolicyStats(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)
	skipIfNetworkPolicyStatsDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testANNPNetworkPolicyStatsWithDropAction", func(t *testing.T) {
		testANNPNetworkPolicyStatsWithDropAction(t, data)
	})
	t.Run("testAntreaClusterNetworkPolicyStats", func(t *testing.T) {
		testAntreaClusterNetworkPolicyStats(t, data)
	})
}

// testANPNetworkPolicyStatsWithDropAction tests antreanetworkpolicystats can correctly collect dropped packets stats from ANP if
// networkpolicystats feature is enabled
func testANNPNetworkPolicyStatsWithDropAction(t *testing.T, data *TestData) {
	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", data.testNamespace, false)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createToolboxPodOnNode, "test-client-", "", data.testNamespace, false)
	defer cleanupFunc()
	var err error
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	p10 := float64(10)
	intstr80 := intstr.FromInt(80)
	intstr443 := intstr.FromInt(443)
	dropAction := crdv1beta1.RuleActionDrop
	allowAction := crdv1beta1.RuleActionAllow
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientName}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": serverName}}
	protocol, _ := AntreaPolicyProtocolToK8sProtocol(ProtocolUDP)

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.IPv4.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.IPv6.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
	}
	var annp = &crdv1beta1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: "np1", Labels: map[string]string{"antrea-e2e": "np1"}},
		Spec: crdv1beta1.NetworkPolicySpec{
			AppliedTo: []crdv1beta1.AppliedTo{
				{PodSelector: &selectorC},
			},
			Priority: p10,
			Ingress: []crdv1beta1.Rule{
				{
					Ports: []crdv1beta1.NetworkPolicyPort{
						{
							Port:     &intstr80,
							Protocol: &protocol,
						},
					},
					From: []crdv1beta1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &dropAction,
				},
				{
					Ports: []crdv1beta1.NetworkPolicyPort{
						{
							Port:     &intstr443,
							Protocol: &protocol,
						},
					},
					From: []crdv1beta1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &allowAction,
				},
			},
			Egress: []crdv1beta1.Rule{},
		},
	}

	if _, err = k8sUtils.CreateOrUpdateANNP(annp); err != nil {
		failOnError(fmt.Errorf("create ANNP failed for ANNP %s: %v", annp.Name, err), t)
	}

	// Wait for the policy to be realized before attempting connections
	failOnError(data.waitForANNPRealized(t, annp.Namespace, annp.Name, policyRealizedTimeout), t)

	sessionsPerAddressFamily := 10
	var wg sync.WaitGroup
	for i := 0; i < sessionsPerAddressFamily; i++ {
		wg.Add(1)
		go func() {
			if clusterInfo.podV4NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.IPv4.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 443", serverIPs.IPv4.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd2)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.IPv6.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 443", serverIPs.IPv6.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd2)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	totalSessionsPerRule := 0
	if clusterInfo.podV4NetworkCIDR != "" {
		totalSessionsPerRule += sessionsPerAddressFamily
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		totalSessionsPerRule += sessionsPerAddressFamily
	}

	if err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		stats, err := data.crdClient.StatsV1alpha1().AntreaNetworkPolicyStats(data.testNamespace).Get(context.TODO(), "np1", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		t.Logf("Got AntreaNetworkPolicy stats: %v", stats)
		if len(stats.RuleTrafficStats) != 2 {
			return false, nil
		}
		if stats.RuleTrafficStats[0].TrafficStats.Sessions != int64(totalSessionsPerRule) {
			return false, nil
		}
		if stats.RuleTrafficStats[1].TrafficStats.Sessions != int64(totalSessionsPerRule) {
			return false, nil
		}
		if stats.TrafficStats.Sessions != stats.RuleTrafficStats[1].TrafficStats.Sessions+stats.RuleTrafficStats[0].TrafficStats.Sessions {
			return false, fmt.Errorf("the rules stats under one policy should sum up to its total policy")
		}
		if stats.TrafficStats.Packets < stats.TrafficStats.Sessions || stats.TrafficStats.Bytes < stats.TrafficStats.Sessions {
			return false, fmt.Errorf("neither 'Packets' nor 'Bytes' should be smaller than 'Sessions'")
		}
		return true, nil
	}); err != nil {
		failOnError(err, t)
	}
	k8sUtils.Cleanup(namespaces)
}

func testAntreaClusterNetworkPolicyStats(t *testing.T, data *TestData) {
	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", data.testNamespace, false)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createToolboxPodOnNode, "test-client-", "", data.testNamespace, false)
	defer cleanupFunc()
	var err error
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	p10 := float64(10)
	intstr800 := intstr.FromInt(800)
	intstr4430 := intstr.FromInt(4430)
	dropAction := crdv1beta1.RuleActionDrop
	allowAction := crdv1beta1.RuleActionAllow
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientName}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": serverName}}
	protocol, _ := AntreaPolicyProtocolToK8sProtocol(ProtocolUDP)

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.IPv4.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.IPv6.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
	}
	var acnp = &crdv1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: "cnp1", Labels: map[string]string{"antrea-e2e": "cnp1"}},
		Spec: crdv1beta1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1beta1.AppliedTo{
				{PodSelector: &selectorC},
			},
			Priority: p10,
			Ingress: []crdv1beta1.Rule{
				{
					Ports: []crdv1beta1.NetworkPolicyPort{
						{
							Port:     &intstr800,
							Protocol: &protocol,
						},
					},
					From: []crdv1beta1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &allowAction,
				},
				{
					Ports: []crdv1beta1.NetworkPolicyPort{
						{
							Port:     &intstr4430,
							Protocol: &protocol,
						},
					},
					From: []crdv1beta1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &dropAction,
				},
			},
			Egress: []crdv1beta1.Rule{},
		},
	}

	if _, err = k8sUtils.CreateOrUpdateACNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP failed for ACNP %s: %v", acnp.Name, err), t)
	}

	// Wait for the policy to be realized before attempting connections
	failOnError(data.waitForACNPRealized(t, acnp.Name, policyRealizedTimeout), t)

	sessionsPerAddressFamily := 10
	var wg sync.WaitGroup
	for i := 0; i < sessionsPerAddressFamily; i++ {
		wg.Add(1)
		go func() {
			if clusterInfo.podV4NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 800", serverIPs.IPv4.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 4430", serverIPs.IPv4.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd2)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 800", serverIPs.IPv6.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 4430", serverIPs.IPv6.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, toolboxContainerName, cmd2)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	totalSessionsPerRule := 0
	if clusterInfo.podV4NetworkCIDR != "" {
		totalSessionsPerRule += sessionsPerAddressFamily
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		totalSessionsPerRule += sessionsPerAddressFamily
	}

	if err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		stats, err := data.crdClient.StatsV1alpha1().AntreaClusterNetworkPolicyStats().Get(context.TODO(), "cnp1", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		t.Logf("Got AntreaNetworkPolicy stats: %v", stats)
		if len(stats.RuleTrafficStats) != 2 {
			return false, nil
		}
		if stats.RuleTrafficStats[0].TrafficStats.Sessions != int64(totalSessionsPerRule) {
			return false, nil
		}
		if stats.RuleTrafficStats[1].TrafficStats.Sessions != int64(totalSessionsPerRule) {
			return false, nil
		}
		if stats.TrafficStats.Sessions != stats.RuleTrafficStats[1].TrafficStats.Sessions+stats.RuleTrafficStats[0].TrafficStats.Sessions {
			return false, fmt.Errorf("the rules stats under one policy should sum up to its total policy")
		}
		if stats.TrafficStats.Packets < stats.TrafficStats.Sessions || stats.TrafficStats.Bytes < stats.TrafficStats.Sessions {
			return false, fmt.Errorf("neither 'Packets' nor 'Bytes' should be smaller than 'Sessions'")
		}
		return true, nil
	}); err != nil {
		failOnError(err, t)
	}
	k8sUtils.Cleanup(namespaces)
}
