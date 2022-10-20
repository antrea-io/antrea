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

	"antrea.io/antrea/pkg/agent/apiserver/handlers/podinterface"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	"antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/features"
	. "antrea.io/antrea/test/e2e/utils"
)

// common for all tests.
var (
	allPods                                     []Pod
	podsByNamespace                             map[string][]Pod
	k8sUtils                                    *KubernetesUtils
	allTestList                                 []*TestCase
	pods                                        []string
	namespaces                                  map[string]string
	podIPs                                      map[string][]string
	p80, p81, p8080, p8081, p8082, p8085, p6443 int32
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

	t.Run("testANPNetworkPolicyStatsWithDropAction", func(t *testing.T) {
		testANPNetworkPolicyStatsWithDropAction(t, data)
	})
	t.Run("testAntreaClusterNetworkPolicyStats", func(t *testing.T) {
		testAntreaClusterNetworkPolicyStats(t, data)
	})
}

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

func initialize(t *testing.T, data *TestData) {
	p80 = 80
	p81 = 81
	p8080 = 8080
	p8081 = 8081
	p8082 = 8082
	p8085 = 8085
	pods = []string{"a", "b", "c"}
	namespaces = make(map[string]string)
	suffix := randName("")
	namespaces["x"] = "x-" + suffix
	namespaces["y"] = "y-" + suffix
	namespaces["z"] = "z-" + suffix
	// This function "initialize" will be used more than once, and variable "allPods" is global.
	// It should be empty every time when "initialize" is performed, otherwise there will be unexpected
	// results.
	allPods = []Pod{}
	podsByNamespace = make(map[string][]Pod)

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
			podsByNamespace[ns] = append(podsByNamespace[ns], NewPod(ns, podName))
		}
	}
	skipIfAntreaPolicyDisabled(t)

	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, pods)
	failOnError(err, t)
	podIPs = *ips
}

func skipIfAntreaPolicyDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.AntreaPolicy, true, true)
}

func applyDefaultDenyToAllNamespaces(k8s *KubernetesUtils, namespaces map[string]string) error {
	if err := k8s.CleanNetworkPolicies(namespaces); err != nil {
		return err
	}
	for _, ns := range namespaces {
		builder := &NetworkPolicySpecBuilder{}
		builder = builder.SetName(ns, "default-deny-namespace")
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

func cleanupDefaultDenyNPs(k8s *KubernetesUtils, namespaces map[string]string) error {
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
	log.Debugf("creating ACNP %v", acnp.Name)
	acnp, err := k8sUtils.CreateOrUpdateACNP(acnp)
	if err != nil {
		failOnError(fmt.Errorf("ACNP create failed %v", err), t)
	}
	if acnp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanACNPs(), t)
}

func testMutateANPNoTier(t *testing.T) {
	invalidNpErr := fmt.Errorf("ANP tier not mutated to default tier")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-no-tier").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0)
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	anp, err := k8sUtils.CreateOrUpdateANP(anp)
	if err != nil {
		failOnError(fmt.Errorf("ANP create failed %v", err), t)
	}
	if anp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanANPs([]string{anp.Namespace}), t)
}

func testMutateACNPNoRuleName(t *testing.T) {
	mutateErr := fmt.Errorf("ACNP Rule name not mutated automatically")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-rule-name").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	acnp, err := k8sUtils.CreateOrUpdateACNP(acnp)
	if err != nil {
		failOnError(fmt.Errorf("ACNP create failed %v", err), t)
	}
	ir := acnp.Spec.Ingress
	if len(ir) != 1 {
		failOnError(fmt.Errorf("unexpected number of rules present in ACNP: %d rules present instead of 1", len(ir)), t)
	}
	// Here we created a single rule
	if ir[0].Name == "" {
		failOnError(mutateErr, t)
	}
	failOnError(k8sUtils.CleanACNPs(), t)
}

func testMutateANPNoRuleName(t *testing.T) {
	mutateErr := fmt.Errorf("ANP Rule name not mutated automatically")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-no-rule-name").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
			nil, nil, nil, nil, crdv1alpha1.RuleActionAllow, "", "")
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	anp, err := k8sUtils.CreateOrUpdateANP(anp)
	if err != nil {
		failOnError(fmt.Errorf("ANP create failed %v", err), t)
	}
	ir := anp.Spec.Ingress
	if len(ir) != 1 {
		failOnError(fmt.Errorf("unexpected number of rules present in ANP: %d rules present instead of 1", len(ir)), t)
	}
	// Here we created a single rule
	if ir[0].Name == "" {
		failOnError(mutateErr, t)
	}
	failOnError(k8sUtils.CleanANPs([]string{anp.Namespace}), t)
}

func testInvalidACNPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without a priority accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-priority").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPIngressPeerGroupSetWithPodSelector(t *testing.T) {
	gA := "gA"
	namespace := "x"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	ruleAppTo := ANPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"},
	}
	k8sUtils.CreateGroup(namespace, gA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy with group and podSelector in NetworkPolicyPeer set")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespace, "anp-ingress-group-podselector-set").
		SetPriority(1.0)
	builder = builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil,
		nil, nil, nil, []ANPAppliedToSpec{ruleAppTo}, crdv1alpha1.RuleActionAllow, gA, "")
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanGroups(namespace), t)
}

func testInvalidANPIngressPeerGroupSetWithIPBlock(t *testing.T) {
	gA := "gA"
	namespace := "x"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	k8sUtils.CreateGroup(namespace, gA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy with group and ipBlock in NetworkPolicyPeer set")
	cidr := "10.0.0.10/32"
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespace, "anp-ingress-group-ipblock-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{Group: "gA"}})
	builder = builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, &cidr, map[string]string{"pod": "b"}, map[string]string{"ns": "x"}, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionAllow, gA, "")
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanGroups(namespace), t)
}

func testInvalidANPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without a priority accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-no-priority").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPRuleNameNotUnique(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without unique rule names accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-rule-name-not-unique").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
			nil, nil, nil, nil, crdv1alpha1.RuleActionAllow, "", "not-unique").
		AddIngress(ProtocolTCP, &p81, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": namespaces["x"]}, nil,
			nil, nil, nil, nil, crdv1alpha1.RuleActionAllow, "", "not-unique")
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPTierDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without existing Tier accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-tier-not-exist").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("i-dont-exist")
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPPortRangePortUnset(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy egress rule with endPort but no port accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "anp-egress-port-range-port-unset").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(ProtocolTCP, nil, nil, &p8085, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "anp-port-range")

	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPPortRangeEndPortSmall(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy egress rule with endPort smaller than port accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "anp-egress-port-range-endport-small").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(ProtocolTCP, &p8082, nil, &p8081, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "anp-port-range")

	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidTierReservedDelete(t *testing.T) {
	invalidErr := fmt.Errorf("reserved Tier deleted")
	if err := k8sUtils.DeleteTier("emergency"); err == nil {
		// Above deletion of reserved Tier must fail.
		failOnError(invalidErr, t)
	}
}

func testInvalidTierPriorityUpdate(t *testing.T) {
	invalidErr := fmt.Errorf("tier priority updated")
	oldTier, err := k8sUtils.CreateNewTier("prio-updated-tier", 21)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier prio-updated-tier: %v", err), t)
	}
	// Update this tier with new priority
	newTier := crdv1alpha1.Tier{
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

func testInvalidTierPriorityOverlap(t *testing.T) {
	invalidErr := fmt.Errorf("tiers created with overlapping priorities")
	tr, err := k8sUtils.CreateNewTier("tier-prio-20", 20)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-prio-20: %v", err), t)
	}
	// Attempt to create Tier with same priority.
	if _, err = k8sUtils.CreateNewTier("another-tier-prio-20", 20); err == nil {
		// Above creation of Tier must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteTier(tr.Name), t)
}

func testInvalidTierReservedPriority(t *testing.T) {
	invalidErr := fmt.Errorf("tier created with reserved priority")
	if _, err := k8sUtils.CreateNewTier("tier-reserved-prio", 251); err == nil {
		// Above creation of Tier must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidTierACNPRefDelete(t *testing.T) {
	invalidErr := fmt.Errorf("tier deleted with referenced ACNPs")
	tr, err := k8sUtils.CreateNewTier("tier-acnp", 10)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-acnp: %v", err), t)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-for-tier").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("tier-acnp").
		SetPriority(13.0)
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err = k8sUtils.CreateOrUpdateACNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP failed for ACNP %s: %v", acnp.Name, err), t)
	}
	// Deleting this Tier must fail as it has referenced ACNP
	if err = k8sUtils.DeleteTier(tr.Name); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.CleanACNPs(), t)
	failOnError(k8sUtils.DeleteTier(tr.Name), t)
}

func testInvalidTierANPRefDelete(t *testing.T) {
	invalidErr := fmt.Errorf("tier deleted with referenced ANPs")
	tr, err := k8sUtils.CreateNewTier("tier-anp-ref", 11)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-anp: %v", err), t)
	}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-for-tier").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("tier-anp-ref").
		SetPriority(13.0)
	anp := builder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err = k8sUtils.CreateOrUpdateANP(anp); err != nil {
		failOnError(fmt.Errorf("create ANP failed for ANP %s: %v", anp.Name, err), t)
	}
	// Deleting this Tier must fail as it has referenced ANP
	if err = k8sUtils.DeleteTier(tr.Name); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.CleanANPs([]string{anp.Namespace}), t)
	failOnError(k8sUtils.DeleteTier(tr.Name), t)
}

// testInvalidACNPPodSelectorNsSelectorMatchExpressions tests creating a ClusterNetworkPolicy with invalid LabelSelector(MatchExpressions)
func testInvalidACNPPodSelectorNsSelectorMatchExpressions(t *testing.T, data *TestData) {
	invalidLSErr := fmt.Errorf("create Antrea NetworkPolicy with namespaceSelector but matchExpressions invalid")

	allowAction := crdv1alpha1.RuleActionAllow
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"env": "dummy"}}
	nsSelectA := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "env", Operator: "xxx", Values: []string{"xxxx"}}}}

	var acnp = &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: data.testNamespace, Name: "cnptest", Labels: map[string]string{"antrea-e2e": "cnp1"}},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.AppliedTo{
				{PodSelector: &selectorA},
				{NamespaceSelector: &nsSelectA},
			},
			Priority: 10,
			Ingress: []crdv1alpha1.Rule{
				{
					Action: &allowAction,
				},
			},
		},
	}

	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		failOnError(invalidLSErr, t)
	}
}

// testACNPAllowXBtoA tests traffic from X/B to pods with label A, after applying the default deny
// k8s NetworkPolicies in all namespaces and ACNP to allow X/B to A.
func testACNPAllowXBtoA(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-allow-xb-to-a").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["z"]+"/a"), Connected)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow X/B to A", testStep},
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["y"]}}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Connected)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{81},
			ProtocolTCP,
			0,
			nil,
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority1").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	// Ingress from ns:z to x/a will be dropped since acnp-priority1 has higher precedence.
	reachabilityBothACNP := NewReachability(allPods, Dropped)
	reachabilityBothACNP.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/b"), Connected)
	reachabilityBothACNP.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/c"), Connected)
	reachabilityBothACNP.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/b"), Connected)
	reachabilityBothACNP.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/c"), Connected)
	reachabilityBothACNP.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/b"), Connected)
	reachabilityBothACNP.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/c"), Connected)
	reachabilityBothACNP.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder1.Get(), builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder.AddIngress(protocol, &p81, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["y"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)
	builder.AddEgress(protocol, &p81, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	testStep := []*TestStep{
		{
			"Port 81",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{81},
			protocol,
			0,
			nil,
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
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Dropped)
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, nil,
		crdv1alpha1.RuleActionDrop, "", "drop-all-ingress", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectAllIngress(Pod(namespaces["x"]+"/a"), Dropped)
	reachability.ExpectAllIngress(Pod(namespaces["x"]+"/b"), Dropped)
	reachability.ExpectAllIngress(Pod(namespaces["x"]+"/c"), Dropped)
	reachability.ExpectSelf(allPods, Connected)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
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
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability1 := NewReachability(allPods, Connected)
	reachability1.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["z"]+"/a"), Dropped)
	reachability1.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["z"]+"/a"), Dropped)

	reachability2 := NewReachability(allPods, Connected)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability1,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80",
			reachability2,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolUDP,
			0,
			nil,
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
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": namespaces["y"]}, nil).
		SetPodSelector(map[string]string{"pod": "a"}, nil)
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-ya-from-xb").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			// Note in this testcase the ClusterGroup is created after the ACNP
			[]metav1.Object{builder.Get(), cgBuilder.Get()},
			[]int32{81},
			ProtocolTCP,
			0,
			nil,
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
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": namespaces["x"]}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-xb-to-ya").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["y"]}}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{cgBuilder.Get(), builder.Get()},
			[]int32{81},
			ProtocolTCP,
			0,
			nil,
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
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetPodSelector(map[string]string{"pod": "a"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-a-to-z").
		SetPriority(1.0)
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, []ACNPAppliedToSpec{{Group: cgName}}, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			// Note in this testcase the ClusterGroup is created after the ACNP
			[]metav1.Object{builder.Get(), cgBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
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
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": namespaces["z"]}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			// Note in this testcase the ClusterGroup is created after the ACNP
			[]metav1.Object{builder.Get(), cgBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to ClusterGroup with NS:z", testStep},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupUpdateAppliedTo(t *testing.T) {
	cgName := "cg-pods-a-then-c"
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetPodSelector(map[string]string{"pod": "a"}, nil)
	// Update CG Pod selector to group Pods C
	updatedCgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName).SetPodSelector(map[string]string{"pod": "c"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/c"), namespaces["z"], Dropped)
	updatedReachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/c"), namespaces["z"], Dropped)
	updatedReachability.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["z"]+"/a"), Dropped)
	updatedReachability.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["z"]+"/b"), Dropped)
	testStep := []*TestStep{
		{
			"CG Pods A",
			reachability,
			[]metav1.Object{cgBuilder.Get(), builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
		{
			"CG Pods C - update",
			updatedReachability,
			[]metav1.Object{updatedCgBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From CG Pod:a to NS:z updated to ClusterGroup with Pod:c", testStep},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupUpdate(t *testing.T) {
	cgName := "cg-ns-z-then-y"
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": namespaces["z"]}, nil)
	// Update CG NS selector to group Pods from Namespace Y
	updatedCgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": namespaces["y"]}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["y"], Dropped)
	updatedReachability.ExpectEgressToNamespace(Pod(namespaces["z"]+"/a"), namespaces["y"], Dropped)
	updatedReachability.Expect(Pod(namespaces["y"]+"/a"), Pod(namespaces["y"]+"/b"), Dropped)
	updatedReachability.Expect(Pod(namespaces["y"]+"/a"), Pod(namespaces["y"]+"/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{cgBuilder.Get(), builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80 - update",
			updatedReachability,
			[]metav1.Object{updatedCgBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to ClusterGroup with NS:z updated to ClusterGroup with NS:y", testStep},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupAppliedToPodAdd(t *testing.T, data *TestData) {
	cgName := "cg-pod-custom-pod-zj"
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": namespaces["z"]}, nil).
		SetPodSelector(map[string]string{"pod": "j"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-zj-to-xj-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "j"}, map[string]string{"ns": namespaces["x"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["z"], "j"),
				Labels: map[string]string{"pod": "j"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["x"], "j"),
				Labels: map[string]string{"pod": "j"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep := []*TestStep{
		{
			"Port 80",
			nil,
			[]metav1.Object{cgBuilder.Get(), builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			cp,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From ClusterGroup with Pod: z/j to Pod: x/j for Pod ADD events", testStep},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPClusterGroupRefRulePodAdd(t *testing.T, data *TestData) {
	cgName := "cg-pod-custom-pod-zk"
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": namespaces["z"]}, nil).
		SetPodSelector(map[string]string{"pod": "k"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-xk-to-cg-with-zk-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "k"},
				NSSelector:  map[string]string{"ns": namespaces["x"]},
			},
		})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "", nil)
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["x"], "k"),
				Labels: map[string]string{"pod": "k"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["z"], "k"),
				Labels: map[string]string{"pod": "k"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep := []*TestStep{
		{
			"Port 80",
			nil,
			// Note in this testcase the ClusterGroup is created after the ACNP
			[]metav1.Object{builder.Get(), cgBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			cp,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From Pod: x/k to ClusterGroup with Pod: z/k for Pod ADD event", testStep},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPClusterGroupRefRuleIPBlocks(t *testing.T) {
	podXAIP, _ := podIPs[namespaces["x"]+"/a"]
	podXBIP, _ := podIPs[namespaces["x"]+"/b"]
	podXCIP, _ := podIPs[namespaces["x"]+"/c"]
	podZAIP, _ := podIPs[namespaces["z"]+"/a"]
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
	var ipBlock1, ipBlock2 []crdv1alpha1.IPBlock
	for i := 0; i < len(podXAIP); i++ {
		ipBlock1 = append(ipBlock1, crdv1alpha1.IPBlock{CIDR: genCIDR(podXAIP[i])})
		ipBlock1 = append(ipBlock1, crdv1alpha1.IPBlock{CIDR: genCIDR(podXBIP[i])})
		ipBlock1 = append(ipBlock1, crdv1alpha1.IPBlock{CIDR: genCIDR(podXCIP[i])})
		ipBlock2 = append(ipBlock2, crdv1alpha1.IPBlock{CIDR: genCIDR(podZAIP[i])})
	}

	cgv1a3Name := "cg-ipblocks-pod-in-ns-x"
	cgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgv1a3Name).
		SetIPBlocks(ipBlock1)
	// crd/v1alpha2 ClusterGroups should be converted to crd/v1alpha3.
	cgv1a2Name := "cg-ipblock-pod-za"
	cgBuilder2 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cgv1a2Name).
		SetIPBlocks(ipBlock2)

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-x-ips-ingress-for-ya").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "a"},
				NSSelector:  map[string]string{"ns": namespaces["y"]},
			},
		})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgv1a3Name, "", nil)
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgv1a2Name, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/c"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["y"]+"/a"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), cgBuilder.Get(), cgBuilder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Ingress From x to Pod y/a to ClusterGroup with ipBlocks", testStep},
	}
	executeTests(t, testCase)
}

// testANPEgressRulePodsAToGrpWithPodsC tests that an ANP is able to drop egress traffic from x/a to x/c.
func testANPEgressRulePodsAToGrpWithPodsC(t *testing.T) {
	grpName := "grp-xc"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "c"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-xa-to-grp-xc-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			// Note in this testcase the Group is created after the ANP
			[]metav1.Object{builder.Get(), grpBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop Egress From All Pod:x/a to Group with Pod:x/c", testStep},
	}
	executeTests(t, testCase)
}

// testANPIngressRuleDenyGrpWithXCtoXA tests traffic from Group with X/B to X/A on named port 81 is dropped.
func testANPIngressRuleDenyGrpWithXCtoXA(t *testing.T) {
	grpName := "grp-pods-xb"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "b"}, nil)
	port81Name := "serve-81"
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-grp-with-xb-to-xa").
		SetPriority(2.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{grpBuilder.Get(), builder.Get()},
			[]int32{81},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Deny Group X/B to X/A", testStep},
	}
	executeTests(t, testCase)
}

func testANPGroupUpdate(t *testing.T) {
	grpName := "grp-pod-xc-then-pod-xb"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "c"}, nil)
	// Update Group Pod selector from X/C to X/B
	updatedGrpBuilder := &GroupSpecBuilder{}
	updatedGrpBuilder = updatedGrpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "b"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-xa-to-grp-with-xc-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{grpBuilder.Get(), builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80 - update",
			updatedReachability,
			[]metav1.Object{updatedGrpBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop Egress From All Pod:x/a to Group with Pod:x/c updated to Group with Pod:x/b", testStep},
	}
	executeTests(t, testCase)
}

// testANPAppliedToDenyXBtoGrpWithXA tests traffic from X/B to Group X/A on named port 81 is dropped.
func testANPAppliedToDenyXBtoGrpWithXA(t *testing.T) {
	grpName := "grp-pods-ya"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "a"}, nil)
	port81Name := "serve-81"
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-grp-with-xa-from-xb").
		SetPriority(2.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{Group: grpName}})
	builder.AddIngress(ProtocolTCP, nil, &port81Name, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			// Note in this testcase the Group is created after the ANP
			[]metav1.Object{builder.Get(), grpBuilder.Get()},
			[]int32{81},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Deny Group X/A from X/B", testStep},
	}
	executeTests(t, testCase)
}

// testANPAppliedToRuleGrpWithPodsAToPodsC tests that an ANP is able to drop egress traffic from GRP with pods labelled A to pods C.
func testANPAppliedToRuleGrpWithPodsAToPodsC(t *testing.T) {
	grpName := "grp-pods-a"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "a"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-grp-with-a-to-c").
		SetPriority(1.0)
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil, nil,
		nil, nil, nil, []ANPAppliedToSpec{{Group: grpName}}, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			// Note in this testcase the Group is created after the ANP
			[]metav1.Object{builder.Get(), grpBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop Egress From Group with All Pod:a to Pod:c", testStep},
	}
	executeTests(t, testCase)
}

func testANPGroupUpdateAppliedTo(t *testing.T) {
	grpName := "grp-pods-xa-then-xb"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "a"}, nil)
	// Update GRP Pod selector to group Pods x/b
	updatedGrpBuilder := &GroupSpecBuilder{}
	updatedGrpBuilder = updatedGrpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "b"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-grp-xc-to-xa-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{Group: grpName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	testStep := []*TestStep{
		{
			"GRP Pods X/C",
			reachability,
			[]metav1.Object{grpBuilder.Get(), builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
		{
			"GRP Pods X/B - update",
			updatedReachability,
			[]metav1.Object{updatedGrpBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop Egress From Pod:x/c to Group Pod:x/a updated to Group with Pod:x/b", testStep},
	}
	executeTests(t, testCase)
}

func testANPGroupAppliedToPodAdd(t *testing.T, data *TestData) {
	grpName := "grp-pod-custom-pod-xj"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "j"}, nil)
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-grp-with-xj-to-xd-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{Group: grpName}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "d"}, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["x"], "j"),
				Labels: map[string]string{"pod": "j"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["x"], "d"),
				Labels: map[string]string{"pod": "d"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep := []*TestStep{
		{
			"Port 80",
			nil,
			[]metav1.Object{grpBuilder.Get(), builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			cp,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop Egress From Group with Pod: x/j to Pod: x/d for Pod ADD events", testStep},
	}
	executeTestsWithData(t, testCase, data)
}

func testANPGroupServiceRefPodAdd(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", namespaces["x"], 80, 80, map[string]string{"app": "b"}, nil)

	grp1Name, grp2Name := "grp-svc1", "grp-svc2"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc2")

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-grp-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ANPAppliedToSpec{{Group: grp1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grp2Name, "")

	svc1PodName := randName("test-pod-svc1-")
	svc2PodName := randName("test-pod-svc2-")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["x"], svc2PodName),
				Labels: map[string]string{"pod": svc2PodName, "app": "b"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["x"], svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "a"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	testStep := &TestStep{
		"Port 80 updated",
		reachability,
		[]metav1.Object{svc1, svc2, grpBuilder1.Get(), grpBuilder2.Get(), builder.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		cp,
	}

	testSteps := []*TestStep{testStep}
	testCase := []*TestCase{
		{"ANP Group Service Reference add pod", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testANPGroupServiceRefDelete(t *testing.T) {
	svc1 := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", namespaces["x"], 80, 80, map[string]string{"app": "b"}, nil)
	k8sUtils.CreateOrUpdateService(svc1)
	failOnError(waitForResourceReady(t, timeout, svc1), t)
	k8sUtils.CreateOrUpdateService(svc2)
	failOnError(waitForResourceReady(t, timeout, svc2), t)

	grp1Name, grp2Name := "grp-svc1", "grp-svc2"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc2")
	grp1 := grpBuilder1.Get()
	k8sUtils.CreateOrUpdateV1Alpha3Group(grp1)
	failOnError(waitForResourceReady(t, timeout, grp1), t)
	grp2 := grpBuilder2.Get()
	k8sUtils.CreateOrUpdateV1Alpha3Group(grp2)
	failOnError(waitForResourceReady(t, timeout, grp2), t)

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-grp-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ANPAppliedToSpec{{Group: grp1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grp2Name, "")
	anp := builder.Get()
	k8sUtils.CreateOrUpdateANP(anp)
	failOnError(waitForResourceReady(t, timeout, anp), t)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ := reachability.Summary()
	if wrong != 0 {
		t.Errorf("failure -- %d wrong results", wrong)
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
		t.Errorf("failure -- %d wrong results", wrong)
		reachability2.PrintSummary(true, true, true)
	}
	// Cleanup test resources.
	failOnError(k8sUtils.DeleteANP(builder.Namespace, builder.Name), t)
}

func testANPGroupServiceRefCreateAndUpdate(t *testing.T) {
	svc1 := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", namespaces["x"], 80, 80, map[string]string{"app": "b"}, nil)

	grp1Name, grp2Name := "grp-svc1", "grp-svc2"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc2")

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-grp-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ANPAppliedToSpec{{Group: grp1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grp2Name, "")

	// Pods backing svc1 (label pod=a) in Namespace x should not allow ingress from Pods backing svc2 (label pod=b) in Namespace x.
	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{svc1, svc2, grpBuilder1.Get(), grpBuilder2.Get(), builder.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	// Test update selector of Service referred in grp-svc1, and update serviceReference of grp-svc2.
	svc1Updated := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "b"}, nil)
	svc3 := k8sUtils.BuildService("svc3", namespaces["x"], 80, 80, map[string]string{"app": "c"}, nil)
	grpBuilder2Updated := grpBuilder2.SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc3")

	// Pods backing svc1 (label pod=b) in namespace x should not allow ingress from Pods backing svc3 (label pod=d) in namespace x.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod(namespaces["x"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	testStep2 := &TestStep{
		"Port 80 updated",
		reachability2,
		[]metav1.Object{svc1Updated, svc3, grpBuilder1.Get(), grpBuilder2Updated.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	testSteps := []*TestStep{testStep1, testStep2}
	testCase := []*TestCase{
		{"ANP Group Service Reference create and update", testSteps},
	}
	executeTests(t, testCase)
}

func testANPGroupRefRuleIPBlocks(t *testing.T) {
	podXBIP, _ := podIPs[namespaces["x"]+"/b"]
	podXCIP, _ := podIPs[namespaces["x"]+"/c"]
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
	var ipBlock []crdv1alpha1.IPBlock
	for i := 0; i < len(podXBIP); i++ {
		ipBlock = append(ipBlock, crdv1alpha1.IPBlock{CIDR: genCIDR(podXBIP[i])})
		ipBlock = append(ipBlock, crdv1alpha1.IPBlock{CIDR: genCIDR(podXCIP[i])})
	}

	grpName := "grp-ipblocks-pod-xb-xc"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(namespaces["x"]).SetIPBlocks(ipBlock)

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-deny-xb-xc-ips-ingress-for-xa").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grpName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/c"), Pod(namespaces["x"]+"/a"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), grpBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop Ingress From Group with ipBlocks to Pod: x/a", testStep},
	}
	executeTests(t, testCase)
}

func testANPNestedGroupCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "a"}, nil)
	svc1PodName := randName("test-pod-svc1-")
	grp1Name, grp2Name, grp3Name := "grp-svc-x-a", "grp-select-x-b", "grp-select-x-c"
	grpBuilder1 := &GroupSpecBuilder{}
	grpBuilder1 = grpBuilder1.SetName(grp1Name).SetNamespace(namespaces["x"]).SetServiceReference(namespaces["x"], "svc1")
	grpBuilder2 := &GroupSpecBuilder{}
	grpBuilder2 = grpBuilder2.SetName(grp2Name).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "b"}, nil)
	grpBuilder3 := &GroupSpecBuilder{}
	grpBuilder3 = grpBuilder3.SetName(grp3Name).SetNamespace(namespaces["x"]).SetPodSelector(map[string]string{"pod": "c"}, nil)
	grpNestedName := "grp-nested"
	grpBuilderNested := &GroupSpecBuilder{}
	grpBuilderNested = grpBuilderNested.SetName(grpNestedName).SetNamespace(namespaces["x"]).SetChildGroups([]string{grp1Name, grp3Name})

	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["x"], "anp-nested-grp").SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{}}).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, grpNestedName, "")

	// Pods in Namespace x should not allow traffic from Pods backing svc1 (label pod=a) in Namespace x.
	// Note that in this testStep grp3 will not be created yet, so even though grp-nested selects grp1 and
	// grp3 as childGroups, only members of grp1 will be included as this time.
	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["x"], Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep1 := &TestStep{
		"Port 80",
		reachability,
		// Note in this testcase the Group is created after the ANP
		[]metav1.Object{builder.Get(), svc1, grpBuilder1.Get(), grpBuilderNested.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	// Test update "grp-nested" to include "grp-select-x-b" as well.
	grpBuilderNested = grpBuilderNested.SetChildGroups([]string{grp1Name, grp2Name, grp3Name})
	// In addition to x/a, all traffic from x/b to Namespace x should also be denied.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["x"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/b"), namespaces["x"], Dropped)
	reachability2.ExpectSelf(allPods, Connected)
	// New member in grp-svc-x-a should be reflected in grp-nested as well.
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["x"], svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["x"], "test-add-pod-ns-x"),
				Labels: map[string]string{"pod": "test-add-pod-ns-x"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep2 := &TestStep{
		"Port 80 updated",
		reachability2,
		[]metav1.Object{grpBuilder2.Get(), grpBuilderNested.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		cp,
	}

	// In this testStep grp3 is created. It's members should reflect in grp-nested
	// and as a result, all traffic from x/c to Namespace x should be denied as well.
	reachability3 := NewReachability(allPods, Connected)
	reachability3.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["x"], Dropped)
	reachability3.ExpectEgressToNamespace(Pod(namespaces["x"]+"/b"), namespaces["x"], Dropped)
	reachability3.ExpectEgressToNamespace(Pod(namespaces["x"]+"/c"), namespaces["x"], Dropped)
	reachability3.ExpectSelf(allPods, Connected)
	testStep3 := &TestStep{
		"Port 80 updated",
		reachability3,
		[]metav1.Object{grpBuilder3.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ANP nested Group create and update", testSteps},
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
		Values:   []string{namespaces["x"]},
	}
	builder = builder.SetName("acnp-baseline-isolate-ns-x").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, []metav1.LabelSelectorRequirement{nsExpOtherThanX}, false,
		nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	// create a K8s NetworkPolicy for Pods in namespace x to allow ingress traffic from Pods in the same namespace,
	// as well as from the y/a Pod. It should open up ingress from y/a since it's evaluated before the baseline tier.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(namespaces["x"], "allow-ns-x-and-y-a").
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			nil, map[string]string{"ns": namespaces["x"]}, nil, nil).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "a"}, map[string]string{"ns": namespaces["y"]}, nil, nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["y"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["y"]+"/c"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability.ExpectIngressFromNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["y"]+"/b"), Pod(namespaces["x"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["y"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	reachability.ExpectIngressFromNamespace(Pod(namespaces["x"]+"/b"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["y"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	reachability.Expect(Pod(namespaces["y"]+"/c"), Pod(namespaces["x"]+"/c"), Dropped)
	reachability.ExpectIngressFromNamespace(Pod(namespaces["x"]+"/c"), namespaces["z"], Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), k8sNPBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP baseline tier namespace isolation", testStep},
	}
	executeTests(t, testCase)
	// Cleanup the K8s NetworkPolicy created for this test.
	failOnError(k8sUtils.CleanNetworkPolicies(map[string]string{"x": namespaces["x"]}), t)
	time.Sleep(networkPolicyDelay)
}

// testACNPPriorityOverride tests priority overriding in three Policies. Those three Policies are applied in a specific order to
// test priority reassignment, and each controls a smaller set of traffic patterns as priority increases.
func testACNPPriorityOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-priority1").
		SetPriority(1.001).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Highest priority. Drops traffic from z/b to x/a.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority2").
		SetPriority(1.002).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Medium priority. Allows traffic from z to x/a.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-priority3").
		SetPriority(1.003).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Lowest priority. Drops traffic from z to x.
	builder3.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/c"), Dropped)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/c"), Dropped)

	testStepTwoACNP := []*TestStep{
		{
			"Two Policies with different priorities",
			reachabilityTwoACNPs,
			[]metav1.Object{builder3.Get(), builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	// Create the Policies in specific order to make sure that priority re-assignments work as expected.
	testStepAll := []*TestStep{
		{
			"All three Policies",
			reachabilityAllACNPs,
			[]metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP PriorityOverride Intermediate", testStepTwoACNP},
		{"ACNP PriorityOverride All", testStepAll},
	}
	executeTests(t, testCase)
}

// testACNPTierOverride tests tier priority overriding in three Policies.
// Each ACNP controls a smaller set of traffic patterns as tier priority increases.
func testACNPTierOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-emergency").
		SetTier("emergency").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Highest priority tier. Drops traffic from z/b to x/a.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-securityops").
		SetTier("securityops").
		SetPriority(10).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-tier-application").
		SetTier("application").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Lowest priority tier. Drops traffic from z to x.
	builder3.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/c"), Dropped)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/c"), Dropped)

	testStepTwoACNP := []*TestStep{
		{
			"Two Policies in different tiers",
			reachabilityTwoACNPs,
			[]metav1.Object{builder3.Get(), builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testStepAll := []*TestStep{
		{
			"All three Policies in different tiers",
			reachabilityAllACNPs,
			[]metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP TierOverride Intermediate", testStepTwoACNP},
		{"ACNP TierOverride All", testStepAll},
	}
	executeTests(t, testCase)
}

// testACNPTierOverride tests tier priority overriding in three Policies with custom created tiers.
// Each ACNP controls a smaller set of traffic patterns as tier priority increases.
func testACNPCustomTiers(t *testing.T) {
	k8sUtils.DeleteTier("high-priority")
	k8sUtils.DeleteTier("low-priority")
	// Create two custom tiers with tier priority immediately next to each other.
	_, err := k8sUtils.CreateNewTier("high-priority", 245)
	failOnError(err, t)
	_, err = k8sUtils.CreateNewTier("low-priority", 246)
	failOnError(err, t)

	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-high").
		SetTier("high-priority").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-low").
		SetTier("low-priority").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// Lowest priority tier. Drops traffic from z to x.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["x"]+"/c"), Dropped)
	testStepTwoACNP := []*TestStep{
		{
			"Two Policies in different tiers",
			reachabilityTwoACNPs,
			[]metav1.Object{builder2.Get(), builder1.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Custom Tier priority", testStepTwoACNP},
	}
	executeTests(t, testCase)
	// Cleanup customed tiers. ACNPs created in those tiers need to be deleted first.
	failOnError(k8sUtils.CleanACNPs(), t)
	failOnError(k8sUtils.DeleteTier("high-priority"), t)
	failOnError(k8sUtils.DeleteTier("low-priority"), t)
	time.Sleep(networkPolicyDelay)
}

// testACNPPriorityConflictingRule tests that if there are two Policies in the cluster with rules that conflicts with
// each other, the ACNP with higher priority will prevail.
func testACNPPriorityConflictingRule(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-drop").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder1.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(2).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	// The following ingress rule will take no effect as it is exactly the same as ingress rule of cnp-drop,
	// but cnp-allow has lower priority.
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.ExpectEgressToNamespace(Pod(namespaces["z"]+"/a"), namespaces["x"], Dropped)
	reachabilityBothACNP.ExpectEgressToNamespace(Pod(namespaces["z"]+"/b"), namespaces["x"], Dropped)
	reachabilityBothACNP.ExpectEgressToNamespace(Pod(namespaces["z"]+"/c"), namespaces["x"], Dropped)
	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder1.Get(), builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Priority Conflicting Rule", testStep},
	}
	executeTests(t, testCase)
}

// testACNPPriorityConflictingRule tests that if there are two rules in the cluster that conflicts with
// each other, the rule with higher precedence will prevail.
func testACNPRulePriority(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	// acnp-deny will apply to all pods in namespace x
	builder1 = builder1.SetName("acnp-deny").
		SetPriority(5).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["y"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)
	// This rule should take no effect as it will be overridden by the first rule of cnp-allow
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	// acnp-allow will also apply to all pods in namespace x
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(5).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder2.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)
	// This rule should take no effect as it will be overridden by the first rule of cnp-drop
	builder2.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["y"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)

	// Only egress from pods in namespace x to namespace y should be denied
	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.ExpectIngressFromNamespace(Pod(namespaces["y"]+"/a"), namespaces["x"], Dropped)
	reachabilityBothACNP.ExpectIngressFromNamespace(Pod(namespaces["y"]+"/b"), namespaces["x"], Dropped)
	reachabilityBothACNP.ExpectIngressFromNamespace(Pod(namespaces["y"]+"/c"), namespaces["x"], Dropped)
	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder2.Get(), builder1.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
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
	builder.AddEgress(ProtocolTCP, &p8080, nil, &p8082, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Dropped)
	testSteps := []*TestStep{
		{
			fmt.Sprintf("ACNP Drop Ports 8080:8082"),
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{8080, 8081, 8082},
			ProtocolTCP,
			0,
			nil,
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
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Rejected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Rejected)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/b"), Rejected)
	reachability.Expect(Pod(namespaces["z"]+"/a"), Pod(namespaces["z"]+"/c"), Rejected)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Reject egress From All Pod:a to NS:z", testStep},
	}
	executeTests(t, testCase)
}

// testACNPRejectIngress tests that an ACNP is able to reject egress traffic from pods labelled A to namespace Z.
func testACNPRejectIngress(t *testing.T, protocol AntreaPolicyProtocol) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-a-from-z-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectIngressFromNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Rejected)
	reachability.ExpectIngressFromNamespace(Pod(namespaces["y"]+"/a"), namespaces["z"], Rejected)
	reachability.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["z"]+"/a"), Rejected)
	reachability.Expect(Pod(namespaces["z"]+"/c"), Pod(namespaces["z"]+"/a"), Rejected)
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
		{"ACNP Reject ingress from NS:z to All Pod:a", testStep},
	}
	executeTests(t, testCase)
}

func testRejectServiceTraffic(t *testing.T, data *TestData) {
	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, data.testNamespace, nodeName(0), false))
	defer data.deletePodAndWait(defaultTimeout, clientName, data.testNamespace)
	_, err := data.podWaitForIPs(defaultTimeout, clientName, data.testNamespace)
	require.NoError(t, err)

	svc1, cleanup1 := data.createAgnhostServiceAndBackendPods(t, "s1", data.testNamespace, nodeName(0), v1.ServiceTypeClusterIP)
	defer cleanup1()

	svc2, cleanup2 := data.createAgnhostServiceAndBackendPods(t, "s2", data.testNamespace, nodeName(1), v1.ServiceTypeClusterIP)
	defer cleanup2()

	testcases := []podToAddrTestStep{
		{
			Pod(data.testNamespace + "/agnhost-client"),
			svc1.Spec.ClusterIP,
			80,
			Rejected,
		},
		{
			Pod(data.testNamespace + "/agnhost-client"),
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
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)
	builder1.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": "s2"}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	acnpEgress := builder1.Get()
	k8sUtils.CreateOrUpdateACNP(acnpEgress)
	failOnError(waitForResourcesReady(t, timeout, acnpEgress, svc1, svc2), t)

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder1.Name), t)

	// Test ingress.
	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-reject-ingress-svc-traffic").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": "s1"}}, {PodSelector: map[string]string{"antrea-e2e": "s2"}}})
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": "agnhost-client"}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	acnpIngress := builder2.Get()
	k8sUtils.CreateOrUpdateACNP(acnpIngress)
	failOnError(waitForResourceReady(t, timeout, acnpIngress), t)

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder2.Name), t)
}

// RejectNoInfiniteLoop tests that a reject action in both traffic directions won't cause an infinite rejection loop.
func testRejectNoInfiniteLoop(t *testing.T, data *TestData) {
	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, data.testNamespace, nodeName(0), false))
	defer data.deletePodAndWait(defaultTimeout, clientName, data.testNamespace)
	_, err := data.podWaitForIPs(defaultTimeout, clientName, data.testNamespace)
	require.NoError(t, err)

	_, server0IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server", nodeName(0), data.testNamespace, false)
	defer cleanupFunc()

	_, server1IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server", nodeName(1), data.testNamespace, false)
	defer cleanupFunc()

	var testcases []podToAddrTestStep
	if clusterInfo.podV4NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(data.testNamespace + "/agnhost-client"),
				server0IP.ipv4.String(),
				80,
				Rejected,
			},
			{
				Pod(data.testNamespace + "/agnhost-client"),
				server1IP.ipv4.String(),
				80,
				Rejected,
			},
		}...)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(data.testNamespace + "/agnhost-client"),
				server0IP.ipv6.String(),
				80,
				Rejected,
			},
			{
				Pod(data.testNamespace + "/agnhost-client"),
				server1IP.ipv6.String(),
				80,
				Rejected,
			},
		}...)
	}

	runTestsWithACNP := func(acnp *crdv1alpha1.ClusterNetworkPolicy, testcases []podToAddrTestStep) {
		k8sUtils.CreateOrUpdateACNP(acnp)
		failOnError(waitForResourceReady(t, timeout, acnp), t)

		for _, tc := range testcases {
			log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
			connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
			if err != nil {
				t.Errorf("failure -- could not complete probe: %v", err)
			}
			if connectivity != tc.expectedConnectivity {
				t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
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
		nil, nil, false, []ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}}, crdv1alpha1.RuleActionReject, "", "", nil)
	builder1.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, false, []ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}, crdv1alpha1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder1.Get(), testcases)

	// Test client and server reject traffic that egress to each other.
	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-reject-egress-double-dir").
		SetPriority(1.0)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, false, []ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}}, crdv1alpha1.RuleActionReject, "", "", nil)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, false, []ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}, crdv1alpha1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder2.Get(), testcases)

	// Test server reject traffic that egress to client and ingress from client.
	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-reject-server-double-dir").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	builder3.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)
	builder3.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": clientName}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder3.Get(), testcases)

	// Test client reject traffic that egress to server and ingress from server.
	builder4 := &ClusterNetworkPolicySpecBuilder{}
	builder4 = builder4.SetName("acnp-reject-client-double-dir").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": clientName}}})
	builder4.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)
	builder4.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"app": "nginx"}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	runTestsWithACNP(builder4.Get(), testcases)
}

// testANPPortRange tests the port range in a ANP can work.
func testANPPortRange(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "anp-deny-yb-to-xc-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(ProtocolTCP, &p8080, nil, &p8082, nil, nil, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "anp-port-range")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["y"]+"/b"), Pod(namespaces["x"]+"/c"), Dropped)

	var testSteps []*TestStep
	testSteps = append(testSteps, &TestStep{
		fmt.Sprintf("ANP Drop Ports 8080:8082"),
		reachability,
		[]metav1.Object{builder.Get()},
		[]int32{8080, 8081, 8082},
		ProtocolTCP,
		0,
		nil,
	})

	testCase := []*TestCase{
		{"ANP Drop Egress y/b to x/c with a portRange", testSteps},
	}
	executeTests(t, testCase)
}

// testANPBasic tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea NetworkPolicy
// that specifies that. Also it tests that a K8s NetworkPolicy with same appliedTo will not affect its behavior.
func testANPBasic(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "np-same-name").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	// build a K8s NetworkPolicy that has the same appliedTo but allows all traffic.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(namespaces["y"], "np-same-name").
		SetPodSelector(map[string]string{"pod": "a"})
	k8sNPBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
		nil, nil, nil, nil)
	testStep2 := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), k8sNPBuilder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop X/B to Y/A", testStep},
		{"With K8s NetworkPolicy of the same name", testStep2},
	}
	executeTests(t, testCase)
}

// testANPMultipleAppliedTo tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea
// NetworkPolicy that applies to multiple AppliedTos, one of which doesn't select any Pod. It also ensures the Policy is
// updated correctly when one of its AppliedToGroup starts and stops selecting Pods.
func testANPMultipleAppliedTo(t *testing.T, data *TestData, singleRule bool) {
	tempLabel := randName("temp-")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "np-multiple-appliedto").SetPriority(1.0)
	// Make it apply to an extra dummy AppliedTo to ensure it handles multiple AppliedToGroups correctly.
	// See https://github.com/antrea-io/antrea/issues/2083.
	if singleRule {
		builder.SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}, {PodSelector: map[string]string{tempLabel: ""}}})
		builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
			nil, nil, nil, nil, crdv1alpha1.RuleActionDrop, "", "")
	} else {
		builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
			nil, nil, nil, []ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}, crdv1alpha1.RuleActionDrop, "", "")
		builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
			nil, nil, nil, []ANPAppliedToSpec{{PodSelector: map[string]string{tempLabel: ""}}}, crdv1alpha1.RuleActionDrop, "", "")
	}

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)

	anp, err := k8sUtils.CreateOrUpdateANP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForANPRealized(t, anp.Namespace, anp.Name, policyRealizedTimeout), t)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ := reachability.Summary()
	if wrong != 0 {
		t.Errorf("failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	t.Logf("Making the Policy apply to y/c by labeling it with the temporary label that matches the dummy AppliedTo")
	podYC, err := k8sUtils.GetPodByLabel(namespaces["y"], "c")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace y with label 'pod=c': %v", err)
	}
	podYC.Labels[tempLabel] = ""
	podYC, err = k8sUtils.clientset.CoreV1().Pods(podYC.Namespace).Update(context.TODO(), podYC, metav1.UpdateOptions{})
	assert.NoError(t, err)
	reachability = NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/c"), Dropped)
	time.Sleep(networkPolicyDelay)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ = reachability.Summary()
	if wrong != 0 {
		t.Errorf("failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	t.Logf("Making the Policy not apply to y/c by removing the temporary label")
	delete(podYC.Labels, tempLabel)
	_, err = k8sUtils.clientset.CoreV1().Pods(podYC.Namespace).Update(context.TODO(), podYC, metav1.UpdateOptions{})
	assert.NoError(t, err)
	reachability = NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	time.Sleep(networkPolicyDelay)
	k8sUtils.Validate(allPods, reachability, []int32{80}, ProtocolTCP)
	_, wrong, _ = reachability.Summary()
	if wrong != 0 {
		t.Errorf("failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	failOnError(k8sUtils.DeleteANP(builder.Namespace, builder.Name), t)
}

// testAuditLoggingBasic tests that audit logs are generated when egress drop applied
func testAuditLoggingBasic(t *testing.T, data *TestData) {
	npRef := "test-log-acnp-deny"
	ruleName := "DropToZ"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(npRef).
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builder.AddEgress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", ruleName, nil)
	builder.AddEgressLogging()

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForACNPRealized(t, acnp.Name, policyRealizedTimeout), t)

	// generate some traffic that will be dropped by test-log-acnp-deny
	var wg sync.WaitGroup
	oneProbe := func(ns1, pod1, ns2, pod2 string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k8sUtils.Probe(ns1, pod1, ns2, pod2, p80, ProtocolTCP)
		}()
	}
	oneProbe(namespaces["x"], "a", namespaces["z"], "a")
	oneProbe(namespaces["x"], "a", namespaces["z"], "b")
	oneProbe(namespaces["x"], "a", namespaces["z"], "c")
	wg.Wait()

	podXA, err := k8sUtils.GetPodByLabel(namespaces["x"], "a")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace x with label 'pod=a': %v", err)
	}
	// nodeName is guaranteed to be set at this stage, since the framework waits for all Pods to be in Running phase
	nodeName := podXA.Spec.NodeName
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		t.Errorf("Error occurred when trying to get the Antrea Agent Pod running on Node %s: %v", nodeName, err)
	}
	cmd := []string{"cat", logDir + logfileName}

	if err := wait.Poll(1*time.Second, 10*time.Second, func() (bool, error) {
		stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
		if err != nil || stderr != "" {
			// file may not exist yet
			t.Logf("Error when printing the audit log file, err: %v, stderr: %v", err, stderr)
			return false, nil
		}
		if !strings.Contains(stdout, "test-log-acnp-deny") {
			t.Logf("Audit log file does not contain entries for 'test-log-acnp-deny' yet")
			return false, nil
		}

		destinations := []string{namespaces["z"] + "/a", namespaces["z"] + "/b", namespaces["z"] + "/c"}
		srcIPs, _ := podIPs[namespaces["x"]+"/a"]
		var expectedNumEntries, actualNumEntries int
		for _, d := range destinations {
			dstIPs, _ := podIPs[d]
			for i := 0; i < len(srcIPs); i++ {
				for j := 0; j < len(dstIPs); j++ {
					// only look for an entry in the audit log file if srcIP and
					// dstIP are of the same family
					if strings.Contains(srcIPs[i], ".") != strings.Contains(dstIPs[j], ".") {
						continue
					}
					expectedNumEntries += 1
					// The audit log should contain log entry `... Drop <ofPriority> <x/a IP> <z/* IP> ...`
					re := regexp.MustCompile(npRef + ` ` + ruleName + ` Drop [0-9]+ ` + srcIPs[i] + ` [0-9]+ ` + dstIPs[j] + ` ` + strconv.Itoa(int(p80)))
					if re.MatchString(stdout) {
						actualNumEntries += 1
					} else {
						t.Logf("Audit log does not contain expected entry for x/a (%s) to %s (%s)", srcIPs[i], d, dstIPs[j])
					}
					break
				}
			}
		}
		if actualNumEntries != expectedNumEntries {
			t.Logf("Missing entries in audit log: expected %d but found %d", expectedNumEntries, actualNumEntries)
			return false, nil
		}
		return true, nil
	}); err != nil {
		t.Errorf("Error when polling audit log files for required entries: %v", err)
	}

	failOnError(k8sUtils.CleanACNPs(), t)
}

// testAuditLoggingEnableNP tests that audit logs are generated when K8s NP is applied
// tests both Allow traffic by K8s NP and Drop traffic by implicit K8s policy drop
func testAuditLoggingEnableNP(t *testing.T, data *TestData) {
	failOnError(data.updateNamespaceWithAnnotations(namespaces["x"], map[string]string{networkpolicy.EnableNPLoggingAnnotationKey: "true"}), t)
	// Add a K8s namespaced NetworkPolicy in ns x that allow ingress traffic from
	// Pod x/b to x/a which default denies other ingress including from Pod x/c to x/a
	npRef := "allow-x-b-to-x-a"
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName(namespaces["x"], npRef).
		SetPodSelector(map[string]string{"pod": "a"}).
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "b"}, nil, nil, nil)

	knp, err := k8sUtils.CreateOrUpdateNetworkPolicy(k8sNPBuilder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, knp), t)

	// generate some traffic that will be dropped by implicit K8s policy drop
	var wg sync.WaitGroup
	oneProbe := func(ns1, pod1, ns2, pod2 string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k8sUtils.Probe(ns1, pod1, ns2, pod2, p80, ProtocolTCP)
		}()
	}
	oneProbe(namespaces["x"], "b", namespaces["x"], "a")
	oneProbe(namespaces["x"], "c", namespaces["x"], "a")
	wg.Wait()

	podXA, err := k8sUtils.GetPodByLabel(namespaces["x"], "a")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace x with label 'pod=a': %v", err)
	}
	// nodeName is guaranteed to be set at this stage, since the framework waits for all Pods to be in Running phase
	nodeName := podXA.Spec.NodeName
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		t.Errorf("Error occurred when trying to get the Antrea Agent Pod running on Node %s: %v", nodeName, err)
	}
	cmd := []string{"cat", logDir + logfileName}

	if err := wait.Poll(1*time.Second, 10*time.Second, func() (bool, error) {
		stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
		if err != nil || stderr != "" {
			// file may not exist yet
			t.Logf("Error when printing the audit log file, err: %v, stderr: %v", err, stderr)
			return false, nil
		}
		if !strings.Contains(stdout, "K8sNetworkPolicy") {
			t.Logf("Audit log file does not contain entries for 'test-log-acnp-deny' yet")
			return false, nil
		}

		var expectedNumEntries, actualNumEntries int
		srcPods := []string{namespaces["x"] + "/b", namespaces["x"] + "/c"}
		expectedLogPrefix := []string{npRef + " <nil> Allow [0-9]+ ", "K8sNetworkPolicy <nil> Drop <nil> "}
		destIPs, _ := podIPs[namespaces["x"]+"/a"]
		for i := 0; i < len(srcPods); i++ {
			srcIPs, _ := podIPs[srcPods[i]]
			for _, srcIP := range srcIPs {
				for _, destIP := range destIPs {
					// only look for an entry in the audit log file if srcIP and
					// dstIP are of the same family
					if strings.Contains(srcIP, ".") != strings.Contains(destIP, ".") {
						continue
					}
					expectedNumEntries += 1
					// The audit log should contain log entry `... Drop <ofPriority> <x/a IP> <z/* IP> ...`
					re := regexp.MustCompile(expectedLogPrefix[i] + srcIP + ` [0-9]+ ` + destIP + ` ` + strconv.Itoa(int(p80)))
					if re.MatchString(stdout) {
						actualNumEntries += 1
					} else {
						t.Logf("Audit log does not contain expected entry from %s (%s) to x/a (%s)", srcPods[i], srcIP, destIP)
					}
					break
				}
			}
		}
		if actualNumEntries != expectedNumEntries {
			t.Logf("Missing entries in audit log with K8s NP: expected %d but found %d", expectedNumEntries, actualNumEntries)
			return false, nil
		}
		return true, nil
	}); err != nil {
		t.Errorf("Error when polling audit log files for required entries: %v", err)
	}
	failOnError(k8sUtils.DeleteNetworkPolicy(namespaces["x"], "allow-x-b-to-x-a"), t)
	failOnError(data.UpdateNamespace(namespaces["x"], func(namespace *v1.Namespace) {
		delete(namespace.Annotations, networkpolicy.EnableNPLoggingAnnotationKey)
	}), t)
}

func testAppliedToPerRule(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(namespaces["y"], "np1").SetPriority(1.0)
	anpATGrp1 := ANPAppliedToSpec{PodSelector: map[string]string{"pod": "a"}, PodSelectorMatchExp: nil}
	anpATGrp2 := ANPAppliedToSpec{PodSelector: map[string]string{"pod": "b"}, PodSelectorMatchExp: nil}
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, []ANPAppliedToSpec{anpATGrp1}, crdv1alpha1.RuleActionDrop, "", "")
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["z"]}, nil,
		nil, nil, nil, []ANPAppliedToSpec{anpATGrp2}, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["y"]+"/b"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp1").SetPriority(1.0)
	cnpATGrp1 := ACNPAppliedToSpec{PodSelector: map[string]string{"pod": "a"}, PodSelectorMatchExp: nil}
	cnpATGrp2 := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"}, NSSelector: map[string]string{"ns": namespaces["y"]},
		PodSelectorMatchExp: nil, NSSelectorMatchExp: nil}
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]},
		nil, nil, false, []ACNPAppliedToSpec{cnpATGrp1}, crdv1alpha1.RuleActionDrop, "", "", nil)
	builder2.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["z"]},
		nil, nil, false, []ACNPAppliedToSpec{cnpATGrp2}, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	reachability2.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability2.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["z"]+"/a"), Dropped)
	reachability2.Expect(Pod(namespaces["z"]+"/b"), Pod(namespaces["y"]+"/b"), Dropped)
	testStep2 := []*TestStep{
		{
			"Port 80",
			reachability2,
			[]metav1.Object{builder2.Get()},
			[]int32{80},
			ProtocolTCP,
			0,
			nil,
		},
	}

	testCase := []*TestCase{
		{"ANP AppliedTo per rule", testStep},
		{"ACNP AppliedTo per rule", testStep2},
	}
	executeTests(t, testCase)
}

func testACNPClusterGroupServiceRefCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", namespaces["y"], 80, 80, map[string]string{"app": "b"}, nil)

	cg1Name, cg2Name := "cg-svc1", "cg-svc2"
	cgBuilder1 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference(namespaces["x"], "svc1")
	cgBuilder2 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetServiceReference(namespaces["y"], "svc2")

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-cg-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cg1Name}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		false, nil, crdv1alpha1.RuleActionDrop, cg2Name, "", nil)

	// Pods backing svc1 (label pod=a) in Namespace x should not allow ingress from Pods backing svc2 (label pod=b) in Namespace y.
	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["y"]+"/b"), Pod(namespaces["x"]+"/a"), Dropped)
	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{svc1, svc2, cgBuilder1.Get(), cgBuilder2.Get(), builder.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	// Test update selector of Service referred in cg-svc1, and update serviceReference of cg-svc2.
	svc1Updated := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "b"}, nil)
	svc3 := k8sUtils.BuildService("svc3", namespaces["y"], 80, 80, map[string]string{"app": "a"}, nil)
	svc1PodName := randName("test-pod-svc1-")
	svc3PodName := randName("test-pod-svc3-")
	cgBuilder2Updated := cgBuilder2.SetServiceReference(namespaces["y"], "svc3")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["y"], svc3PodName),
				Labels: map[string]string{"pod": svc3PodName, "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["x"], svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "b"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}

	// Pods backing svc1 (label pod=b) in namespace x should not allow ingress from Pods backing svc3 (label pod=a) in namespace y.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod(namespaces["y"]+"/a"), Pod(namespaces["x"]+"/b"), Dropped)
	testStep2 := &TestStep{
		"Port 80 updated",
		reachability2,
		[]metav1.Object{svc1Updated, svc3, cgBuilder1.Get(), cgBuilder2Updated.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		cp,
	}

	builderUpdated := &ClusterNetworkPolicySpecBuilder{}
	builderUpdated = builderUpdated.SetName("cnp-cg-svc-ref").SetPriority(1.0)
	builderUpdated.SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": namespaces["x"]}}})
	builderUpdated.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["y"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	// Pod x/a should not allow ingress from y/b per the updated ACNP spec.
	testStep3 := &TestStep{
		"Port 80 ACNP spec updated to selector",
		reachability,
		[]metav1.Object{builderUpdated.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ACNP ClusterGroup Service Reference create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPNestedClusterGroupCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", namespaces["x"], 80, 80, map[string]string{"app": "a"}, nil)
	svc1PodName := randName("test-pod-svc1-")
	cg1Name, cg2Name, cg3Name := "cg-svc-x-a", "cg-select-y-b", "cg-select-y-c"
	cgBuilder1 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference(namespaces["x"], "svc1")
	cgBuilder2 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).
		SetNamespaceSelector(map[string]string{"ns": namespaces["y"]}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
	cgBuilder3 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder3 = cgBuilder3.SetName(cg3Name).
		SetNamespaceSelector(map[string]string{"ns": namespaces["y"]}, nil).
		SetPodSelector(map[string]string{"pod": "c"}, nil)
	cgNestedName := "cg-nested"
	cgBuilderNested := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilderNested = cgBuilderNested.SetName(cgNestedName).SetChildGroups([]string{cg1Name, cg3Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-nested-cg").SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["z"]}}}).
		AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			false, nil, crdv1alpha1.RuleActionDrop, cgNestedName, "", nil)

	// Pods in Namespace z should not allow traffic from Pods backing svc1 (label pod=a) in Namespace x.
	// Note that in this testStep cg3 will not be created yet, so even though cg-nested selects cg1 and
	// cg3 as childGroups, only members of cg1 will be included as this time.
	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)

	testStep1 := &TestStep{
		"Port 80",
		reachability,
		// Note in this testcase the ClusterGroup is created after the ACNP
		[]metav1.Object{builder.Get(), svc1, cgBuilder1.Get(), cgBuilderNested.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	// Test update "cg-nested" to include "cg-select-y-b" as well.
	cgBuilderNested = cgBuilderNested.SetChildGroups([]string{cg1Name, cg2Name, cg3Name})
	// In addition to x/a, all traffic from y/b to Namespace z should also be denied.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["y"]+"/b"), namespaces["z"], Dropped)
	// New member in cg-svc-x-a should be reflected in cg-nested as well.
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod(namespaces["x"], svc1PodName),
				Labels: map[string]string{"pod": svc1PodName, "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod(namespaces["z"], "test-add-pod-ns-z"),
				Labels: map[string]string{"pod": "test-add-pod-ns-z"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep2 := &TestStep{
		"Port 80 updated",
		reachability2,
		[]metav1.Object{cgBuilder2.Get(), cgBuilderNested.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		cp,
	}

	// In this testStep cg3 is created. It's members should reflect in cg-nested
	// and as a result, all traffic from y/c to Namespace z should be denied as well.
	reachability3 := NewReachability(allPods, Connected)
	reachability3.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability3.ExpectEgressToNamespace(Pod(namespaces["y"]+"/b"), namespaces["z"], Dropped)
	reachability3.ExpectEgressToNamespace(Pod(namespaces["y"]+"/c"), namespaces["z"], Dropped)
	testStep3 := &TestStep{
		"Port 80 updated",
		reachability3,
		[]metav1.Object{cgBuilder3.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ACNP nested ClusterGroup create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPNestedIPBlockClusterGroupCreateAndUpdate(t *testing.T) {
	podXAIP, _ := podIPs[namespaces["x"]+"/a"]
	podXBIP, _ := podIPs[namespaces["x"]+"/b"]
	genCIDR := func(ip string) string {
		if strings.Contains(ip, ".") {
			return ip + "/32"
		}
		return ip + "/128"
	}
	cg1Name, cg2Name, cg3Name := "cg-x-a-ipb", "cg-x-b-ipb", "cg-select-x-c"
	cgParentName := "cg-parent"
	var ipBlockXA, ipBlockXB []crdv1alpha1.IPBlock
	for i := 0; i < len(podXAIP); i++ {
		ipBlockXA = append(ipBlockXA, crdv1alpha1.IPBlock{CIDR: genCIDR(podXAIP[i])})
		ipBlockXB = append(ipBlockXB, crdv1alpha1.IPBlock{CIDR: genCIDR(podXBIP[i])})
	}
	cgBuilder1 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetIPBlocks(ipBlockXA)
	cgBuilder2 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetIPBlocks(ipBlockXB)
	cgParent := &ClusterGroupV1Alpha3SpecBuilder{}
	cgParent = cgParent.SetName(cgParentName).SetChildGroups([]string{cg1Name, cg2Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-x-ips-ingress-for-ya").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "a"},
				NSSelector:  map[string]string{"ns": namespaces["y"]},
			},
		})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgParentName, "", nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability.Expect(Pod(namespaces["x"]+"/b"), Pod(namespaces["y"]+"/a"), Dropped)
	testStep := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{builder.Get(), cgBuilder1.Get(), cgBuilder2.Get(), cgParent.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	cgBuilder3 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder3 = cgBuilder3.SetName(cg3Name).
		SetNamespaceSelector(map[string]string{"ns": namespaces["x"]}, nil).
		SetPodSelector(map[string]string{"pod": "c"}, nil)
	updatedCGParent := &ClusterGroupV1Alpha3SpecBuilder{}
	updatedCGParent = updatedCGParent.SetName(cgParentName).SetChildGroups([]string{cg1Name, cg3Name})

	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod(namespaces["x"]+"/a"), Pod(namespaces["y"]+"/a"), Dropped)
	reachability2.Expect(Pod(namespaces["x"]+"/c"), Pod(namespaces["y"]+"/a"), Dropped)
	testStep2 := &TestStep{
		"Port 80, updated",
		reachability2,
		[]metav1.Object{cgBuilder3.Get(), updatedCGParent.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
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
		true, nil, crdv1alpha1.RuleActionAllow, "", "", nil)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil,
		false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability := NewReachability(allPods, Dropped)
	reachability.ExpectAllSelfNamespace(Connected)
	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{builder.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("test-acnp-ns-isolation-applied-to-per-rule").
		SetTier("baseline").
		SetPriority(1.0)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		true, []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}}, crdv1alpha1.RuleActionAllow, "", "", nil)
	builder2.AddEgress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil,
		false, []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}}, crdv1alpha1.RuleActionDrop, "", "", nil)

	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["y"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/a"), namespaces["z"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/b"), namespaces["y"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/b"), namespaces["z"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/c"), namespaces["y"], Dropped)
	reachability2.ExpectEgressToNamespace(Pod(namespaces["x"]+"/c"), namespaces["z"], Dropped)
	testStep2 := &TestStep{
		"Port 80",
		reachability2,
		[]metav1.Object{builder2.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
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
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		true, nil, crdv1alpha1.RuleActionPass, "", "", nil)
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{}, nil, nil,
		false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)
	// deny ingress traffic except from own namespace, which is delegated to Namespace owners (who can create K8s
	// NetworkPolicies to regulate intra-Namespace traffic)
	reachability := NewReachability(allPods, Dropped)
	reachability.ExpectAllSelfNamespace(Connected)
	testStep1 := &TestStep{
		"Namespace isolation, Port 80",
		reachability,
		[]metav1.Object{builder.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	// Add a K8s namespaced NetworkPolicy in ns x that isolates all Pods in that namespace.
	builder2 := &NetworkPolicySpecBuilder{}
	builder2 = builder2.SetName(namespaces["x"], "default-deny-in-namespace-x")
	builder2.SetTypeIngress()
	reachability2 := NewReachability(allPods, Dropped)
	reachability2.ExpectAllSelfNamespace(Connected)
	reachability2.ExpectSelfNamespace(namespaces["x"], Dropped)
	reachability2.ExpectSelf(allPods, Connected)
	testStep2 := &TestStep{
		"Namespace isolation with K8s NP, Port 80",
		reachability2,
		[]metav1.Object{builder2.Get()},
		[]int32{80},
		ProtocolTCP,
		0,
		nil,
	}

	testCase := []*TestCase{
		{"ACNP strict Namespace isolation for all namespaces", []*TestStep{testStep1, testStep2}},
	}
	executeTests(t, testCase)
}

func testFQDNPolicy(t *testing.T) {
	// The ipv6-only test env doesn't have IPv6 access to the web.
	skipIfNotIPv4Cluster(t)
	// It is convenient to have higher log verbosity for FQDNtests for troubleshooting failures.
	logLevel := log.GetLevel()
	log.SetLevel(log.TraceLevel)
	defer log.SetLevel(logLevel)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-reject-all-github").
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
	builder.AddFQDNRule("*github.com", ProtocolTCP, nil, nil, nil, "r1", nil, crdv1alpha1.RuleActionReject)
	builder.AddFQDNRule("wayfair.com", ProtocolTCP, nil, nil, nil, "r2", nil, crdv1alpha1.RuleActionDrop)

	testcases := []podToAddrTestStep{
		{
			Pod(namespaces["x"] + "/a"),
			"docs.github.com",
			80,
			Rejected,
		},
		{
			Pod(namespaces["x"] + "/b"),
			"api.github.com",
			80,
			Rejected,
		},
		{
			Pod(namespaces["y"] + "/a"),
			"wayfair.com",
			80,
			Dropped,
		},
		{
			Pod(namespaces["y"] + "/b"),
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
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
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
// name resolves to the ClusterIP for the Service. But when traffic arrives to the
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
		ipv4Svc := k8sUtils.BuildService("ipv4-svc", namespaces["x"], 80, 80, map[string]string{"pod": "a"}, nil)
		ipv4Svc.Spec.ClusterIP = "None"
		ipv4Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv4Protocol}
		services = append(services, ipv4Svc)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Svc := k8sUtils.BuildService("ipv6-svc", namespaces["x"], 80, 80, map[string]string{"pod": "b"}, nil)
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
		builder.AddFQDNRule(svcDNSName(service), ProtocolTCP, nil, nil, nil, fmt.Sprintf("r%d", idx*2), []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["y"]}, PodSelector: map[string]string{"pod": "b"}}}, crdv1alpha1.RuleActionReject)
		builder.AddFQDNRule(svcDNSName(service), ProtocolTCP, nil, nil, nil, fmt.Sprintf("r%d", idx*2+1), []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["z"]}, PodSelector: map[string]string{"pod": "c"}}}, crdv1alpha1.RuleActionDrop)
	}
	acnp := builder.Get()
	k8sUtils.CreateOrUpdateACNP(acnp)
	failOnError(waitForResourceReady(t, timeout, acnp), t)

	var testcases []podToAddrTestStep
	for _, service := range services {
		eachServiceCases := []podToAddrTestStep{
			{
				Pod(namespaces["y"] + "/b"),
				// To indicate the server name is a FQDN, end it with a dot. Then DNS resolver won't attempt to append
				// domain names (e.g. svc.cluster.local, cluster.local) when resolving it, making it get resolution
				// result more quickly.
				svcDNSName(service) + ".",
				80,
				Rejected,
			},
			{
				Pod(namespaces["z"] + "/c"),
				svcDNSName(service) + ".",
				80,
				Dropped,
			},
			{
				Pod(namespaces["x"] + "/c"),
				svcDNSName(service) + ".",
				80,
				Connected,
			},
		}
		testcases = append(testcases, eachServiceCases...)
	}

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	for _, service := range services {
		failOnError(k8sUtils.DeleteService(service.Namespace, service.Name), t)
	}
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testToServices(t *testing.T) {
	skipIfProxyDisabled(t)
	var services []*v1.Service
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4Svc := k8sUtils.BuildService("ipv4-svc", namespaces["x"], 81, 81, map[string]string{"pod": "a"}, nil)
		ipv4Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv4Protocol}
		services = append(services, ipv4Svc)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Svc := k8sUtils.BuildService("ipv6-svc", namespaces["x"], 80, 80, map[string]string{"pod": "b"}, nil)
		ipv6Svc.Spec.IPFamilies = []v1.IPFamily{v1.IPv6Protocol}
		services = append(services, ipv6Svc)
	}

	var svcRefs []crdv1alpha1.NamespacedName
	var builtSvcs []*v1.Service
	for _, service := range services {
		builtSvc, _ := k8sUtils.CreateOrUpdateService(service)
		failOnError(waitForResourceReady(t, timeout, service), t)
		svcRefs = append(svcRefs, crdv1alpha1.NamespacedName{
			Name:      service.Name,
			Namespace: service.Namespace,
		})
		builtSvcs = append(builtSvcs, builtSvc)
	}

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-to-services").
		SetTier("application").
		SetPriority(1.0)
	builder.AddToServicesRule(svcRefs, "svc", []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["y"]}}}, crdv1alpha1.RuleActionDrop)
	time.Sleep(networkPolicyDelay)

	acnp := builder.Get()
	k8sUtils.CreateOrUpdateACNP(acnp)
	failOnError(waitForResourceReady(t, timeout, acnp), t)

	var testcases []podToAddrTestStep
	for _, service := range builtSvcs {
		eachServiceCases := []podToAddrTestStep{
			{
				Pod(namespaces["y"] + "/b"),
				service.Spec.ClusterIP,
				service.Spec.Ports[0].Port,
				Dropped,
			},
			{
				Pod(namespaces["z"] + "/c"),
				service.Spec.ClusterIP,
				service.Spec.Ports[0].Port,
				Connected,
			},
		}
		testcases = append(testcases, eachServiceCases...)
	}

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s", tc.clientPod.PodName(), tc.destAddr)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
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
	k8sUtils.CreateOrUpdateServiceAccount(k8sUtils.BuildServiceAccount("test-sa", namespaces["x"], nil))
	defer k8sUtils.DeleteServiceAccount(namespaces["x"], "test-sa")

	serverName, serverIP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server", controlPlaneNodeName(), data.testNamespace, false)
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPodWithServiceAccount(t, data, data.createAgnhostPodWithSAOnNode, "client", controlPlaneNodeName(), namespaces["x"], false, "test-sa")
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPodWithServiceAccount(t, data, data.createAgnhostPodWithSAOnNode, "client", controlPlaneNodeName(), namespaces["x"], false, "default")
	defer cleanupFunc()

	sa := &crdv1alpha1.NamespacedName{
		Name:      "test-sa",
		Namespace: namespaces["x"],
	}

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-service-account").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": serverName}}})
	builder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", sa)

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
				Pod(namespaces["x"] + "/" + client0Name),
				serverIP.ipv4.String(),
				80,
				Dropped,
			},
			{
				Pod(namespaces["x"] + "/" + client1Name),
				serverIP.ipv4.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv4Testcases...)
	}

	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6Testcases := []podToAddrTestStep{
			{
				Pod(namespaces["x"] + "/" + client0Name),
				serverIP.ipv6.String(),
				80,
				Dropped,
			},
			{
				Pod(namespaces["x"] + "/" + client1Name),
				serverIP.ipv6.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv6Testcases...)
	}

	for _, tc := range testcases {
		log.Tracef("Probing: %s -> %s:%d", tc.clientPod.PodName(), tc.destAddr, tc.destPort)
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
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
		[]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}, PodSelector: map[string]string{"pod": "a"}}},
		crdv1alpha1.RuleActionDrop, true)

	var testcases []podToAddrTestStep
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4Testcases := []podToAddrTestStep{
			{
				Pod(namespaces["x"] + "/a"),
				controlPlaneNodeIPv4(),
				6443,
				Dropped,
			},
			{
				Pod(namespaces["x"] + "/b"),
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
				Pod(namespaces["x"] + "/a"),
				controlPlaneNodeIPv6(),
				6443,
				Dropped,
			},
			{
				Pod(namespaces["x"] + "/b"),
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
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "pod", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPNodeSelectorIngress(t *testing.T, data *TestData) {
	_, serverIP0, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server0", nodeName(1), namespaces["x"], false)
	defer cleanupFunc()

	_, serverIP1, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server1", nodeName(1), namespaces["y"], false)
	defer cleanupFunc()

	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, namespaces["z"], controlPlaneNodeName(), true))
	defer data.deletePodAndWait(defaultTimeout, clientName, namespaces["z"])
	_, err := data.podWaitForIPs(defaultTimeout, clientName, namespaces["z"])
	require.NoError(t, err)

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-drop-ingress-from-control-plane").
		SetPriority(1.0)
	nodeSelector := metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/hostname": controlPlaneNodeName()}}
	builder.AddNodeSelectorRule(&nodeSelector, ProtocolTCP, &p80, "ingress-control-plane-drop",
		[]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": namespaces["x"]}}},
		crdv1alpha1.RuleActionDrop, false)

	testcases := []podToAddrTestStep{}
	if clusterInfo.podV4NetworkCIDR != "" {
		ipv4TestCases := []podToAddrTestStep{
			{
				Pod(namespaces["z"] + "/" + clientName),
				serverIP0.ipv4.String(),
				80,
				Dropped,
			},
			{
				Pod(namespaces["z"] + "/" + clientName),
				serverIP1.ipv4.String(),
				80,
				Connected,
			},
		}
		testcases = append(testcases, ipv4TestCases...)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		ipv6TestCases := []podToAddrTestStep{
			{
				Pod(namespaces["z"] + "/" + clientName),
				serverIP0.ipv6.String(),
				80,
				Dropped,
			},
			{
				Pod(namespaces["z"] + "/" + clientName),
				serverIP1.ipv6.String(),
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
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolTCP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPICMPSupport(t *testing.T, data *TestData) {
	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNetshootPodOnNode, "client", nodeName(1), data.testNamespace, false)
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
	builder.AddEgress(ProtocolICMP, nil, nil, nil, &icmpType, &icmpCode, nil, nil, nil, map[string]string{"antrea-e2e": server0Name}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)
	builder.AddEgress(ProtocolICMP, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": server1Name}, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "", nil)

	testcases := []podToAddrTestStep{}
	if clusterInfo.podV4NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server0IP.ipv4.String(),
				-1,
				Rejected,
			},
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server1IP.ipv4.String(),
				-1,
				Dropped,
			},
		}...)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		testcases = append(testcases, []podToAddrTestStep{
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server0IP.ipv6.String(),
				-1,
				Rejected,
			},
			{
				Pod(fmt.Sprintf("%s/%s", data.testNamespace, clientName)),
				server1IP.ipv6.String(),
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
		connectivity, err := k8sUtils.ProbeAddr(tc.clientPod.Namespace(), "antrea-e2e", tc.clientPod.PodName(), tc.destAddr, tc.destPort, ProtocolICMP)
		if err != nil {
			t.Errorf("failure -- could not complete probe: %v", err)
		}
		if connectivity != tc.expectedConnectivity {
			t.Errorf("failure -- wrong results for probe: Source %s/%s --> Dest %s:%d connectivity: %v, expected: %v",
				tc.clientPod.Namespace(), tc.clientPod.PodName(), tc.destAddr, tc.destPort, connectivity, tc.expectedConnectivity)
		}
	}
	// cleanup test resources
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPNodePortServiceSupport(t *testing.T, data *TestData) {
	skipIfProxyAllDisabled(t, data)

	// Create a NodePort Service.
	ipProtocol := v1.IPv4Protocol
	var nodePort int32
	nodePortSvc, err := data.createNginxNodePortService("test-nodeport-svc", false, false, &ipProtocol)
	failOnError(err, t)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			nodePort = port.NodePort
			break
		}
	}

	backendPodName := "test-nodeport-backend-pod"
	require.NoError(t, data.createNginxPodOnNode(backendPodName, data.testNamespace, nodeName(0), false))
	if err := data.podWaitForRunning(defaultTimeout, backendPodName, data.testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", backendPodName)
	}
	defer deletePodWrapper(t, data, data.testNamespace, backendPodName)

	// Create another netns to fake an external network on the host network Pod.
	testNetns := "test-ns"
	cmd := fmt.Sprintf(`ip netns add %[1]s && \
ip link add dev %[1]s-a type veth peer name %[1]s-b && \
ip link set dev %[1]s-a netns %[1]s && \
ip addr add %[3]s/%[4]d dev %[1]s-b && \
ip link set dev %[1]s-b up && \
ip netns exec %[1]s ip addr add %[2]s/%[4]d dev %[1]s-a && \
ip netns exec %[1]s ip link set dev %[1]s-a up && \
ip netns exec %[1]s ip route replace default via %[3]s && \
sleep 3600
`, testNetns, "1.1.1.1", "1.1.1.254", 24)
	clientNames := []string{"client0", "client1"}
	for idx, clientName := range clientNames {
		if err := NewPodBuilder(clientName, data.testNamespace, agnhostImage).OnNode(nodeName(idx)).WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data); err != nil {
			t.Fatalf("Failed to create client Pod: %v", err)
		}
		defer data.deletePodAndWait(defaultTimeout, clientName, data.testNamespace)
		err = data.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
		failOnError(err, t)
	}

	cidr := "1.1.1.1/24"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-nodeport-svc").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				Service: &crdv1alpha1.NamespacedName{
					Name:      nodePortSvc.Name,
					Namespace: nodePortSvc.Namespace,
				},
			},
		})
	builder.AddIngress(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, &cidr, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "", nil)

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, acnp), t)
	for idx, clientName := range clientNames {
		log.Tracef("Probing: 1.1.1.1 -> %s:%d", nodeIP(idx), nodePort)
		// Connect to NodePort in the fake external network.
		cmd = fmt.Sprintf("for i in $(seq 1 3); do ip netns exec %s /agnhost connect %s:%d --timeout=1s --protocol=tcp; done;", testNetns, nodeIP(idx), nodePort)
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientName, agnhostContainerName, []string{"sh", "-c", cmd})
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
			t.Errorf("failure -- wrong results for probe: Source 1.1.1.1 --> Dest %s:%d connectivity: %v, expected: Rej", nodeIP(idx), nodePort, connectivity)
		}
	}
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func testACNPIGMPQueryAllow(t *testing.T, data *TestData) {
	testACNPIGMPQuery(t, data, "test-acnp-igmp-query-allow", "testMulticastIGMPQueryAllow", "224.3.4.13", crdv1alpha1.RuleActionAllow)
}

func testACNPIGMPQueryDrop(t *testing.T, data *TestData) {
	testACNPIGMPQuery(t, data, "test-acnp-igmp-query-drop", "testMulticastIGMPQueryDrop", "224.3.4.14", crdv1alpha1.RuleActionDrop)
}

func testACNPIGMPQuery(t *testing.T, data *TestData, acnpName, caseName, groupAddress string, action crdv1alpha1.RuleAction) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	testNamespace := data.testNamespace
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
	receiverNames, cleanupFuncs := setupReceivers(t, data, mc, mcjoinWaitTimeout, &wg)
	for _, cleanupFunc := range cleanupFuncs {
		defer cleanupFunc()
	}
	// Wait 2 seconds(-w 2) before sending multicast traffic.
	// It sends two multicast packets for every second(-f 500 means it takes 500 milliseconds for sending one packet).
	sendMulticastCommand := []string{"/bin/sh", "-c", fmt.Sprintf("mcjoin -f 500 -o -p %d -s -t 3 -w 2 -W %d %s", mc.port, mcjoinWaitTimeout, mc.group.String())}
	go func() {
		data.RunCommandFromPod(testNamespace, senderName, mcjoinContainerName, sendMulticastCommand)
	}()

	tcpdumpName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNetshootPodOnNode, "test-tcpdump-", nodeName(mc.receiverConfigs[0].nodeIdx), testNamespace, true)
	defer cleanupFunc()

	queryGroupAddress := "224.0.0.1"
	cmd, err := generatePacketCaptureCmd(t, data, 15, queryGroupAddress, nodeName(mc.receiverConfigs[0].nodeIdx), receiverNames[0])
	if err != nil {
		t.Fatalf("failed to call generateConnCheckCmd: %v", err)
	}

	// check if IGMP can be sent to Pod
	if err := wait.Poll(3*time.Second, defaultTimeout, func() (bool, error) {
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
	igmpType := crdv1alpha1.IGMPQuery
	builder.AddIngress(ProtocolIGMP, nil, nil, nil, nil, nil, &igmpType, &queryGroupAddress, nil, nil, nil,
		nil, nil, false, nil, action, "", "", nil)
	acnp := builder.Get()
	_, err = k8sUtils.CreateOrUpdateACNP(acnp)
	defer data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("failed to create acnp %v: %v", acnpName, err)
	}

	// check if IGMP is dropped or not based on rule action
	captured, err := checkPacketCaptureResult(t, data, tcpdumpName, cmd)
	if action == crdv1alpha1.RuleActionAllow {
		if !captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v ", *acnp, err)
		}
	} else {
		if captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v", *acnp, err)
		}
	}
}

func testACNPMulticastEgressAllow(t *testing.T, data *TestData) {
	testACNPMulticastEgress(t, data, "test-acnp-multicast-egress-allow", "testMulticastEgressAllowTraffic", "224.3.4.15", crdv1alpha1.RuleActionAllow)
}

func testACNPMulticastEgressDrop(t *testing.T, data *TestData) {
	testACNPMulticastEgress(t, data, "test-acnp-multicast-egress-drop", "testMulticastEgressDropTrafficFor", "224.3.4.16", crdv1alpha1.RuleActionDrop)
}

func testACNPMulticastEgress(t *testing.T, data *TestData, acnpName, caseName, groupAddress string, action crdv1alpha1.RuleAction) {
	mcjoinWaitTimeout := defaultTimeout / time.Second
	testNamespace := data.testNamespace
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
	receiverNames, cleanupFuncs := setupReceivers(t, data, mc, mcjoinWaitTimeout, &wg)
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
	tcpdumpName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNetshootPodOnNode, "test-tcpdump-", nodeName(mc.receiverConfigs[0].nodeIdx), testNamespace, true)
	defer cleanupFunc()
	cmd, err := generatePacketCaptureCmd(t, data, 5, mc.group.String(), nodeName(mc.receiverConfigs[0].nodeIdx), receiverNames[0])
	if err != nil {
		t.Fatalf("failed to call generateConnCheckCmd: %v", err)
	}

	if err := wait.Poll(3*time.Second, defaultTimeout, func() (bool, error) {
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
	builder.AddEgress(ProtocolUDP, nil, nil, nil, nil, nil, nil, nil, &cidr, nil, nil,
		nil, nil, false, nil, action, "", "", nil)
	acnp := builder.Get()
	_, err = k8sUtils.CreateOrUpdateACNP(acnp)
	if err != nil {
		t.Fatalf("failed to create acnp %v: %v", acnpName, err)
	}
	defer data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})

	captured, err := checkPacketCaptureResult(t, data, tcpdumpName, cmd)
	if action == crdv1alpha1.RuleActionAllow {
		if !captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v", *acnp, err)
		}
	} else if action == crdv1alpha1.RuleActionDrop {
		if captured || err != nil {
			t.Fatalf("failed to apply acnp policy: %+v, err: %v", *acnp, err)
		}
	}
}

func generatePacketCaptureCmd(t *testing.T, data *TestData, timeout int, hostIP, nodeName, podName string) (string, error) {
	agentPodName := getAntreaPodName(t, data, nodeName)
	cmds := []string{"antctl", "get", "podinterface", podName, "-n", data.testNamespace, "-o", "json"}
	stdout, stderr, err := runAntctl(agentPodName, cmds, data)
	var podInterfaceInfo []podinterface.Response
	if err := json.Unmarshal([]byte(stdout), &podInterfaceInfo); err != nil {
		return "", err
	}
	t.Logf("%s returned: stdout %v, stderr : %v", cmds, stdout, stderr)
	if err != nil {
		return "", err
	}

	cmd := fmt.Sprintf("timeout %ds tcpdump -q -i %s -c 1 -W 90 host %s", timeout, podInterfaceInfo[0].InterfaceName, hostIP)
	return cmd, nil
}

func checkPacketCaptureResult(t *testing.T, data *TestData, tcpdumpName, cmd string) (captured bool, err error) {
	stdout, stderr := "", ""
	stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, tcpdumpName, tcpdumpContainerName, []string{"/bin/sh", "-c", cmd})
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

			reachability := step.Reachability
			if reachability != nil {
				start := time.Now()
				k8sUtils.Validate(allPods, reachability, step.Ports, step.Protocol)
				step.Duration = time.Now().Sub(start)

				_, wrong, _ := step.Reachability.Summary()
				if wrong != 0 {
					t.Errorf("failure -- %d wrong results", wrong)
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
	connectivity, err := k8sUtils.Probe(p.SourcePod.Pod.Namespace(), p.SourcePod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.DestPod.Pod.PodName(), p.Port, protocol)
	if err != nil {
		t.Errorf("failure -- could not complete probe: %v", err)
	}
	if connectivity != p.ExpectConnectivity {
		t.Errorf("failure -- wrong results for custom probe: Source %s/%s --> Dest %s/%s connectivity: %v, expected: %v",
			p.SourcePod.Pod.Namespace(), p.SourcePod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.DestPod.Pod.PodName(), connectivity, p.ExpectConnectivity)
	}
}

// applyTestStepResources creates in the resources of a testStep in specified order.
// The ordering can be used to test different scenarios, like creating an ACNP before
// creating its referred ClusterGroup, and vice versa.
func applyTestStepResources(t *testing.T, step *TestStep) {
	for _, r := range step.TestResources {
		switch o := r.(type) {
		case *crdv1alpha1.ClusterNetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateACNP(o)
			failOnError(err, t)
		case *crdv1alpha1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateANP(o)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(o)
			failOnError(err, t)
		case *crdv1alpha3.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateV1Alpha3CG(o)
			failOnError(err, t)
		case *crdv1alpha2.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateV1Alpha2CG(o)
			failOnError(err, t)
		case *crdv1alpha3.Group:
			_, err := k8sUtils.CreateOrUpdateV1Alpha3Group(o)
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
	acnpsToDelete, anpsToDelete, npsToDelete := sets.String{}, sets.String{}, sets.String{}
	svcsToDelete, v1a2ClusterGroupsToDelete, v1a3ClusterGroupsToDelete, v1a3GroupsToDelete := sets.String{}, sets.String{}, sets.String{}, sets.String{}
	for _, step := range c.Steps {
		for _, r := range step.TestResources {
			switch o := r.(type) {
			case *crdv1alpha1.ClusterNetworkPolicy:
				acnpsToDelete.Insert(o.Name)
			case *crdv1alpha1.NetworkPolicy:
				anpsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *crdv1alpha3.ClusterGroup:
				v1a3ClusterGroupsToDelete.Insert(o.Name)
			case *crdv1alpha2.ClusterGroup:
				v1a2ClusterGroupsToDelete.Insert(o.Name)
			case *crdv1alpha3.Group:
				v1a3GroupsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}
	for acnp := range acnpsToDelete {
		failOnError(k8sUtils.DeleteACNP(acnp), t)
	}
	for anp := range anpsToDelete {
		namespace := strings.Split(anp, "/")[0]
		name := strings.Split(anp, "/")[1]
		failOnError(k8sUtils.DeleteANP(namespace, name), t)
	}
	for np := range npsToDelete {
		namespace := strings.Split(np, "/")[0]
		name := strings.Split(np, "/")[1]
		failOnError(k8sUtils.DeleteNetworkPolicy(namespace, name), t)
	}
	for cg := range v1a2ClusterGroupsToDelete {
		failOnError(k8sUtils.DeleteV1Alpha2CG(cg), t)
	}
	for cg := range v1a3ClusterGroupsToDelete {
		failOnError(k8sUtils.DeleteV1Alpha3CG(cg), t)
	}
	for grp := range v1a3GroupsToDelete {
		namespace := strings.Split(grp, "/")[0]
		name := strings.Split(grp, "/")[1]
		failOnError(k8sUtils.DeleteV1Alpha3Group(namespace, name), t)
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
	case *crdv1alpha1.ClusterNetworkPolicy:
		return k8sUtils.waitForACNPRealized(t, p.Name, timeout)
	case *crdv1alpha1.NetworkPolicy:
		return k8sUtils.waitForANPRealized(t, p.Namespace, p.Name, timeout)
	case *v1net.NetworkPolicy:
		time.Sleep(100 * time.Millisecond)
	case *v1.Service:
		// The minInterval of AntreaProxy's BoundedFrequencyRunner is 1s, which means a Service may be handled after 1s.
		time.Sleep(1 * time.Second)
	case *crdv1alpha1.Tier:
	case *crdv1alpha2.ClusterGroup:
	case *crdv1alpha3.ClusterGroup:
	case *crdv1alpha3.Group:
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
// AntreaPolicy related test cases so they can share setup, teardown.
func TestAntreaPolicy(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	initialize(t, data)

	t.Run("TestGroupValidateAntreaNativePolicies", func(t *testing.T) {
		t.Run("Case=ACNPNoPriority", func(t *testing.T) { testInvalidACNPNoPriority(t) })
		t.Run("Case=ANPNoPriority", func(t *testing.T) { testInvalidANPNoPriority(t) })
		t.Run("Case=ANPRuleNameNotUniqueDenied", func(t *testing.T) { testInvalidANPRuleNameNotUnique(t) })
		t.Run("Case=ANPTierDoesNotExistDenied", func(t *testing.T) { testInvalidANPTierDoesNotExist(t) })
		t.Run("Case=ANPPortRangePortUnsetDenied", func(t *testing.T) { testInvalidANPPortRangePortUnset(t) })
		t.Run("Case=ANPPortRangePortEndPortSmallDenied", func(t *testing.T) { testInvalidANPPortRangeEndPortSmall(t) })
		t.Run("Case=ANPIngressPeerGroupSetWithIPBlock", func(t *testing.T) { testInvalidANPIngressPeerGroupSetWithIPBlock(t) })
		t.Run("Case=ANPIngressPeerGroupSetWithPodSelector", func(t *testing.T) { testInvalidANPIngressPeerGroupSetWithPodSelector(t) })
		t.Run("Case=ACNPInvalidPodSelectorNsSelectorMatchExpressions", func(t *testing.T) { testInvalidACNPPodSelectorNsSelectorMatchExpressions(t, data) })
	})

	t.Run("TestGroupValidateTiers", func(t *testing.T) {
		t.Run("Case=TierOverlapPriorityDenied", func(t *testing.T) { testInvalidTierPriorityOverlap(t) })
		t.Run("Case=TierOverlapReservedTierPriorityDenied", func(t *testing.T) { testInvalidTierReservedPriority(t) })
		t.Run("Case=TierPriorityUpdateDenied", func(t *testing.T) { testInvalidTierPriorityUpdate(t) })
		t.Run("Case=TierACNPReferencedDeleteDenied", func(t *testing.T) { testInvalidTierACNPRefDelete(t) })
		t.Run("Case=TierANPRefDeleteDenied", func(t *testing.T) { testInvalidTierANPRefDelete(t) })
		t.Run("Case=TierReservedDeleteDenied", func(t *testing.T) { testInvalidTierReservedDelete(t) })
	})

	t.Run("TestGroupMutateAntreaNativePolicies", func(t *testing.T) {
		t.Run("Case=ACNPNoTierSetDefaultTier", func(t *testing.T) { testMutateACNPNoTier(t) })
		t.Run("Case=ANPNoTierSetDefaultTier", func(t *testing.T) { testMutateANPNoTier(t) })
		t.Run("Case=ANPNoRuleNameSetRuleName", func(t *testing.T) { testMutateANPNoRuleName(t) })
		t.Run("Case=ACNPNoRuleNameSetRuleName", func(t *testing.T) { testMutateACNPNoRuleName(t) })
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
		t.Run("Case=ACNPRejectEgress", func(t *testing.T) { testACNPRejectEgress(t) })
		t.Run("Case=ACNPRejectIngress", func(t *testing.T) { testACNPRejectIngress(t, ProtocolTCP) })
		t.Run("Case=ACNPRejectIngressUDP", func(t *testing.T) { testACNPRejectIngress(t, ProtocolUDP) })
		t.Run("Case=RejectServiceTraffic", func(t *testing.T) { testRejectServiceTraffic(t, data) })
		t.Run("Case=RejectNoInfiniteLoop", func(t *testing.T) { testRejectNoInfiniteLoop(t, data) })
		t.Run("Case=ACNPNoEffectOnOtherProtocols", func(t *testing.T) { testACNPNoEffectOnOtherProtocols(t) })
		t.Run("Case=ACNPBaselinePolicy", func(t *testing.T) { testBaselineNamespaceIsolation(t) })
		t.Run("Case=ACNPPriorityOverride", func(t *testing.T) { testACNPPriorityOverride(t) })
		t.Run("Case=ACNPTierOverride", func(t *testing.T) { testACNPTierOverride(t) })
		t.Run("Case=ACNPCustomTiers", func(t *testing.T) { testACNPCustomTiers(t) })
		t.Run("Case=ACNPPriorityConflictingRule", func(t *testing.T) { testACNPPriorityConflictingRule(t) })
		t.Run("Case=ACNPRulePriority", func(t *testing.T) { testACNPRulePriority(t) })
		t.Run("Case=ANPPortRange", func(t *testing.T) { testANPPortRange(t) })
		t.Run("Case=ANPBasic", func(t *testing.T) { testANPBasic(t) })
		t.Run("Case=testANPMultipleAppliedToSingleRule", func(t *testing.T) { testANPMultipleAppliedTo(t, data, true) })
		t.Run("Case=testANPMultipleAppliedToMultipleRules", func(t *testing.T) { testANPMultipleAppliedTo(t, data, false) })
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
		t.Run("Case=ANPGroupEgressRulePodsAToGrpWithPodsC", func(t *testing.T) { testANPEgressRulePodsAToGrpWithPodsC(t) })
		t.Run("Case=ANPIngressRuleDenyGrpWithXCtoXA", func(t *testing.T) { testANPIngressRuleDenyGrpWithXCtoXA(t) })
		t.Run("Case=ANPGroupUpdate", func(t *testing.T) { testANPGroupUpdate(t) })
		t.Run("Case=ANPGroupAppliedToDenyXBToGrpWithXA", func(t *testing.T) { testANPAppliedToDenyXBtoGrpWithXA(t) })
		t.Run("Case=ANPGroupAppliedToRuleGrpWithPodsAToPodsC", func(t *testing.T) { testANPAppliedToRuleGrpWithPodsAToPodsC(t) })
		t.Run("Case=ANPGroupUpdateAppliedTo", func(t *testing.T) { testANPGroupUpdateAppliedTo(t) })
		t.Run("Case=ANPGroupAppliedToPodAdd", func(t *testing.T) { testANPGroupAppliedToPodAdd(t, data) })
		t.Run("Case=ANPGroupServiceRefPodAdd", func(t *testing.T) { testANPGroupServiceRefPodAdd(t, data) })
		t.Run("Case=ANPGroupServiceRefDelete", func(t *testing.T) { testANPGroupServiceRefDelete(t) })
		t.Run("Case=ANPGroupServiceRef", func(t *testing.T) { testANPGroupServiceRefCreateAndUpdate(t) })
		t.Run("Case=ANPGroupRefRuleIPBlocks", func(t *testing.T) { testANPGroupRefRuleIPBlocks(t) })
		t.Run("Case=ANPNestedGroup", func(t *testing.T) { testANPNestedGroupCreateAndUpdate(t, data) })
		t.Run("Case=ACNPFQDNPolicy", func(t *testing.T) { testFQDNPolicy(t) })
		t.Run("Case=FQDNPolicyInCluster", func(t *testing.T) { testFQDNPolicyInClusterService(t) })
		t.Run("Case=ACNPToServices", func(t *testing.T) { testToServices(t) })
		t.Run("Case=ACNPServiceAccountSelector", func(t *testing.T) { testServiceAccountSelector(t, data) })
		t.Run("Case=ACNPNodeSelectorEgress", func(t *testing.T) { testACNPNodeSelectorEgress(t) })
		t.Run("Case=ACNPNodeSelectorIngress", func(t *testing.T) { testACNPNodeSelectorIngress(t, data) })
		t.Run("Case=ACNPICMPSupport", func(t *testing.T) { testACNPICMPSupport(t, data) })
		t.Run("Case=ACNPNodePortServiceSupport", func(t *testing.T) { testACNPNodePortServiceSupport(t, data) })
	})
	// print results for reachability tests
	printResults()

	t.Run("TestGroupAuditLogging", func(t *testing.T) {
		t.Run("Case=AuditLoggingBasic", func(t *testing.T) { testAuditLoggingBasic(t, data) })
		t.Run("Case=AuditLoggingEnableNP", func(t *testing.T) { testAuditLoggingEnableNP(t, data) })
	})

	t.Run("TestMulticastNP", func(t *testing.T) {
		skipIfMulticastDisabled(t)
		t.Run("Case=MulticastNPIGMPQueryAllow", func(t *testing.T) { testACNPIGMPQueryAllow(t, data) })
		t.Run("Case=MulticastNPIGMPQueryDrop", func(t *testing.T) { testACNPIGMPQueryDrop(t, data) })
		t.Run("Case=MulticastNPPolicyEgressAllow", func(t *testing.T) { testACNPMulticastEgressAllow(t, data) })
		t.Run("Case=MulticastNPPolicyEgressDrop", func(t *testing.T) { testACNPMulticastEgressDrop(t, data) })
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

	anpBuilder := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(data.testNamespace, "anp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	anpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, nil, crdv1alpha1.RuleActionAllow, "", "")
	anp := anpBuilder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	_, err = data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Delete(context.TODO(), anp.Name, metav1.DeleteOptions{})

	acnpBuilder := &ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("acnp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	acnpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "", nil)
	acnp := acnpBuilder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	_, err = data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Create(context.TODO(), acnp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})

	expectedStatus := crdv1alpha1.NetworkPolicyStatus{
		Phase:                crdv1alpha1.NetworkPolicyRealized,
		ObservedGeneration:   1,
		CurrentNodesRealized: 2,
		DesiredNodesRealized: 2,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	}
	checkANPStatus(t, data, anp, expectedStatus)
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

	anpBuilder := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(data.testNamespace, "anp-applied-to-per-rule").
		SetPriority(1.0)
	anpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, []ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": server0Name}}}, crdv1alpha1.RuleActionAllow, "", "")
	anpBuilder.AddIngress(ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": namespaces["x"]}, nil,
		nil, nil, nil, []ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": server1Name}}}, crdv1alpha1.RuleActionAllow, "", "")
	anp := anpBuilder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	anp, err = data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Delete(context.TODO(), anp.Name, metav1.DeleteOptions{})

	anp = checkANPStatus(t, data, anp, crdv1alpha1.NetworkPolicyStatus{
		Phase:                crdv1alpha1.NetworkPolicyRealized,
		ObservedGeneration:   1,
		CurrentNodesRealized: 2,
		DesiredNodesRealized: 2,
		Conditions:           networkpolicy.GenerateNetworkPolicyCondition(nil),
	})

	// Remove the second ingress rule.
	anp.Spec.Ingress = anp.Spec.Ingress[0:1]
	_, err = data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Update(context.TODO(), anp, metav1.UpdateOptions{})
	assert.NoError(t, err)
	checkANPStatus(t, data, anp, crdv1alpha1.NetworkPolicyStatus{
		Phase:                crdv1alpha1.NetworkPolicyRealized,
		ObservedGeneration:   2,
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

	initialize(t, data)

	testNamespace := namespaces["x"]
	// Build a Group with namespaceSelector selecting namespaces outside testNamespace.
	grpName := "grp-with-ns-selector"
	grpBuilder := &GroupSpecBuilder{}
	grpBuilder = grpBuilder.SetName(grpName).SetNamespace(testNamespace).
		SetPodSelector(map[string]string{"pod": "b"}, nil).
		SetNamespaceSelector(map[string]string{"ns": namespaces["y"]}, nil)
	grp, err := k8sUtils.CreateOrUpdateV1Alpha3Group(grpBuilder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, grp), t)
	// Build a Group with the unsupported Group as child Group.
	grpNestedName := "grp-nested"
	grpBuilderNested := &GroupSpecBuilder{}
	grpBuilderNested = grpBuilderNested.SetName(grpNestedName).SetNamespace(testNamespace).SetChildGroups([]string{grpName})
	grp, err = k8sUtils.CreateOrUpdateV1Alpha3Group(grpBuilderNested.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, timeout, grp), t)

	anpBuilder := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(testNamespace, "anp-applied-to-unsupported-group").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{Group: grpName}})
	anp, err := k8sUtils.CreateOrUpdateANP(anpBuilder.Get())
	failOnError(err, t)
	expectedStatus := crdv1alpha1.NetworkPolicyStatus{
		Phase:                crdv1alpha1.NetworkPolicyPending,
		ObservedGeneration:   1,
		CurrentNodesRealized: 0,
		DesiredNodesRealized: 0,
		Conditions: []crdv1alpha1.NetworkPolicyCondition{
			{
				Type:               crdv1alpha1.NetworkPolicyConditionRealizable,
				Status:             metav1.ConditionFalse,
				LastTransitionTime: metav1.Now(),
				Reason:             "NetworkPolicyAppliedToUnsupportedGroup",
				Message:            fmt.Sprintf("Group %s/%s with Pods in other Namespaces can not be used as AppliedTo", testNamespace, grpName),
			},
		},
	}
	checkANPStatus(t, data, anp, expectedStatus)

	anpBuilder2 := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder2 = anpBuilder2.SetName(testNamespace, "anp-applied-to-unsupported-child-group").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{Group: grpNestedName}})
	anp2, err := k8sUtils.CreateOrUpdateANP(anpBuilder2.Get())
	failOnError(err, t)
	expectedStatus.Conditions[0].Message = fmt.Sprintf("Group %s/%s with Pods in other Namespaces can not be used as AppliedTo", testNamespace, grpNestedName)
	checkANPStatus(t, data, anp2, expectedStatus)

	failOnError(k8sUtils.DeleteANP(anp.Namespace, anp.Name), t)
	failOnError(k8sUtils.DeleteANP(anp2.Namespace, anp2.Name), t)
	failOnError(k8sUtils.DeleteV1Alpha3Group(testNamespace, grpName), t)
	failOnError(k8sUtils.DeleteV1Alpha3Group(testNamespace, grpNestedName), t)
	k8sUtils.Cleanup(namespaces)
}

func checkANPStatus(t *testing.T, data *TestData, anp *crdv1alpha1.NetworkPolicy, expectedStatus crdv1alpha1.NetworkPolicyStatus) *crdv1alpha1.NetworkPolicy {
	err := wait.Poll(100*time.Millisecond, policyRealizedTimeout, func() (bool, error) {
		var err error
		anp, err = data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return networkpolicy.NetworkPolicyStatusEqual(anp.Status, expectedStatus), nil
	})
	assert.NoError(t, err, "Antrea NetworkPolicy failed to reach expected status")
	return anp
}

func checkACNPStatus(t *testing.T, data *TestData, acnp *crdv1alpha1.ClusterNetworkPolicy, expectedStatus crdv1alpha1.NetworkPolicyStatus) *crdv1alpha1.ClusterNetworkPolicy {
	err := wait.Poll(100*time.Millisecond, policyRealizedTimeout, func() (bool, error) {
		var err error
		acnp, err = data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), acnp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return networkpolicy.NetworkPolicyStatusEqual(acnp.Status, expectedStatus), nil
	})
	assert.NoError(t, err, "Antrea ClusterNetworkPolicy failed to reach expected status")
	return acnp
}

// waitForANPRealized waits until an ANP is realized and returns, or times out. A policy is
// considered realized when its Status has been updated so that the ObservedGeneration matches the
// resource's Generation and the Phase is set to Realized.
func (data *TestData) waitForANPRealized(t *testing.T, namespace string, name string, timeout time.Duration) error {
	t.Logf("Waiting for ANP '%s/%s' to be realized", namespace, name)
	if err := wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		anp, err := data.crdClient.CrdV1alpha1().NetworkPolicies(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status.ObservedGeneration == anp.Generation && anp.Status.Phase == crdv1alpha1.NetworkPolicyRealized, nil
	}); err != nil {
		return fmt.Errorf("error when waiting for ANP '%s/%s' to be realized: %v", namespace, name, err)
	}
	return nil
}

// waitForACNPRealized waits until an ACNP is realized and returns, or times out. A policy is
// considered realized when its Status has been updated so that the ObservedGeneration matches the
// resource's Generation and the Phase is set to Realized.
func (data *TestData) waitForACNPRealized(t *testing.T, name string, timeout time.Duration) error {
	t.Logf("Waiting for ACNP '%s' to be realized", name)
	if err := wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		acnp, err := data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return acnp.Status.ObservedGeneration == acnp.Generation && acnp.Status.Phase == crdv1alpha1.NetworkPolicyRealized, nil
	}); err != nil {
		return fmt.Errorf("error when waiting for ACNP '%s' to be realized: %v", name, err)
	}
	return nil
}

// testANPNetworkPolicyStatsWithDropAction tests antreanetworkpolicystats can correctly collect dropped packets stats from ANP if
// networkpolicystats feature is enabled
func testANPNetworkPolicyStatsWithDropAction(t *testing.T, data *TestData) {
	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", data.testNamespace, false)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", data.testNamespace, false)
	defer cleanupFunc()
	var err error
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	p10 := float64(10)
	intstr80 := intstr.FromInt(80)
	intstr443 := intstr.FromInt(443)
	dropAction := crdv1alpha1.RuleActionDrop
	allowAction := crdv1alpha1.RuleActionAllow
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientName}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": serverName}}
	protocol, _ := AntreaPolicyProtocolToK8sProtocol(ProtocolUDP)

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv4.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv6.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
	}
	var anp = &crdv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: "np1", Labels: map[string]string{"antrea-e2e": "np1"}},
		Spec: crdv1alpha1.NetworkPolicySpec{
			AppliedTo: []crdv1alpha1.AppliedTo{
				{PodSelector: &selectorC},
			},
			Priority: p10,
			Ingress: []crdv1alpha1.Rule{
				{
					Ports: []crdv1alpha1.NetworkPolicyPort{
						{
							Port:     &intstr80,
							Protocol: &protocol,
						},
					},
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &dropAction,
				},
				{
					Ports: []crdv1alpha1.NetworkPolicyPort{
						{
							Port:     &intstr443,
							Protocol: &protocol,
						},
					},
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &allowAction,
				},
			},
			Egress: []crdv1alpha1.Rule{},
		},
	}

	if _, err = k8sUtils.CreateOrUpdateANP(anp); err != nil {
		failOnError(fmt.Errorf("create ANP failed for ANP %s: %v", anp.Name, err), t)
	}

	// Wait for the policy to be realized before attempting connections
	failOnError(data.waitForANPRealized(t, anp.Namespace, anp.Name, policyRealizedTimeout), t)

	sessionsPerAddressFamily := 10
	var wg sync.WaitGroup
	for i := 0; i < sessionsPerAddressFamily; i++ {
		wg.Add(1)
		go func() {
			if clusterInfo.podV4NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.ipv4.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 443", serverIPs.ipv4.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd2)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.ipv6.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 443", serverIPs.ipv6.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd2)
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

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
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

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", data.testNamespace, false)
	defer cleanupFunc()
	var err error
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	p10 := float64(10)
	intstr800 := intstr.FromInt(800)
	intstr4430 := intstr.FromInt(4430)
	dropAction := crdv1alpha1.RuleActionDrop
	allowAction := crdv1alpha1.RuleActionAllow
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientName}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": serverName}}
	protocol, _ := AntreaPolicyProtocolToK8sProtocol(ProtocolUDP)

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv4.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv6.String())}
		data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
	}
	var acnp = &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: "cnp1", Labels: map[string]string{"antrea-e2e": "cnp1"}},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.AppliedTo{
				{PodSelector: &selectorC},
			},
			Priority: p10,
			Ingress: []crdv1alpha1.Rule{
				{
					Ports: []crdv1alpha1.NetworkPolicyPort{
						{
							Port:     &intstr800,
							Protocol: &protocol,
						},
					},
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &allowAction,
				},
				{
					Ports: []crdv1alpha1.NetworkPolicyPort{
						{
							Port:     &intstr4430,
							Protocol: &protocol,
						},
					},
					From: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &dropAction,
				},
			},
			Egress: []crdv1alpha1.Rule{},
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
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 800", serverIPs.ipv4.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 4430", serverIPs.ipv4.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd2)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 800", serverIPs.ipv6.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 4430", serverIPs.ipv6.String())}
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd)
				data.RunCommandFromPod(data.testNamespace, clientName, busyboxContainerName, cmd2)
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

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
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
