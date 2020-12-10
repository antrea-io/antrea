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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/features"
	. "github.com/vmware-tanzu/antrea/test/e2e/utils"
)

// common for all tests.
var (
	allPods          []Pod
	k8sUtils         *KubernetesUtils
	allTestList      []*TestCase
	pods, namespaces []string
	podIPs           map[string]string
	p80, p81         int
)

const (
	// provide enough time for policies to be enforced & deleted by the CNI plugin.
	networkPolicyDelay = 2 * time.Second
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

// TestCase is a collection of TestSteps to be tested against.
type TestCase struct {
	Name  string
	Steps []*TestStep
}

// TestStep is a single unit of testing spec. It includes the CNP specs that need to be
// applied for this test, the port to test traffic on and the expected Reachability matrix.
type TestStep struct {
	Name         string
	Reachability *Reachability
	Policies     []metav1.Object
	Port         int
	Duration     time.Duration
}

func initialize(t *testing.T, data *TestData) {
	p80 = 80
	p81 = 81
	pods = []string{"a", "b", "c"}
	namespaces = []string{"x", "y", "z"}

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
		}
	}
	skipIfAntreaPolicyDisabled(t, data)
	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, pods)
	failOnError(err, t)
	podIPs = *ips
}

func skipIfAntreaPolicyDisabled(tb testing.TB, data *TestData) {
	if featureGate, err := data.GetControllerFeatures(antreaNamespace); err != nil {
		tb.Fatalf("Cannot determine if CNP enabled: %v", err)
	} else if !featureGate.Enabled(features.AntreaPolicy) {
		tb.Skipf("Skipping test as it required CNP to be enabled")
	}
}

func applyDefaultDenyToAllNamespaces(k8s *KubernetesUtils, namespaces []string) error {
	if err := k8s.CleanNetworkPolicies(namespaces); err != nil {
		return err
	}
	for _, ns := range namespaces {
		builder := &NetworkPolicySpecBuilder{}
		builder = builder.SetName(ns, "default-deny-namespace")
		builder.SetTypeIngress()
		if _, err := k8s.CreateOrUpdateNetworkPolicy(ns, builder.Get()); err != nil {
			return err
		}
	}
	time.Sleep(networkPolicyDelay)
	r := NewReachability(allPods, false)
	k8s.Validate(allPods, r, p80)
	_, wrong, _ := r.Summary()
	if wrong != 0 {
		return fmt.Errorf("error when creating default deny k8s NetworkPolicies")
	}
	return nil
}

func cleanupDefaultDenyNPs(k8s *KubernetesUtils, namespaces []string) error {
	if err := k8s.CleanNetworkPolicies(namespaces); err != nil {
		return err
	}
	time.Sleep(networkPolicyDelay * 2)
	r := NewReachability(allPods, true)
	k8s.Validate(allPods, r, p80)
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
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil).
		SetPriority(10.0)
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	acnp, err := k8sUtils.CreateOrUpdateCNP(acnp)
	if err != nil {
		failOnError(fmt.Errorf("ACNP create failed %v", err), t)
	}
	if acnp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanCNPs(), t)
}

func testMutateANPNoTier(t *testing.T) {
	invalidNpErr := fmt.Errorf("ANP tier not mutated to default tier")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-tier").
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil).
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
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil).
		SetPriority(10.0).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, secv1alpha1.RuleActionAllow, "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	acnp, err := k8sUtils.CreateOrUpdateCNP(acnp)
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
	failOnError(k8sUtils.CleanCNPs(), t)
}

func testMutateANPNoRuleName(t *testing.T) {
	mutateErr := fmt.Errorf("ANP Rule name not mutated automatically")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-rule-name").
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil).
		SetPriority(10.0).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, secv1alpha1.RuleActionAllow, "")
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
	builder = builder.SetName("acnp-no-priority").SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil)
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateCNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPRuleNameNotUnique(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without unique rule names accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-rule-name-not-unique").SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, secv1alpha1.RuleActionAllow, "not-unique").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, secv1alpha1.RuleActionAllow, "not-unique")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateCNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPTierDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without existing Tier accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-tier-not-exist").SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil).
		SetTier("i-dont-exist")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateCNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without a priority accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-priority").SetAppliedToGroup(map[string]string{"pod": "a"}, nil)
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
	builder = builder.SetName("x", "anp-rule-name-not-unique").SetAppliedToGroup(map[string]string{"pod": "a"}, nil).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, secv1alpha1.RuleActionAllow, "not-unique").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, secv1alpha1.RuleActionAllow, "not-unique")
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
	builder = builder.SetName("x", "anp-tier-not-exist").SetAppliedToGroup(map[string]string{"pod": "a"}, nil).
		SetTier("i-dont-exist")
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
	invalidErr := fmt.Errorf("Tier priority updated")
	oldTier, err := k8sUtils.CreateNewTier("prio-updated-tier", 21)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier prio-updated-tier: %v", err), t)
	}
	// Update this tier with new priority
	newTier := secv1alpha1.Tier{
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
	invalidErr := fmt.Errorf("Tiers created with overlapping priorities")
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
	invalidErr := fmt.Errorf("Tier created with reserved priority")
	if _, err := k8sUtils.CreateNewTier("tier-reserved-prio", 251); err == nil {
		// Above creation of Tier must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidTierACNPRefDelete(t *testing.T) {
	invalidErr := fmt.Errorf("Tier deleted with referenced ACNPs")
	tr, err := k8sUtils.CreateNewTier("tier-acnp", 10)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-acnp: %v", err), t)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-for-tier").
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil).
		SetTier("tier-acnp").
		SetPriority(13.0)
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err = k8sUtils.CreateOrUpdateCNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP failed for ACNP %s: %v", acnp.Name, err), t)
	}
	// Deleting this Tier must fail as it has referenced ACNP
	if err = k8sUtils.DeleteTier(tr.Name); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.CleanCNPs(), t)
	failOnError(k8sUtils.DeleteTier(tr.Name), t)
}

func testInvalidTierANPRefDelete(t *testing.T) {
	invalidErr := fmt.Errorf("Tier deleted with referenced ANPs")
	tr, err := k8sUtils.CreateNewTier("tier-anp", 10)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-anp: %v", err), t)
	}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-for-tier").
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil).
		SetTier("tier-anp").
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

// testCNPAllowXBtoA tests traffic from X/B to pods with label A, after applying the default deny
// k8s NetworkPolicies in all namespaces and CNP to allow X/B to A.
func testCNPAllowXBtoA(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-allow-xb-to-a").
		SetPriority(1.0).
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	reachability := NewReachability(allPods, false)
	reachability.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability.Expect(Pod("x/b"), Pod("y/a"), true)
	reachability.Expect(Pod("x/b"), Pod("z/a"), true)
	reachability.ExpectSelf(allPods, true)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Allow X/B to A", testStep},
	}
	executeTests(t, testCase)
}

// testCNPAllowXBtoYA tests traffic from X/B to Y/A on named port 81, after applying the default deny
// k8s NetworkPolicies in all namespaces and CNP to allow X/B to Y/A.
func testCNPAllowXBtoYA(t *testing.T) {
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-allow-xb-to-ya").
		SetPriority(2.0).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "y"}, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, nil, &port81Name, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	reachability := NewReachability(allPods, false)
	reachability.Expect(Pod("x/b"), Pod("y/a"), true)
	reachability.ExpectSelf(allPods, true)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{builder.Get()},
			81,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Allow X/B to Y/A", testStep},
	}
	executeTests(t, testCase)
}

// testCNPPriorityOverrideDefaultDeny tests priority override in CNP. It applies a higher priority CNP to drop
// traffic from namespace Z to X/A, and in the meantime applies a lower priority CNP to allow traffic from Z to X.
// It is tested with default deny k8s NetworkPolicies in all namespaces.
func testCNPPriorityOverrideDefaultDeny(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("cnp-priority2").
		SetPriority(2).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp-priority1").
		SetPriority(1).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	// Ingress from ns:z to x/a will be dropped since cnp-priority1 has higher precedence.
	reachabilityBothCNP := NewReachability(allPods, false)
	reachabilityBothCNP.Expect(Pod("z/a"), Pod("x/b"), true)
	reachabilityBothCNP.Expect(Pod("z/a"), Pod("x/c"), true)
	reachabilityBothCNP.Expect(Pod("z/b"), Pod("x/b"), true)
	reachabilityBothCNP.Expect(Pod("z/b"), Pod("x/c"), true)
	reachabilityBothCNP.Expect(Pod("z/c"), Pod("x/b"), true)
	reachabilityBothCNP.Expect(Pod("z/c"), Pod("x/c"), true)
	reachabilityBothCNP.ExpectSelf(allPods, true)

	testStep := []*TestStep{
		{
			"Both CNP",
			reachabilityBothCNP,
			[]metav1.Object{builder1.Get(), builder2.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP PriorityOverride Default Deny", testStep},
	}
	executeTests(t, testCase)
}

// testCNPAllowNoDefaultIsolation tests that no default isolation rules are created for Policies.
func testCNPAllowNoDefaultIsolation(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-allow-x-ingress-y-egress-z").
		SetPriority(1.1).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"ns": "y"},
		nil, nil, secv1alpha1.RuleActionAllow, "")
	builder.AddEgress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	reachability := NewReachability(allPods, true)
	testStep := []*TestStep{
		{
			"Port 81",
			reachability,
			[]metav1.Object{builder.Get()},
			81,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Allow No Default Isolation", testStep},
	}
	executeTests(t, testCase)
}

// testCNPDropEgress tests that a CNP is able to drop egress traffic from pods labelled A to namespace Z.
func testCNPDropEgress(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-deny-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil, nil, nil)
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	reachability := NewReachability(allPods, true)
	reachability.Expect(Pod("x/a"), Pod("z/a"), false)
	reachability.Expect(Pod("x/a"), Pod("z/b"), false)
	reachability.Expect(Pod("x/a"), Pod("z/c"), false)
	reachability.Expect(Pod("y/a"), Pod("z/a"), false)
	reachability.Expect(Pod("y/a"), Pod("z/b"), false)
	reachability.Expect(Pod("y/a"), Pod("z/c"), false)
	reachability.Expect(Pod("z/a"), Pod("z/b"), false)
	reachability.Expect(Pod("z/a"), Pod("z/c"), false)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Drop Egress From All Pod:a to NS:z", testStep},
	}
	executeTests(t, testCase)
}

// testBaselineNamespaceIsolation tests that a CNP in the baseline Tier is able to enforce default namespace isolation,
// which can be later overridden by developer K8s NetworkPolicies.
func testBaselineNamespaceIsolation(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	nsExpOtherThanX := metav1.LabelSelectorRequirement{
		Key:      "ns",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"x"},
	}
	builder = builder.SetName("cnp-baseline-isolate-ns-x").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil,
		nil, &[]metav1.LabelSelectorRequirement{nsExpOtherThanX}, secv1alpha1.RuleActionDrop, "")

	// create a K8s NetworkPolicy for Pods in namespace x to allow ingress traffic from Pods in the same namespace,
	// as well as from the y/a Pod. It should open up ingress from y/a since it's evaluated before the baseline tier.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName("x", "allow-ns-x-and-y-a").
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			nil, map[string]string{"ns": "x"}, nil, nil).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "a"}, map[string]string{"ns": "y"}, nil, nil)

	reachability := NewReachability(allPods, true)
	reachability.Expect(Pod("y/b"), Pod("x/a"), false)
	reachability.Expect(Pod("y/c"), Pod("x/a"), false)
	reachability.Expect(Pod("z/a"), Pod("x/a"), false)
	reachability.Expect(Pod("z/b"), Pod("x/a"), false)
	reachability.Expect(Pod("z/c"), Pod("x/a"), false)
	reachability.Expect(Pod("y/b"), Pod("x/b"), false)
	reachability.Expect(Pod("y/c"), Pod("x/b"), false)
	reachability.Expect(Pod("z/a"), Pod("x/b"), false)
	reachability.Expect(Pod("z/b"), Pod("x/b"), false)
	reachability.Expect(Pod("z/c"), Pod("x/b"), false)
	reachability.Expect(Pod("y/b"), Pod("x/c"), false)
	reachability.Expect(Pod("y/c"), Pod("x/c"), false)
	reachability.Expect(Pod("z/a"), Pod("x/c"), false)
	reachability.Expect(Pod("z/b"), Pod("x/c"), false)
	reachability.Expect(Pod("z/c"), Pod("x/c"), false)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), k8sNPBuilder.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP baseline tier namespace isolation", testStep},
	}
	executeTests(t, testCase)
	// Cleanup the K8s NetworkPolicy created for this test.
	failOnError(k8sUtils.CleanNetworkPolicies([]string{"x"}), t)
	time.Sleep(networkPolicyDelay)
}

// testCNPPriorityOverride tests priority overriding in three Policies. Those three Policies are applied in a specific order to
// test priority reassignment, and each controls a smaller set of traffic patterns as priority increases.
func testCNPPriorityOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("cnp-priority1").
		SetPriority(1.001).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	podZBIP, _ := podIPs["z/b"]
	cidr := podZBIP + "/32"
	// Highest priority. Drops traffic from z/b to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, &cidr, nil, nil,
		nil, nil, secv1alpha1.RuleActionDrop, "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp-priority2").
		SetPriority(1.002).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	// Medium priority. Allows traffic from z to x/a.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("cnp-priority3").
		SetPriority(1.003).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	// Lowest priority. Drops traffic from z to x.
	builder3.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	reachabilityTwoCNPs := NewReachability(allPods, true)
	reachabilityTwoCNPs.Expect(Pod("z/a"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/a"), Pod("x/c"), false)
	reachabilityTwoCNPs.Expect(Pod("z/b"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/b"), Pod("x/c"), false)
	reachabilityTwoCNPs.Expect(Pod("z/c"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/c"), Pod("x/c"), false)

	reachabilityAllCNPs := NewReachability(allPods, true)
	reachabilityAllCNPs.Expect(Pod("z/a"), Pod("x/b"), false)
	reachabilityAllCNPs.Expect(Pod("z/a"), Pod("x/c"), false)
	reachabilityAllCNPs.Expect(Pod("z/b"), Pod("x/a"), false)
	reachabilityAllCNPs.Expect(Pod("z/b"), Pod("x/b"), false)
	reachabilityAllCNPs.Expect(Pod("z/b"), Pod("x/c"), false)
	reachabilityAllCNPs.Expect(Pod("z/c"), Pod("x/b"), false)
	reachabilityAllCNPs.Expect(Pod("z/c"), Pod("x/c"), false)

	testStepTwoCNP := []*TestStep{
		{
			"Two Policies with different priorities",
			reachabilityTwoCNPs,
			[]metav1.Object{builder3.Get(), builder2.Get()},
			80,
			0,
		},
	}
	// Create the Policies in specific order to make sure that priority re-assignments work as expected.
	testStepAll := []*TestStep{
		{
			"All three Policies",
			reachabilityAllCNPs,
			[]metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP PriorityOverride Intermediate", testStepTwoCNP},
		{"CNP PriorityOverride All", testStepAll},
	}
	executeTests(t, testCase)
}

// testCNPTierOverride tests tier priority overriding in three Policies.
// Each CNP controls a smaller set of traffic patterns as tier priority increases.
func testCNPTierOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("cnp-tier-emergency").
		SetTier("emergency").
		SetPriority(100).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	podZBIP, _ := podIPs["z/b"]
	cidr := podZBIP + "/32"
	// Highest priority tier. Drops traffic from z/b to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, &cidr, nil, nil,
		nil, nil, secv1alpha1.RuleActionDrop, "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp-tier-securityops").
		SetTier("securityops").
		SetPriority(10).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	// Medium priority tier. Allows traffic from z to x/a.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("cnp-tier-application").
		SetTier("application").
		SetPriority(1).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	// Lowest priority tier. Drops traffic from z to x.
	builder3.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	reachabilityTwoCNPs := NewReachability(allPods, true)
	reachabilityTwoCNPs.Expect(Pod("z/a"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/a"), Pod("x/c"), false)
	reachabilityTwoCNPs.Expect(Pod("z/b"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/b"), Pod("x/c"), false)
	reachabilityTwoCNPs.Expect(Pod("z/c"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/c"), Pod("x/c"), false)

	reachabilityAllCNPs := NewReachability(allPods, true)
	reachabilityAllCNPs.Expect(Pod("z/a"), Pod("x/b"), false)
	reachabilityAllCNPs.Expect(Pod("z/a"), Pod("x/c"), false)
	reachabilityAllCNPs.Expect(Pod("z/b"), Pod("x/a"), false)
	reachabilityAllCNPs.Expect(Pod("z/b"), Pod("x/b"), false)
	reachabilityAllCNPs.Expect(Pod("z/b"), Pod("x/c"), false)
	reachabilityAllCNPs.Expect(Pod("z/c"), Pod("x/b"), false)
	reachabilityAllCNPs.Expect(Pod("z/c"), Pod("x/c"), false)

	testStepTwoCNP := []*TestStep{
		{
			"Two Policies in different tiers",
			reachabilityTwoCNPs,
			[]metav1.Object{builder3.Get(), builder2.Get()},
			80,
			0,
		},
	}
	testStepAll := []*TestStep{
		{
			"All three Policies in different tiers",
			reachabilityAllCNPs,
			[]metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP TierOverride Intermediate", testStepTwoCNP},
		{"CNP TierOverride All", testStepAll},
	}
	executeTests(t, testCase)
}

// testCNPTierOverride tests tier priority overriding in three Policies with custom created tiers.
// Each CNP controls a smaller set of traffic patterns as tier priority increases.
func testCNPCustomTiers(t *testing.T) {
	// Create two custom tiers with tier priority immediately next to each other.
	_, err := k8sUtils.CreateNewTier("high-priority", 245)
	failOnError(err, t)
	_, err = k8sUtils.CreateNewTier("low-priority", 246)
	failOnError(err, t)

	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("cnp-tier-high").
		SetTier("high-priority").
		SetPriority(100).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	// Medium priority tier. Allows traffic from z to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp-tier-low").
		SetTier("low-priority").
		SetPriority(1).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	// Lowest priority tier. Drops traffic from z to x.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	reachabilityTwoCNPs := NewReachability(allPods, true)
	reachabilityTwoCNPs.Expect(Pod("z/a"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/a"), Pod("x/c"), false)
	reachabilityTwoCNPs.Expect(Pod("z/b"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/b"), Pod("x/c"), false)
	reachabilityTwoCNPs.Expect(Pod("z/c"), Pod("x/b"), false)
	reachabilityTwoCNPs.Expect(Pod("z/c"), Pod("x/c"), false)
	testStepTwoCNP := []*TestStep{
		{
			"Two Policies in different tiers",
			reachabilityTwoCNPs,
			[]metav1.Object{builder2.Get(), builder1.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Custom Tier priority", testStepTwoCNP},
	}
	executeTests(t, testCase)
	// Cleanup customed tiers. CNPs created in those tiers need to be deleted first.
	failOnError(k8sUtils.CleanCNPs(), t)
	time.Sleep(networkPolicyDelay)
	failOnError(k8sUtils.DeleteTier("high-priority"), t)
	failOnError(k8sUtils.DeleteTier("low-priority"), t)
}

// testCNPPriorityConflictingRule tests that if there are two Policies in the cluster with rules that conflicts with
// each other, the CNP with higher priority will prevail.
func testCNPPriorityConflictingRule(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("cnp-drop").
		SetPriority(1).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp-allow").
		SetPriority(2).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	// The following ingress rule will take no effect as it is exactly the same as ingress rule of cnp-drop,
	// but cnp-allow has lower priority.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	reachabilityBothCNP := NewReachability(allPods, true)
	reachabilityBothCNP.Expect(Pod("z/a"), Pod("x/a"), false)
	reachabilityBothCNP.Expect(Pod("z/a"), Pod("x/b"), false)
	reachabilityBothCNP.Expect(Pod("z/a"), Pod("x/c"), false)
	reachabilityBothCNP.Expect(Pod("z/b"), Pod("x/a"), false)
	reachabilityBothCNP.Expect(Pod("z/b"), Pod("x/b"), false)
	reachabilityBothCNP.Expect(Pod("z/b"), Pod("x/c"), false)
	reachabilityBothCNP.Expect(Pod("z/c"), Pod("x/a"), false)
	reachabilityBothCNP.Expect(Pod("z/c"), Pod("x/b"), false)
	reachabilityBothCNP.Expect(Pod("z/c"), Pod("x/c"), false)

	testStep := []*TestStep{
		{
			"Both CNP",
			reachabilityBothCNP,
			[]metav1.Object{builder1.Get(), builder2.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Priority Conflicting Rule", testStep},
	}
	executeTests(t, testCase)
}

// testCNPPriorityConflictingRule tests that if there are two rules in the cluster that conflicts with
// each other, the rule with higher precedence will prevail.
func testCNPRulePrioirty(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	// cnp-deny will apply to all pods in namespace x
	builder1 = builder1.SetName("cnp-deny").
		SetPriority(5).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	builder1.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "y"},
		nil, nil, secv1alpha1.RuleActionDrop, "")
	// This rule should take no effect as it will be overridden by the first rule of cnp-allow
	builder1.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	// cnp-allow will also apply to all pods in namespace x
	builder2 = builder2.SetName("cnp-allow").
		SetPriority(5).
		SetAppliedToGroup(nil, map[string]string{"ns": "x"}, nil, nil)
	builder2.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionAllow, "")
	// This rule should take no effect as it will be overridden by the first rule of cnp-drop
	builder2.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "y"},
		nil, nil, secv1alpha1.RuleActionAllow, "")

	// Only egress from pods in namespace x to namespace y should be denied
	reachabilityBothCNP := NewReachability(allPods, true)
	reachabilityBothCNP.Expect(Pod("x/a"), Pod("y/a"), false)
	reachabilityBothCNP.Expect(Pod("x/b"), Pod("y/a"), false)
	reachabilityBothCNP.Expect(Pod("x/c"), Pod("y/a"), false)
	reachabilityBothCNP.Expect(Pod("x/a"), Pod("y/b"), false)
	reachabilityBothCNP.Expect(Pod("x/b"), Pod("y/b"), false)
	reachabilityBothCNP.Expect(Pod("x/c"), Pod("y/b"), false)
	reachabilityBothCNP.Expect(Pod("x/a"), Pod("y/c"), false)
	reachabilityBothCNP.Expect(Pod("x/b"), Pod("y/c"), false)
	reachabilityBothCNP.Expect(Pod("x/c"), Pod("y/c"), false)

	testStep := []*TestStep{
		{
			"Both CNP",
			reachabilityBothCNP,
			[]metav1.Object{builder2.Get(), builder1.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"CNP Rule Priority", testStep},
	}
	executeTests(t, testCase)
}

// testANPBasic tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea NetworkPolicy
// that specifies that. Also it tests that a K8s NetworkPolicy with same appliedTo will not affect its behavior.
// TODO: test with K8s NP having the same name and namespace as ANP after Issue #1173 is resolved.
func testANPBasic(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "np1").
		SetPriority(1.0).
		SetAppliedToGroup(map[string]string{"pod": "a"}, nil)
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, secv1alpha1.RuleActionDrop, "")

	reachability := NewReachability(allPods, true)
	reachability.Expect(Pod("x/b"), Pod("y/a"), false)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			80,
			0,
		},
	}
	// build a K8s NetworkPolicy that has the same appliedTo but allows all traffic.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName("y", "np2").
		SetPodSelector(map[string]string{"pod": "a"})
	k8sNPBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
		nil, nil, nil, nil)
	testStep2 := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), k8sNPBuilder.Get()},
			80,
			0,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop X/B to Y/A", testStep},
		{"With K8s NetworkPolicy of the same name", testStep2},
	}
	executeTests(t, testCase)
}

// testAuditLoggingBasic tests that a audit log is generated when egress drop applied
func testAuditLoggingBasic(t *testing.T, data *TestData) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-log-cnp-deny").
		SetPriority(1.0).
		SetAppliedToGroup(map[string]string{"pod": "a"}, map[string]string{"ns": "x"}, nil, nil)
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, secv1alpha1.RuleActionDrop, "")
	builder.AddEgressLogging()

	_, err := k8sUtils.CreateOrUpdateCNP(builder.Get())
	failOnError(err, t)
	time.Sleep(networkPolicyDelay)

	// generate some traffic that will be dropped by test-log-cnp-deny
	k8sUtils.Probe("x", "a", "z", "a", p80)
	k8sUtils.Probe("x", "a", "z", "b", p80)
	k8sUtils.Probe("x", "a", "z", "c", p80)
	time.Sleep(networkPolicyDelay)

	podXA, _ := k8sUtils.GetPod("x", "a")
	// nodeName is guaranteed to be set at this stage, since the framework waits for all Pods to be in Running phase
	nodeName := podXA.Spec.NodeName
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		t.Errorf("error occurred when trying to get the Antrea Agent pod running on node %s: %v", nodeName, err)
	}
	cmd := []string{"cat", logDir + logfileName}
	stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
	if err != nil || stderr != "" {
		t.Errorf("error occurred when inspecting the audit log file. err: %v, stderr: %v", err, stderr)
	}
	assert.Equalf(t, true, strings.Contains(stdout, "test-log-cnp-deny"), "audit log does not contain entries for test-log-cnp-deny")

	destinations := []string{"z/a", "z/b", "z/c"}
	srcIP, _ := podIPs["x/a"]
	for _, d := range destinations {
		dstIP, _ := podIPs[d]
		// The audit log should contain log entry `... Drop <ofPriority> SRC: <x/a IP> DEST: <z/* IP> ...`
		pattern := `Drop [0-9]+ SRC: ` + srcIP + ` DEST: ` + dstIP
		assert.Regexp(t, pattern, stdout, "audit log does not contain expected entry for x/a to %s", d)
	}
	failOnError(k8sUtils.CleanCNPs(), t)
}

// executeTests runs all the tests in testList and prints results
func executeTests(t *testing.T, testList []*TestCase) {
	for _, testCase := range testList {
		log.Infof("running test case %s", testCase.Name)
		log.Debugf("cleaning-up previous policies and sleeping for %v", networkPolicyDelay)
		failOnError(k8sUtils.CleanCNPs(), t)
		failOnError(k8sUtils.CleanANPs(namespaces), t)
		time.Sleep(networkPolicyDelay)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			applyPolicies(t, step)
			reachability := step.Reachability
			start := time.Now()
			k8sUtils.Validate(allPods, reachability, step.Port)
			step.Duration = time.Now().Sub(start)
			reachability.PrintSummary(true, true, true)

			_, wrong, _ := step.Reachability.Summary()
			if wrong != 0 {
				t.Errorf("failure -- %d wrong results", wrong)
			}
		}
	}
	allTestList = append(allTestList, testList...)
}

func applyPolicies(t *testing.T, step *TestStep) {
	for _, np := range step.Policies {
		if cnp, ok := np.(*secv1alpha1.ClusterNetworkPolicy); ok {
			log.Debugf("creating CNP %v", cnp.Name)
			_, err := k8sUtils.CreateOrUpdateCNP(cnp)
			failOnError(err, t)
		} else if anp, ok := np.(*secv1alpha1.NetworkPolicy); ok {
			log.Debugf("creating ANP %v in namespace %v", anp.Name, anp.Namespace)
			_, err := k8sUtils.CreateOrUpdateANP(anp)
			failOnError(err, t)
		} else {
			k8sNP, _ := np.(*v1net.NetworkPolicy)
			log.Debugf("creating K8s NetworkPolicy %v in namespace %v", k8sNP.Name, k8sNP.Namespace)
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(k8sNP.Namespace, k8sNP)
			failOnError(err, t)
		}
	}
	if len(step.Policies) > 0 {
		log.Debugf("Sleeping for %v for all policies to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

// printResults summarizes test results for all the testcases
func printResults() {
	fmt.Printf("\n\n---------------- Test Results ------------------\n\n")
	failCount := 0
	for _, testCase := range allTestList {
		fmt.Printf("Test %s:\n", testCase.Name)
		testFailed := false
		for _, step := range testCase.Steps {
			_, wrong, comparison := step.Reachability.Summary()
			var result string
			if wrong == 0 {
				result = "success"
			} else {
				result = fmt.Sprintf("failure -- %d wrong results", wrong)
				testFailed = true
			}
			fmt.Printf("\tStep %s on port %d, duration %d seconds, result: %s\n",
				step.Name, step.Port, int(step.Duration.Seconds()), result)
			fmt.Printf("\n%s\n", comparison.PrettyPrint("\t\t"))
		}
		if testFailed {
			failCount++
		}
		fmt.Printf("\n\n")
	}
	fmt.Printf("=== TEST FAILURES: %d/%d ===\n", failCount, len(allTestList))
	fmt.Printf("\n\n")
}

func TestAntreaPolicy(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	initialize(t, data)

	t.Run("TestGroupValidateAntreaNativePolicies", func(t *testing.T) {
		t.Run("Case=ACNPNoPriority", func(t *testing.T) { testInvalidACNPNoPriority(t) })
		t.Run("Case=ACNPRuleNameNotUniqueDenied", func(t *testing.T) { testInvalidACNPRuleNameNotUnique(t) })
		t.Run("Case=ACNPTierDoesNotExistDenied", func(t *testing.T) { testInvalidACNPTierDoesNotExist(t) })
		t.Run("Case=ANPNoPriority", func(t *testing.T) { testInvalidANPNoPriority(t) })
		t.Run("Case=ANPRuleNameNotUniqueDenied", func(t *testing.T) { testInvalidANPRuleNameNotUnique(t) })
		t.Run("Case=ANPTierDoesNotExistDenied", func(t *testing.T) { testInvalidANPTierDoesNotExist(t) })
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
		// testcases below require default deny k8s NetworkPolicies to work
		applyDefaultDenyToAllNamespaces(k8sUtils, namespaces)
		t.Run("Case=CNPAllowXBtoA", func(t *testing.T) { testCNPAllowXBtoA(t) })
		t.Run("Case=CNPAllowXBtoYA", func(t *testing.T) { testCNPAllowXBtoYA(t) })
		t.Run("Case=CNPPriorityOverrideDefaultDeny", func(t *testing.T) { testCNPPriorityOverrideDefaultDeny(t) })
		cleanupDefaultDenyNPs(k8sUtils, namespaces)
	})

	t.Run("TestGroupNoK8sNP", func(t *testing.T) {
		// testcases below do not depend on underlying k8s NetworkPolicies
		t.Run("Case=CNPAllowNoDefaultIsolation", func(t *testing.T) { testCNPAllowNoDefaultIsolation(t) })
		t.Run("Case=CNPDropEgress", func(t *testing.T) { testCNPDropEgress(t) })
		t.Run("Case=CNPBaselinePolicy", func(t *testing.T) { testBaselineNamespaceIsolation(t) })
		t.Run("Case=CNPPrioirtyOverride", func(t *testing.T) { testCNPPriorityOverride(t) })
		t.Run("Case=CNPTierOverride", func(t *testing.T) { testCNPTierOverride(t) })
		t.Run("Case=CNPCustomTiers", func(t *testing.T) { testCNPCustomTiers(t) })
		t.Run("Case=CNPPriorityConflictingRule", func(t *testing.T) { testCNPPriorityConflictingRule(t) })
		t.Run("Case=CNPRulePriority", func(t *testing.T) { testCNPRulePrioirty(t) })
		t.Run("Case=ANPBasic", func(t *testing.T) { testANPBasic(t) })
	})
	// print results for reachability tests
	printResults()

	t.Run("TestGroupAuditLogging", func(t *testing.T) {
		t.Run("Case=AuditLoggingBasic", func(t *testing.T) { testAuditLoggingBasic(t, data) })
	})
	k8sUtils.Cleanup(namespaces)
}

func TestAntreaPolicyStatus(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfAntreaPolicyDisabled(t, data)

	_, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-0", masterNodeName())
	defer cleanupFunc()
	_, _, cleanupFunc = createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-1", workerNodeName(1))
	defer cleanupFunc()

	anpBuilder := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(testNamespace, "anp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup(map[string]string{"app": "nginx"}, nil)
	anpBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, secv1alpha1.RuleActionAllow, "")
	anp := anpBuilder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	_, err = data.securityClient.NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.securityClient.NetworkPolicies(anp.Namespace).Delete(context.TODO(), anp.Name, metav1.DeleteOptions{})

	cnpBuilder := &ClusterNetworkPolicySpecBuilder{}
	cnpBuilder = cnpBuilder.SetName("cnp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup(map[string]string{"app": "nginx"}, nil, nil, nil)
	cnpBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, secv1alpha1.RuleActionAllow, "")
	cnp := cnpBuilder.Get()
	log.Debugf("creating CNP %v", cnp.Name)
	_, err = data.securityClient.ClusterNetworkPolicies().Create(context.TODO(), cnp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.securityClient.ClusterNetworkPolicies().Delete(context.TODO(), cnp.Name, metav1.DeleteOptions{})

	expectedStatus := secv1alpha1.NetworkPolicyStatus{
		Phase:                secv1alpha1.NetworkPolicyRealized,
		ObservedGeneration:   1,
		CurrentNodesRealized: 2,
		DesiredNodesRealized: 2,
	}
	err = wait.Poll(100*time.Millisecond, 3*time.Second, func() (bool, error) {
		anp, err := data.securityClient.NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status == expectedStatus, nil
	})
	assert.NoError(t, err, "Antrea NetworkPolicy failed to reach expected status")
	err = wait.Poll(100*time.Millisecond, 3*time.Second, func() (bool, error) {
		anp, err := data.securityClient.ClusterNetworkPolicies().Get(context.TODO(), cnp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status == expectedStatus, nil
	})
	assert.NoError(t, err, "Antrea ClusterNetworkPolicy failed to reach expected status")
}

// TestANPNetworkPolicyStatsWithDropAction tests antreanetworkpolicystats can correctly collect dropped packets stats from ANP if
// networkpolicystats feature is enabled
func TestANPNetworkPolicyStatsWithDropAction(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfAntreaPolicyDisabled(t, data)

	if err := testData.mutateAntreaConfigMap(func(data map[string]string) {
		antreaControllerConf, _ := data["antrea-controller.conf"]
		antreaControllerConf = strings.Replace(antreaControllerConf, "#  NetworkPolicyStats: false", "  NetworkPolicyStats: true", 1)
		data["antrea-controller.conf"] = antreaControllerConf
		antreaAgentConf, _ := data["antrea-agent.conf"]
		antreaAgentConf = strings.Replace(antreaAgentConf, "#  NetworkPolicyStats: false", "  NetworkPolicyStats: true", 1)
		data["antrea-agent.conf"] = antreaAgentConf
	}, true, true); err != nil {
		t.Fatalf("Failed to enable NetworkPolicyStats feature: %v", err)
	}

	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "")
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "")
	defer cleanupFunc()
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	p10 := float64(10)
	intstr80 := intstr.FromInt(80)
	dropAction := secv1alpha1.RuleActionDrop
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": clientName}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": serverName}}
	protocol := v1.ProtocolUDP

	var anp = &secv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "np1", Labels: map[string]string{"antrea-e2e": "np1"}},
		Spec: secv1alpha1.NetworkPolicySpec{
			AppliedTo: []secv1alpha1.NetworkPolicyPeer{
				{PodSelector: &selectorC},
			},
			Priority: p10,
			Ingress: []secv1alpha1.Rule{
				{
					Ports: []secv1alpha1.NetworkPolicyPort{
						{
							Port:     &intstr80,
							Protocol: &protocol,
						},
					},
					From: []secv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
					Action: &dropAction,
				},
			},
			Egress: []secv1alpha1.Rule{},
		},
	}

	if _, err = k8sUtils.CreateOrUpdateANP(anp); err != nil {
		failOnError(fmt.Errorf("create ANP failed for ANP %s: %v", anp.Name, err), t)
	}

	// Wait for a few seconds in case that connections are established before policies are enforced.
	time.Sleep(networkPolicyDelay)

	sessionsPerAddressFamily := 10
	var wg sync.WaitGroup
	for i := 0; i < sessionsPerAddressFamily; i++ {
		wg.Add(1)
		go func() {
			if clusterInfo.podV4NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.ipv4.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.ipv6.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	totalSessions := 0
	if clusterInfo.podV4NetworkCIDR != "" {
		totalSessions += sessionsPerAddressFamily
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		totalSessions += sessionsPerAddressFamily
	}

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
		stats, err := data.crdClient.StatsV1alpha1().AntreaNetworkPolicyStats(testNamespace).Get(context.TODO(), "np1", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		t.Logf("Got AntreaNetworkPolicy stats: %v", stats)
		if stats.TrafficStats.Sessions != int64(totalSessions) {
			return false, nil
		}
		if stats.TrafficStats.Packets < stats.TrafficStats.Sessions || stats.TrafficStats.Bytes < stats.TrafficStats.Sessions {
			return false, fmt.Errorf("Neither 'Packets' nor 'Bytes' should be smaller than 'Sessions'")
		}
		return true, nil
	}); err != nil {
		failOnError(err, t)
	}
	k8sUtils.Cleanup(namespaces)
}
