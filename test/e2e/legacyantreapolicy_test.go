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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	legacycorev1a2 "antrea.io/antrea/pkg/legacyapis/core/v1alpha2"
	legacysecv1alpha1 "antrea.io/antrea/pkg/legacyapis/security/v1alpha1"
	. "antrea.io/antrea/test/e2e/utils"
)

const (
	mockWait = 900 * time.Millisecond
)

// TestLegacyAntreaPolicyStats is the top-level test which contains all subtests for
// LegacyAntreaPolicyStats related test cases so they can share setup, teardown.
func TestLegacyAntreaPolicyStats(t *testing.T) {
	skipIfProviderIs(t, "kind", "This test is for legacy API groups and is almost the same as new API groups'.")
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testLegacyANPNetworkPolicyStatsWithDropAction", func(t *testing.T) {
		skipIfNetworkPolicyStatsDisabled(t)
		testLegacyANPNetworkPolicyStatsWithDropAction(t, data)
	})
	t.Run("testLegacyAntreaClusterNetworkPolicyStats", func(t *testing.T) {
		skipIfNetworkPolicyStatsDisabled(t)
		testLegacyAntreaClusterNetworkPolicyStats(t, data)
	})
}

func testLegacyMutateACNPNoTier(t *testing.T) {
	invalidNpErr := fmt.Errorf("ACNP tier not mutated to default tier")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-tier").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0)
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	acnp, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp)
	if err != nil {
		failOnError(fmt.Errorf("ACNP create failed %v", err), t)
	}
	if acnp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanLegacyACNPs(), t)
}

func testLegacyMutateANPNoTier(t *testing.T) {
	invalidNpErr := fmt.Errorf("ANP tier not mutated to default tier")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-tier").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0)
	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	anp, err := k8sUtils.CreateOrUpdateLegacyANP(anp)
	if err != nil {
		failOnError(fmt.Errorf("ANP create failed %v", err), t)
	}
	if anp.Spec.Tier != defaultTierName {
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanLegacyANPs([]string{anp.Namespace}), t)
}

func testLegacyMutateACNPNoRuleName(t *testing.T) {
	mutateErr := fmt.Errorf("ACNP Rule name not mutated automatically")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-rule-name").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	acnp, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp)
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
	failOnError(k8sUtils.CleanLegacyACNPs(), t)
}

func testLegacyMutateANPNoRuleName(t *testing.T) {
	mutateErr := fmt.Errorf("ANP Rule name not mutated automatically")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-rule-name").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionAllow, "")
	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	anp, err := k8sUtils.CreateOrUpdateLegacyANP(anp)
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
	failOnError(k8sUtils.CleanLegacyANPs([]string{anp.Namespace}), t)
}

func testLegacyInvalidACNPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without a priority accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-no-priority").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPRuleNameNotUnique(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without unique rule names accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-rule-name-not-unique").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "not-unique").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "not-unique")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPTierDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without existing Tier accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-tier-not-exist").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("i-dont-exist")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPPortRangePortUnset(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy egress rule with endPort but no port accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-egress-port-range-port-unset").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, nil, nil, &p8085, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range")

	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPPortRangeEndPortSmall(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy egress rule with endPort smaller than port accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-egress-port-range-endport-small").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8082, nil, &p8081, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range")

	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPSpecAppliedToRuleAppliedToSet(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with spec appliedTo and rules appliedTo set")
	ruleAppTo := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"},
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-spec-appto-and-rules-appto").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, []ACNPAppliedToSpec{ruleAppTo}, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPAppliedToNotSetInAllRules(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with appliedTo not set in all rules")
	ruleAppTo := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"},
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-appto-not-set-in-all-rules").
		SetPriority(1.0)
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, []ACNPAppliedToSpec{ruleAppTo}, crdv1alpha1.RuleActionAllow, "", "").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPAppliedToCGDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy AppliedTo with non-existent clustergroup")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-appliedto-group-not-exist").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: "cgA"}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil,
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPCGDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy rules with non-existent clustergroup")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-not-exist").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil,
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "cgA", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidACNPIngressPeerCGSetWithPodSelector(t *testing.T) {
	cgA := "cgA"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	ruleAppTo := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"},
	}
	k8sUtils.CreateLegacyCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and podSelector in NetworkPolicyPeer set")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-podselector-set").
		SetPriority(1.0)
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil,
		nil, nil, false, []ACNPAppliedToSpec{ruleAppTo}, crdv1alpha1.RuleActionAllow, "cgA", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanCGs(), t)
}

func testLegacyInvalidACNPIngressPeerCGSetWithNSSelector(t *testing.T) {
	cgA := "cgA"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	k8sUtils.CreateLegacyCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and namespaceSelector in NetworkPolicyPeer set")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-nsselector-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "cgA", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanCGs(), t)
}

func testLegacyInvalidACNPIngressPeerCGSetWithIPBlock(t *testing.T) {
	cgA := "cgA"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	k8sUtils.CreateLegacyCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and ipBlock in NetworkPolicyPeer set")
	cidr := "10.0.0.10/32"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-ipblock-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: "cgA"}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, &cidr, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, []ACNPAppliedToSpec{{Group: "cgB"}}, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidANPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without a priority accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-priority").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidANPRuleNameNotUnique(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without unique rule names accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-rule-name-not-unique").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionAllow, "not-unique").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionAllow, "not-unique")
	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidANPTierDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without existing Tier accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-tier-not-exist").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("i-dont-exist")
	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidANPPortRangePortUnset(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy egress rule with endPort but no port accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "anp-egress-port-range-port-unset").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, nil, nil, &p8085, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionDrop, "anp-port-range")

	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidANPPortRangeEndPortSmall(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy egress rule with endPort smaller than port accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "anp-egress-port-range-endport-small").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8082, nil, &p8081, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionDrop, "anp-port-range")

	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err := k8sUtils.CreateOrUpdateLegacyANP(anp); err == nil {
		// Above creation of ANP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testLegacyInvalidTierReservedDelete(t *testing.T) {
	invalidErr := fmt.Errorf("reserved Tier deleted")
	if err := k8sUtils.DeleteLegacyTier("emergency"); err == nil {
		// Above deletion of reserved Tier must fail.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidTierPriorityUpdate(t *testing.T) {
	invalidErr := fmt.Errorf("tier priority updated")
	oldTier, err := k8sUtils.CreateNewLegacyTier("prio-updated-tier", 21)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier prio-updated-tier: %v", err), t)
	}
	// Update this tier with new priority
	newTier := legacysecv1alpha1.Tier{
		ObjectMeta: oldTier.ObjectMeta,
		Spec:       oldTier.Spec,
	}
	// Attempt to update Tier's priority
	newTier.Spec.Priority = 31
	// Above update of Tier must fail as it is an invalid case.
	if _, err = k8sUtils.UpdateLegacyTier(&newTier); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteLegacyTier(oldTier.Name), t)
}

func testLegacyInvalidTierPriorityOverlap(t *testing.T) {
	invalidErr := fmt.Errorf("tiers created with overlapping priorities")
	tr, err := k8sUtils.CreateNewLegacyTier("tier-prio-20", 20)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-prio-20: %v", err), t)
	}
	time.Sleep(mockWait)
	// Attempt to create Tier with same priority.
	if _, err = k8sUtils.CreateNewLegacyTier("another-tier-prio-20", 20); err == nil {
		// Above creation of Tier must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.DeleteLegacyTier(tr.Name), t)
}

func testLegacyInvalidTierReservedPriority(t *testing.T) {
	invalidErr := fmt.Errorf("tier created with reserved priority")
	if _, err := k8sUtils.CreateNewLegacyTier("tier-reserved-prio", 251); err == nil {
		// Above creation of Tier must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidTierACNPRefDelete(t *testing.T) {
	invalidErr := fmt.Errorf("tier deleted with referenced ACNPs")
	tr, err := k8sUtils.CreateNewLegacyTier("tier-acnp", 10)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-acnp: %v", err), t)
	}
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-for-tier").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("tier-acnp").
		SetPriority(13.0)
	acnp := builder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err = k8sUtils.CreateOrUpdateLegacyACNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP failed for ACNP %s: %v", acnp.Name, err), t)
	}
	// Deleting this Tier must fail as it has referenced ACNP
	if err = k8sUtils.DeleteLegacyTier(tr.Name); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.CleanLegacyACNPs(), t)
	failOnError(k8sUtils.DeleteLegacyTier(tr.Name), t)
}

func testLegacyInvalidTierANPRefDelete(t *testing.T) {
	invalidErr := fmt.Errorf("tier deleted with referenced ANPs")
	tr, err := k8sUtils.CreateNewLegacyTier("tier-anp", 10)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-anp: %v", err), t)
	}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-for-tier").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("tier-anp").
		SetPriority(13.0)
	anp := builder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	if _, err = k8sUtils.CreateOrUpdateLegacyANP(anp); err != nil {
		failOnError(fmt.Errorf("create ANP failed for ANP %s: %v", anp.Name, err), t)
	}
	// Deleting this Tier must fail as it has referenced ANP
	if err = k8sUtils.DeleteLegacyTier(tr.Name); err == nil {
		failOnError(invalidErr, t)
	}
	failOnError(k8sUtils.CleanLegacyANPs([]string{anp.Namespace}), t)
	failOnError(k8sUtils.DeleteLegacyTier(tr.Name), t)
}

// testACNPAllowXBtoA tests traffic from X/B to pods with label A, after applying the default deny
// k8s NetworkPolicies in all namespaces and ACNP to allow X/B to A.
func testLegacyACNPAllowXBtoA(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-allow-xb-to-a").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	reachability := NewReachability(allPods, Dropped)
	reachability.Expect(Pod("x/b"), Pod("x/a"), Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Connected)
	reachability.Expect(Pod("x/b"), Pod("z/a"), Connected)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow X/B to A", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPAllowXBtoYA tests traffic from X/B to Y/A on named port 81, after applying the default deny
// k8s NetworkPolicies in all namespaces and ACNP to allow X/B to Y/A.
func testLegacyACNPAllowXBtoYA(t *testing.T) {
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-allow-xb-to-ya").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "y"}}})
	builder.AddIngress(v1.ProtocolTCP, nil, &port81Name, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	reachability := NewReachability(allPods, Dropped)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Connected)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{81},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow X/B to Y/A", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPPriorityOverrideDefaultDeny tests priority override in ACNP. It applies a higher priority ACNP to drop
// traffic from namespace Z to X/A, and in the meantime applies a lower priority ACNP to allow traffic from Z to X.
// It is tested with default deny k8s NetworkPolicies in all namespaces.
func testLegacyACNPPriorityOverrideDefaultDeny(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-priority2").
		SetPriority(2).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority1").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	// Ingress from ns:z to x/a will be dropped since acnp-priority1 has higher precedence.
	reachabilityBothACNP := NewReachability(allPods, Dropped)
	reachabilityBothACNP.Expect(Pod("z/a"), Pod("x/b"), Connected)
	reachabilityBothACNP.Expect(Pod("z/a"), Pod("x/c"), Connected)
	reachabilityBothACNP.Expect(Pod("z/b"), Pod("x/b"), Connected)
	reachabilityBothACNP.Expect(Pod("z/b"), Pod("x/c"), Connected)
	reachabilityBothACNP.Expect(Pod("z/c"), Pod("x/b"), Connected)
	reachabilityBothACNP.Expect(Pod("z/c"), Pod("x/c"), Connected)
	reachabilityBothACNP.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder1.GetLegacy(), builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP PriorityOverride Default Deny", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testLegacyACNPAllowNoDefaultIsolation tests that no default isolation rules are created for Policies.
func testLegacyACNPAllowNoDefaultIsolation(t *testing.T, protocol v1.Protocol) {
	if protocol == v1.ProtocolSCTP {
		skipIfProviderIs(t, "kind", "OVS userspace conntrack does not have the SCTP support for now.")
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder.AddIngress(protocol, &p81, nil, nil, nil, nil, map[string]string{"ns": "y"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	builder.AddEgress(protocol, &p81, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	reachability := NewReachability(allPods, Connected)
	testStep := []*TestStep{
		{
			"Port 81",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{81},
			protocol,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Allow No Default Isolation", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testLegacyACNPDropEgress tests that a ACNP is able to drop egress traffic from pods labelled A to namespace Z.
func testLegacyACNPDropEgress(t *testing.T, protocol v1.Protocol) {
	if protocol == v1.ProtocolSCTP {
		skipIfProviderIs(t, "kind", "OVS userspace conntrack does not have the SCTP support for now.")
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
	builder.AddEgress(protocol, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			protocol,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to NS:z", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testLegacyACNPNoEffectOnOtherProtocols tests that a ACNP which drops TCP traffic won't affect other protocols (e.g. UDP).
func testLegacyACNPNoEffectOnOtherProtocols(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability1 := NewReachability(allPods, Connected)
	reachability1.Expect(Pod("z/a"), Pod("x/a"), Dropped)
	reachability1.Expect(Pod("z/b"), Pod("x/a"), Dropped)
	reachability1.Expect(Pod("z/c"), Pod("x/a"), Dropped)
	reachability1.Expect(Pod("z/a"), Pod("y/a"), Dropped)
	reachability1.Expect(Pod("z/b"), Pod("y/a"), Dropped)
	reachability1.Expect(Pod("z/c"), Pod("y/a"), Dropped)
	reachability1.Expect(Pod("z/b"), Pod("z/a"), Dropped)
	reachability1.Expect(Pod("z/c"), Pod("z/a"), Dropped)

	reachability2 := NewReachability(allPods, Connected)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability1,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80",
			reachability2,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolUDP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Ingress From All Pod:a to NS:z TCP Not UDP", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPAppliedToDenyXBtoCGWithYA tests traffic from X/B to ClusterGroup Y/A on named port 81 is dropped.
func testLegacyACNPAppliedToDenyXBtoCGWithYA(t *testing.T) {
	cgName := "cg-pods-ya"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetNamespaceSelector(map[string]string{"ns": "y"}, nil)
	cgBuilder = cgBuilder.SetPodSelector(map[string]string{"pod": "a"}, nil)
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-ya-from-xb").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddIngress(v1.ProtocolTCP, nil, &port81Name, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{81},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Deny ClusterGroup Y/A from X/B", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPIngressRuleDenyCGWithXBtoYA tests traffic from ClusterGroup with X/B to Y/A on named port 81 is dropped.
func testLegacyACNPIngressRuleDenyCGWithXBtoYA(t *testing.T) {
	cgName := "cg-pods-xb"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetNamespaceSelector(map[string]string{"ns": "x"}, nil)
	cgBuilder = cgBuilder.SetPodSelector(map[string]string{"pod": "b"}, nil)
	port81Name := "serve-81"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-xb-to-ya").
		SetPriority(2.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "y"}}})
	builder.AddIngress(v1.ProtocolTCP, nil, &port81Name, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachability.ExpectSelf(allPods, Connected)

	testStep := []*TestStep{
		{
			"NamedPort 81",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{81},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Deny ClusterGroup X/B to Y/A", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPAppliedToRuleCGWithPodsAToNsZ tests that a ACNP is able to drop egress traffic from CG with pods labelled A namespace Z.
func testLegacyACNPAppliedToRuleCGWithPodsAToNsZ(t *testing.T) {
	cgName := "cg-pods-a"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetPodSelector(map[string]string{"pod": "a"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-a-to-z").
		SetPriority(1.0)
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, []ACNPAppliedToSpec{{Group: cgName}}, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From ClusterGroup with All Pod:a to NS:z", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPEgressRulePodsAToCGWithNsZ tests that a ACNP is able to drop egress traffic from pods labelled A to a CG with namespace Z.
func testLegacyACNPEgressRulePodsAToCGWithNsZ(t *testing.T) {
	cgName := "cg-ns-z"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetNamespaceSelector(map[string]string{"ns": "z"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to ClusterGroup with NS:z", testStep},
	}
	executeLegacyTests(t, testCase)
}

func testLegacyACNPClusterGroupUpdateAppliedTo(t *testing.T) {
	cgName := "cg-pods-a-then-c"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetPodSelector(map[string]string{"pod": "a"}, nil)
	// Update CG Pod selector to group Pods C
	updatedCgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName)
	updatedCgBuilder = updatedCgBuilder.SetPodSelector(map[string]string{"pod": "c"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.Expect(Pod("x/c"), Pod("z/a"), Dropped)
	updatedReachability.Expect(Pod("x/c"), Pod("z/b"), Dropped)
	updatedReachability.Expect(Pod("x/c"), Pod("z/c"), Dropped)
	updatedReachability.Expect(Pod("y/c"), Pod("z/a"), Dropped)
	updatedReachability.Expect(Pod("y/c"), Pod("z/b"), Dropped)
	updatedReachability.Expect(Pod("y/c"), Pod("z/c"), Dropped)
	updatedReachability.Expect(Pod("z/c"), Pod("z/a"), Dropped)
	updatedReachability.Expect(Pod("z/c"), Pod("z/b"), Dropped)
	testStep := []*TestStep{
		{
			"CG Pods A",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
		{
			"CG Pods C - update",
			updatedReachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{updatedCgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From CG Pod:a to NS:z updated to ClusterGroup with Pod:c", testStep},
	}
	executeLegacyTests(t, testCase)
}

func testLegacyACNPClusterGroupUpdate(t *testing.T) {
	cgName := "cg-ns-z-then-y"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetNamespaceSelector(map[string]string{"ns": "z"}, nil)
	// Update CG NS selector to group Pods from Namespace Y
	updatedCgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName)
	updatedCgBuilder = updatedCgBuilder.SetNamespaceSelector(map[string]string{"ns": "y"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.Expect(Pod("x/a"), Pod("y/a"), Dropped)
	updatedReachability.Expect(Pod("x/a"), Pod("y/b"), Dropped)
	updatedReachability.Expect(Pod("x/a"), Pod("y/c"), Dropped)
	updatedReachability.Expect(Pod("y/a"), Pod("y/b"), Dropped)
	updatedReachability.Expect(Pod("y/a"), Pod("y/c"), Dropped)
	updatedReachability.Expect(Pod("z/a"), Pod("y/a"), Dropped)
	updatedReachability.Expect(Pod("z/a"), Pod("y/b"), Dropped)
	updatedReachability.Expect(Pod("z/a"), Pod("y/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80 - update",
			updatedReachability,
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{updatedCgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to ClusterGroup with NS:z updated to ClusterGroup with NS:y", testStep},
	}
	executeLegacyTests(t, testCase)
}

func testLegacyACNPClusterGroupAppliedToPodAdd(t *testing.T, data *TestData) {
	cgName := "cg-pod-custom-pod-zj"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetNamespaceSelector(map[string]string{"ns": "z"}, nil)
	cgBuilder = cgBuilder.SetPodSelector(map[string]string{"pod": "j"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-cg-with-zj-to-xj-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cgName}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "j"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod("z", "j"),
				Labels: map[string]string{"pod": "j"},
			},
			DestPod: CustomPod{
				Pod:    NewPod("x", "j"),
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
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			cp,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From ClusterGroup with Pod: z/j to Pod: x/j for Pod ADD events", testStep},
	}
	executeLegacyTestsWithData(t, testCase, data)
}

func testLegacyACNPClusterGroupRefRulePodAdd(t *testing.T, data *TestData) {
	cgName := "cg-pod-custom-pod-zk"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName)
	cgBuilder = cgBuilder.SetNamespaceSelector(map[string]string{"ns": "z"}, nil)
	cgBuilder = cgBuilder.SetPodSelector(map[string]string{"pod": "k"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-xk-to-cg-with-zk-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "k"},
			NSSelector: map[string]string{"ns": "x"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod("x", "k"),
				Labels: map[string]string{"pod": "k"},
			},
			DestPod: CustomPod{
				Pod:    NewPod("z", "k"),
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
			[]metav1.Object{builder.GetLegacy()},
			[]metav1.Object{cgBuilder.GetLegacy()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			cp,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Egress From Pod: x/k to ClusterGroup with Pod: z/k for Pod ADD event", testStep},
	}
	executeLegacyTestsWithData(t, testCase, data)
}

// testBaselineNamespaceIsolation tests that a ACNP in the baseline Tier is able to enforce default namespace isolation,
// which can be later overridden by developer K8s NetworkPolicies.
func testLegacyBaselineNamespaceIsolation(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	nsExpOtherThanX := metav1.LabelSelectorRequirement{
		Key:      "ns",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"x"},
	}
	builder = builder.SetName("acnp-baseline-isolate-ns-x").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, []metav1.LabelSelectorRequirement{nsExpOtherThanX},
		false, nil, crdv1alpha1.RuleActionDrop, "", "")

	// create a K8s NetworkPolicy for Pods in namespace x to allow ingress traffic from Pods in the same namespace,
	// as well as from the y/a Pod. It should open up ingress from y/a since it's evaluated before the baseline tier.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName("x", "allow-ns-x-and-y-a").
		SetTypeIngress().
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			nil, map[string]string{"ns": "x"}, nil, nil).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
			map[string]string{"pod": "a"}, map[string]string{"ns": "y"}, nil, nil)

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("y/b"), Pod("x/a"), Dropped)
	reachability.Expect(Pod("y/c"), Pod("x/a"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("x/a"), Dropped)
	reachability.Expect(Pod("z/b"), Pod("x/a"), Dropped)
	reachability.Expect(Pod("z/c"), Pod("x/a"), Dropped)
	reachability.Expect(Pod("y/b"), Pod("x/b"), Dropped)
	reachability.Expect(Pod("y/c"), Pod("x/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachability.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachability.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachability.Expect(Pod("y/b"), Pod("x/c"), Dropped)
	reachability.Expect(Pod("y/c"), Pod("x/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachability.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachability.Expect(Pod("z/c"), Pod("x/c"), Dropped)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy(), k8sNPBuilder.Get()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP baseline tier namespace isolation", testStep},
	}
	executeLegacyTests(t, testCase)
	// Cleanup the K8s NetworkPolicy created for this test.
	failOnError(k8sUtils.CleanNetworkPolicies([]string{"x"}), t)
	time.Sleep(networkPolicyDelay)
}

// testACNPPriorityOverride tests priority overriding in three Policies. Those three Policies are applied in a specific order to
// test priority reassignment, and each controls a smaller set of traffic patterns as priority increases.
func testLegacyACNPPriorityOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-priority1").
		SetPriority(1.001).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Highest priority. Drops traffic from z/b to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-priority2").
		SetPriority(1.002).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Medium priority. Allows traffic from z to x/a.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-priority3").
		SetPriority(1.003).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	// Lowest priority. Drops traffic from z to x.
	builder3.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/c"), Pod("x/c"), Dropped)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/b"), Pod("x/a"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/c"), Pod("x/c"), Dropped)

	testStepTwoACNP := []*TestStep{
		{
			"Two Policies with different priorities",
			reachabilityTwoACNPs,
			[]metav1.Object{builder3.GetLegacy(), builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	// Create the Policies in specific order to make sure that priority re-assignments work as expected.
	testStepAll := []*TestStep{
		{
			"All three Policies",
			reachabilityAllACNPs,
			[]metav1.Object{builder3.GetLegacy(), builder1.GetLegacy(), builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP PriorityOverride Intermediate", testStepTwoACNP},
		{"ACNP PriorityOverride All", testStepAll},
	}
	executeLegacyTests(t, testCase)
}

// testACNPTierOverride tests tier priority overriding in three Policies.
// Each ACNP controls a smaller set of traffic patterns as tier priority increases.
func testLegacyACNPTierOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-emergency").
		SetTier("emergency").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Highest priority. Drops traffic from z/b to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-securityops").
		SetTier("securityops").
		SetPriority(10).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	builder3 := &ClusterNetworkPolicySpecBuilder{}
	builder3 = builder3.SetName("acnp-tier-application").
		SetTier("application").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	// Lowest priority tier. Drops traffic from z to x.
	builder3.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/c"), Pod("x/c"), Dropped)

	reachabilityAllACNPs := NewReachability(allPods, Connected)
	reachabilityAllACNPs.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/b"), Pod("x/a"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachabilityAllACNPs.Expect(Pod("z/c"), Pod("x/c"), Dropped)

	testStepTwoACNP := []*TestStep{
		{
			"Two Policies in different tiers",
			reachabilityTwoACNPs,
			[]metav1.Object{builder3.GetLegacy(), builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testStepAll := []*TestStep{
		{
			"All three Policies in different tiers",
			reachabilityAllACNPs,
			[]metav1.Object{builder3.GetLegacy(), builder1.GetLegacy(), builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP TierOverride Intermediate", testStepTwoACNP},
		{"ACNP TierOverride All", testStepAll},
	}
	executeLegacyTests(t, testCase)
}

// testACNPTierOverride tests tier priority overriding in three Policies with custom created tiers.
// Each ACNP controls a smaller set of traffic patterns as tier priority increases.
func testLegacyACNPCustomTiers(t *testing.T) {
	k8sUtils.DeleteLegacyTier("high-priority")
	k8sUtils.DeleteLegacyTier("low-priority")
	// Create two custom tiers with tier priority immediately next to each other.
	_, err := k8sUtils.CreateNewLegacyTier("high-priority", 245)
	failOnError(err, t)
	_, err = k8sUtils.CreateNewLegacyTier("low-priority", 246)
	failOnError(err, t)

	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-high").
		SetTier("high-priority").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	time.Sleep(mockWait)
	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-tier-low").
		SetTier("low-priority").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	// Lowest priority tier. Drops traffic from z to x.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachabilityTwoACNPs := NewReachability(allPods, Connected)
	reachabilityTwoACNPs.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachabilityTwoACNPs.Expect(Pod("z/c"), Pod("x/c"), Dropped)
	testStepTwoACNP := []*TestStep{
		{
			"Two Policies in different tiers",
			reachabilityTwoACNPs,
			[]metav1.Object{builder2.GetLegacy(), builder1.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Custom Tier priority", testStepTwoACNP},
	}
	executeLegacyTests(t, testCase)
	// Cleanup customed tiers. ACNPs created in those tiers need to be deleted first.
	failOnError(k8sUtils.CleanLegacyACNPs(), t)
	failOnError(k8sUtils.DeleteLegacyTier("high-priority"), t)
	failOnError(k8sUtils.DeleteLegacyTier("low-priority"), t)
}

// testACNPPriorityConflictingRule tests that if there are two Policies in the cluster with rules that conflicts with
// each other, the ACNP with higher priority will prevail.
func testLegacyACNPPriorityConflictingRule(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-drop").
		SetPriority(1).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(2).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	// The following ingress rule will take no effect as it is exactly the same as ingress rule of cnp-drop,
	// but cnp-allow has lower priority.
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.Expect(Pod("z/a"), Pod("x/a"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/a"), Pod("x/b"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/a"), Pod("x/c"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/b"), Pod("x/a"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/b"), Pod("x/b"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/b"), Pod("x/c"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/c"), Pod("x/a"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/c"), Pod("x/b"), Dropped)
	reachabilityBothACNP.Expect(Pod("z/c"), Pod("x/c"), Dropped)

	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder1.GetLegacy(), builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Priority Conflicting Rule", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPPriorityConflictingRule tests that if there are two rules in the cluster that conflicts with
// each other, the rule with higher precedence will prevail.
func testLegacyACNPRulePrioirty(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	// acnp-deny will apply to all pods in namespace x
	builder1 = builder1.SetName("acnp-deny").
		SetPriority(5).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder1.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "y"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")
	// This rule should take no effect as it will be overridden by the first rule of cnp-allow
	builder1.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	// acnp-allow will also apply to all pods in namespace x
	builder2 = builder2.SetName("acnp-allow").
		SetPriority(5).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder2.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	// This rule should take no effect as it will be overridden by the first rule of cnp-drop
	builder2.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "y"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

	// Only egress from pods in namespace x to namespace y should be denied
	reachabilityBothACNP := NewReachability(allPods, Connected)
	reachabilityBothACNP.Expect(Pod("x/a"), Pod("y/a"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/c"), Pod("y/a"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/a"), Pod("y/b"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/b"), Pod("y/b"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/c"), Pod("y/b"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/a"), Pod("y/c"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/b"), Pod("y/c"), Dropped)
	reachabilityBothACNP.Expect(Pod("x/c"), Pod("y/c"), Dropped)

	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder2.GetLegacy(), builder1.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Rule Priority", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testACNPPortRange tests the port range in a ACNP can work.
func testLegacyACNPPortRange(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8080, nil, &p8085, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	var testSteps []*TestStep
	testSteps = append(testSteps, &TestStep{
		fmt.Sprint("ACNP Drop Port 8080:8085"),
		reachability,
		[]metav1.Object{builder.GetLegacy()},
		nil,
		[]int32{8080, 8081, 8082, 8083, 8084, 8085},
		v1.ProtocolTCP,
		0,
		nil,
	})

	testCase := []*TestCase{
		{"ACNP Drop Egress From All Pod:a to NS:z with a portRange", testSteps},
	}
	executeLegacyTests(t, testCase)
}

// testACNPRejectEgress tests that a ACNP is able to reject egress traffic from pods labelled A to namespace Z.
func testLegacyACNPRejectEgress(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-a-to-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Rejected)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Rejected)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Rejected)
	reachability.Expect(Pod("y/a"), Pod("z/a"), Rejected)
	reachability.Expect(Pod("y/a"), Pod("z/b"), Rejected)
	reachability.Expect(Pod("y/a"), Pod("z/c"), Rejected)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Rejected)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Rejected)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Reject egress From All Pod:a to NS:z", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testLegacyACNPRejectIngress tests that a ACNP is able to reject egress traffic from pods labelled A to namespace Z.
func testLegacyACNPRejectIngress(t *testing.T, protocol v1.Protocol) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-a-from-z-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("z/a"), Pod("x/a"), Rejected)
	reachability.Expect(Pod("z/b"), Pod("x/a"), Rejected)
	reachability.Expect(Pod("z/c"), Pod("x/a"), Rejected)
	reachability.Expect(Pod("z/a"), Pod("y/a"), Rejected)
	reachability.Expect(Pod("z/b"), Pod("y/a"), Rejected)
	reachability.Expect(Pod("z/c"), Pod("y/a"), Rejected)
	reachability.Expect(Pod("z/b"), Pod("z/a"), Rejected)
	reachability.Expect(Pod("z/c"), Pod("z/a"), Rejected)

	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			protocol,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Reject ingress from NS:z to All Pod:a", testStep},
	}
	executeLegacyTests(t, testCase)
}

// testANPPortRange tests the port range in a ANP can work.
func testLegacyANPPortRange(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "anp-deny-yb-to-xc-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8080, nil, &p8085, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionDrop, "anp-port-range")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("y/b"), Pod("x/c"), Dropped)

	var testSteps []*TestStep
	testSteps = append(testSteps, &TestStep{
		fmt.Sprint("ANP Drop Port 8080:8085"),
		reachability,
		[]metav1.Object{builder.GetLegacy()},
		nil,
		[]int32{8080, 8081, 8082, 8083, 8084, 8085},
		v1.ProtocolTCP,
		0,
		nil,
	})

	testCase := []*TestCase{
		{"ANP Drop Egress y/b to x/c with a portRange", testSteps},
	}
	executeLegacyTests(t, testCase)
}

// testANPBasic tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea NetworkPolicy
// that specifies that. Also it tests that a K8s NetworkPolicy with same appliedTo will not affect its behavior.
func testLegacyANPBasic(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "np-same-name").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionDrop, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	// build a K8s NetworkPolicy that has the same appliedTo but allows all traffic.
	k8sNPBuilder := &NetworkPolicySpecBuilder{}
	k8sNPBuilder = k8sNPBuilder.SetName("y", "np-same-name").
		SetPodSelector(map[string]string{"pod": "a"})
	k8sNPBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil,
		nil, nil, nil, nil)
	testStep2 := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy(), k8sNPBuilder.Get()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ANP Drop X/B to Y/A", testStep},
		{"With K8s NetworkPolicy of the same name", testStep2},
	}
	executeLegacyTests(t, testCase)
}

// testAuditLoggingBasic tests that a audit log is generated when egress drop applied
func testLegacyAuditLoggingBasic(t *testing.T, data *TestData) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-log-acnp-deny").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")
	builder.AddEgressLogging()

	_, err := k8sUtils.CreateOrUpdateLegacyACNP(builder.GetLegacy())
	failOnError(err, t)
	time.Sleep(networkPolicyDelay)

	// generate some traffic that will be dropped by test-log-acnp-deny
	k8sUtils.Probe("x", "a", "z", "a", p80, v1.ProtocolTCP)
	k8sUtils.Probe("x", "a", "z", "b", p80, v1.ProtocolTCP)
	k8sUtils.Probe("x", "a", "z", "c", p80, v1.ProtocolTCP)
	time.Sleep(networkPolicyDelay)

	podXA, err := k8sUtils.GetPodByLabel("x", "a")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace x with label 'pod=a': %v", err)
	}
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
	assert.Equalf(t, true, strings.Contains(stdout, "test-log-acnp-deny"), "audit log does not contain entries for test-log-acnp-deny")

	destinations := []string{"z/a", "z/b", "z/c"}
	srcIPs := podIPs["x/a"]
	for _, d := range destinations {
		dstIPs := podIPs[d]
		for i := 0; i < len(srcIPs); i++ {
			for j := 0; j < len(dstIPs); j++ {
				if strings.Contains(srcIPs[i], ".") == strings.Contains(dstIPs[j], ".") {
					// The audit log should contain log entry `... Drop <ofPriority> SRC: <x/a IP> DEST: <z/* IP> ...`
					pattern := `Drop [0-9]+ SRC: ` + srcIPs[i] + ` DEST: ` + dstIPs[j]
					assert.Regexp(t, pattern, stdout, "audit log does not contain expected entry for x/a to %s", d)
					break
				}
			}
		}
	}
	failOnError(k8sUtils.CleanLegacyACNPs(), t)
}

func testLegacyAppliedToPerRule(t *testing.T) {
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "np1").SetPriority(1.0)
	anpATGrp1 := ANPAppliedToSpec{PodSelector: map[string]string{"pod": "a"}, PodSelectorMatchExp: nil}
	anpATGrp2 := ANPAppliedToSpec{PodSelector: map[string]string{"pod": "b"}, PodSelectorMatchExp: nil}
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, []ANPAppliedToSpec{anpATGrp1}, crdv1alpha1.RuleActionDrop, "")
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"},
		nil, nil, []ANPAppliedToSpec{anpATGrp2}, crdv1alpha1.RuleActionDrop, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachability.Expect(Pod("z/b"), Pod("y/b"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("cnp1").SetPriority(1.0)
	cnpATGrp1 := ACNPAppliedToSpec{PodSelector: map[string]string{"pod": "a"}, PodSelectorMatchExp: nil}
	cnpATGrp2 := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"}, NSSelector: map[string]string{"ns": "y"},
		PodSelectorMatchExp: nil, NSSelectorMatchExp: nil}
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, []ACNPAppliedToSpec{cnpATGrp1}, crdv1alpha1.RuleActionDrop, "", "")
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"},
		nil, nil, false, []ACNPAppliedToSpec{cnpATGrp2}, crdv1alpha1.RuleActionDrop, "", "")

	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod("x/b"), Pod("x/a"), Dropped)
	reachability2.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachability2.Expect(Pod("x/b"), Pod("z/a"), Dropped)
	reachability2.Expect(Pod("z/b"), Pod("y/b"), Dropped)
	testStep2 := []*TestStep{
		{
			"Port 80",
			reachability2,
			[]metav1.Object{builder2.GetLegacy()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}

	testCase := []*TestCase{
		{"ANP AppliedTo per rule", testStep},
		{"ACNP AppliedTo per rule", testStep2},
	}
	executeLegacyTests(t, testCase)
}

func testLegacyACNPClusterGroupServiceRefCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", "x", 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", "y", 80, 80, map[string]string{"app": "b"}, nil)

	cg1Name, cg2Name := "cg-svc1", "cg-svc2"
	cgBuilder1 := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference("x", "svc1")
	cgBuilder2 := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).SetServiceReference("y", "svc2")

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-cg-svc-ref").SetPriority(1.0).SetAppliedToGroup([]ACNPAppliedToSpec{{Group: cg1Name}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil,
		false, nil, crdv1alpha1.RuleActionDrop, cg2Name, "")

	// Pods backing svc1 (label pod=a) in Namespace x should not allow ingress from Pods backing svc2 (label pod=b) in Namespace y.
	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("y/b"), Pod("x/a"), Dropped)
	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{builder.GetLegacy()},
		[]metav1.Object{svc1, svc2, cgBuilder1.GetLegacy(), cgBuilder2.GetLegacy()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	// Test update selector of Service referred in cg-svc1, and update serviceReference of cg-svc2.
	svc1Updated := k8sUtils.BuildService("svc1", "x", 80, 80, map[string]string{"app": "b"}, nil)
	svc3 := k8sUtils.BuildService("svc3", "y", 80, 80, map[string]string{"app": "a"}, nil)
	cgBuilder2Updated := cgBuilder2.SetServiceReference("y", "svc3")
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod("y", "test-add-pod-svc3"),
				Labels: map[string]string{"pod": "test-add-pod-svc3", "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod("x", "test-add-pod-svc1"),
				Labels: map[string]string{"pod": "test-add-pod-svc1", "app": "b"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}

	// Pods backing svc1 (label pod=b) in namespace x should not allow ingress from Pods backing svc3 (label pod=a) in namespace y.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod("y/a"), Pod("x/b"), Dropped)
	testStep2 := &TestStep{
		"Port 80 updated",
		reachability2,
		[]metav1.Object{builder.GetLegacy()},
		[]metav1.Object{svc1Updated, svc3, cgBuilder1.GetLegacy(), cgBuilder2Updated.GetLegacy()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		cp,
	}

	builderUpdated := &ClusterNetworkPolicySpecBuilder{}
	builderUpdated = builderUpdated.SetName("cnp-cg-svc-ref").SetPriority(1.0)
	builderUpdated.SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	builderUpdated.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	// Pod x/a should not allow ingress from y/b per the updated ACNP spec.
	testStep3 := &TestStep{
		"Port 80 ACNP spec updated to selector",
		reachability,
		[]metav1.Object{builderUpdated.GetLegacy()},
		[]metav1.Object{},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ACNP ClusterGroup Service Reference create and update", testSteps},
	}
	executeLegacyTestsWithData(t, testCase, data)
}

func testLegacyACNPNestedClusterGroupCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", "x", 80, 80, map[string]string{"app": "a"}, nil)
	cg1Name, cg2Name := "cg-svc-x-a", "cg-select-y-b"
	cgBuilder1 := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference("x", "svc1")
	cgBuilder2 := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).
		SetNamespaceSelector(map[string]string{"ns": "y"}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
	cgNestedName := "cg-nested"
	cgBuilderNested := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilderNested = cgBuilderNested.SetName(cgNestedName).SetChildGroups([]string{cg1Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-nested-cg").SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "z"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil,
			false, nil, crdv1alpha1.RuleActionDrop, cgNestedName, "")

	// Pods in Namespace z should not allow ingress from Pods backing svc1 (label pod=a) in Namespace x.
	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("x/a"), Pod("z/c"), Dropped)

	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{builder.GetLegacy()},
		[]metav1.Object{svc1, cgBuilder1.GetLegacy(), cgBuilderNested.GetLegacy()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	// Test update "cg-nested" to include "cg-select-y-b" as well.
	cgBuilderNested = cgBuilderNested.SetChildGroups([]string{cg1Name, cg2Name})
	// In addition to x/a, all traffic from y/b to Namespace z should also be denied.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.Expect(Pod("x/a"), Pod("z/a"), Dropped)
	reachability2.Expect(Pod("x/a"), Pod("z/b"), Dropped)
	reachability2.Expect(Pod("x/a"), Pod("z/c"), Dropped)
	reachability2.Expect(Pod("y/b"), Pod("z/a"), Dropped)
	reachability2.Expect(Pod("y/b"), Pod("z/b"), Dropped)
	reachability2.Expect(Pod("y/b"), Pod("z/c"), Dropped)
	// New member in cg-svc-x-a should be reflected in cg-nested as well.
	cp := []*CustomProbe{
		{
			SourcePod: CustomPod{
				Pod:    NewPod("x", "test-add-pod-svc1"),
				Labels: map[string]string{"pod": "test-add-pod-svc1", "app": "a"},
			},
			DestPod: CustomPod{
				Pod:    NewPod("z", "test-add-pod-ns-z"),
				Labels: map[string]string{"pod": "test-add-pod-ns-z"},
			},
			ExpectConnectivity: Dropped,
			Port:               p80,
		},
	}
	testStep2 := &TestStep{
		"Port 80 updated",
		reachability2,
		nil,
		[]metav1.Object{cgBuilder2.GetLegacy(), cgBuilderNested.GetLegacy()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		cp,
	}

	testSteps := []*TestStep{testStep1, testStep2}
	testCase := []*TestCase{
		{"ACNP nested ClusterGroup create and update", testSteps},
	}
	executeLegacyTestsWithData(t, testCase, data)
}

// executeTests runs all the tests in testList and prints results
func executeLegacyTests(t *testing.T, testList []*TestCase) {
	executeLegacyTestsWithData(t, testList, nil)
}

func executeLegacyTestsWithData(t *testing.T, testList []*TestCase, data *TestData) {
	for _, testCase := range testList {
		log.Infof("running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			applyLegacyTestStepServicesAndGroups(t, step)
			applyLegacyTestStepPolicies(t, step)
			time.Sleep(networkPolicyDelay)

			reachability := step.Reachability
			if reachability != nil {
				start := time.Now()
				for _, port := range step.Port {
					k8sUtils.Validate(allPods, reachability, port, step.Protocol)
				}
				step.Duration = time.Since(start)

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
		cleanupLegacyTestCasePolicies(t, testCase)
		cleanupLegacyTestCaseServicesAndGroups(t, testCase)
		time.Sleep(networkPolicyDelay)
	}
	allTestList = append(allTestList, testList...)
}

func applyLegacyTestStepPolicies(t *testing.T, step *TestStep) {
	for _, policy := range step.Policies {
		switch p := policy.(type) {
		case *legacysecv1alpha1.ClusterNetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateLegacyACNP(p)
			failOnError(err, t)
		case *legacysecv1alpha1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateLegacyANP(p)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(p)
			failOnError(err, t)
		}
		warningOnTimeoutError(waitForResourceReady(policy, timeout), t)
	}
	if len(step.Policies) > 0 {
		log.Debugf("Sleeping for %v for all policies to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

func cleanupLegacyTestCasePolicies(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same policy.
	// Use sets to avoid duplicates.
	acnpsToDelete, anpsToDelete, npsToDelete := sets.String{}, sets.String{}, sets.String{}
	for _, step := range c.Steps {
		for _, policy := range step.Policies {
			switch p := policy.(type) {
			case *legacysecv1alpha1.ClusterNetworkPolicy:
				acnpsToDelete.Insert(p.Name)
			case *legacysecv1alpha1.NetworkPolicy:
				anpsToDelete.Insert(p.Namespace + "/" + p.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(p.Namespace + "/" + p.Name)
			}
		}
	}
	for _, acnp := range acnpsToDelete.List() {
		failOnError(k8sUtils.DeleteLegacyACNP(acnp), t)
		warningOnTimeoutError(waitForResourceDelete("", acnp, resourceACNP, timeout), t)
	}
	for _, anp := range anpsToDelete.List() {
		namespace := strings.Split(anp, "/")[0]
		name := strings.Split(anp, "/")[1]
		failOnError(k8sUtils.DeleteLegacyANP(namespace, name), t)
		warningOnTimeoutError(waitForResourceDelete(namespace, name, resourceANP, timeout), t)
	}
	for _, np := range npsToDelete.List() {
		namespace := strings.Split(np, "/")[0]
		name := strings.Split(np, "/")[1]
		failOnError(k8sUtils.DeleteNetworkPolicy(namespace, name), t)
		warningOnTimeoutError(waitForResourceDelete(namespace, name, resourceNetworkPolicy, timeout), t)
	}
	if acnpsToDelete.Len()+anpsToDelete.Len()+npsToDelete.Len() > 0 {
		log.Debugf("Sleeping for %v for all policy deletions to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

func applyLegacyTestStepServicesAndGroups(t *testing.T, step *TestStep) {
	for _, obj := range step.ServicesAndGroups {
		switch o := obj.(type) {
		case *legacycorev1a2.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateLegacyCG(o)
			failOnError(err, t)
		case *v1.Service:
			_, err := k8sUtils.CreateOrUpdateService(o)
			failOnError(err, t)
		}
		warningOnTimeoutError(waitForResourceReady(obj, timeout), t)
	}
	if len(step.ServicesAndGroups) > 0 {
		log.Debugf("Sleeping for %v for all groups to have members computed", groupDelay)
		time.Sleep(groupDelay)
	}
}

func cleanupLegacyTestCaseServicesAndGroups(t *testing.T, c *TestCase) {
	svcsToDelete, groupsToDelete := sets.String{}, sets.String{}
	var orderedGroups []string
	for _, step := range c.Steps {
		for _, obj := range step.ServicesAndGroups {
			switch o := obj.(type) {
			case *legacycorev1a2.ClusterGroup:
				groupsToDelete.Insert(o.Name)
				orderedGroups = append(orderedGroups, o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}

	for i := len(orderedGroups) - 1; i >= 0; i-- {
		cg := orderedGroups[i]
		if groupsToDelete.Has(cg) {
			failOnError(k8sUtils.DeleteLegacyCG(cg), t)
			warningOnTimeoutError(waitForResourceDelete("", cg, resourceCG, timeout), t)
			groupsToDelete.Delete(cg)
		}
	}

	for _, svc := range svcsToDelete.List() {
		namespace := strings.Split(svc, "/")[0]
		name := strings.Split(svc, "/")[1]
		failOnError(k8sUtils.DeleteService(namespace, name), t)
		warningOnTimeoutError(waitForResourceDelete(namespace, name, resourceSVC, timeout), t)
	}
}

func TestLegacyAntreaPolicy(t *testing.T) {
	skipIfProviderIs(t, "kind", "This test is for legacy API groups and is almost the same as new API groups'.")
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	initialize(t, data)

	t.Run("TestGroupValidateAntreaNativePolicies", func(t *testing.T) {
		t.Run("Case=LegacyACNPNoPriority", func(t *testing.T) { testLegacyInvalidACNPNoPriority(t) })
		t.Run("Case=LegacyACNPRuleNameNotUniqueDenied", func(t *testing.T) { testLegacyInvalidACNPRuleNameNotUnique(t) })
		t.Run("Case=LegacyACNPTierDoesNotExistDenied", func(t *testing.T) { testLegacyInvalidACNPTierDoesNotExist(t) })
		t.Run("Case=LegacyACNPPortRangePortUnsetDenied", func(t *testing.T) { testLegacyInvalidACNPPortRangePortUnset(t) })
		t.Run("Case=LegacyACNPPortRangePortEndPortSmallDenied", func(t *testing.T) { testLegacyInvalidACNPPortRangeEndPortSmall(t) })
		t.Run("Case=LegacyACNPIngressPeerCGSetWithIPBlock", func(t *testing.T) { testLegacyInvalidACNPIngressPeerCGSetWithIPBlock(t) })
		t.Run("Case=LegacyACNPIngressPeerCGSetWithPodSelector", func(t *testing.T) { testLegacyInvalidACNPIngressPeerCGSetWithPodSelector(t) })
		t.Run("Case=LegacyACNPIngressPeerCGSetWithNSSelector", func(t *testing.T) { testLegacyInvalidACNPIngressPeerCGSetWithNSSelector(t) })
		t.Run("Case=LegacyACNPCGDoesNotExist", func(t *testing.T) { testLegacyInvalidACNPCGDoesNotExist(t) })
		t.Run("Case=LegacyACNPAppliedToCGDoesNotExist", func(t *testing.T) { testLegacyInvalidACNPAppliedToCGDoesNotExist(t) })
		t.Run("Case=LegacyACNPSpecAppliedToRuleAppliedToSet", func(t *testing.T) { testLegacyInvalidACNPSpecAppliedToRuleAppliedToSet(t) })
		t.Run("Case=LegacyACNPAppliedToNotSetInAllRules", func(t *testing.T) { testLegacyInvalidACNPAppliedToNotSetInAllRules(t) })
		t.Run("Case=LegacyANPNoPriority", func(t *testing.T) { testLegacyInvalidANPNoPriority(t) })
		t.Run("Case=LegacyANPRuleNameNotUniqueDenied", func(t *testing.T) { testLegacyInvalidANPRuleNameNotUnique(t) })
		t.Run("Case=LegacyANPTierDoesNotExistDenied", func(t *testing.T) { testLegacyInvalidANPTierDoesNotExist(t) })
		t.Run("Case=LegacyANPPortRangePortUnsetDenied", func(t *testing.T) { testLegacyInvalidANPPortRangePortUnset(t) })
		t.Run("Case=LegacyANPPortRangePortEndPortSmallDenied", func(t *testing.T) { testLegacyInvalidANPPortRangeEndPortSmall(t) })
	})

	t.Run("TestGroupValidateTiers", func(t *testing.T) {
		t.Run("Case=LegacyTierOverlapPriorityDenied", func(t *testing.T) { testLegacyInvalidTierPriorityOverlap(t) })
		t.Run("Case=LegacyTierOverlapReservedTierPriorityDenied", func(t *testing.T) { testLegacyInvalidTierReservedPriority(t) })
		t.Run("Case=LegacyTierPriorityUpdateDenied", func(t *testing.T) { testLegacyInvalidTierPriorityUpdate(t) })
		t.Run("Case=LegacyTierACNPReferencedDeleteDenied", func(t *testing.T) { testLegacyInvalidTierACNPRefDelete(t) })
		t.Run("Case=LegacyTierANPRefDeleteDenied", func(t *testing.T) { testLegacyInvalidTierANPRefDelete(t) })
		t.Run("Case=LegacyTierReservedDeleteDenied", func(t *testing.T) { testLegacyInvalidTierReservedDelete(t) })
	})

	t.Run("TestGroupMutateAntreaNativePolicies", func(t *testing.T) {
		t.Run("Case=LegacyACNPNoTierSetDefaultTier", func(t *testing.T) { testLegacyMutateACNPNoTier(t) })
		t.Run("Case=LegacyANPNoTierSetDefaultTier", func(t *testing.T) { testLegacyMutateANPNoTier(t) })
		t.Run("Case=LegacyANPNoRuleNameSetRuleName", func(t *testing.T) { testLegacyMutateANPNoRuleName(t) })
		t.Run("Case=LegacyACNPNoRuleNameSetRuleName", func(t *testing.T) { testLegacyMutateACNPNoRuleName(t) })
	})

	t.Run("TestGroupDefaultDENY", func(t *testing.T) {
		// testcases below require default-deny k8s NetworkPolicies to work
		applyDefaultDenyToAllNamespaces(k8sUtils, namespaces)
		t.Run("Case=LegacyACNPAllowXBtoA", func(t *testing.T) { testLegacyACNPAllowXBtoA(t) })
		t.Run("Case=LegacyACNPAllowXBtoYA", func(t *testing.T) { testLegacyACNPAllowXBtoYA(t) })
		t.Run("Case=LegacyACNPPriorityOverrideDefaultDeny", func(t *testing.T) { testLegacyACNPPriorityOverrideDefaultDeny(t) })
		cleanupDefaultDenyNPs(k8sUtils, namespaces)
	})

	t.Run("TestGroupNoK8sNP", func(t *testing.T) {
		// testcases below do not depend on underlying default-deny K8s NetworkPolicies.
		t.Run("Case=LegacyACNPAllowNoDefaultIsolationTCP", func(t *testing.T) { testLegacyACNPAllowNoDefaultIsolation(t, v1.ProtocolTCP) })
		t.Run("Case=LegacyACNPAllowNoDefaultIsolationUDP", func(t *testing.T) { testLegacyACNPAllowNoDefaultIsolation(t, v1.ProtocolUDP) })
		t.Run("Case=LegacyACNPAllowNoDefaultIsolationSCTP", func(t *testing.T) { testLegacyACNPAllowNoDefaultIsolation(t, v1.ProtocolSCTP) })
		t.Run("Case=LegacyACNPDropEgress", func(t *testing.T) { testLegacyACNPDropEgress(t, v1.ProtocolTCP) })
		t.Run("Case=LegacyACNPDropEgressUDP", func(t *testing.T) { testLegacyACNPDropEgress(t, v1.ProtocolUDP) })
		t.Run("Case=LegacyACNPDropEgressSCTP", func(t *testing.T) { testLegacyACNPDropEgress(t, v1.ProtocolSCTP) })
		t.Run("Case=LegacyACNPPortRange", func(t *testing.T) { testLegacyACNPPortRange(t) })
		t.Run("Case=LegacyACNPRejectEgress", func(t *testing.T) { testLegacyACNPRejectEgress(t) })
		t.Run("Case=LegacyACNPRejectIngress", func(t *testing.T) { testLegacyACNPRejectIngress(t, v1.ProtocolTCP) })
		t.Run("Case=LegacyACNPRejectIngressUDP", func(t *testing.T) { testLegacyACNPRejectIngress(t, v1.ProtocolUDP) })
		t.Run("Case=LegacyACNPNoEffectOnOtherProtocols", func(t *testing.T) { testLegacyACNPNoEffectOnOtherProtocols(t) })
		t.Run("Case=LegacyACNPBaselinePolicy", func(t *testing.T) { testLegacyBaselineNamespaceIsolation(t) })
		t.Run("Case=LegacyACNPPrioirtyOverride", func(t *testing.T) { testLegacyACNPPriorityOverride(t) })
		t.Run("Case=LegacyACNPTierOverride", func(t *testing.T) { testLegacyACNPTierOverride(t) })
		t.Run("Case=LegacyACNPCustomTiers", func(t *testing.T) { testLegacyACNPCustomTiers(t) })
		t.Run("Case=LegacyACNPPriorityConflictingRule", func(t *testing.T) { testLegacyACNPPriorityConflictingRule(t) })
		t.Run("Case=LegacyACNPRulePriority", func(t *testing.T) { testLegacyACNPRulePrioirty(t) })
		t.Run("Case=LegacyANPPortRange", func(t *testing.T) { testLegacyANPPortRange(t) })
		t.Run("Case=LegacyANPBasic", func(t *testing.T) { testLegacyANPBasic(t) })
		t.Run("Case=LegacyAppliedToPerRule", func(t *testing.T) { testLegacyAppliedToPerRule(t) })
		t.Run("Case=LegacyACNPClusterGroupEgressRulePodsAToCGWithNsZ", func(t *testing.T) { testLegacyACNPEgressRulePodsAToCGWithNsZ(t) })
		t.Run("Case=LegacyACNPClusterGroupUpdate", func(t *testing.T) { testLegacyACNPClusterGroupUpdate(t) })
		t.Run("Case=LegacyACNPClusterGroupAppliedToDenyXBToCGWithYA", func(t *testing.T) { testLegacyACNPAppliedToDenyXBtoCGWithYA(t) })
		t.Run("Case=LegacyACNPClusterGroupAppliedToRuleCGWithPodsAToNsZ", func(t *testing.T) { testLegacyACNPAppliedToRuleCGWithPodsAToNsZ(t) })
		t.Run("Case=LegacyACNPClusterGroupUpdateAppliedTo", func(t *testing.T) { testLegacyACNPClusterGroupUpdateAppliedTo(t) })
		t.Run("Case=LegacyACNPClusterGroupAppliedToPodAdd", func(t *testing.T) { testLegacyACNPClusterGroupAppliedToPodAdd(t, data) })
		t.Run("Case=LegacyACNPClusterGroupRefRulePodAdd", func(t *testing.T) { testLegacyACNPClusterGroupRefRulePodAdd(t, data) })
		t.Run("Case=LegacyACNPClusterGroupIngressRuleDenyCGWithXBtoYA", func(t *testing.T) { testLegacyACNPIngressRuleDenyCGWithXBtoYA(t) })
		t.Run("Case=LegacyACNPClusterGroupServiceRef", func(t *testing.T) { testLegacyACNPClusterGroupServiceRefCreateAndUpdate(t, data) })
		t.Run("Case=LegacyACNPNestedClusterGroup", func(t *testing.T) { testLegacyACNPNestedClusterGroupCreateAndUpdate(t, data) })
	})
	// print results for reachability tests
	printResults()

	t.Run("TestGroupAuditLogging", func(t *testing.T) {
		t.Run("Case=LegacyAuditLoggingBasic", func(t *testing.T) { testLegacyAuditLoggingBasic(t, data) })
	})
	k8sUtils.LegacyCleanup(namespaces)
}

func TestLegacyAntreaPolicyStatus(t *testing.T) {
	skipIfProviderIs(t, "kind", "This test is for legacy API groups and is almost the same as new API groups'.")
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	_, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-0", controlPlaneNodeName(), testNamespace)
	defer cleanupFunc()
	_, _, cleanupFunc = createAndWaitForPod(t, data, data.createNginxPodOnNode, "server-1", workerNodeName(1), testNamespace)
	defer cleanupFunc()

	anpBuilder := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(testNamespace, "anp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	anpBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionAllow, "")
	anp := anpBuilder.GetLegacy()
	log.Debugf("creating ANP %v", anp.Name)
	_, err = data.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(anp.Namespace).Delete(context.TODO(), anp.Name, metav1.DeleteOptions{})

	acnpBuilder := &ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("acnp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	acnpBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	acnp := acnpBuilder.GetLegacy()
	log.Debugf("creating ACNP %v", acnp.Name)
	_, err = data.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Create(context.TODO(), acnp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), acnp.Name, metav1.DeleteOptions{})

	expectedStatus := crdv1alpha1.NetworkPolicyStatus{
		Phase:                crdv1alpha1.NetworkPolicyRealized,
		ObservedGeneration:   1,
		CurrentNodesRealized: 2,
		DesiredNodesRealized: 2,
	}
	err = wait.Poll(100*time.Millisecond, 3*time.Second, func() (bool, error) {
		anp, err := data.legacyCrdClient.SecurityV1alpha1().NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status == expectedStatus, nil
	})
	assert.NoError(t, err, "Antrea NetworkPolicy failed to reach expected status")
	err = wait.Poll(100*time.Millisecond, 3*time.Second, func() (bool, error) {
		anp, err := data.legacyCrdClient.SecurityV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), acnp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status == expectedStatus, nil
	})
	assert.NoError(t, err, "Antrea ClusterNetworkPolicy failed to reach expected status")
}

// testLegacyANPNetworkPolicyStatsWithDropAction tests antreanetworkpolicystats can correctly collect dropped packets stats from ANP if
// networkpolicystats feature is enabled
func testLegacyANPNetworkPolicyStatsWithDropAction(t *testing.T, data *TestData) {
	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", testNamespace)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
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
	protocol := v1.ProtocolUDP

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv4.String())}
		data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv6.String())}
		data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
	}
	var anp = &legacysecv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "np1", Labels: map[string]string{"antrea-e2e": "np1"}},
		Spec: crdv1alpha1.NetworkPolicySpec{
			AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
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

	if _, err = k8sUtils.CreateOrUpdateLegacyANP(anp); err != nil {
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
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 443", serverIPs.ipv4.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd2)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 80", serverIPs.ipv6.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 443", serverIPs.ipv6.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd2)
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
		stats, err := data.crdClient.StatsV1alpha1().AntreaNetworkPolicyStats(testNamespace).Get(context.TODO(), "np1", metav1.GetOptions{})
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
	k8sUtils.LegacyCleanup(namespaces)
}

func testLegacyAntreaClusterNetworkPolicyStats(t *testing.T, data *TestData) {
	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", testNamespace)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
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
	protocol := v1.ProtocolUDP

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv4.String())}
		data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv6.String())}
		data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
	}
	var acnp = &legacysecv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "cnp1", Labels: map[string]string{"antrea-e2e": "cnp1"}},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
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

	if _, err = k8sUtils.CreateOrUpdateLegacyACNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP failed for ACNP %s: %v", acnp.Name, err), t)
	}

	// Wait for a few seconds in case that connections are established before policies are enforced.
	time.Sleep(networkPolicyDelay)

	sessionsPerAddressFamily := 10
	var wg sync.WaitGroup
	for i := 0; i < sessionsPerAddressFamily; i++ {
		wg.Add(1)
		go func() {
			if clusterInfo.podV4NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 800", serverIPs.ipv4.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 4430", serverIPs.ipv4.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd2)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 800", serverIPs.ipv6.String())}
				cmd2 := []string{"/bin/sh", "-c", fmt.Sprintf("echo test | nc -w 4 -u %s 4430", serverIPs.ipv6.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd2)
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
	k8sUtils.LegacyCleanup(namespaces)
}
