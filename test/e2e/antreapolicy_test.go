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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	"antrea.io/antrea/pkg/features"
	legacycorev1a2 "antrea.io/antrea/pkg/legacyapis/core/v1alpha2"
	legacysecv1alpha1 "antrea.io/antrea/pkg/legacyapis/security/v1alpha1"
	. "antrea.io/antrea/test/e2e/utils"
)

// common for all tests.
var (
	allPods                              []Pod
	podsByNamespace                      map[string][]Pod
	k8sUtils                             *KubernetesUtils
	allTestList                          []*TestCase
	pods, namespaces                     []string
	podIPs                               map[string][]string
	p80, p81, p8080, p8081, p8082, p8085 int32
)

const (
	// Provide enough time for policies to be enforced & deleted by the CNI plugin.
	networkPolicyDelay = 2000 * time.Millisecond
	// Timeout when waiting for a policy status to be updated and for the
	// policy to be considered realized.
	policyRealizedTimeout = 5 * time.Second
	// provide enough time for groups to have members computed.
	groupDelay = time.Second
	// Verification of deleting/creating resources timed out.
	timeout = 10 * time.Second
	// audit log directory on Antrea Agent
	logDir          = "/var/log/antrea/networkpolicy/"
	logfileName     = "np.log"
	defaultTierName = "application"

	resourceACNP          = "acnp"
	resourceANP           = "anp"
	resourceNetworkPolicy = "networkPolicy"
	resourceCG            = "clusterGroup"
	resourceSVC           = "service"
	resourceTier          = "tier"
)

// TestAntreaPolicyStats is the top-level test which contains all subtests for
// AntreaPolicyStats related test cases so they can share setup, teardown.
func TestAntreaPolicyStats(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testANPNetworkPolicyStatsWithDropAction", func(t *testing.T) {
		skipIfNetworkPolicyStatsDisabled(t)
		testANPNetworkPolicyStatsWithDropAction(t, data)
	})
	t.Run("testAntreaClusterNetworkPolicyStats", func(t *testing.T) {
		skipIfNetworkPolicyStatsDisabled(t)
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

func warningOnTimeoutError(err error, t *testing.T) {
	if err != nil {
		log.Warningf("Timeout for getting expected status and the tests may get unexpted results.")
		t.Fatalf("test warned: %v", err)
	}
}

// TestCase is a collection of TestSteps to be tested against.
type TestCase struct {
	Name  string
	Steps []*TestStep
}

// TestStep is a single unit of testing spec. It includes the policy specs that need to be
// applied for this test, the port to test traffic on and the expected Reachability matrix.
type TestStep struct {
	Name              string
	Reachability      *Reachability
	Policies          []metav1.Object
	ServicesAndGroups []metav1.Object
	Port              []int32
	Protocol          v1.Protocol
	Duration          time.Duration
	CustomProbes      []*CustomProbe
}

// CustomProbe will spin up (or update) SourcePod and DestPod such that Add event of Pods
// can be tested against expected connectivity among those Pods.
type CustomProbe struct {
	// Create or update a source Pod.
	SourcePod CustomPod
	// Create or update a destination Pod.
	DestPod CustomPod
	// Port on which the probe will be made.
	Port int32
	// Set the expected connectivity.
	ExpectConnectivity PodConnectivityMark
}

func initialize(t *testing.T, data *TestData) {
	p80 = 80
	p81 = 81
	p8080 = 8080
	p8081 = 8081
	p8082 = 8082
	p8085 = 8085
	pods = []string{"a", "b", "c"}
	namespaces = []string{"x", "y", "z"}
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

func applyDefaultDenyToAllNamespaces(k8s *KubernetesUtils, namespaces []string) error {
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
	k8s.Validate(allPods, r, p80, v1.ProtocolTCP)
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
	r := NewReachability(allPods, Connected)
	k8s.Validate(allPods, r, p80, v1.ProtocolTCP)
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
	builder = builder.SetName("x", "anp-no-tier").
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
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
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
	builder = builder.SetName("x", "anp-no-rule-name").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetPriority(10.0).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionAllow, "")
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

func testInvalidACNPRuleNameNotUnique(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without unique rule names accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-rule-name-not-unique").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "not-unique").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "not-unique")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPTierDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy without existing Tier accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-tier-not-exist").
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		SetTier("i-dont-exist")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPPortRangePortUnset(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy egress rule with endPort but no port accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-egress-port-range-port-unset").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, nil, nil, &p8085, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range")

	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPPortRangeEndPortSmall(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy egress rule with endPort smaller than port accepted")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-egress-port-range-endport-small").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8082, nil, &p8081, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range")

	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPSpecAppliedToRuleAppliedToSet(t *testing.T) {
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
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPAppliedToNotSetInAllRules(t *testing.T) {
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
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPAppliedToCGDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy AppliedTo with non-existent clustergroup")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-appliedto-group-not-exist").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: "cgA"}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil,
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPCGDoesNotExist(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy rules with non-existent clustergroup")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-not-exist").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil,
			nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "cgA", "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPIngressPeerCGSetWithPodSelector(t *testing.T) {
	cgA := "cgA"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	ruleAppTo := ACNPAppliedToSpec{
		PodSelector: map[string]string{"pod": "b"},
	}
	k8sUtils.CreateCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and podSelector in NetworkPolicyPeer set")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-podselector-set").
		SetPriority(1.0)
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil,
		nil, nil, false, []ACNPAppliedToSpec{ruleAppTo}, crdv1alpha1.RuleActionAllow, "cgA", "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanCGs(), t)
}

func testInvalidACNPIngressPeerCGSetWithNSSelector(t *testing.T) {
	cgA := "cgA"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	k8sUtils.CreateCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and namespaceSelector in NetworkPolicyPeer set")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-nsselector-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "cgA", "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
	failOnError(k8sUtils.CleanCGs(), t)
}

func testInvalidACNPIngressPeerCGSetWithIPBlock(t *testing.T) {
	cgA := "cgA"
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	k8sUtils.CreateCG(cgA, &selectorA, nil, nil)
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with group and ipBlock in NetworkPolicyPeer set")
	cidr := "10.0.0.10/32"
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-group-ipblock-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{Group: "cgA"}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, &cidr, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, []ACNPAppliedToSpec{{Group: "cgB"}}, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidACNPIngressPeerNamespacesSetWithNSSelector(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea ClusterNetworkPolicy with namespaces and namespaceSelector in NetworkPolicyPeer set")
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-ingress-namespaces-nsselector-set").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder = builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "x"},
		nil, nil, true, nil, crdv1alpha1.RuleActionAllow, "", "")
	acnp := builder.Get()
	log.Debugf("creating ACNP %v", acnp.Name)
	if _, err := k8sUtils.CreateOrUpdateACNP(acnp); err == nil {
		// Above creation of ACNP must fail as it is an invalid spec.
		failOnError(invalidNpErr, t)
	}
}

func testInvalidANPNoPriority(t *testing.T) {
	invalidNpErr := fmt.Errorf("invalid Antrea NetworkPolicy without a priority accepted")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-no-priority").
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
	builder = builder.SetName("x", "anp-rule-name-not-unique").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionAllow, "not-unique").
		AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionAllow, "not-unique")
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
	builder = builder.SetName("x", "anp-tier-not-exist").
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
	builder = builder.SetName("y", "anp-egress-port-range-port-unset").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, nil, nil, &p8085, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionDrop, "anp-port-range")

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
	builder = builder.SetName("y", "anp-egress-port-range-endport-small").
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "b"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8082, nil, &p8081, nil, map[string]string{"pod": "c"}, map[string]string{"ns": "x"},
		nil, nil, nil, crdv1alpha1.RuleActionDrop, "anp-port-range")

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
	tr, err := k8sUtils.CreateNewTier("tier-anp", 10)
	if err != nil {
		failOnError(fmt.Errorf("create Tier failed for tier tier-anp: %v", err), t)
	}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "anp-for-tier").
		SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}).
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

// testInvalidACNPPodSelectorNsSelectorMatchExpressions tests creating a ClusterNetworkPolicy with invalid LabelSelector(MatchExpressions)
func testInvalidACNPPodSelectorNsSelectorMatchExpressions(t *testing.T) {
	invalidLSErr := fmt.Errorf("create Antrea NetworkPolicy with namespaceSelector but matchExpressions invalid")

	allowAction := crdv1alpha1.RuleActionAllow
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"env": "dummy"}}
	nsSelectA := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "env", Operator: "xxx", Values: []string{"xxxx"}}}}

	var acnp = &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: "cnptest", Labels: map[string]string{"antrea-e2e": "cnp1"}},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
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
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testACNPAllowXBtoYA tests traffic from X/B to Y/A on named port 81, after applying the default deny
// k8s NetworkPolicies in all namespaces and ACNP to allow X/B to Y/A.
func testACNPAllowXBtoYA(t *testing.T) {
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
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testACNPPriorityOverrideDefaultDeny tests priority override in ACNP. It applies a higher priority ACNP to drop
// traffic from namespace Z to X/A, and in the meantime applies a lower priority ACNP to allow traffic from Z to X.
// It is tested with default deny k8s NetworkPolicies in all namespaces.
func testACNPPriorityOverrideDefaultDeny(t *testing.T) {
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
			[]metav1.Object{builder1.Get(), builder2.Get()},
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
	executeTests(t, testCase)
}

// testACNPAllowNoDefaultIsolation tests that no default isolation rules are created for Policies.
func testACNPAllowNoDefaultIsolation(t *testing.T, protocol v1.Protocol) {
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
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testACNPDropEgress tests that an ACNP is able to drop egress traffic from pods labelled A to namespace Z.
func testACNPDropEgress(t *testing.T, protocol v1.Protocol) {
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
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testACNPDropIngressInSelectedNamespace tests that an ACNP is able to drop all ingress traffic towards a specific Namespace.
// The ACNP is created by selecting the Namespace as an appliedTo, and adding an ingress rule with Drop action and
// no `From` (which translate to drop ingress from everywhere).
func testACNPDropIngressInSelectedNamespace(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-ingress-to-x").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil, false, nil,
		crdv1alpha1.RuleActionDrop, "", "drop-all-ingress")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectAllIngress("x/a", Dropped)
	reachability.ExpectAllIngress("x/b", Dropped)
	reachability.ExpectAllIngress("x/c", Dropped)
	reachability.ExpectSelf(allPods, Connected)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
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
			[]metav1.Object{builder.Get()},
			nil,
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80",
			reachability2,
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testACNPAppliedToDenyXBtoCGWithYA tests traffic from X/B to ClusterGroup Y/A on named port 81 is dropped.
func testACNPAppliedToDenyXBtoCGWithYA(t *testing.T) {
	cgName := "cg-pods-ya"
	cgBuilder := &ClusterGroupV1Alpha2SpecBuilder{}
	cgBuilder = cgBuilder.SetName(cgName).
		SetNamespaceSelector(map[string]string{"ns": "y"}, nil).
		SetPodSelector(map[string]string{"pod": "a"}, nil)
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
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{81},
			v1.ProtocolTCP,
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
		SetNamespaceSelector(map[string]string{"ns": "x"}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
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
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{81},
			v1.ProtocolTCP,
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
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, []ACNPAppliedToSpec{{Group: cgName}}, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
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
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": "z"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
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
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(Pod("x/c"), "z", Dropped)
	updatedReachability.ExpectEgressToNamespace(Pod("y/c"), "z", Dropped)
	updatedReachability.Expect(Pod("z/c"), Pod("z/a"), Dropped)
	updatedReachability.Expect(Pod("z/c"), Pod("z/b"), Dropped)
	testStep := []*TestStep{
		{
			"CG Pods A",
			reachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
		{
			"CG Pods C - update",
			updatedReachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{updatedCgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
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
	cgBuilder = cgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": "z"}, nil)
	// Update CG NS selector to group Pods from Namespace Y
	updatedCgBuilder := &ClusterGroupV1Alpha3SpecBuilder{}
	updatedCgBuilder = updatedCgBuilder.SetName(cgName).SetNamespaceSelector(map[string]string{"ns": "y"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-cg-with-z-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgName, "")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)

	updatedReachability := NewReachability(allPods, Connected)
	updatedReachability.ExpectEgressToNamespace(Pod("x/a"), "y", Dropped)
	updatedReachability.ExpectEgressToNamespace(Pod("z/a"), "y", Dropped)
	updatedReachability.Expect(Pod("y/a"), Pod("y/b"), Dropped)
	updatedReachability.Expect(Pod("y/a"), Pod("y/c"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
		{
			"Port 80 - update",
			updatedReachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{updatedCgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
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
		SetNamespaceSelector(map[string]string{"ns": "z"}, nil).
		SetPodSelector(map[string]string{"pod": "j"}, nil)
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
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
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
		SetNamespaceSelector(map[string]string{"ns": "z"}, nil).
		SetPodSelector(map[string]string{"pod": "k"}, nil)
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-xk-to-cg-with-zk-egress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "k"},
				NSSelector:  map[string]string{"ns": "x"},
			},
		})
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
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get()},
			[]int32{80},
			v1.ProtocolTCP,
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
	podXAIP, _ := podIPs["x/a"]
	podXBIP, _ := podIPs["x/b"]
	podXCIP, _ := podIPs["x/c"]
	podZAIP, _ := podIPs["z/a"]
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
	builder = builder.SetName("acnp-deny-ya-to-x-ips-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{
			{
				PodSelector: map[string]string{"pod": "a"},
				NSSelector:  map[string]string{"ns": "y"},
			},
		})
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgv1a3Name, "")
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil,
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, cgv1a2Name, "")

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/a"), Pod("y/a"), Dropped)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachability.Expect(Pod("x/c"), Pod("y/a"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("y/a"), Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
			[]metav1.Object{cgBuilder.Get(), cgBuilder2.Get()},
			[]int32{80},
			v1.ProtocolTCP,
			0,
			nil,
		},
	}
	testCase := []*TestCase{
		{"ACNP Drop Ingress From Pod: y/a to ClusterGroup with ipBlocks", testStep},
	}
	executeTests(t, testCase)
}

// testBaselineNamespaceIsolation tests that an ACNP in the baseline Tier is able to enforce default namespace isolation,
// which can be later overridden by developer K8s NetworkPolicies.
func testBaselineNamespaceIsolation(t *testing.T) {
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
		nil, []metav1.LabelSelectorRequirement{nsExpOtherThanX}, false,
		nil, crdv1alpha1.RuleActionDrop, "", "")

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
	reachability.ExpectIngressFromNamespace(Pod("x/a"), "z", Dropped)
	reachability.Expect(Pod("y/b"), Pod("x/b"), Dropped)
	reachability.Expect(Pod("y/c"), Pod("x/b"), Dropped)
	reachability.ExpectIngressFromNamespace(Pod("x/b"), "z", Dropped)
	reachability.Expect(Pod("y/b"), Pod("x/c"), Dropped)
	reachability.Expect(Pod("y/c"), Pod("x/c"), Dropped)
	reachability.ExpectIngressFromNamespace(Pod("x/c"), "z", Dropped)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get(), k8sNPBuilder.Get()},
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
	executeTests(t, testCase)
	// Cleanup the K8s NetworkPolicy created for this test.
	failOnError(k8sUtils.CleanNetworkPolicies([]string{"x"}), t)
	time.Sleep(networkPolicyDelay)
}

// testACNPPriorityOverride tests priority overriding in three Policies. Those three Policies are applied in a specific order to
// test priority reassignment, and each controls a smaller set of traffic patterns as priority increases.
func testACNPPriorityOverride(t *testing.T) {
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
			[]metav1.Object{builder3.Get(), builder2.Get()},
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
			[]metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
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
	executeTests(t, testCase)
}

// testACNPTierOverride tests tier priority overriding in three Policies.
// Each ACNP controls a smaller set of traffic patterns as tier priority increases.
func testACNPTierOverride(t *testing.T) {
	builder1 := &ClusterNetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("acnp-tier-emergency").
		SetTier("emergency").
		SetPriority(100).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Highest priority tier. Drops traffic from z/b to x/a.
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
			[]metav1.Object{builder3.Get(), builder2.Get()},
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
			[]metav1.Object{builder3.Get(), builder1.Get(), builder2.Get()},
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
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	// Medium priority tier. Allows traffic from z to x/a.
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")

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
			[]metav1.Object{builder2.Get(), builder1.Get()},
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
	reachabilityBothACNP.ExpectEgressToNamespace(Pod("z/a"), "x", Dropped)
	reachabilityBothACNP.ExpectEgressToNamespace(Pod("z/b"), "x", Dropped)
	reachabilityBothACNP.ExpectEgressToNamespace(Pod("z/c"), "x", Dropped)
	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder1.Get(), builder2.Get()},
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
	executeTests(t, testCase)
}

// testACNPPriorityConflictingRule tests that if there are two rules in the cluster that conflicts with
// each other, the rule with higher precedence will prevail.
func testACNPRulePriority(t *testing.T) {
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
	reachabilityBothACNP.ExpectIngressFromNamespace("y/a", "x", Dropped)
	reachabilityBothACNP.ExpectIngressFromNamespace("y/b", "x", Dropped)
	reachabilityBothACNP.ExpectIngressFromNamespace("y/c", "x", Dropped)
	testStep := []*TestStep{
		{
			"Both ACNP",
			reachabilityBothACNP,
			[]metav1.Object{builder2.Get(), builder1.Get()},
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
	executeTests(t, testCase)
}

// testACNPPortRange tests the port range in an ACNP can work.
func testACNPPortRange(t *testing.T) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-deny-a-to-z-egress-port-range").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddEgress(v1.ProtocolTCP, &p8080, nil, &p8085, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "acnp-port-range")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Dropped)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Dropped)
	testSteps := []*TestStep{
		{
			fmt.Sprintf("ACNP Drop Port 8080:8085"),
			reachability,
			[]metav1.Object{builder.Get()},
			nil,
			[]int32{8080, 8081, 8082, 8083, 8084, 8085},
			v1.ProtocolTCP,
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
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace(Pod("x/a"), "z", Rejected)
	reachability.ExpectEgressToNamespace(Pod("y/a"), "z", Rejected)
	reachability.Expect(Pod("z/a"), Pod("z/b"), Rejected)
	reachability.Expect(Pod("z/a"), Pod("z/c"), Rejected)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testACNPRejectIngress tests that an ACNP is able to reject egress traffic from pods labelled A to namespace Z.
func testACNPRejectIngress(t *testing.T, protocol v1.Protocol) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("acnp-reject-a-from-z-ingress").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}})
	builder.AddIngress(protocol, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionReject, "", "")

	reachability := NewReachability(allPods, Connected)
	reachability.ExpectIngressFromNamespace(Pod("x/a"), "z", Rejected)
	reachability.ExpectIngressFromNamespace(Pod("y/a"), "z", Rejected)
	reachability.Expect(Pod("z/b"), Pod("z/a"), Rejected)
	reachability.Expect(Pod("z/c"), Pod("z/a"), Rejected)
	testStep := []*TestStep{
		{
			"Port 80",
			reachability,
			[]metav1.Object{builder.Get()},
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
	executeTests(t, testCase)
}

// testANPPortRange tests the port range in a ANP can work.
func testANPPortRange(t *testing.T) {
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
		fmt.Sprintf("ANP Drop Port 8080:8085"),
		reachability,
		[]metav1.Object{builder.Get()},
		nil,
		[]int32{8080, 8081, 8082, 8083, 8084, 8085},
		v1.ProtocolTCP,
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
			[]metav1.Object{builder.Get()},
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
			[]metav1.Object{builder.Get(), k8sNPBuilder.Get()},
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
	executeTests(t, testCase)
}

// testANPMultipleAppliedTo tests traffic from X/B to Y/A on port 80 will be dropped, after applying Antrea
// NetworkPolicy that applies to multiple AppliedTos, one of which doesn't select any Pod. It also ensures the Policy is
// updated correctly when one of its AppliedToGroup starts and stops selecting Pods.
func testANPMultipleAppliedTo(t *testing.T, data *TestData, singleRule bool) {
	tempLabel := randName("temp-")
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName("y", "np-multiple-appliedto").SetPriority(1.0)
	// Make it apply to an extra dummy AppliedTo to ensure it handles multiple AppliedToGroups correctly.
	// See https://github.com/antrea-io/antrea/issues/2083.
	if singleRule {
		builder.SetAppliedToGroup([]ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}, {PodSelector: map[string]string{tempLabel: ""}}})
		builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, nil, crdv1alpha1.RuleActionDrop, "")
	} else {
		builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, []ANPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}}}, crdv1alpha1.RuleActionDrop, "")
		builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
			nil, nil, []ANPAppliedToSpec{{PodSelector: map[string]string{tempLabel: ""}}}, crdv1alpha1.RuleActionDrop, "")
	}

	reachability := NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)

	anp, err := k8sUtils.CreateOrUpdateANP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForANPRealized(t, anp.Namespace, anp.Name), t)
	k8sUtils.Validate(allPods, reachability, 80, v1.ProtocolTCP)
	_, wrong, _ := reachability.Summary()
	if wrong != 0 {
		t.Errorf("failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	t.Logf("Making the Policy apply to y/c by labeling it with the temporary label that matches the dummy AppliedTo")
	podYC, err := k8sUtils.GetPodByLabel("y", "c")
	if err != nil {
		t.Errorf("Failed to get Pod in Namespace y with label 'pod=c': %v", err)
	}
	podYC.Labels[tempLabel] = ""
	podYC, err = k8sUtils.clientset.CoreV1().Pods(podYC.Namespace).Update(context.TODO(), podYC, metav1.UpdateOptions{})
	assert.NoError(t, err)
	reachability = NewReachability(allPods, Connected)
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	reachability.Expect(Pod("x/b"), Pod("y/c"), Dropped)
	time.Sleep(networkPolicyDelay)
	k8sUtils.Validate(allPods, reachability, 80, v1.ProtocolTCP)
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
	reachability.Expect(Pod("x/b"), Pod("y/a"), Dropped)
	time.Sleep(networkPolicyDelay)
	k8sUtils.Validate(allPods, reachability, 80, v1.ProtocolTCP)
	_, wrong, _ = reachability.Summary()
	if wrong != 0 {
		t.Errorf("failure -- %d wrong results", wrong)
		reachability.PrintSummary(true, true, true)
	}

	failOnError(k8sUtils.DeleteANP(builder.Namespace, builder.Name), t)
}

// testAuditLoggingBasic tests that a audit log is generated when egress drop applied
func testAuditLoggingBasic(t *testing.T, data *TestData) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-log-acnp-deny").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"pod": "a"}, NSSelector: map[string]string{"ns": "x"}}})
	builder.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "z"},
		nil, nil, false, nil, crdv1alpha1.RuleActionDrop, "", "")
	builder.AddEgressLogging()

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(data.waitForACNPRealized(t, acnp.Name), t)

	// generate some traffic that will be dropped by test-log-acnp-deny
	var wg sync.WaitGroup
	oneProbe := func(ns1, pod1, ns2, pod2 string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k8sUtils.Probe(ns1, pod1, ns2, pod2, p80, v1.ProtocolTCP)
		}()
	}
	oneProbe("x", "a", "z", "a")
	oneProbe("x", "a", "z", "b")
	oneProbe("x", "a", "z", "c")
	wg.Wait()

	podXA, err := k8sUtils.GetPodByLabel("x", "a")
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
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
		if err != nil || stderr != "" {
			// file may not exist yet
			t.Logf("Error when printing the audit log file, err: %v, stderr: %v", err, stderr)
			return false, nil
		}
		if !strings.Contains(stdout, "test-log-acnp-deny") {
			t.Logf("Audit log file does not contain entries for 'test-log-acnp-deny' yet")
			return false, nil
		}

		destinations := []string{"z/a", "z/b", "z/c"}
		srcIPs, _ := podIPs["x/a"]
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
					// The audit log should contain log entry `... Drop <ofPriority> SRC: <x/a IP> DEST: <z/* IP> ...`
					re := regexp.MustCompile(`Drop [0-9]+ SRC: ` + srcIPs[i] + ` DEST: ` + dstIPs[j])
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

func testAppliedToPerRule(t *testing.T) {
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
			[]metav1.Object{builder.Get()},
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
			[]metav1.Object{builder2.Get()},
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
	executeTests(t, testCase)
}

func testACNPClusterGroupServiceRefCreateAndUpdate(t *testing.T, data *TestData) {
	svc1 := k8sUtils.BuildService("svc1", "x", 80, 80, map[string]string{"app": "a"}, nil)
	svc2 := k8sUtils.BuildService("svc2", "y", 80, 80, map[string]string{"app": "b"}, nil)

	cg1Name, cg2Name := "cg-svc1", "cg-svc2"
	cgBuilder1 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference("x", "svc1")
	cgBuilder2 := &ClusterGroupV1Alpha3SpecBuilder{}
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
		[]metav1.Object{builder.Get()},
		[]metav1.Object{svc1, svc2, cgBuilder1.Get(), cgBuilder2.Get()},
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
		[]metav1.Object{builder.Get()},
		[]metav1.Object{svc1Updated, svc3, cgBuilder1.Get(), cgBuilder2Updated.Get()},
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
		[]metav1.Object{builderUpdated.Get()},
		nil,
		[]int32{80},
		v1.ProtocolTCP,
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
	svc1 := k8sUtils.BuildService("svc1", "x", 80, 80, map[string]string{"app": "a"}, nil)
	cg1Name, cg2Name, cg3Name := "cg-svc-x-a", "cg-select-y-b", "cg-select-y-c"
	cgBuilder1 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder1 = cgBuilder1.SetName(cg1Name).SetServiceReference("x", "svc1")
	cgBuilder2 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder2 = cgBuilder2.SetName(cg2Name).
		SetNamespaceSelector(map[string]string{"ns": "y"}, nil).
		SetPodSelector(map[string]string{"pod": "b"}, nil)
	cgBuilder3 := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilder3 = cgBuilder3.SetName(cg3Name).
		SetNamespaceSelector(map[string]string{"ns": "y"}, nil).
		SetPodSelector(map[string]string{"pod": "c"}, nil)
	cgNestedName := "cg-nested"
	cgBuilderNested := &ClusterGroupV1Alpha3SpecBuilder{}
	cgBuilderNested = cgBuilderNested.SetName(cgNestedName).SetChildGroups([]string{cg1Name, cg3Name})

	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("cnp-nested-cg").SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "z"}}}).
		AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil,
			false, nil, crdv1alpha1.RuleActionDrop, cgNestedName, "")

	// Pods in Namespace z should not allow traffic from Pods backing svc1 (label pod=a) in Namespace x.
	// Note that in this testStep cg3 will not be created yet, so even though cg-nested selects cg1 and
	// cg3 as childGroups, only members of cg1 will be included as this time.
	reachability := NewReachability(allPods, Connected)
	reachability.ExpectEgressToNamespace("x/a", "z", Dropped)

	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{builder.Get()},
		[]metav1.Object{svc1, cgBuilder1.Get(), cgBuilderNested.Get()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	// Test update "cg-nested" to include "cg-select-y-b" as well.
	cgBuilderNested = cgBuilderNested.SetChildGroups([]string{cg1Name, cg2Name, cg3Name})
	// In addition to x/a, all traffic from y/b to Namespace z should also be denied.
	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace("x/a", "z", Dropped)
	reachability2.ExpectEgressToNamespace("y/b", "z", Dropped)
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
		[]metav1.Object{cgBuilder2.Get(), cgBuilderNested.Get()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		cp,
	}

	// In this testStep cg3 is created. It's members should reflect in cg-nested
	// and as a result, all traffic from y/c to Namespace z should be denied as well.
	reachability3 := NewReachability(allPods, Connected)
	reachability3.ExpectEgressToNamespace("x/a", "z", Dropped)
	reachability3.ExpectEgressToNamespace("y/b", "z", Dropped)
	reachability3.ExpectEgressToNamespace("y/c", "z", Dropped)
	testStep3 := &TestStep{
		"Port 80 updated",
		reachability3,
		nil,
		[]metav1.Object{cgBuilder3.Get()},
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	testSteps := []*TestStep{testStep1, testStep2, testStep3}
	testCase := []*TestCase{
		{"ACNP nested ClusterGroup create and update", testSteps},
	}
	executeTestsWithData(t, testCase, data)
}

func testACNPNamespaceIsolation(t *testing.T, data *TestData) {
	builder := &ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-ns-isolation").
		SetTier("baseline").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{}}})
	// deny ingress traffic except from own namespace
	builder.AddIngress(v1.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil,
		true, nil, crdv1alpha1.RuleActionAllow, "", "")
	builder.AddIngress(v1.ProtocolTCP, nil, nil, nil, nil, nil, map[string]string{}, nil, nil,
		false, nil, crdv1alpha1.RuleActionDrop, "", "")

	reachability := NewReachability(allPods, Dropped)
	reachability.ExpectAllSelfNamespace(Connected)
	testStep1 := &TestStep{
		"Port 80",
		reachability,
		[]metav1.Object{builder.Get()},
		nil,
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	builder2 := &ClusterNetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("test-acnp-ns-isolation-applied-to-per-rule").
		SetTier("baseline").
		SetPriority(1.0)
	//SetAppliedToGroup([]ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}})
	builder2.AddEgress(v1.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil,
		true, []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}}, crdv1alpha1.RuleActionAllow, "", "")
	builder2.AddEgress(v1.ProtocolTCP, nil, nil, nil, nil, nil, map[string]string{}, nil, nil,
		false, []ACNPAppliedToSpec{{NSSelector: map[string]string{"ns": "x"}}}, crdv1alpha1.RuleActionDrop, "", "")

	reachability2 := NewReachability(allPods, Connected)
	reachability2.ExpectEgressToNamespace(Pod("x/a"), "y", Dropped)
	reachability2.ExpectEgressToNamespace(Pod("x/a"), "z", Dropped)
	reachability2.ExpectEgressToNamespace(Pod("x/b"), "y", Dropped)
	reachability2.ExpectEgressToNamespace(Pod("x/b"), "z", Dropped)
	reachability2.ExpectEgressToNamespace(Pod("x/c"), "y", Dropped)
	reachability2.ExpectEgressToNamespace(Pod("x/c"), "z", Dropped)
	testStep2 := &TestStep{
		"Port 80",
		reachability2,
		[]metav1.Object{builder2.Get()},
		nil,
		[]int32{80},
		v1.ProtocolTCP,
		0,
		nil,
	}

	testCase := []*TestCase{
		{"ACNP Namespace isolation for all namespaces", []*TestStep{testStep1}},
		{"ACNP Namespace isolation for namespace x", []*TestStep{testStep2}},
	}
	executeTestsWithData(t, testCase, data)
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
			applyTestStepServicesAndGroups(t, step)
			applyTestStepPolicies(t, step)
			time.Sleep(networkPolicyDelay)

			reachability := step.Reachability
			if reachability != nil {
				start := time.Now()
				for _, port := range step.Port {
					k8sUtils.Validate(allPods, reachability, port, step.Protocol)
				}
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
		log.Debugf("Cleaning-up all policies and groups created by this Testcase and sleeping for %v", networkPolicyDelay)
		cleanupTestCasePolicies(t, testCase)
		cleanupTestCaseServicesAndGroups(t, testCase)
		time.Sleep(networkPolicyDelay)
	}
	allTestList = append(allTestList, testList...)
}

func doProbe(t *testing.T, data *TestData, p *CustomProbe, protocol v1.Protocol) {
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

func applyTestStepPolicies(t *testing.T, step *TestStep) {
	for _, policy := range step.Policies {
		switch p := policy.(type) {
		case *crdv1alpha1.ClusterNetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateACNP(p)
			failOnError(err, t)
		case *crdv1alpha1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateANP(p)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(p)
			failOnError(err, t)
		}
		failOnError(waitForResourceReady(policy, timeout), t)
	}
	if len(step.Policies) > 0 {
		log.Debugf("Sleeping for %v for all policies to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

func cleanupTestCasePolicies(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same policy.
	// Use sets to avoid duplicates.
	acnpsToDelete, anpsToDelete, npsToDelete := sets.String{}, sets.String{}, sets.String{}
	for _, step := range c.Steps {
		for _, policy := range step.Policies {
			switch p := policy.(type) {
			case *crdv1alpha1.ClusterNetworkPolicy:
				acnpsToDelete.Insert(p.Name)
			case *crdv1alpha1.NetworkPolicy:
				anpsToDelete.Insert(p.Namespace + "/" + p.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(p.Namespace + "/" + p.Name)
			}
		}
	}
	for _, acnp := range acnpsToDelete.List() {
		failOnError(k8sUtils.DeleteACNP(acnp), t)
		failOnError(waitForResourceDelete("", acnp, resourceACNP, timeout), t)
	}
	for _, anp := range anpsToDelete.List() {
		namespace := strings.Split(anp, "/")[0]
		name := strings.Split(anp, "/")[1]
		failOnError(k8sUtils.DeleteANP(namespace, name), t)
		failOnError(waitForResourceDelete(namespace, name, resourceANP, timeout), t)
	}
	for _, np := range npsToDelete.List() {
		namespace := strings.Split(np, "/")[0]
		name := strings.Split(np, "/")[1]
		failOnError(k8sUtils.DeleteNetworkPolicy(namespace, name), t)
		failOnError(waitForResourceDelete(namespace, name, resourceNetworkPolicy, timeout), t)
	}
	if acnpsToDelete.Len()+anpsToDelete.Len()+npsToDelete.Len() > 0 {
		log.Debugf("Sleeping for %v for all policy deletions to take effect", networkPolicyDelay)
		time.Sleep(networkPolicyDelay)
	}
}

func applyTestStepServicesAndGroups(t *testing.T, step *TestStep) {
	for _, obj := range step.ServicesAndGroups {
		switch o := obj.(type) {
		case *crdv1alpha3.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateV1Alpha3CG(o)
			failOnError(err, t)
		case *crdv1alpha2.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateV1Alpha2CG(o)
			failOnError(err, t)
		case *v1.Service:
			_, err := k8sUtils.CreateOrUpdateService(o)
			failOnError(err, t)
		}
		failOnError(waitForResourceReady(obj, timeout), t)
	}
	if len(step.ServicesAndGroups) > 0 {
		log.Debugf("Sleeping for %v for all groups to have members computed", groupDelay)
		time.Sleep(groupDelay)
	}
}

func cleanupTestCaseServicesAndGroups(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same Group/Service.
	// Use sets to avoid duplicates. Furthermore, since childGroups in ClusterGroup must
	// be created before referred and can only be deleted after the parentGroup is deleted,
	// CG deletion must be performed in the reverse order of creation. An orderedGroups
	// list is used to maintain the order of group creation.
	svcsToDelete, v1a2GroupsToDelete, v1a3GroupsToDelete := sets.String{}, sets.String{}, sets.String{}
	var orderedGroups []string
	for _, step := range c.Steps {
		for _, obj := range step.ServicesAndGroups {
			switch o := obj.(type) {
			case *crdv1alpha3.ClusterGroup:
				v1a3GroupsToDelete.Insert(o.Name)
				orderedGroups = append(orderedGroups, o.Name)
			case *crdv1alpha2.ClusterGroup:
				v1a2GroupsToDelete.Insert(o.Name)
				orderedGroups = append(orderedGroups, o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}
	for i := len(orderedGroups) - 1; i >= 0; i-- {
		cg := orderedGroups[i]
		if v1a2GroupsToDelete.Has(cg) {
			failOnError(k8sUtils.DeleteV1Alpha2CG(cg), t)
			v1a2GroupsToDelete.Delete(cg)
		} else if v1a3GroupsToDelete.Has(cg) {
			failOnError(k8sUtils.DeleteV1Alpha3CG(cg), t)
			v1a3GroupsToDelete.Delete(cg)
		}
	}
	for _, svc := range svcsToDelete.List() {
		namespace := strings.Split(svc, "/")[0]
		name := strings.Split(svc, "/")[1]
		failOnError(k8sUtils.DeleteService(namespace, name), t)
		failOnError(waitForResourceDelete(namespace, name, resourceSVC, timeout), t)
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
				step.Name, step.Port, int(step.Duration.Seconds()), result)
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

func waitForResourceReady(obj metav1.Object, timeout time.Duration) error {
	var err error
	defer timeCost()("ready")
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		switch p := obj.(type) {
		case *legacysecv1alpha1.ClusterNetworkPolicy:
			_, err = k8sUtils.GetACNP(p.Name)
		case *legacysecv1alpha1.NetworkPolicy:
			_, err = k8sUtils.GetANP(p.Namespace, p.Name)
		case *legacysecv1alpha1.Tier:
			_, err = k8sUtils.GetTier(p.Name)
		case *legacycorev1a2.ClusterGroup:
			_, err = k8sUtils.GetV1Alpha2CG(p.Name)
		case *crdv1alpha1.ClusterNetworkPolicy:
			_, err = k8sUtils.GetACNP(p.Name)
		case *crdv1alpha1.NetworkPolicy:
			_, err = k8sUtils.GetANP(p.Namespace, p.Name)
		case *crdv1alpha1.Tier:
			_, err = k8sUtils.GetTier(p.Name)
		case *crdv1alpha2.ClusterGroup:
			_, err = k8sUtils.GetV1Alpha2CG(p.Name)
		case *crdv1alpha3.ClusterGroup:
			_, err = k8sUtils.GetV1Alpha3CG(p.Name)
		case *v1net.NetworkPolicy:
			_, err = k8sUtils.GetNetworkPolicy(p.Namespace, p.Name)
		case *v1.Service:
			_, err = k8sUtils.GetService(p.Namespace, p.Name)
		}
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return err
	}
	return nil
}

func waitForResourceDelete(namespace, name string, resource string, timeout time.Duration) error {
	var err error
	defer timeCost()("deleted")
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		switch resource {
		case resourceACNP:
			_, err = k8sUtils.GetACNP(name)
		case resourceANP:
			_, err = k8sUtils.GetANP(namespace, name)
		case resourceTier:
			_, err = k8sUtils.GetTier(name)
		case resourceCG:
			_, err = k8sUtils.GetV1Alpha3CG(name)
		case resourceNetworkPolicy:
			_, err = k8sUtils.GetNetworkPolicy(namespace, name)
		case resourceSVC:
			_, err = k8sUtils.GetService(namespace, name)
		}
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
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
		t.Run("Case=ACNPRuleNameNotUniqueDenied", func(t *testing.T) { testInvalidACNPRuleNameNotUnique(t) })
		t.Run("Case=ACNPTierDoesNotExistDenied", func(t *testing.T) { testInvalidACNPTierDoesNotExist(t) })
		t.Run("Case=ACNPPortRangePortUnsetDenied", func(t *testing.T) { testInvalidACNPPortRangePortUnset(t) })
		t.Run("Case=ACNPPortRangePortEndPortSmallDenied", func(t *testing.T) { testInvalidACNPPortRangeEndPortSmall(t) })
		t.Run("Case=ACNPIngressPeerCGSetWithIPBlock", func(t *testing.T) { testInvalidACNPIngressPeerCGSetWithIPBlock(t) })
		t.Run("Case=ACNPIngressPeerCGSetWithPodSelector", func(t *testing.T) { testInvalidACNPIngressPeerCGSetWithPodSelector(t) })
		t.Run("Case=ACNPIngressPeerCGSetWithNSSelector", func(t *testing.T) { testInvalidACNPIngressPeerCGSetWithNSSelector(t) })
		t.Run("Case=ACNPIngressPeerNamespaceSetWithNSSelector", func(t *testing.T) { testInvalidACNPIngressPeerNamespacesSetWithNSSelector(t) })
		t.Run("Case=ACNPCGDoesNotExist", func(t *testing.T) { testInvalidACNPCGDoesNotExist(t) })
		t.Run("Case=ACNPAppliedToCGDoesNotExist", func(t *testing.T) { testInvalidACNPAppliedToCGDoesNotExist(t) })
		t.Run("Case=ACNPSpecAppliedToRuleAppliedToSet", func(t *testing.T) { testInvalidACNPSpecAppliedToRuleAppliedToSet(t) })
		t.Run("Case=ACNPAppliedToNotSetInAllRules", func(t *testing.T) { testInvalidACNPAppliedToNotSetInAllRules(t) })
		t.Run("Case=ANPNoPriority", func(t *testing.T) { testInvalidANPNoPriority(t) })
		t.Run("Case=ANPRuleNameNotUniqueDenied", func(t *testing.T) { testInvalidANPRuleNameNotUnique(t) })
		t.Run("Case=ANPTierDoesNotExistDenied", func(t *testing.T) { testInvalidANPTierDoesNotExist(t) })
		t.Run("Case=ANPPortRangePortUnsetDenied", func(t *testing.T) { testInvalidANPPortRangePortUnset(t) })
		t.Run("Case=ANPPortRangePortEndPortSmallDenied", func(t *testing.T) { testInvalidANPPortRangeEndPortSmall(t) })
		t.Run("Case=ACNPInvalidPodSelectorNsSelectorMatchExpressions", func(t *testing.T) { testInvalidACNPPodSelectorNsSelectorMatchExpressions(t) })
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
		t.Run("Case=ACNPAllowNoDefaultIsolationTCP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, v1.ProtocolTCP) })
		t.Run("Case=ACNPAllowNoDefaultIsolationUDP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, v1.ProtocolUDP) })
		t.Run("Case=ACNPAllowNoDefaultIsolationSCTP", func(t *testing.T) { testACNPAllowNoDefaultIsolation(t, v1.ProtocolSCTP) })
		t.Run("Case=ACNPDropEgress", func(t *testing.T) { testACNPDropEgress(t, v1.ProtocolTCP) })
		t.Run("Case=ACNPDropEgressUDP", func(t *testing.T) { testACNPDropEgress(t, v1.ProtocolUDP) })
		t.Run("Case=ACNPDropEgressSCTP", func(t *testing.T) { testACNPDropEgress(t, v1.ProtocolSCTP) })
		t.Run("Case=ACNPDropIngressInNamespace", func(t *testing.T) { testACNPDropIngressInSelectedNamespace(t) })
		t.Run("Case=ACNPPortRange", func(t *testing.T) { testACNPPortRange(t) })
		t.Run("Case=ACNPRejectEgress", func(t *testing.T) { testACNPRejectEgress(t) })
		t.Run("Case=ACNPRejectIngress", func(t *testing.T) { testACNPRejectIngress(t, v1.ProtocolTCP) })
		t.Run("Case=ACNPRejectIngressUDP", func(t *testing.T) { testACNPRejectIngress(t, v1.ProtocolUDP) })
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
		t.Run("Case=ACNPNamespaceIsolation", func(t *testing.T) { testACNPNamespaceIsolation(t, data) })
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
	})
	// print results for reachability tests
	printResults()

	t.Run("TestGroupAuditLogging", func(t *testing.T) {
		t.Run("Case=AuditLoggingBasic", func(t *testing.T) { testAuditLoggingBasic(t, data) })
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
	anp := anpBuilder.Get()
	log.Debugf("creating ANP %v", anp.Name)
	_, err = data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
	assert.NoError(t, err)
	defer data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Delete(context.TODO(), anp.Name, metav1.DeleteOptions{})

	acnpBuilder := &ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("acnp-applied-to-two-nodes").
		SetPriority(1.0).
		SetAppliedToGroup([]ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}})
	acnpBuilder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"},
		nil, nil, false, nil, crdv1alpha1.RuleActionAllow, "", "")
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
	}
	err = wait.Poll(100*time.Millisecond, policyRealizedTimeout, func() (bool, error) {
		anp, err := data.crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status == expectedStatus, nil
	})
	assert.NoError(t, err, "Antrea NetworkPolicy failed to reach expected status")
	err = wait.Poll(100*time.Millisecond, policyRealizedTimeout, func() (bool, error) {
		anp, err := data.crdClient.CrdV1alpha1().ClusterNetworkPolicies().Get(context.TODO(), acnp.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return anp.Status == expectedStatus, nil
	})
	assert.NoError(t, err, "Antrea ClusterNetworkPolicy failed to reach expected status")
}

// waitForANPRealized waits untils an ANP is realized and returns, or times out. A policy is
// considered realized when its Status has been updated so that the ObservedGeneration matches the
// resource's Generation and the Phase is set to Realized.
func (data *TestData) waitForANPRealized(t *testing.T, namespace string, name string) error {
	t.Logf("Waiting for ANP '%s/%s' to be realized", namespace, name)
	if err := wait.Poll(100*time.Millisecond, policyRealizedTimeout, func() (bool, error) {
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

// waitForACNPRealized waits untils an ACNP is realized and returns, or times out. A policy is
// considered realized when its Status has been updated so that the ObservedGeneration matches the
// resource's Generation and the Phase is set to Realized.
func (data *TestData) waitForACNPRealized(t *testing.T, name string) error {
	t.Logf("Waiting for ACNP '%s' to be realized", name)
	if err := wait.Poll(100*time.Millisecond, policyRealizedTimeout, func() (bool, error) {
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
	var anp = &crdv1alpha1.NetworkPolicy{
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

	if _, err = k8sUtils.CreateOrUpdateANP(anp); err != nil {
		failOnError(fmt.Errorf("create ANP failed for ANP %s: %v", anp.Name, err), t)
	}

	// Wait for the policy to be realized before attempting connections
	failOnError(data.waitForANPRealized(t, anp.Namespace, anp.Name), t)

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
	k8sUtils.Cleanup(namespaces)
}

func testAntreaClusterNetworkPolicyStats(t *testing.T, data *TestData) {
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
	var acnp = &crdv1alpha1.ClusterNetworkPolicy{
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

	if _, err = k8sUtils.CreateOrUpdateACNP(acnp); err != nil {
		failOnError(fmt.Errorf("create ACNP failed for ACNP %s: %v", acnp.Name, err), t)
	}

	// Wait for the policy to be realized before attempting connections
	failOnError(data.waitForACNPRealized(t, acnp.Name), t)

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
	k8sUtils.Cleanup(namespaces)
}
