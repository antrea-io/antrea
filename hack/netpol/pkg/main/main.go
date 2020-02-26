package main

import (
	"fmt"
	. "github.com/vmware-tanzu/antrea/hack/netpol/pkg/utils"
	log "github.com/sirupsen/logrus"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetPolConfig struct {
	pods       []string
	namespaces []string
	k8s        *Kubernetes
}

// common for all tests.  these get hardcoded into the Expect() clauses,
// so, we cant easily parameterize them (well, we could, but that would
// make the code harder to interpret.
var pods []string
var namespaces []string
var p80 int
var p81 int
var allPods []Pod

func init() {
	p80 = 80
	p81 = 81
	pods = []string{"a", "b", "c"}
	namespaces = []string{"x", "y", "z"}

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
		}
	}
}

func bootstrap(k8s *Kubernetes) {
	k8s.CleanNetworkPolicies([]string{"x","y","z"})
	//p81 := 81
	for _, ns := range namespaces {
		k8s.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		for _, pod := range pods {
			fmt.Println(ns)
			k8s.CreateOrUpdateDeployment(ns, ns+pod, 1,
				map[string]string{
					"pod": pod,
				})
		}
	}
	k8s.CleanNetworkPolicies([]string{"x","y","z"})
}

func validate(k8s *Kubernetes, reachability *Reachability, port int) {
	// better as metrics, obviously, this is only for POC.
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			log.Infof("Probing: %s, %s", string(pod1), string(pod2))
			connected, err := k8s.Probe(pod1.Namespace(), pod1.PodName(), pod2.Namespace(), pod2.PodName(), port)
			log.Infof("... expected %v , got %v", reachability.Expected.Get(string(pod1), string(pod2)), connected)
			if err != nil {
				log.Errorf("unable to make main observation on %s -> %s: %s", string(pod1), string(pod2), err)
			}
			reachability.Observe(pod1, pod2, connected)
			if !connected {
				if reachability.Expected.Get(string(pod1), string(pod2)) {
					log.Warnf("FAILED CONNECTION FOR WHITELISTED PODS %s -> %s !!!! ", string(pod1), string(pod2))
				}
			}
		}
	}
}

func main() {
	k8s, err := NewKubernetes()
	if err != nil {
		panic(err)
	}
	k8s.CleanNetworkPolicies(namespaces)

	bootstrap(k8s)
	testWrapperPort80(k8s, TestDefaultDeny)

	bootstrap(k8s)
	testWrapperPort80(k8s, TestPodLabelWhitelistingFromBToA)

	bootstrap(k8s)
	testWrapperPort80(k8s, testInnerNamespaceTraffic)

	bootstrap(k8s)
	testWrapperPort80(k8s, testEnforcePodAndNSSelector)

	bootstrap(k8s)
	testWrapperPort80(k8s, testEnforcePodOrNSSelector)

	bootstrap(k8s)
	testPortsPolicies(k8s)

	// stacked port policies
	bootstrap(k8s)
	testWrapperStacked(k8s, testPortsPoliciesStackedOrUpdated, true)
	// updated port policies
	bootstrap(k8s)
	testWrapperStacked(k8s, testPortsPoliciesStackedOrUpdated, false)

	bootstrap(k8s)
	testWrapperPort80(k8s, testAllowAll)

	bootstrap(k8s)
	testWrapperPort80(k8s, testNamedPort)

	bootstrap(k8s)
	testWrapperPort80(k8s, testNamedPortWNamespace)

	bootstrap(k8s)
	testWrapperPort80(k8s, testEgressOnNamedPort)

	bootstrap(k8s)
	testWrapperStacked(k8s, TestAllowAllPrecedenceIngress,true )

	/**
		// TestCIDR
		TestEgressAndIngressIntegration
		TestMultipleUpdates(k8s)
	**/
}

// testWrapperStaged is for tests which involve steps of mutation.
type Stack struct {
	Reachability  *Reachability
	NetworkPolicy *networkingv1.NetworkPolicy
	Port          int
}

// catch all for any type of test, where we use stacks.  these are validated one at a time.
// probably use this for *all* tests when we port to upstream.
func testWrapperStacked(k8s *Kubernetes, theTest func(*Kubernetes, bool) (stack []*Stack), stacked bool) {
	bootstrap(k8s)

	stack := theTest(k8s, stacked)
	for _, s := range stack {
		reachability := s.Reachability
		policy := s.NetworkPolicy
		if policy != nil {
			_, err := k8s.CreateOrUpdateNetworkPolicy(policy.Namespace, policy)
			if err != nil {
				panic(err)
			}
		}
		validate(k8s, reachability, s.Port)
		reachability.PrintSummary(true, true, true)
	}
}

// For dual port tests... confirms both ports 80 and 81
func testWrapperPort8081(k8s *Kubernetes, theTest func(k8s *Kubernetes) (*Reachability, *Reachability)) {
	bootstrap(k8s)
	reachability80, reachability81 := theTest(k8s)
	validate(k8s, reachability80, 80)
	validate(k8s, reachability81, 81)

	for _, reachability := range []*Reachability{reachability80, reachability81} {
		reachability.PrintSummary(true, true, true)
	}
}

// simple type of test, majority of tests use this, just port 80
func testWrapperPort80(k8s *Kubernetes, theTest func(k8s *Kubernetes) *Reachability) {
	bootstrap(k8s)
	reachability := theTest(k8s)
	validate(k8s, reachability, 80)

	reachability.PrintSummary(true, true, true)
}

/**
CIDR tests.... todo
*/

/**
	ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
	ginkgo.It("should allow ingress access from updated pod [Feature:NetworkPolicy]", func() {

	TODO: These 3 tests should be implemented using a different strategy, possibly combined.

	ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
	ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {
**/
func TestMultipleUpdates(k8s *Kubernetes) {
	bootstrap(k8s)

	func() {
		builder := &NetworkPolicySpecBuilder{}
		builder = builder.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
		builder.SetTypeIngress()
		builder.AddIngress(nil, &p80, nil, nil, nil, map[string]string{"ns-updated": "true", "ns": "y"}, nil, nil)
		builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod-updated": "true", "pod": "b"}, nil, nil, nil)

		k8s.CreateOrUpdateNetworkPolicy("deny-all-to-x", builder.Get())
		reachability1 := NewReachability(allPods, true)
		reachability1.ExpectAllIngress(Pod("x/a"), false)
		validate(k8s, reachability1, 80)

		reachability1.PrintSummary(true, true, true)
	}()

	func() {
		k8s.CreateOrUpdateNamespace("y", map[string]string{"ns-updated": "true", "ns": "y"})
		reachability1 := NewReachability(allPods, true)
		reachability1.ExpectAllIngress(Pod("x/a"), false)
		reachability1.Expect(Pod("y/a"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/c"), Pod("x/a"), true)
		validate(k8s, reachability1, 80)

		reachability1.PrintSummary(true, true, true)
	}()

	func() {
		k8s.CreateOrUpdateNamespace("y", map[string]string{"ns-updated": "true", "ns": "y"})
		reachability1 := NewReachability(allPods, true)
		reachability1.ExpectAllIngress(Pod("x/a"), false)
		reachability1.Expect(Pod("y/a"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/c"), Pod("x/a"), true)
		validate(k8s, reachability1, 80)

		reachability1.PrintSummary(true, true, true)
	}()

	func() {
		k8s.CreateOrUpdateDeployment("z", "zb", 1,
			map[string]string{
				"pod":     "b",
				"updated": "true",
			} ) // old nginx cause it was before people deleted everything useful from containers
		// copied from above
		reachability1 := NewReachability(allPods, true)
		reachability1.ExpectAllIngress(Pod("x/a"), false)
		reachability1.Expect(Pod("y/a"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/c"), Pod("x/a"), true)

		// delta... pod z in b has 'updated=true' so its whitelisted.
		reachability1.Expect(Pod("z/b"), Pod("x/a"), true)

		validate(k8s, reachability1, 80)

		reachability1.PrintSummary(true, true, true)
	}()

	// NOTE THIS TEST IS COPIED FROM THE ABOVE TEST, only delta being that we
	// dont have the udpated=true annotation above.
	func() {
		k8s.CreateOrUpdateDeployment("z", "zb", 1,
			map[string]string{
				"pod": "b",
				// REMOVE UPDATED ANNOTATION, otherwise identical to above function.
			} ) // old nginx cause it was before people deleted everything useful from containers
		// copied from above
		reachability1 := NewReachability(allPods, true)
		reachability1.ExpectAllIngress(Pod("x/a"), false)
		reachability1.Expect(Pod("y/a"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability1.Expect(Pod("y/c"), Pod("x/a"), true)

		// REMOVED DELTA, otherwise identical... this confirms that access is blocked again.
		validate(k8s, reachability1, 80)

		reachability1.PrintSummary(true, true, true)
	}()

}

/**
ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:NetworkPolicy]", func() {
ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
*/
func TestEgressAndIngressIntegration(k8s *Kubernetes, stacked bool) []*Stack {
	// ingress policies stack
	builder1 := &NetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder1.SetTypeIngress()
	builder1.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	policy1 := builder1.Get()
	reachability1 := NewReachability(allPods, false)
	reachability1.ExpectAllIngress(Pod("x/a"), false)
	reachability1.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability1.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability1.Expect(Pod("z/b"), Pod("x/a"), true)
	reachability1.Expect(Pod("x/a"), Pod("x/a"), true)

	// egress policies stack w pod selector and ns selector
	builder2 := &NetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeEgress().AddEgress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	policy2 := builder1.Get()
	reachability2 := NewReachability(allPods, false)
	// copied from m1
	reachability2.ExpectAllIngress(Pod("x/a"), false)
	reachability2.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability2.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability2.Expect(Pod("z/b"), Pod("x/a"), true)
	reachability2.Expect(Pod("x/a"), Pod("x/a"), true)

	// new egress rule.
	reachability2.Expect(Pod("x/a"), Pod("y/b"), true)

	builder3 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder3 = builder2.SetName("x", "allow-all").SetPodSelector(map[string]string{"pod": "a"})
	builder3.SetTypeEgress()
	builder3.AddEgress(nil, &p80, nil, nil, nil, nil, nil, nil)

	policy3 := builder2.Get()
	reachability3 := NewReachability(allPods, true)

	return []*Stack{
		&Stack{
			reachability1,
			policy1,
			p80,
		},
		&Stack{
			reachability2,
			policy2,
			p80,
		},
		&Stack{
			reachability3,
			policy3,
			p80,
		},
	}
}

// should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]"
func TestAllowAllPrecedenceIngress(k8s *Kubernetes, stackedOrUpdated bool) []*Stack {
	if !stackedOrUpdated {
		panic("this test always true")
	}

	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{}, nil, nil, nil)

	policy1 := builder.Get()
	reachability1 := NewReachability(allPods, true)
	reachability1.ExpectAllIngress(Pod("x/a"), false)
	reachability1.Expect(Pod("x/a"), Pod("x/a"), true)

	builder2 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder2 = builder2.SetName("x", "allow-all").SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeIngress()
	builder2.AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)

	policy2 := builder2.Get()
	reachability2 := NewReachability(allPods, true)

	return []*Stack{
		&Stack{
			reachability1,
			policy1,
			p81,
		},
		&Stack{
			reachability2,
			policy2,
			p80,
		},
	}
}

// should allow egress access on one named port [Feature:NetworkPolicy]
func testEgressOnNamedPort(k8s *Kubernetes) *Reachability {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-egress-rule").SetPodSelector(map[string]string{"pod": "a"})

	// note egress DNS isnt necessary to test egress over a named port.
	builder.SetTypeEgress().WithEgressDNS().AddEgress(nil, nil, &namedPorts, nil, nil, nil, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)

	// TODO, maybe add validation that 81 doesn't work as well?
	return reachability
}

// should allow ingress access from namespace on one named port [Feature:NetworkPolicy]
func testNamedPortWNamespace(k8s *Kubernetes) *Reachability {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-ingress-rule").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, nil, &namedPorts, nil, nil, map[string]string{"ns": "x"}, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(Pod("x/a"), false)
	reachability.Expect(Pod("x/a"), Pod("x/a"), true)
	reachability.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability.Expect(Pod("x/c"), Pod("x/a"), true)

	// TODO, add validation that 81 doesn't work.
	return reachability
}

// testNamedPort should allow ingress access on one named port [Feature:NetworkPolicy]
func testNamedPort(k8s *Kubernetes) *Reachability {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-ingress-rule").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, nil, &namedPorts, nil, nil, nil, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	// No egress rules because we're deny all !
	reachability := NewReachability(allPods, true)

	// TODO, add validation that 81 doesn't work.
	return reachability
}

// testAllowAll should support allow-all policy [Feature:NetworkPolicy]
func testAllowAll(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "default-deny").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)
	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	// No egress rules because we're deny all !
	reachability := NewReachability(allPods, true)
	return reachability
}

// This covers two test cases: stacked policy's and updated policies.
// 1) should enforce policy based on Ports [Feature:NetworkPolicy] (allow 80 -> allow 81 by changing the policy) (stacked == false)
// 2) should enforce updated policy (stacked == true), in which (allow 81 -> allow 81+80 by stacking a 2nd whitelist for 81)
func testPortsPoliciesStackedOrUpdated(k8s *Kubernetes, stackInsteadOfUpdate bool) []*Stack {
	blocked := func() *Reachability {
		r := NewReachability(allPods, true)
		r.ExpectAllIngress(Pod("x/a"), false)
		r.Expect(Pod("x/a"), Pod("x/a"), true)
		return r
	}
	unblocked := func() *Reachability {
		return NewReachability(allPods, true)
	}

	/***
	Initially, only whitelist port 80, and verify 81 is blocked.
	*/
	policyName := "policy-that-will-update-for-ports"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", policyName).SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)
	policy1 := builder.Get()

	/***
	  Now, whitelist port 81, and verify 81 it is open.
	*/
	// using false makes this a test for 'updated' policies...
	if stackInsteadOfUpdate {
		policyName = "policy-that-will-update-for-ports-2"
	}
	builder2 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder2 = builder2.SetName("x", policyName).SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeIngress()
	builder2.AddIngress(nil, &p81, nil, nil, nil, nil, nil, nil)
	policy2 := builder2.Get()

	// The first policy was on port 80, which was whitelisted, while 81 wasn't.
	// The second policy was on port 81, which was whitelisted.
	// At this point, if we stacked, make sure 80 is still unblocked
	// Whereas if we DIDNT stack, make sure 80 is blocked.
	r3 := blocked()
	if stackInsteadOfUpdate {
		r3 = NewReachability(allPods, true)
	}
	return []*Stack{
		&Stack{
			blocked(), // 81 blocked
			policy1,
			81,
		},
		&Stack{
			unblocked(), // 81 open now
			policy2,
			81,
		},
		&Stack{
			r3,
			nil, // nil policy wont be created, this is just a 2nd validation, this time, of port 81.
			80,
		},
	}
}

// "should enforce policy based on Ports [Feature:NetworkPolicy] (disallow 80)
func testPortsPolicies(k8s *Kubernetes) {
	bootstrap(k8s)
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-port-81-not-port-80").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	// anyone on port 81 is ok...
	builder.AddIngress(nil, &p81, nil, nil, nil, nil, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())

	r80 := NewReachability(allPods, true)
	r80.ExpectAllIngress(Pod("x/a"), false)
	r80.Expect(Pod("x/a"), Pod("x/a"), true)
	validate(k8s, r80, 80)
	r80.PrintSummary(true, true, true)

	fmt.Println("***** port 81 *****")
	r81 := NewReachability(allPods, true)
	r81.ExpectAllIngress(Pod("x/a"), true)
	validate(k8s, r81, 81)
	r81.PrintSummary(true, true, true)
}

// should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]
// should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]
func testEnforcePodAndNSSelector(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-x-via-pod-and-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(NewPod("x", "a"), false)
	reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
	reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)

	return reachability
}

// should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]
func testEnforcePodOrNSSelector(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-x-via-pod-or-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, nil, map[string]string{"ns": "y"}, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	//m.Expect("z", "b", "x", "a", true)
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(Pod("x/a"), false)
	reachability.Expect(Pod("y/a"), Pod("x/a"), true)
	reachability.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability.Expect(Pod("y/c"), Pod("x/a"), true)
	reachability.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability.Expect(Pod("x/a"), Pod("x/a"), true)

	return reachability
}

// should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]
func testNamespaceSelectorMatchExpressions(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	selector := []metav1.LabelSelectorRequirement{{
		Key:      "ns",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"y"},
	}}
	builder = builder.SetName("x", "allow-a-via-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, nil, &selector, nil)
	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(Pod("x/a"), false)
	reachability.Expect(Pod("y/a"), Pod("x/a"), true)
	reachability.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability.Expect(Pod("y/c"), Pod("x/a"), true)
	reachability.Expect(Pod("x/a"), Pod("x/a"), true)

	return reachability
}

// testPodSelectorMatchExpressions should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]
func testPodSelectorMatchExpressions(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	selector := []metav1.LabelSelectorRequirement{{
		Key:      "pod",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"b"},
	}}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, nil, &selector, nil)
	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(Pod("x/a"), false)
	reachability.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability.Expect(Pod("z/b"), Pod("x/a"), true)
	reachability.Expect(Pod("x/a"), Pod("x/a"), true)

	return reachability
}

// testInnerNamespaceTraffic should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:NetworkPolicy]
func testIntraNamespaceTrafficOnly(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, map[string]string{"ns": "y"}, nil, nil)
	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(Pod("x/a"), false)
	reachability.Expect(Pod("y/a"), Pod("x/a"), true)
	reachability.Expect(Pod("y/b"), Pod("x/a"), true)
	reachability.Expect(Pod("y/c"), Pod("x/a"), true)

	return reachability
}

// testInnerNamespaceTraffic should enforce policy to allow traffic from pods within server namespace, based on PodSelector [Feature:NetworkPolicy]
// note : network policies are applied to a namespace by default, meaning that you need a specific policy to select pods in external namespaces.
// thus in this case, we don't expect y/b -> x/a, because even though it is labelled 'b', it is in a different namespace.
func testInnerNamespaceTraffic(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(NewPod("x", "a"), false)
	reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
	reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)

	return reachability
}

func TestDefaultDeny(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "default-deny")
	builder.SetTypeIngress() //	.AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)
	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())

	// No egress rules because we're deny all !
	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(NewPod("x", "a"), false)
	reachability.ExpectAllIngress(NewPod("x", "b"), false)
	reachability.ExpectAllIngress(NewPod("x", "c"), false)
	reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
	reachability.Expect(NewPod("x", "b"), NewPod("x", "b"), true)
	reachability.Expect(NewPod("x", "c"), NewPod("x", "c"), true)

	return reachability
}

func TestPodLabelWhitelistingFromBToA(k8s *Kubernetes) *Reachability {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"}, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"}, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())

	reachability := NewReachability(allPods, true)
	reachability.ExpectAllIngress(NewPod("x", "a"), false)
	reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
	reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
	reachability.Expect(NewPod("z", "b"), NewPod("x", "a"), true)
	reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)

	// TODO move this to a unit test !
	//if m.Expected["z_c"]["x_a"] {
	//	panic("expectations are wrong")
	//}
	return reachability
}
