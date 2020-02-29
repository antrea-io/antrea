package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	. "github.com/vmware-tanzu/antrea/hack/netpol/pkg/utils"
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
	for _, ns := range namespaces {
		k8s.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		for _, pod := range pods {
			fmt.Println(ns)
			k8s.CreateOrUpdateDeployment(ns, ns+pod, 1, map[string]string{"pod": pod,})
		}
	}
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

	testList := []func(*Kubernetes)[]*TestStep{
		testDefaultDeny,
		testPodLabelWhitelistingFromBToA,
		testInnerNamespaceTraffic,
		testEnforcePodAndNSSelector,
		testEnforcePodOrNSSelector,
		testPortsPolicies,
		testAllowAll,
		testNamedPort,
		testNamedPortWNamespace,
		testEgressOnNamedPort,
		testEgressAndIngressIntegration,

		// TODO: not tested
		//testAllowAllPrecedenceIngress,
		//testPortsPoliciesStackedOrUpdated,
		//testMultipleUpdates,
	}
	executeTests(k8s, testList)
}

type TestStep struct {
	Reachability  *Reachability
	NetworkPolicy *networkingv1.NetworkPolicy
	Port          int
}

// executeTests runs all the tests in testList and print results
func executeTests(k8s *Kubernetes, testList []func(*Kubernetes) []*TestStep) {
	bootstrap(k8s)

	for _, test := range testList {
		k8s.CleanNetworkPolicies(namespaces)
		testStep := test(k8s)
		for _, s := range testStep {
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
func testMultipleUpdates(k8s *Kubernetes) {
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
			}) // old nginx cause it was before people deleted everything useful from containers
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
			}) // old nginx cause it was before people deleted everything useful from containers
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
func testEgressAndIngressIntegration(k8s *Kubernetes) []*TestStep {
	// ingress policies stack
	builder1 := &NetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("x", "allow-client-a-via-ingress-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder1.SetTypeIngress()
	builder1.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	policy1 := builder1.Get()
	reachability1 := NewReachability(allPods, true)
	reachability1.ExpectAllIngress(NewPod("x", "a"), false)
	reachability1.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
	reachability1.Expect(NewPod("x", "a"), NewPod("x", "a"), true)

	// egress policies stack w pod selector and ns selector
	builder2 := &NetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeEgress().AddEgress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	policy2 := builder2.Get()
	reachability2 := NewReachability(allPods, true)
	reachability2.ExpectAllEgress(NewPod("x", "a"), false)
	reachability2.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
	reachability2.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
	reachability2.ExpectAllIngress(NewPod("x", "a"), false)
	reachability2.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
	reachability2.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
	// new egress rule.
	reachability2.Expect(NewPod("x", "a"), NewPod("y", "b"), true)

	builder3 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder3 = builder3.SetName("x", "allow-all").SetPodSelector(map[string]string{"pod": "a"})
	builder3.AddEgress(nil, &p80, nil, nil, nil, nil, nil, nil)
	builder3.AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)

	policy3 := builder3.Get()
	reachability3 := NewReachability(allPods, true)

	return []*TestStep{
		&TestStep{
			reachability1,
			policy1,
			p80,
		},
		&TestStep{
			reachability2,
			policy2,
			p80,
		},
		&TestStep{
			reachability3,
			policy3,
			p80,
		},
	}
}

// testAllowAllPrecedenceIngress should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]"
func testAllowAllPrecedenceIngress(k8s *Kubernetes, stackedOrUpdated bool) []*TestStep {
	if !stackedOrUpdated {
		panic("this test always true")
	}

	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{}, nil, nil, nil)

	policy1 := builder.Get()
	reachability1 := NewReachability(allPods, true)
	reachability1.ExpectAllIngress(NewPod("x", "a"), false)
	reachability1.Expect(NewPod("x", "a"), NewPod("x", "a"), true)

	builder2 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder2 = builder2.SetName("x", "allow-all").SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeIngress()
	builder2.AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)

	policy2 := builder2.Get()
	reachability2 := NewReachability(allPods, true)

	return []*TestStep{
		&TestStep{
			reachability1,
			policy1,
			p81,
		},
		&TestStep{
			reachability2,
			policy2,
			p80,
		},
	}
}

// testEgressOnNamedPort should allow egress access on one named port [Feature:NetworkPolicy]
func testEgressOnNamedPort(k8s *Kubernetes) []*TestStep {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-egress-rule").SetPodSelector(map[string]string{"pod": "a"})

	// note egress DNS isnt necessary to test egress over a named port.
	builder.SetTypeEgress().WithEgressDNS().AddEgress(nil, nil, &namedPorts, nil, nil, nil, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())
	reachability80 := NewReachability(allPods, true)

	// TODO: test if this works for egress
	// disallow port 81
	reachability81 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllEgress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability80,
			builder.Get(),
			80,
		},
		&TestStep{
			reachability81(),
			builder.Get(),
			81,
		},
	}
}

// testNamedPortWNamespace should allow ingress access from namespace on one named port [Feature:NetworkPolicy]
// TODO: This test should be an "and". Check if AddIngress() should be called twice for this!
func testNamedPortWNamespace(k8s *Kubernetes) []*TestStep {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-ingress-rule").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, nil, &namedPorts, nil, nil, map[string]string{"ns": "x"}, nil, nil)

	reachability80 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "c"), NewPod("x", "a"), true)
		return reachability
	}

	// disallow port 81
	reachability81 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability80(),
			builder.Get(),
			80,
		},
		&TestStep{
			reachability81(),
			builder.Get(),
			81,
		},
	}
}

// testNamedPort should allow ingress access on one named port [Feature:NetworkPolicy]
func testNamedPort(k8s *Kubernetes) []*TestStep {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-ingress-rule").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, nil, &namedPorts, nil, nil, nil, nil, nil)

	// allow port 80
	reachability80 := NewReachability(allPods, true)

	// disallow port 81
	reachability81 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability80,
			builder.Get(),
			80,
		},
		&TestStep{
			reachability81(),
			builder.Get(),
			81,
		},

	}
}

// testAllowAll should support allow-all policy [Feature:NetworkPolicy]
func testAllowAll(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "default-deny").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, nil, nil, nil)

	reachability := NewReachability(allPods, true)
	return []*TestStep{
		&TestStep{
			reachability,
			builder.Get(),
			80,
		},
	}
}

// This covers two test cases: stacked policy's and updated policies.
// 1) should enforce policy based on Ports [Feature:NetworkPolicy] (disallow 80) (stacked == false)
// 2) should enforce updated policy (stacked == true)
// TODO: This test should get rid of stackInsteadOfUpdate field by dividing this to 2 seperate funcs.
func testPortsPoliciesStackedOrUpdated(k8s *Kubernetes, stackInsteadOfUpdate bool) []*TestStep {
	blocked := func() *Reachability {
		r := NewReachability(allPods, true)
		r.ExpectAllIngress(NewPod("x", "a"), false)
		r.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
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
	return []*TestStep{
		&TestStep{
			blocked(), // 81 blocked
			policy1,
			81,
		},
		&TestStep{
			unblocked(), // 81 open now
			policy2,
			81,
		},
		&TestStep{
			r3,
			nil, // nil policy wont be created, this is just a 2nd validation, this time, of port 81.
			80,
		},
	}
}

// testPortsPolicies should enforce policy based on Ports [Feature:NetworkPolicy] (disallow 80)
func testPortsPolicies(k8s *Kubernetes) []*TestStep {
	bootstrap(k8s)
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-port-81-not-port-80").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	// anyone on port 81 is ok...
	builder.AddIngress(nil, &p81, nil, nil, nil, nil, nil, nil)


	// disallow port 80
	reachability1 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	// allow port 81
	reachability2 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability1(),
			builder.Get(),
			80,
		},
		&TestStep{
			// Applying the same nw policy to test a different port
			reachability2(),
			builder.Get(),
			81,
		},
	}
}

// testEnforcePodAndNSSelector should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]
// testEnforcePodAndNSSelector should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]
func testEnforcePodAndNSSelector(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-x-via-pod-and-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// testEnforcePodOrNSSelector should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]
func testEnforcePodOrNSSelector(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-x-via-pod-or-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, nil, map[string]string{"ns": "y"}, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("y", "a"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "c"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// testNamespaceSelectorMatchExpressions should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]
func testNamespaceSelectorMatchExpressions(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	selector := []metav1.LabelSelectorRequirement{{
		Key:      "ns",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"y"},
	}}
	builder = builder.SetName("x", "allow-a-via-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, nil, &selector, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("y", "a"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "c"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// testPodSelectorMatchExpressions should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]
func testPodSelectorMatchExpressions(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	selector := []metav1.LabelSelectorRequirement{{
		Key:      "pod",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"b"},
	}}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, nil, &selector, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)

		reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// TODO: Find the matching upstream test
func testIntraNamespaceTrafficOnly(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, nil, map[string]string{"ns": "y"}, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("y", "a"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "c"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// testInnerNamespaceTraffic should enforce policy to allow traffic from pods within server namespace, based on PodSelector [Feature:NetworkPolicy]
// note : network policies are applied to a namespace by default, meaning that you need a specific policy to select pods in external namespaces.
// thus in this case, we don't expect y/b -> x/a, because even though it is labelled 'b', it is in a different namespace.
func testInnerNamespaceTraffic(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
		return reachability
	}

	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// testDefaultDeny should support a 'default-deny' policy
func testDefaultDeny(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "default-deny")
	builder.SetTypeIngress()

	// No egress rules because we're deny all !
	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.ExpectAllIngress(NewPod("x", "b"), false)
		reachability.ExpectAllIngress(NewPod("x", "c"), false)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "b"), NewPod("x", "b"), true)
		reachability.Expect(NewPod("x", "c"), NewPod("x", "c"), true)
		return reachability
	}
	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}

// TODO: Check if there is a similar upstream test
func testPodLabelWhitelistingFromBToA(k8s *Kubernetes) []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"}, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"}, nil, nil)

	k8s.CreateOrUpdateNetworkPolicy("x", builder.Get())

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(NewPod("x", "a"), false)
		reachability.Expect(NewPod("x", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("y", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("z", "b"), NewPod("x", "a"), true)
		reachability.Expect(NewPod("x", "a"), NewPod("x", "a"), true)
		return reachability
	}
	return []*TestStep{
		&TestStep{
			reachability(),
			builder.Get(),
			80,
		},
	}
}