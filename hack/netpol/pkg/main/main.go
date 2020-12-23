package main

import (
	"fmt"
	"net"
	"time"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	. "github.com/vmware-tanzu/antrea/hack/netpol/pkg/utils"
)

// common for all tests.  these get hardcoded into the Expect() clauses,
// so, we cant easily parameterize them (well, we could, but that would
// make the code harder to interpret).
var pods []string
var namespaces []string
var p80 int
var p81 int
var allPods []Pod
var podIPs map[string]string

// provide enough time for policies to be enforced & deleted by the CNI plugin.
const networkPolicyDelay = 2 * time.Second

func init() {
	p80 = 80
	p81 = 81
	pods = []string{"a", "b", "c"}
	namespaces = []string{"x", "y", "z"}
	podIPs = make(map[string]string, len(pods)*len(namespaces))

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
		}
	}
}

type TestCase struct {
	Name  string
	Steps []*TestStep
}

type TestStep struct {
	Name          string
	Reachability  *Reachability
	NetworkPolicy *networkingv1.NetworkPolicy
	Port          int
	Duration      time.Duration
}

func waitForPodInNamespace(k8s *Kubernetes, ns string, pod string) error {
	log.Infof("waiting for pod %s/%s", ns, pod)
	for {
		k8sPod, err := k8s.GetPod(ns, pod)
		if err != nil {
			return errors.WithMessagef(err, "unable to get pod %s/%s", ns, pod)
		}

		if k8sPod != nil && k8sPod.Status.Phase == v1.PodRunning {
			if k8sPod.Status.PodIP == "" {
				return errors.WithMessagef(err, "unable to get IP of pod %s/%s", ns, pod)
			} else {
				log.Debugf("IP of pod %s/%s is: %s", ns, pod, k8sPod.Status.PodIP)
				podIPs[ns+"/"+pod] = k8sPod.Status.PodIP
			}

			log.Debugf("pod running: %s/%s", ns, pod)
			return nil
		}
		log.Infof("pod %s/%s not ready, waiting ...", ns, pod)
		time.Sleep(2 * time.Second)
	}
}

func waitForHTTPServers(k8s *Kubernetes) error {
	const maxTries = 10
	const sleepInterval = 1 * time.Second
	log.Infof("waiting for HTTP servers (ports 80 and 81) to become ready")
	var wrong int
	for i := 0; i < maxTries; i++ {
		reachability := NewReachability(allPods, true)
		validate(k8s, reachability, 80)
		validate(k8s, reachability, 81)
		_, wrong, _ = reachability.Summary()
		if wrong == 0 {
			log.Infof("all HTTP servers are ready")
			return nil
		}
		log.Debugf("%d HTTP servers not ready", wrong)
		time.Sleep(sleepInterval)
	}
	return errors.Errorf("after %d tries, %d HTTP servers are not ready", maxTries, wrong)
}

func bootstrap(k8s *Kubernetes) error {
	for _, ns := range namespaces {
		_, err := k8s.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		if err != nil {
			return errors.WithMessagef(err, "unable to create/update ns %s", ns)
		}
		for _, pod := range pods {
			log.Infof("creating/updating pod %s/%s", ns, pod)
			_, err := k8s.CreateOrUpdateDeployment(ns, ns+pod, 1, map[string]string{"pod": pod})
			if err != nil {
				return errors.WithMessagef(err, "unable to create/update deployment %s/%s", ns, pod)
			}
		}
	}

	for _, pod := range allPods {
		err := waitForPodInNamespace(k8s, pod.Namespace(), pod.PodName())
		if err != nil {
			return errors.WithMessagef(err, "unable to wait for pod %s/%s", pod.Namespace(), pod.PodName())
		}
	}

	// Ensure that all the HTTP servers have time to start properly.
	// See https://github.com/vmware-tanzu/antrea/issues/472.
	if err := waitForHTTPServers(k8s); err != nil {
		return err
	}

	return nil
}

func validate(k8s *Kubernetes, reachability *Reachability, port int) {
	type probeResult struct {
		podFrom   Pod
		podTo     Pod
		connected bool
		err       error
	}
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	// TODO: find better metrics, this is only for POC.
	oneProbe := func(podFrom, podTo Pod) {
		log.Tracef("Probing: %s -> %s", podFrom, podTo)
		connected, err := k8s.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), port)
		resultsCh <- &probeResult{podFrom, podTo, connected, err}
	}
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			go oneProbe(pod1, pod2)
		}
	}
	for i := 0; i < numProbes; i++ {
		r := <-resultsCh
		if r.err != nil {
			log.Errorf("unable to perform probe %s -> %s: %v", r.podFrom, r.podTo, r.err)
		}
		reachability.Observe(r.podFrom, r.podTo, r.connected)
		if !r.connected && reachability.Expected.Get(r.podFrom.String(), r.podTo.String()) {
			log.Warnf("FAILED CONNECTION FOR ALLOWED PODS %s -> %s !!!! ", r.podFrom, r.podTo)
		}
	}
}

func failOnError(err error) {
	if err != nil {
		log.Errorf("%+v", err)
		panic(err)
	}
}

func main() {
	log.SetLevel(log.DebugLevel)

	k8s, err := NewKubernetes()
	failOnError(err)
	err = k8s.CleanNetworkPolicies(namespaces)
	failOnError(err)

	testList := []*TestCase{
		{"DefaultDeny", testDefaultDeny()},
		{"PodLabelAllowTrafficFromBToA", testPodLabelAllowTrafficFromBToA()},
		{"InnerNamespaceTraffic", testInnerNamespaceTraffic()},
		{"EnforcePodAndNSSelector", testEnforcePodAndNSSelector()},
		{"EnforcePodOrNSSelector", testEnforcePodOrNSSelector()},
		{"PortsPolicies", testPortsPolicies()},
		{"AllowAll", testAllowAll()},
		{"NamedPort", testNamedPort()},
		{"NamedPortWithNamespace", testNamedPortWNamespace()},
		{"EgressOnNamedPort", testEgressOnNamedPort()},
		{"EgressAndIngressIntegration", testEgressAndIngressIntegration()},
		{"AllowAllPrecedenceIngress", testAllowAllPrecedenceIngress()},
		{"PortsPoliciesStackedOrUpdated", testPortsPoliciesStackedOrUpdated()},
		//testMultipleUpdates,  // Todo: not suitable in new stacked structure
	}
	// testList is modified with tests that include policies with CIDRs
	testList = executeTests(k8s, testList)
	printResults(testList)
}

func printResults(testList []*TestCase) {
	fmt.Printf("\n\n---------------- Test Results ------------------\n\n")
	failCount := 0
	for _, testCase := range testList {
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
			fmt.Printf("\tStep %s on port %d, duration %d seconds, result: %s\n", step.Name, step.Port, int(step.Duration.Seconds()), result)
			fmt.Printf("\n%s\n", comparison.PrettyPrint("\t\t"))
			fmt.Printf("\n\n")
		}
		if testFailed {
			failCount++
		}
		fmt.Printf("\n\n\n")
	}
	fmt.Printf("=== TEST FAILURES: %d/%d ===\n", failCount, len(testList))
	fmt.Printf("\n\n\n")
}

// executeTests runs all the tests in testList and print results
func executeTests(k8s *Kubernetes, testList []*TestCase) []*TestCase {
	err := bootstrap(k8s)
	failOnError(err)

	//make a copy and append the tests with CIDRs
	cidrTests := []*TestCase{
		{"IngressOverlapCIDRBlocks", testIngressOverlapCIDRBlocks()},
	}
	modifiedTestList := append(testList, cidrTests...)

	for _, testCase := range modifiedTestList {
		log.Infof("running test case %s", testCase.Name)
		log.Debugf("cleaning-up previous policies and sleeping for %v", networkPolicyDelay)
		err = k8s.CleanNetworkPolicies(namespaces)
		time.Sleep(networkPolicyDelay)
		failOnError(err)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			reachability := step.Reachability
			policy := step.NetworkPolicy
			if policy != nil {
				log.Debugf("creating policy and sleeping for %v", networkPolicyDelay)
				_, err := k8s.CreateOrUpdateNetworkPolicy(policy.Namespace, policy)
				failOnError(err)
				time.Sleep(networkPolicyDelay)
			}
			start := time.Now()
			validate(k8s, reachability, step.Port)
			step.Duration = time.Now().Sub(start)
			reachability.PrintSummary(true, true, true)
		}
	}
	return modifiedTestList
}

/**
ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:NetworkPolicy]", func() {
ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
*/
func testEgressAndIngressIntegration() []*TestStep {
	// ingress policies stack
	builder1 := &NetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("x", "allow-client-a-via-ingress-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder1.SetTypeIngress()
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	policy1 := builder1.Get()
	reachability1 := NewReachability(allPods, true)
	reachability1.ExpectAllIngress(Pod("x/a"), false)
	reachability1.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability1.Expect(Pod("x/a"), Pod("x/a"), true)

	// egress policies stack w pod selector and ns selector
	builder2 := &NetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeEgress().AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	policy2 := builder2.Get()
	reachability2 := NewReachability(allPods, true)
	reachability2.ExpectAllEgress(Pod("x/a"), false)
	reachability2.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability2.Expect(Pod("x/a"), Pod("x/a"), true)
	reachability2.ExpectAllIngress(Pod("x/a"), false)
	reachability2.Expect(Pod("x/b"), Pod("x/a"), true)
	reachability2.Expect(Pod("x/a"), Pod("x/a"), true)
	// new egress rule.
	reachability2.Expect(Pod("x/a"), Pod("y/b"), true)

	builder3 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder3 = builder3.SetName("x", "allow-all").SetPodSelector(map[string]string{"pod": "a"})
	builder3.AddEgress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil)
	builder3.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil)

	policy3 := builder3.Get()
	reachability3 := NewReachability(allPods, true)

	return []*TestStep{
		{
			"Port 80 -- 1",
			reachability1,
			policy1,
			p80,
			0,
		},
		{
			"Port 80 -- 2",
			reachability2,
			policy2,
			p80,
			0,
		},
		{
			"Port 80 -- 3",
			reachability3,
			policy3,
			p80,
			0,
		},
	}
}

// testAllowAllPrecedenceIngress should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]"
func testAllowAllPrecedenceIngress() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "deny-all").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{}, nil, nil, nil)

	policy1 := builder.Get()
	reachability1 := NewReachability(allPods, true)
	reachability1.ExpectAllIngress(Pod("x/a"), false)
	reachability1.Expect(Pod("x/a"), Pod("x/a"), true)

	builder2 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder2 = builder2.SetName("x", "allow-all").SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeIngress()
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil)

	policy2 := builder2.Get()
	reachability2 := NewReachability(allPods, true)

	return []*TestStep{
		{
			"Port 81",
			reachability1,
			policy1,
			p81,
			0,
		},
		{
			"Port 80",
			reachability2,
			policy2,
			p80,
			0,
		},
	}
}

// testEgressOnNamedPort should allow egress access on one named port [Feature:NetworkPolicy]
func testEgressOnNamedPort() []*TestStep {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-egress-rule").SetPodSelector(map[string]string{"pod": "a"})

	// note egress DNS isnt necessary to test egress over a named port.
	builder.SetTypeEgress().WithEgressDNS().AddEgress(v1.ProtocolTCP, nil, &namedPorts, nil, nil, nil, nil, nil, nil)

	reachability80 := NewReachability(allPods, true)

	// TODO: test if this works for egress
	// disallow port 81
	reachability81 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		//reachability.ExpectAllEgress(Pod("x/a"), false)
		//reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		reachability.ExpectConn(&Connectivity{
			From:        Pod("x/a"),
			IsConnected: false,
		})
		reachability.ExpectConn(&Connectivity{
			From:        Pod("x/a"),
			To:          Pod("x/a"),
			IsConnected: true,
		})
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability80,
			builder.Get(),
			80,
			0,
		},
		{
			"Port 81",
			reachability81(),
			builder.Get(),
			81,
			0,
		},
	}
}

// testNamedPortWNamespace should allow ingress access from namespace on one named port [Feature:NetworkPolicy]
// TODO: This test should be an "and". Check if AddIngress() should be called twice for this!
func testNamedPortWNamespace() []*TestStep {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-ingress-rule").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, nil, &namedPorts, nil, nil, nil, map[string]string{"ns": "x"}, nil, nil)

	reachability80 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		//reachability.ExpectAllIngress(Pod("x/a"), false)
		//reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		//reachability.Expect(Pod("x/b"), Pod("x/a"), true)
		//reachability.Expect(Pod("x/c"), Pod("x/a"), true)
		reachability.ExpectConn(&Connectivity{
			To:          Pod("x/a"),
			IsConnected: false,
		})
		reachability.ExpectConn(&Connectivity{
			From:        Pod("x/a"),
			To:          Pod("x/a"),
			IsConnected: true,
		})
		reachability.ExpectConn(&Connectivity{
			From:        Pod("x/b"),
			To:          Pod("x/a"),
			IsConnected: true,
		})
		reachability.ExpectConn(&Connectivity{
			From:        Pod("x/c"),
			To:          Pod("x/a"),
			IsConnected: true,
		})
		return reachability
	}

	// disallow port 81
	reachability81 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		//reachability.ExpectAllIngress(Pod("x/a"), false)
		//reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		reachability.ExpectConn(&Connectivity{
			To:          Pod("x/a"),
			IsConnected: false,
		})
		reachability.ExpectConn(&Connectivity{
			From:        Pod("x/a"),
			To:          Pod("x/a"),
			IsConnected: true,
		})
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability80(),
			builder.Get(),
			80,
			0,
		},
		{
			"Port 81",
			reachability81(),
			builder.Get(),
			81,
			0,
		},
	}
}

// testNamedPort should allow ingress access on one named port [Feature:NetworkPolicy]
func testNamedPort() []*TestStep {
	namedPorts := "serve-80"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-named-port-ingress-rule").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, nil, &namedPorts, nil, nil, nil, nil, nil, nil)

	// allow port 80
	reachability80 := NewReachability(allPods, true)

	// disallow port 81
	reachability81 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability80,
			builder.Get(),
			80,
			0,
		},
		{
			"Port 81",
			reachability81(),
			builder.Get(),
			81,
			0,
		},
	}
}

// testAllowAll should support allow-all policy [Feature:NetworkPolicy]
func testAllowAll() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "default-deny").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil)

	reachability := NewReachability(allPods, true)
	return []*TestStep{
		{
			"Port 80",
			reachability,
			builder.Get(),
			80,
			0,
		},
	}
}

// This covers two test cases: stacked policy's and updated policies.
// 1) should enforce policy based on Ports [Feature:NetworkPolicy] (disallow 80) (stacked == false)
// 2) should enforce updated policy (stacked == true)
func testPortsPoliciesStackedOrUpdated() []*TestStep {
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
	Initially, only allow port 80, and verify 81 is blocked.
	*/
	policyName := "policy-that-will-update-for-ports"
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", policyName).SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, nil, nil)
	policy1 := builder.Get()

	builder2 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy' scenario.
	builder2 = builder2.SetName("x", policyName).SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeIngress()
	builder2.AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, nil, nil, nil, nil)
	policy2 := builder2.Get()

	// The first policy was on port 80, which was allowed, while 81 wasn't.
	// The second policy was on port 81, which was allowed.
	// At this point, if we stacked, make sure 80 is still unblocked
	// Whereas if we DIDNT stack, make sure 80 is blocked.
	return []*TestStep{
		{
			"Port 81 -- blocked",
			blocked(), // 81 blocked
			policy1,
			81,
			0,
		},
		{
			"Port 81 -- unblocked",
			unblocked(), // 81 open now
			policy2,
			81,
			0,
		},
		{
			"Port 80 -- blocked",
			blocked(),
			policy2,
			80,
			0,
		},
	}
}

// testPortsPolicies should enforce policy based on Ports [Feature:NetworkPolicy] (disallow 80)
func testPortsPolicies() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-port-81-not-port-80").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	// anyone on port 81 is ok...
	builder.AddIngress(v1.ProtocolTCP, &p81, nil, nil, nil, nil, nil, nil, nil)

	// disallow port 80
	reachability1 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		return reachability
	}

	// allow port 81
	reachability2 := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), true)
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability1(),
			builder.Get(),
			80,
			0,
		},
		{
			"Port 81",
			// Applying the same nw policy to test a different port
			reachability2(),
			builder.Get(),
			81,
			0,
		},
	}
}

// testEnforcePodAndNSSelector should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]
// testEnforcePodAndNSSelector should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]
func testEnforcePodAndNSSelector() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-x-via-pod-and-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability(),
			builder.Get(),
			80,
			0,
		},
	}
}

// testEnforcePodOrNSSelector should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]
func testEnforcePodOrNSSelector() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-x-via-pod-or-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "y"}, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.Expect(Pod("y/a"), Pod("x/a"), true)
		reachability.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability.Expect(Pod("y/c"), Pod("x/a"), true)
		reachability.Expect(Pod("x/b"), Pod("x/a"), true)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability(),
			builder.Get(),
			80,
			0,
		},
	}
}

// testNamespaceSelectorMatchExpressions should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]
// func testNamespaceSelectorMatchExpressions() []*TestStep {
// 	builder := &NetworkPolicySpecBuilder{}
// 	selector := []metav1.LabelSelectorRequirement{{
// 		Key:      "ns",
// 		Operator: metav1.LabelSelectorOpIn,
// 		Values:   []string{"y"},
// 	}}
// 	builder = builder.SetName("x", "allow-a-via-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
// 	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, &selector, nil)

// 	reachability := func() *Reachability {
// 		reachability := NewReachability(allPods, true)
// 		reachability.ExpectAllIngress(Pod("x/a"), false)
// 		reachability.Expect(Pod("y/a"), Pod("x/a"), true)
// 		reachability.Expect(Pod("y/b"), Pod("x/a"), true)
// 		reachability.Expect(Pod("y/c"), Pod("x/a"), true)
// 		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
// 		return reachability
// 	}

// 	return []*TestStep{
// 		{
// 			"Port 80",
// 			reachability(),
// 			builder.Get(),
// 			80,
// 			0,
// 		},
// 	}
// }

// testPodSelectorMatchExpressions should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]
// func testPodSelectorMatchExpressions() []*TestStep {
// 	builder := &NetworkPolicySpecBuilder{}
// 	selector := []metav1.LabelSelectorRequirement{{
// 		Key:      "pod",
// 		Operator: metav1.LabelSelectorOpIn,
// 		Values:   []string{"b"},
// 	}}
// 	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
// 	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, nil, &selector, nil)

// 	reachability := func() *Reachability {
// 		reachability := NewReachability(allPods, true)
// 		reachability.ExpectAllIngress(Pod("x/a"), false)

// 		reachability.Expect(Pod("x/b"), Pod("x/a"), true)
// 		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
// 		return reachability
// 	}

// 	return []*TestStep{
// 		{
// 			"Port 80",
// 			reachability(),
// 			builder.Get(),
// 			80,
// 			0,
// 		},
// 	}
// }

// TODO: Find the matching upstream test
// func testIntraNamespaceTrafficOnly() []*TestStep {
// 	builder := &NetworkPolicySpecBuilder{}
// 	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
// 	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, nil, map[string]string{"ns": "y"}, nil, nil)

// 	reachability := func() *Reachability {
// 		reachability := NewReachability(allPods, true)
// 		reachability.ExpectAllIngress(Pod("x/a"), false)
// 		reachability.Expect(Pod("y/a"), Pod("x/a"), true)
// 		reachability.Expect(Pod("y/b"), Pod("x/a"), true)
// 		reachability.Expect(Pod("y/c"), Pod("x/a"), true)
// 		return reachability
// 	}

// 	return []*TestStep{
// 		{
// 			"Port 80",
// 			reachability(),
// 			builder.Get(),
// 			80,
// 			0,
// 		},
// 	}
// }

// testInnerNamespaceTraffic should enforce policy to allow traffic from pods within server namespace, based on PodSelector [Feature:NetworkPolicy]
// note : network policies are applied to a namespace by default, meaning that you need a specific policy to select pods in external namespaces.
// thus in this case, we don't expect y/b -> x/a, because even though it is labelled 'b', it is in a different namespace.
func testInnerNamespaceTraffic() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-b-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress().AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		reachability.Expect(Pod("x/b"), Pod("x/a"), true)
		return reachability
	}

	return []*TestStep{
		{
			"Port 80",
			reachability(),
			builder.Get(),
			80,
			0,
		},
	}
}

// testDefaultDeny should support a 'default-deny' policy
func testDefaultDeny() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "default-deny")
	builder.SetTypeIngress()

	// No egress rules because we're deny all !
	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.ExpectAllIngress(Pod("x/b"), false)
		reachability.ExpectAllIngress(Pod("x/c"), false)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		reachability.Expect(Pod("x/b"), Pod("x/b"), true)
		reachability.Expect(Pod("x/c"), Pod("x/c"), true)
		return reachability
	}
	return []*TestStep{
		{
			"Port 80",
			reachability(),
			builder.Get(),
			80,
			0,
		},
	}
}

// TODO: Check if there is a similar upstream test
func testPodLabelAllowTrafficFromBToA() []*TestStep {
	builder := &NetworkPolicySpecBuilder{}
	builder = builder.SetName("x", "allow-client-a-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"}, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	builder.AddIngress(v1.ProtocolTCP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"}, nil, nil)

	reachability := func() *Reachability {
		reachability := NewReachability(allPods, true)
		reachability.ExpectAllIngress(Pod("x/a"), false)
		reachability.Expect(Pod("x/b"), Pod("x/a"), true)
		reachability.Expect(Pod("y/b"), Pod("x/a"), true)
		reachability.Expect(Pod("z/b"), Pod("x/a"), true)
		reachability.Expect(Pod("x/a"), Pod("x/a"), true)
		return reachability
	}
	return []*TestStep{
		{
			"Port 80",
			reachability(),
			builder.Get(),
			80,
			0,
		},
	}
}

// This covers tests with three types of ingress policies with CIDRs.
// Policy-1 with FromCIDR and ExceptCIDR and Policy-2 with FromCIDR that is same as ExceptCIDR of Policy-1
// Policy-3 has same FromCIDR as Policy-2 and exceptCIDR has just the IP of pod "y/a"
// Enforce all policies by ensuring communication of right pods with pod "x/a"
// TODO: If possible, add better CIDR tests. Explore service deployment framework with clusterIPs and a truth table for CIDRs.
func testIngressOverlapCIDRBlocks() []*TestStep {
	exceptBuilder1 := make([]string, 1)
	exceptBuilder3 := make([]string, 1)

	// It does not matter if podCIDR of pod "x/a" and "y/a" are same
	// Build simple allowCIDR block for testing purposes.
	allowCIDRStr := podIPs["y/a"] + "/16"
	_, allowCIDR, err := net.ParseCIDR(allowCIDRStr)
	if err != nil {
		log.Errorf("Unable to parse CIDR string %s", allowCIDRStr)
	}
	allowCIDRStr = allowCIDR.String()

	exceptBuilder1[0] = podIPs["y/a"] + "/24"
	var exceptCIDR *net.IPNet
	_, exceptCIDR, err = net.ParseCIDR(exceptBuilder1[0])
	if err != nil {
		log.Errorf("Unable to parse CIDR string %s", exceptBuilder1[0])
	}
	exceptBuilder1[0] = exceptCIDR.String()

	// Build exceptCIDR to block just the pod "y/a"
	exceptBuilder3[0] = podIPs["y/a"] + "/32"

	allowWithExcept := func() *Reachability {
		r := NewReachability(allPods, true)
		r.ExpectAllIngress(Pod("x/a"), false)
		r.Expect(Pod("x/a"), Pod("x/a"), true)
		// Adding connectivity for all the pods in allowCIDR - exceptCIDR
		for eachPod := range podIPs {
			if allowCIDR.Contains(net.ParseIP(podIPs[eachPod])) && !exceptCIDR.Contains(net.ParseIP(podIPs[eachPod])) {
				r.Expect(Pod(eachPod), Pod("x/a"), true)
			}
		}
		return r
	}
	overlapAllow := func() *Reachability {
		r := NewReachability(allPods, true)
		r.ExpectAllIngress(Pod("x/a"), false)
		r.Expect(Pod("x/a"), Pod("x/a"), true)
		// Adding connectivity for all the pods in the created allowCIDR
		for eachPod := range podIPs {
			if allowCIDR.Contains(net.ParseIP(podIPs[eachPod])) {
				r.Expect(Pod(eachPod), Pod("x/a"), true)
			}
		}
		return r
	}
	overlapAllowAndExcept := func() *Reachability {
		r := NewReachability(allPods, true)
		r.ExpectAllIngress(Pod("x/a"), false)
		r.Expect(Pod("x/a"), Pod("x/a"), true)
		// Adding connectivity for all pods in created allowCIDR except pod "y/a"
		for eachPod := range podIPs {
			if allowCIDR.Contains(net.ParseIP(podIPs[eachPod])) {
				r.Expect(Pod(eachPod), Pod("x/a"), true)
			}
		}
		//Override the connectivity to pod "y/a"
		r.Expect(Pod("y/a"), Pod("x/a"), false)
		return r
	}

	// Policy-1 is added with allow and except CIDR
	policyName := "policy-that-has-except-block"
	builder1 := &NetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("x", policyName).SetPodSelector(map[string]string{"pod": "a"})
	builder1.SetTypeIngress()
	builder1.AddIngress(v1.ProtocolTCP, &p80, nil, &allowCIDRStr, exceptBuilder1, nil, nil, nil, nil)
	policy1 := builder1.Get()
	// Policy-2 is added with allow CIDR that is same as except CIDR of policy-1 (overlap policy)
	policyName2 := "overlap-policy"
	builder2 := &NetworkPolicySpecBuilder{}
	builder2 = builder2.SetName("x", policyName2).SetPodSelector(map[string]string{"pod": "a"})
	builder2.SetTypeIngress()
	builder2.AddIngress(v1.ProtocolTCP, &p80, nil, &exceptBuilder1[0], nil, nil, nil, nil, nil)
	policy2 := builder2.Get()
	// Update policy-2 with exceptCIDR not allowing only pod "y/a"
	builder3 := &NetworkPolicySpecBuilder{}
	// by preserving the same name, this policy will also serve to test the 'updated policy with CIDRs".
	builder3 = builder3.SetName("x", policyName2).SetPodSelector(map[string]string{"pod": "a"})
	builder3.SetTypeIngress()
	builder3.AddIngress(v1.ProtocolTCP, &p80, nil, &exceptBuilder1[0], exceptBuilder3, nil, nil, nil, nil)
	policy3 := builder3.Get()

	return []*TestStep{
		{
			"Pods in built exceptCIDR -- not allowed",
			allowWithExcept(), // exceptCIDR built from pod "y/a"
			policy1,
			80,
			0,
		},
		{
			"All pods in built allowCIDR -- allowed",
			overlapAllow(), // allowCIDR is same as exceptCIDR from policy-1
			policy2,
			80,
			0,
		},
		{
			"Only pod y/a -- not allowed",
			overlapAllowAndExcept(), // exceptCIDR contains only IP of pod "y/a"
			policy3,
			80,
			0,
		},
	}
}
