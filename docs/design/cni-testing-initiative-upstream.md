---
title: Homogenizing Network policy test controls and rearchitecting the NetworkPolicy test framework to support a broader and more relevant test matrix for more fluid discussions around the NetworkPolicy API and how enterprise grade CNI providers implement it.
authors:
  - "@jayunit100"
  - "@abhiraut/sedef please add names"'
  - "@McCodeman"
owning-sig: sig-network
reviewers: TBD
approvers: TBD
editor: TBD
creation-date: 2020-02-04
last-updated: 2020-02-05
status: implementable
---

Special thanks to members of the Calico community, Abhishek Raut (vmware), Sedef Saavas (vmware), Lui Zang (google) and others for helping with this proposal. 

# Homogenizing and expanding NetworkPolicy tests while reducing their complexity

## Summary
This proposal suggest that we leverage truth tables, uniform positive controls tests, and explicit whitelisting mappings to address the opportunities for improvement  in our existing NetworkPolicy test suite, which comprises 23 tests which can take 30 minutes to 1 hour to run.
- Defining a common set of test scenarios for all network policy tests and increasing performance by reusing a set of containers.
- Rearchitecting network policy tests to enhance readibility and reusability.
- Improve coverage for NetworkPolicy functional tests.
- Introduce time to conversion tests to measure performance against perturbed state at scale.

## Motivation 
The current network policy tests have a few issues which, without increasing technical debt, can be addressed architecturally.
 
- *Incompleteness*: We do not confirm that a common set of negative scenarios for different policies.  We also do not confirm a complete set of *positive* connectivity, before starting tests (note: 4 out of the existing 23 tests actually do *some* positive control validation before applying policies, and all tests do postive validation *after* policy application).
- *Understandability*: They are difficult to reason about, due to lack of consistency, completeness, and code duplication
- *Extensibility*: Extending them is a verbose process, which leads to more sprawl in terms of test implementation.
- *Performance*: They suffer from low performance due to the high number of pods created.  Network policy tests can take 30 minutes or longer.  The lack of completeness in positive controls, if fixed, could allow us to rapidly skip many tests destined for failure due to cluster health issues not related to network policy.
- *Dynamic scale*: In addition to increasing the performance of these tests, we also should expand their ability to evaluate CNI's with highly dynamic, realistic workloads, outputting summary metrics.  
- *Documentation and Community*: The overall situation for these tests is that they are underdocumented and poorly understood by the community, and its not clear how these tests are vetted when they are modified; this makes it difficult for CNI providers to compare and contrast compatibility and conformance to K8s standards for NetworkPolicys.
 
### Related issues

As an overall improvement, this KEP will help to address the solutions for several existing issues in upstream Kuberentes.

- https://github.com/kubernetes/kubernetes/issues/87857 (docs and understandability)
- https://github.com/kubernetes/kubernetes/issues/87893 (holes in our test coverage matrix)
- https://github.com/kubernetes/kubernetes/issues/85908 (failing tests, unclear semantics)
- https://github.com/kubernetes/kubernetes/issues/86578 (needs e2e coverage)
- https://github.com/kubernetes/kubernetes/issues/87709 (logging of netpol actions, will help describing states we reach) 
- https://github.com/projectcalico/felix/issues/2032 non-deterministic time frames for policy applications
- https://github.com/projectcalico/felix/issues/2008 need to test postStart pods in networkpolicy upstream
- https://github.com/vmware-tanzu/antrea/issues/381 "It's not detected by e2e test because it can only happen when more than one Pod is scheduled on a single node."


### Consequences of this problem
 
The consequences of this problem is that
 
- CNI providers cannot easily be compared for functionality.
- CNI providers implementing network policies must carry a lot of downstream test functionality.
- Testing a CNI provider for Kubernetes compatibility requires alot of interpretation and time investment.
- Extending NetworkPolicy tests is time consuming and error prone, without a structured review process and acceptance standard.
- It is hard to debug tests, due to the performance characteristics - pods are deleted after each test, so we cannot reproduce the state of the cluster easily.

## Pod Traffic Pathways
TODO: Complete

Intranode
- pod -> pod
- pod -> host 
- host -> pod

Internode
- pod -> pod
- pod -> host
- host -> pod
- `*`host -> host (out-of-scope for K8s Network Policies API)
- host -> pod (host networking)

Traffic Transiting Service DNAT
- Nodeport -> service (DNAT) -> pod
- pod -> service (DNAT) -> pod

* don't need to test
(where to put test probes)

## Security Boundaries

TODO: Complete

Internamespace
- pod -> pod
- pod (host networking) -> pod
- pod -> pod (host networking)

Internamespace
- pod -> pod
- pod (host networking) -> pod
- pod -> pod (host networking)

## Detailed examples of the Problem statement
 
### Incompleteness

A few concrete missing tests are obvious incompleteness examples, such as https://github.com/kubernetes/kubernetes/issues/87893 and https://github.com/kubernetes/kubernetes/issues/46625

As mentioned in the pre-amble, there is sporadic validation of both positive and negative connectivity in all tests, and in many cases this validation is meaningful.  However, in none of the cases, is it complete.  That is, we do not have any tests which validate all obvious intra and inner namespace connectivity holes, both before and after application of policies.  

Examples which visualize this ensue:

For our first example, we will look at the incompleteness of one of the first tests
in the test suite for network_policy.go.  In this test, the following assertions are
made to verify that inter-namespace traffic can be blocked via NetworkPolicys.
 
The "X" lines denote communication which is blocked, whereas standard arrows denote
traffic that is allowed.
 
```
+-------------------------------------------------------------------+
| +------+    +-------+   Figure 1a: The NetworkPolicy Tests        | TODO: maybe include YAML examples side-by-side
| |      |    |       |   current logical structure only verifies   |       visual nomenclature (i.e., cA -> podA)
| |  cA  |    |  cB   |   one of many possible network connectivity |
| |      |    |       |   requirements. Pods and servers are both   |
| +--+---+    +--X----+   in the same node and namespace.           |
|    |           X                                                  |
|    |           X                                                  |
+----v-----------X+---+                                             |
||     server         |    Note that the server runs in the         |
||     80, 81         |    "framework" namespace, and so we don't   |
||                    |    draw that namespace specifically here,   |
||                    |    as that namespace is an e2e default.     |
|---------------------+                                             |
+-------------------------------------------------------------------+
```
 
A *complete* version of this test is suggested when we take the union of all
namespaces created in the entire network policy test suite. 
 
- namespaces B and C, in addition to the framework namespace
- each of these namespaces has 2 containers in them
- each of the containers in each of these namespaces attempts connecting to each port on the server
 
```
+-------------------------------------------------------------------------+
|  +------+              +------+                                         |
|  |      |              |      |                                         |
|  |   cA |              |  cB  |     Figure 1b: The above test           |
|  +--+---+              +----X-+     is only complete if a permutation   |
|     |   +---------------+   X       of other test scenarios which       |
|     |   |    server     |   X       guarantee that (1) There is no      |
|     +--->    80,81      XXXXX       namespace that whitelists traffic   |
|         |               |           and that (2) there is no "container"| TODO: test "default" namespace
|         +----X--X-------+           which whitelists traffic.           |       check for dropped namespaces
| +------------X--X---------------+                                       |       make test instances bidirectional
| |            X  X               |   We limit the amount of namespaces   |          (client/servers)
| |   +------XXX  XXX-------+  nsB|   to test to 3 because 3 is the union |
| |   |      | X  X |       |     |   of all namespaces.                  |
| |   |  cA  | X  X |   cB  |     |                                       |
| |   |      | X  X |       |     |   By leveraging the union of all      |
| |   +------+ X  X +-------+     |   namespaces we make *all* network    |
| |            X  X               |   policy tests comparable,            |
| +-------------------------------+   to one another via a simple         |
|  +-----------X--X---------------+   truth table.                        |
|  |           X  X               |                                       |
|  |  +------XXX  XXX-------+  nsC|   This fulfills one of the cor        |
|  |  |      |      |       |     |   requirements of this proposal:      |
|  |  |  cA  |      |   cB  |     |   comparing and reasoning about       |
|  |  |      |      |       |     |   network policy test completeness    |
|  |  +------+      +-------+     |   in a deterministic manner which     |
|  |                              |   doesnt require reading the code.    |
|  +------------------------------+                                       |
|                                      Note that the tests above are all  |
|                                      done in the "framework" namespace. |
|                                                  similar to figure 1.   |
+-------------------------------------------------------------------------+
```

#### Other concrete examples of incompleteness

The above diagrams show that completeness is virtually impossible, the way the tests are written, because of the fact that each test is manually verifiying bespoke cases.  More concretely, however, a look at `should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:NetworkPolicy]` reveals that some tests don't do positive controls (validation of preexisting connectivity), whereas others *do* do such controls.

#### List of missing/incomplete functional test cases.

TODO: use multiple pods in contiguous CIDR to validate CIDR traffic matching

- IPBlock Except case: Currently, no test case exist to cover a NetworkPolicy
  IPBlock selector which includes an ``except`` clause.
- Stacked IPBlock case: Need to add a test case to verify the traffic when a
  CIDR (say 10.0.1.0/24) is used in an ``except`` clause in one NetworkPolicy,
  and the same CIDR is also used in an allow IPBlock rule in another
  NetworkPolicy, both targeting the same ``spec.PodSelector`` within the same
  Namespace.
- NamedPort resolving to multiple port numbers: Current test cases only test
  named port NetworkPolicies resolving to a single port number. Instead,
  improve the test case by testing that multiple Pods with the same name
  port backed by different port numbers are being allowed correctly by the
  NetworkPolicy rule.

### Understandability

TODO: test case names mean something, and each test case should have accompanying diagram
 
In this next case, we'll take another example test, which is meant to confirm that intra-namespace
traffic rules work properly.  This test has a misleading description, and an incomplete test matrix as well.
 
"Understandability" and "Completeness" are not entirely orthogonal - as illustrated here.  The fact that
we do not cover all communication scenarios (as we did in Figure 1b), means that we have to carefully
read the code for this test, to assert that it is testing the same scenario that its Ginkgo description
connotes.
 
We find that the Ginkgo description for this test isn't entirely correct, because
enforcing traffic *only* from a different namespace also means:
- Blocking traffic from the same namespace
- Confirming traffic from *any* pod in the whitelisted namespace
 
As an example of the pitfall in this test, a network policy provider which, by default
allowed *all internamespaced traffic as whitelisted*, would pass this test while violating
the semantics of it.
 
```
+----------------------------------------------------------------------------------------------+
|                                                                                              |
|           +------------------+       +-------------------+                Figure 2:          |
|           |                  |       | +---+      +---+  |                                   |
|   XXXXXXXXX      nsA         |       | | cA|  nsA | cB|  |                A more advanced    |
|   X    --->                  |       | +X--+      +---+  |                example. In these  |
|   X    |  |                  |       |  X             X  |                cases, we can      |
|   X    |  |     server       |       |  X   server    X  |                increase test      |
|   X    |  |      80,81       |     XXXXXXXXX 80,81 XXXX  |                coverage again     |
|   X    |  +------------------+     X +-------^-----------+                by testing an      |
|   X    |                           X         |                            entire truth       |
|   X    |  +------------------+     X +-------------------+                table (right).     |
|   X    |  |                  |     X |       |           |                                   |
|   X    |  |    +--+   +---+  |     X | +-----+----+---+  |                The "creating a    |
|   X    ------- +cA|   |cB |  |     X | |cA|       | cB|  |                network policy     |
|   X       |    +--+   +---+  |     X | +--+       +---+  |                for the server which
|   X       |   nsB            |     X |      nsB          |                allows traffic     |
|   X       +------------------+     X +-------------------+                from ns different  |
|   X                                X                                      then namespace-a   |
|   X       +------------------+     X  +------------------+                                   |
|   X       |                  |     X  |  +--+            |                test should confirm|
|   X       |   +--+    +--+   |     XXXXXX|cA|     +---+  |              positive connectivity|
|   +XXXXXXXXXXX|cA|    |cB|   |     X  |  +--+     | cB|  |                for both containers|
|           |   +--+    +-++   |     X  |           +---+  |                in nsB.  otherwise |
|           |                  |     X  |             X    |                a policy might not |
|           |     nsC          |     X  |    nsC      X    |                be whitelisting n+1|
|           +------------------+     X  +-------------X----+                pods.              |
|                                    X                X                                        |
|                                    XXXXXXXXXXXXXXXXXX                                        |
|                                                                                              |
|                                                                                              |
+----------------------------------------------------------------------------------------------+
```
 
### Extensibility

The previous scenarios look at logical issues with the current tests.  These issues can be mitigated by simply having more tests, which are as verbose as the existing tests.  However.
 
- Each test can be between 50 to 100 lines long.
- The network policy's created in each test can be around 30 lines or so.
- There are 23 current tests.
 
Thus, in order to build a new test:
 
- We need to read the other tests, and attempt to capture their logic, for consistency's sake.
- The logic is different in each test, so, what positive and negative controls should be run
is not clear.
- Any given network policy test can take a minute or so to verify, because of namespace
deletion and pod startup times, meaning new tests of a simple network policy add a non-trivial
amount of time to the network policy tests, even though the time it takes to apply a network
policy is instantaneous, and the test itself is completely stateless.
- Comparing network policies between tests requires reading verbose Go structs, such as this.
 
As an example of the cost of extensibility, we compare the subtle distinction between the:
 
`should enforce policy based on PodSelector or NamespaceSelector`
and
`should enforce policy based on PodSelector and NamespaceSelector`
 
tests.  These tests use an almost identical harnesses, with a subtle `},{` clause
differentiating the stacked network policy (an or selector) vs. a combined policy.
 
```
 
                    Ingress: []networkingv1.NetworkPolicyIngressRule{{
                        From: []networkingv1.NetworkPolicyPeer{
                            {
                                // TODO add these composably, so that can be disambugated from combo networkpolicypeer
                                PodSelector: &metav1.LabelSelector{
                                    MatchLabels: map[string]string{
                                        "pod-name": "client-b",
                                    },
                                },
                            },
                            {
                                NamespaceSelector: &metav1.LabelSelector{
                                    MatchLabels: map[string]string{
                                        "ns-name": nsBName,
                                    },
                                },
                            },
                        },
                    }},
```
 
The AND test is obviously more selective, although it is tricky to tell from the struct that
it has been correctly written to be different from the OR test...
 
```
                    Ingress: []networkingv1.NetworkPolicyIngressRule{{
                        From: []networkingv1.NetworkPolicyPeer{
                            {
                                PodSelector: &metav1.LabelSelector{
                                    MatchLabels: map[string]string{
                                        "pod-name": "client-b",
                                    },
                                },
                                // because we lack {,} , these are independent stacked
                                // policies.  this is difficult to verify for correctness
                                // at a glance, due to the verbosity of the struct. 
                                NamespaceSelector: &metav1.LabelSelector{
                                    MatchLabels: map[string]string{
                                        "ns-name": nsBName,
                                    },
                                },
                            },
                        },
``` 
We can of course make this much easier to reuse and reasoon about, as well as make it self documenting, and will outline how in the solutions section.

### Performance
 
For every current test, a new container is spun up, and a polling process occurs where we wait for the pod to complete succesfully.  Because all clusters start pods at different rates, heuristics have to be relied on for timing a test out.  A large, slow cluster may not be capable of spinning pods of quickly, and thus may timeout one of the 23 tests, leading to a false negative result.
 
In some clusters, for example, namespace deletion is known to be slow - and in these cases the network policy tests may take more then an hour to complete.
 
- If network policys or pod CIDR's are not correct, its likely all tests can fail, and thus the network policy suite may take an hour to finish, based on the estimate of 3 minutes, for each failed test, alongside 23 tests (in general , NetworkPolicy tests on a healthy EC2 cluster, with no traffic and broken network policy's, take between 150 and 200 seconds complete).

Using `Pod Exec` Functionality, we've determined that 81 verifications can happen rapidly, within 30 seconds, when tests run inside of Kubernetes pods, compared with about the same time for a single test with < 5 verifications, using Pod status indicators.

#### Relationship to Understandability: Logging verbosity is worse for slow tests.
 
Slow running tests are also hard to understand, because logging and metadata is expanded over a larger period of time, increasing the amount
of information needed to be attended to diagnose an issue. For example, to test this, we have intentionally misconfigured my CIDR information for a calico CNI,
and found that the following verbose logging about is returned when running the `NetworkPolicy` suite:
```
Feb  4 16:01:16.747: INFO: Pod "client-a-swm8q": Phase="Pending", Reason="", readiness=false. Elapsed: 1.87729ms
... 26 more lines ...
Feb  4 16:02:04.808: INFO: Pod "client-a-swm8q": Phase="Failed", Reason="", readiness=false. Elapsed: 48.063517483s
```
Thus, the majority of the logging information from a CNI which may have an issue is actually related to the various polling operations
which occured, rather then to the test itself.  Of course, this makes sense - since we always recreate pods, we have to potentially
wait many seconds for those pods to come up.
 
Thus, by increasing the performance of our tests, we also increase their understandability, because the amount of information needed to be
audited for inspecting a failure may be reduced by a 50% (currently, 50% of the output for failing network policy tests is that of the polling
process for pods spinning up, which is easily avoided by a fixed server and client pod).
 
### Documentation
 
Documenting network states is very hard, in any scenario.  Since the NetworkPolicy ginkgo tests are curently not documented outside of the code, no specific evidence is required here.  This proposal aims not to Document these tests, but rather , to make the code more readable, and thus self-documenting.  However, formal documentation of how network policies, generally, are evaluated using a truth table approach, is a part of this proposal.  This generic documentation will be insightful and concise for those needing to test their NetworkPolicy implementations, and likely to not go obsolete, due to the generic nature of the truth-table/matrix approach (compared to the highly specific nature of existing tests).

As a few examples of this:
- the test `Creating a network policy for the server which allows traffic from the pod 'client-a' in same namespace` actually needs to confirm that *no outside* namespace can communicate with the server.
- the test outlined in Figure2 is another examples of a test which isn't described comprehensively.

In the solutions section, we will highlight how the proposal makes these tests, and thus the semantics of network policies, explicit and self documenting.
 
## Solution to the Problem
 
In short, our solution to this problem follows
 
- *Increase performance* of tests by using persistent Deployments.
- *Increase understandability* by defining network scenario objects which can easily by modified and reused between tests, and outputting the entire contents of the truth table for each test, in some manner.
- *Increase completeness* by using a logical truth table which tests connectivity/disconnectivity for each scenario above.
- *Increase extensibility* by leveraging the scenario objects and the completeness checking functionality above.
- *Increase debuggability* by leveraging the performance changes above.
- *Audit all existing tests* For logical redundancy and consistency
 
### Detailed Solution proposal
 
There are many solutions, and this proposal outlines the most obvious approach which is relatively simple to implement, and minimally abstract, so as to not overcomplicate the testing framework or add technical debt.
 
### Code improvements
 
#### Part 1:
 
 
1. Define a common set of namespaces, and pods, used to make a truth table that applies to all tests.  This is demonstrated in diagram 1b and 2.
 
- Namespaces
  - namespace the default framework namespace.
    - server resides here
    - client pods  "a" and "b" also reside here.
  - namespace A
    - client pods "a" and "b" reside here.
  - namespace B
    - client pods "a" and "b" reside here.
- Pods
  - pod a
  - pod b
 
These resources are created for every test.

 
2. Define a structure for expressing the truth table of results.   Since clasically a truth table can be expressed as a 2D matrix, where
rows and columns are the lexically sorted list of all pod namespace pairs defined above, formatted as `namespace-pod`.  For example, a truth table defining a NetworkPolicy where only pods in the same namespace of the server can communicate to it, would look like this.  Capital letters are *namespaces*, and lower case letters are *pods* in those namespaces.  The tuple value represents connectivity to ports *80* and *81*, respectively.
 
|    | As  | Aa  | Ab  | Ab  | Ba  | Bb  | Ca  | Cb  |
|----|-----|-----|-----|-----|-----|-----|-----|-----|
| As | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| Aa | 1,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| Ab | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| Ba | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| Bb | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| Ca | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| Cb | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
 
Most of the Matrices for this table will be permuting the first row and column, since the server pod currently always resides in the framework namespace.  However, tests might confirm two way connectivity
and other types of connectivity in the future, and such an expansion would work very cleanly with a matrix.
 
Part of this invovles a pretty-print functionality for these tables, which can be output at the end of each Network policy test.  In failed
test scenarios, these tables can be compared, and one may easily parse out a logical inference such as "Everything outside the frameowrk
namespace has connectivity, even when the truth table explicitly forbids it", which might, for example, point to a bug in a CNI provider
related to flagrantly allowing internamespace traffic.  Since it is obvious how such a matrix might be defined in Go, we dont provide a
code snippet or API example.
 
#### Part 2:
  
Rewrite each individual test, reviewing semantics, to be precisely worded (and possibly verbose), and to simply define a specific policy and
set of 'whitelisted' communication associated with this policy.  The whitelisting would be defined as a map of namespace->pods, since all other
information in the truth table is false.
 
Example:

Initially, to confirm the logical capacity of the builder mechanism for replacing existing tests, a prototype of inplace replacements of NetworkPolicy definitions was done here (prototype) https://gist.github.com/6a62266e0eec2b15e5250bd65daa4faa.  Now, this underlying API has been implemented in full, and the following repository https://github.com/jayunit100/k8sprototypes, demonstrates a working implementation and port of the network policy tests (Currently about half of these have been ported).  Each test follows a simple and easy to read pattern such as this:

 ```
 builder := &utils.NetworkPolicySpecBuilder{}
	builder = builder.SetName("allow-x-via-pod-and-ns-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod":"b"}, map[string]string{"ns":"y"}, nil, nil)

	k8s.CreateNetworkPolicy("x", builder.Get())
	m := &utils.ReachableMatrix{
		DefaultExpect: true,
		Pods:          pods,
		Namespaces:    namespaces,
	}
	reachability := utils.NewReachability(listAllPods())
	m.ExpectAllIngress("x", "a", false)
	m.Expect("y", "b", "x", "a", true)

	return m, reachability
  ```
 This represents a significant reduction in code complexity, with the equivalent tests using the existing network_policy.go implementation being 3 to 4 times as long, mostly due to boiler plate around verification and go structures.
 
##### Note on Acceptance and Backwards compatibility

Thus far there are two obvious ways to ensure backwards compatibility. 
- Each old test will be converted to a truth table, first, as part of this work, so that the parity between old and new tests is clear and obvious 
- Alternatively, these can be a next generation of policy tests which live in parallel to existing network policy tests for a release cycle, while they are vetted

## Next steps: Defining community standards and establishing ownership

As of now, network policy tests are not run regularly against any CNI.  Although we should not endorse one CNI over another, we should regularly validate
that the NetworkPolicy tests *can* pass on *some* provider.  As part of this proposal, we propose commiting an annotation to the existing network_policy.go code which states, in clear and simple terms, what environment the network_policy.go test suite was run in, the last time which it was commited and passed.  Its also acceptable to commit this as a Markdown file in the documentation.
 
There may be other, better ways of doing this.  Running an upstream validation job of these tests as a weekly PROW job, for example, would be a good way to make sure that these tests don't regress in the future.  this comes at the cost of coupling a job to an external CNI provider, so its not being explicitly suggested.

## Other Improvement Ideas

These may be included in this proposal, but as of now, aren't detailed yet.

### Node specific policy validation (Contributed by Sedef Saavas)

A wider range of scenarios that may be tested can be seen in the figure below.
![](test-scenarios.png)
 In this figure, inter/intra-namespace tests on the same node and inter-intra namespace tests on different nodes are demonstrated.
Another important network-policy-test case is testing host-network only containers. C4, C5, C8, and C9 are host-network only containers.

### Ensuring that large policy stacks evaluate correctly

Right now the coverage of Policy stacks is rudimentary, we may want to test for a large number(i.e. 10) of policy's, stacked, depending on wether we think this may be a bug source for providers.

## Alternative solutions to this proposal
 
#### Keeping the tests as they are and fixing them one by one
 
We could simply audit existing tests for completeness, and one-by-one, add new test coverage where it is lacking.  This may be feasible for the 23 tests we currently have, but it would be likely to bit-rot over time, and not solve the extensibility or debuggability problems.
 
#### Building a framework for NetworkPolicy evaluation
 
In this proposal, we've avoided suggesting a complex framework that could generate large numbers of services and pods, and large permuatations of scenarios.
However, it should be noted that such a framework might be useful in testing performance at larger scales, and comparing CNI providers with one another. Such a framework could easily be adopted to cover the minimal needs of the NetworkPplicy implemetnation in core Kubernetes, so it might be an interesting initiative to work on.  Such an initiative might fall on the shoulders of another Sig, related to performance or scale.  Since NetworkPolicy's have many easy to address
problems which are important as they stand, we avoid going down this rat-hole, for now.
 
That said, the work proposed here might be a first step towared a more generic CNI testing model.

#### Have the CNI organization create such tests

We cannot proxy this work to the CNI organization, because in large part, the semantics of how network policy's are implemented and what we care about from an API perspective is defined by Kubernetes itself.  As we propose expansion of the Network Policy API, we need a way to express the effects of these new APIs in code, concisely, in a manner which is gauranteed to test robustly.

## Performance and Concurrency of Tests
TODO: Cody to write

## Perturbed State Tests

## Scale and Convergence Tests

