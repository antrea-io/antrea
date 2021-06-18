# A Truth-table based Network Policy construction and validation library.

This repo implements upstream [CNI testing initiative](https://github.com/kubernetes/enhancements/pull/1568), a fast, comprehensive truth table matrix for network policies which can be used to ensure that your CNI provider is fast, reliable, and air-tight.

## A super-simple builder for experimenting with and validating your own network policies

One hard thing about network policies is *testing* that they do *exactly* what you thought they did. You can fork this repo and code up a network policy quickly, and in a few lines of code, verify that it works perfectly.

You can add a new test in just a few lines of code, for example, this test creates a network policy which ensures that 
only traffic from `b` pods in the 3 namespaces `x,y,z` can access the `a` pod, which lives in namespace `x`.

```
	builder := &utils.NetworkPolicySpecBuilder{}
	builder = builder.SetName("allow-client-a-via-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder.SetTypeIngress()
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "x"}, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "y"}, nil, nil)
	builder.AddIngress(nil, &p80, nil, nil, map[string]string{"pod": "b"}, map[string]string{"ns": "z"}, nil, nil)
	k8s.CreateNetworkPolicy("x", builder.Get())
	m.ExpectAllIngress("x","a",false)
	m.Expect("x", "b", "x", "a", true)
	m.Expect("y", "b", "x", "a", true)
	m.Expect("z", "b", "x", "a", true)
	m.Expect("x", "a", "x", "a", true)
```

This policy is then validated using the following three-liner:

```
	matrix := TestPodLabelAllowTrafficFromBToA(&k8s)
	validate(&k8s, matrix)
	summary, pass := matrix.Summary()
	fmt.Println(summary, pass)
```

The output of these tests shows all probes, in the logs, so you can reproduce them, and also output the entire truth table of pod<->pod connectivity for you once the test is done. 

```

correct:81, incorrect:0, result=%!(EXTRA bool=true) true

-	x/a	y/a	z/a	x/b	y/b	z/b	x/c	y/c	z/c
x/a	.	.	.	.	.	.	.	.	.
y/a	X	.	.	.	.	.	.	.	.
z/a	X	.	.	.	.	.	.	.	.
x/b	.	.	.	.	.	.	.	.	.
y/b	.	.	.	.	.	.	.	.	.
z/b	.	.	.	.	.	.	.	.	.
x/c	X	.	.	.	.	.	.	.	.
y/c	X	.	.	.	.	.	.	.	.
z/c	X	.	.	.	.	.	.	.	.


observed:

-	x/a	y/a	z/a	x/b	y/b	z/b	x/c	y/c	z/c
x/a	.	.	.	.	.	.	.	.	.
y/a	X	.	.	.	.	.	.	.	.
z/a	X	.	.	.	.	.	.	.	.
x/b	.	.	.	.	.	.	.	.	.
y/b	.	.	.	.	.	.	.	.	.
z/b	.	.	.	.	.	.	.	.	.
x/c	X	.	.	.	.	.	.	.	.
y/c	X	.	.	.	.	.	.	.	.
z/c	X	.	.	.	.	.	.	.	.


comparison:

-	x/a	y/a	z/a	x/b	y/b	z/b	x/c	y/c	z/c
x/a	.	.	.	.	.	.	.	.	.
y/a	.	.	.	.	.	.	.	.	.
z/a	.	.	.	.	.	.	.	.	.
x/b	.	.	.	.	.	.	.	.	.
y/b	.	.	.	.	.	.	.	.	.
z/b	.	.	.	.	.	.	.	.	.
x/c	.	.	.	.	.	.	.	.	.
y/c	.	.	.	.	.	.	.	.	.
z/c	.	.	.	.	.	.	.	.	.

```

## How is this different then NetworkPolicy tests in upstream K8s ?

We are working to merge this into upstream Kubernetes, in the meanwhile, here's the differences.

- We define tests as *truth tables, and have a 'builder' library* for building up network policy structs with almost no boilerplate, meaning you can define a very sophisticated network policy test in just a few lines of code.
- *Comprehensive:* All pod-to-pod connectivity is validated for every test run.  In a typical network policy test in current upstream we only validate 2 or 3 scenarios, leaving out intra and inner namespace connections which might be compromised due to a hard to detect CNI inconsistency.  In these tests, we test all 81 connections for 3 identical pods running in 3 different namespaces (i.e. the 9x9 connectivity matrix).
- *Transparent:* Each test prints out a `kubectl` command you can run to re-probe a given pods connectivity patterns.
- It's *fast:* Because we use `kubectl exec` to run tests with `wget` between pods, all 81 tests can easily finish in 20 seconds or less, even if pod scheduling is slow.  This is because no polling is done, and there is no down/uptime for pods.
- *Easy to reason about:* The pods in this repo stay up forever, so you can reuse the above kubectl commands outputted by your netpol logs to exec into a pod and reproduce any failures.
- *Scalable:* If you want to test 32 policies, all at once ? Just take a look at the example test (in `main`) and copy paste a few lines, and you'll be testing enterprise CNI application patterns in a heartbeat.

## Users

### Test Your Dang CNI !  Now !

Create the policy probe tests:

```
kubectl create clusterrolebinding netpol --clusterrole=cluster-admin --serviceaccount=kube-system:netpol
kubectl create sa netpol -n kube-system
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/hack/netpol/install.yml
```

Now, look at the results of the network policy probe:

```
kubectl logs -n kube-system job.batch/netpol
```
(or add `-f` to stream the logs while the tests are running)
 
## Developers

This is a new library for building complex, comprehensive network policy tests. To build it, cd to antrea/hack/netpol and run `go run ./pkg/main/main.go`. Then, execute the binary.
