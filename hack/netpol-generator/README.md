# Cyclonus: Network policy generator

The [Cyclonus](https://github.com/mattfenwick/cyclonus) tool generates test scenarios involving network policies,
runs the scenarios on kubernetes clusters measuring connectivity between pods, and compares to measure results to
expected results.  The result is a multidimensional conformance matrix of network policy features.

Cyclonus already supports tests for a variety of network policy features, but is not yet comprehensive!
Its long-term goal is to provide a comprehensive test suite for network policy implementations, by generating
exhaustive network policies and network-policy-related cluster scenarios for CNI testing.

## Using Cyclonus to test network policies in a real cluster

Download a [Cyclonus release](https://github.com/mattfenwick/cyclonus/releases), and invoke with:

```bash
$ cyclonus generate --mode=simple-fragments --noisy=true --cleanup-namespaces=true
```

## More options

```bash
$ cyclonus_0.1.1 generate -h
generate network policies, create and probe against kubernetes, and compare to expected results

Usage:
  cyclonus generate [flags]

Flags:
      --allow-dns                          if using egress, allow udp over port 53 for DNS resolution (default true)
      --cleanup-namespaces                 if true, clean up namespaces after completion
      --context string                     kubernetes context to use; if empty, uses default context
  -h, --help                               help for generate
      --ignore-loopback                    if true, ignore loopback for truthtable correctness verification
      --mode string                        mode used to generate network policies
      --namespaces strings                 namespaces to create/use pods in (default [x,y,z])
      --noisy                              if true, print all results
      --perturbation-wait-seconds int      number of seconds to wait after perturbing the cluster (i.e. create a network policy, modify a ns/pod label) before running probes, to give the CNI time to update the cluster state (default 5)
      --pod-creation-timeout-seconds int   number of seconds to wait for pods to create, be running and have IP addresses (default 60)
      --pods strings                       pods to create in namespaces (default [a,b,c])

Global Flags:
  -v, --verbosity string   log level; one of [info, debug, trace, warn, error, fatal, panic] (default "info")
```
