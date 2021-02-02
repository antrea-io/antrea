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
