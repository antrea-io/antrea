# Cyclonus: Network policy generator

The [Cyclonus](https://github.com/mattfenwick/cyclonus) tool generates test scenarios involving network policies,
runs the scenarios on kubernetes clusters measuring connectivity between pods, and compares measured results to
expected results. The result is a multidimensional conformance matrix of network policy features.

Cyclonus already supports tests for a variety of network policy features, but is not yet comprehensive!
Its long-term goal is to provide a comprehensive test suite for network policy implementations, by generating
exhaustive network policies and network-policy-related cluster scenarios for CNI testing.


## Using Cyclonus to test network policies in a real cluster

Cyclonus can be run as a kubernetes job, with the appropriate permissions.
Check out [this k8s job yaml](./install-cyclonus.yml) to see the k8s job yaml. To run:

```bash
kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system

kubectl create -f ./install-cyclonus.yml
```
