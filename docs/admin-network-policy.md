# AdminNetworkPolicy API Support in Antrea

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Sample specs for AdminNetworkPolicy and BaselineAdminNetworkPolicy](#sample-specs-for-adminnetworkpolicy-and-baselineadminnetworkpolicy)
  - [Relationship with Antrea-native Policies](#relationship-with-antrea-native-policies)
<!-- /toc -->

## Introduction

Kubernetes provides the NetworkPolicy API as a simple way for developers to control traffic flows of their applications.
While NetworkPolicy is embraced throughout the community, it was designed for developers instead of cluster admins.
Therefore, traits such as the lack of explicit deny rules make securing workloads at the cluster level difficult.
The Network Policy API working group (subproject of Kubernetes SIG-Network) has then introduced the
[AdminNetworkPolicy APIs](https://network-policy-api.sigs.k8s.io/api-overview/) which aims to solve the cluster admin
policy usecases.

Starting with v1.13, Antrea supports the `AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` API types, except for
advanced Namespace selection mechanisms (namely `sameLabels` and `notSameLabels` rules) which are still in the
experimental phase and not required as part of conformance.

## Prerequisites

AdminNetworkPolicy was introduced in v1.13 as an alpha feature and is disabled by default. A feature gate,
`AdminNetworkPolicy`, must be enabled in antrea-controller.conf in the `antrea-config` ConfigMap when Antrea is deployed:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-controller.conf: |
    featureGates:
      AdminNetworkPolicy: true
```

Note that the `AdminNetworkPolicy` feature also requires the `AntreaPolicy` featureGate to be set to true, which is
enabled by default since Antrea v1.0.

In addition, the AdminNetworkPolicy CRD types need to be installed in the K8s cluster.
Refer to [this document](https://network-policy-api.sigs.k8s.io/getting-started/) for more information.

## Usage

### Sample specs for AdminNetworkPolicy and BaselineAdminNetworkPolicy

Please refer to the [examples page](https://network-policy-api.sigs.k8s.io/reference/examples/) of the network-policy-api
repo, which contains several user stories for the AdminNetworkPolicy APIs, as well as sample specs for each of the user
story. Shown below are sample specs of `AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` for demonstration purposes:

```yaml
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: cluster-wide-deny-example
spec:
  priority: 10
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: sensitive-ns
  ingress:
    - action: Deny
      from:
      - namespaces:
         namespaceSelector: {}
      name: select-all-deny-all
```

```yaml
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces: {}
  ingress:
    - action: Deny   # zero-trust cluster default security posture
      from:
      - namespaces:
          namespaceSelector: {}
```

Note that for a single cluster, the `BaselineAdminNetworkPolicy` resource is supported as a singleton with the name of
`default`.

### Relationship with Antrea-native Policies

AdminNetworkPolicy API objects and Antrea-native policies can co-exist with each other in the same cluster.

AdminNetworkPolicy and BaselineAdminNetworkPolicy API types provide K8s upstream supported, cluster admin facing
guardrails that are portable and CNI-agnostic. AntreaClusterNetworkPolicy and AntreaNetworkPolicy on the other hand,
are designed for similar use cases but provide a richer feature set, including FQDN policies, nodeSelectors and L7 rules.
See the [Antrea-native policy doc](antrea-network-policy.md) and [L7 policy doc](antrea-network-policy.md) for details.

Both the AdminNetworkPolicy object and Antrea-native policy objects use a `priority` field to determine its precedence
compared to other policy objects. The following diagram describes the relative precedence between the AdminNetworkPolicy
API types and Antrea-native policy types:

```text
Antrea-native Policies (tier != baseline) > 
AdminNetworkPolicies                      >
K8s NetworkPolicies                       >
Antrea-native Policies (tier == baseline) >
BaselineAdminNetworkPolicy
```

In other words, any Antrea-native policies that are not created in the `baseline` tier will have higher precedence over,
and thus evaluated before, all AdminNetworkPolicies at any `priority`. Effectively, the AdminNetworkPolicy objects are
associated with a tier priority lower than Antrea-native policies, but higher than K8s NetworkPolicies. Similarly,
baseline-tier Antrea-native policies will have a higher precedence over the BaselineAdminNetworkPolicy object.
For more information on policy and rule precedence, refer to [this section](antrea-network-policy.md#notes-and-constraints).
