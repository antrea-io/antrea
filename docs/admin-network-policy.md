# Kubernetes ClusterNetworkPolicy API Support in Antrea

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Migrating from AdminNetworkPolicy and BaselineAdminNetworkPolicy](#migrating-from-adminnetworkpolicy-and-baselineadminnetworkpolicy)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Sample specs for ClusterNetworkPolicy](#sample-specs-for-clusternetworkpolicy)
  - [Relationship with Antrea-native Policies](#relationship-with-antrea-native-policies)
<!-- /toc -->

## Introduction

Kubernetes provides the NetworkPolicy API as a simple way for developers to control traffic flows of their applications.
While NetworkPolicy is embraced throughout the community, it was designed for developers instead of cluster admins.
Therefore, traits such as the lack of explicit deny rules make securing workloads at the cluster level difficult.
The Network Policy API working group (subproject of Kubernetes SIG-Network) has then introduced the
[network-policy-api](https://network-policy-api.sigs.k8s.io/api-overview/) which aims to solve the cluster admin
policy usecases.

Starting with the v0.2.0 release of the network-policy-api, the previously separate `AdminNetworkPolicy` and
`BaselineAdminNetworkPolicy` resources were unified into a single cluster-scoped `ClusterNetworkPolicy` resource. A
`ClusterNetworkPolicy` selects its precedence tier (`Admin` or `Baseline`) via its `spec.tier` field.

Antrea supports the `ClusterNetworkPolicy` API type. Note that this is the upstream, CNI-agnostic
`policy.networking.k8s.io/ClusterNetworkPolicy` resource, which is distinct from the Antrea-native
`crd.antrea.io/ClusterNetworkPolicy` resource.

## Migrating from AdminNetworkPolicy and BaselineAdminNetworkPolicy

> [!IMPORTANT]
> The `v1alpha1` `AdminNetworkPolicy` (ANP) and `BaselineAdminNetworkPolicy` (BANP) resources are **deprecated** and are
> **no longer supported by Antrea**. Antrea now exclusively supports the `v1alpha2` `ClusterNetworkPolicy` (CNP)
> resource introduced in network-policy-api v0.2.0. Existing ANP/BANP objects will no longer be enforced after the
> upgrade and must be re-authored as `ClusterNetworkPolicy` objects.

To migrate existing policies:

- Replace `apiVersion: policy.networking.k8s.io/v1alpha1` with `apiVersion: policy.networking.k8s.io/v1alpha2`, and
  `kind: AdminNetworkPolicy` / `kind: BaselineAdminNetworkPolicy` with `kind: ClusterNetworkPolicy`.
- Add a `spec.tier` field: use `Admin` for policies migrated from `AdminNetworkPolicy` and `Baseline` for policies
  migrated from `BaselineAdminNetworkPolicy`.
- Rename the `Allow` rule action to `Accept` (`Deny` and `Pass` are unchanged).
- Replace the `ports` field with the restructured `protocols` field (`tcp`/`udp`/`sctp` with a `destinationPort`, or a
  `destinationNamedPort`).
- A `BaselineAdminNetworkPolicy` was a singleton named `default`; once migrated, multiple Baseline-tier
  `ClusterNetworkPolicy` objects can be created and are ordered within the tier by their `priority` field.

The `K8sClusterNetworkPolicy` feature gate replaces the previous `AdminNetworkPolicy` feature gate; update your
`antrea-config` ConfigMap accordingly (see [Prerequisites](#prerequisites)).

## Prerequisites

Support for `ClusterNetworkPolicy` is an alpha feature and is disabled by default. A feature gate,
`K8sClusterNetworkPolicy`, must be enabled in antrea-controller.conf in the `antrea-config` ConfigMap when Antrea is
deployed:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-controller.conf: |
    featureGates:
      K8sClusterNetworkPolicy: true
```

Note that the `K8sClusterNetworkPolicy` feature also requires the `AntreaPolicy` featureGate to be set to true, which is
enabled by default since Antrea v1.0.

In addition, the `ClusterNetworkPolicy` CRD type needs to be installed in the K8s cluster.
Refer to [this document](https://network-policy-api.sigs.k8s.io/getting-started/) for more information.

## Usage

### Sample specs for ClusterNetworkPolicy

Please refer to the [examples page](https://network-policy-api.sigs.k8s.io/reference/examples/) of the network-policy-api
repo, which contains several user stories for the API, as well as sample specs for each of the user story. Shown below
are sample specs of an Admin-tier and a Baseline-tier `ClusterNetworkPolicy` for demonstration purposes:

```yaml
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: cluster-wide-deny-example
spec:
  tier: Admin
  priority: 10
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: sensitive-ns
  ingress:
    - action: Deny
      from:
      - namespaces: {}
      name: select-all-deny-all
```

```yaml
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: baseline-deny-example
spec:
  tier: Baseline
  priority: 10
  subject:
    namespaces: {}
  ingress:
    - action: Deny   # zero-trust cluster default security posture
      from:
      - namespaces: {}
```

Unlike the previous `BaselineAdminNetworkPolicy` resource (which was a singleton named `default`), multiple
Baseline-tier `ClusterNetworkPolicy` objects can be created, and they are prioritized within the tier via their
`priority` field.

The egress `to` peers support selecting `pods`, `namespaces`, and `networks` (CIDR ranges). The experimental `nodes`
and `domainNames` egress peers are not supported, and a ClusterNetworkPolicy that uses them is rejected by the
validating webhook.

### Relationship with Antrea-native Policies

`ClusterNetworkPolicy` API objects and Antrea-native policies can co-exist with each other in the same cluster.

The `ClusterNetworkPolicy` API type provides a K8s upstream supported, cluster admin facing guardrail that is portable
and CNI-agnostic. AntreaClusterNetworkPolicy and AntreaNetworkPolicy on the other hand, are designed for similar use
cases but provide a richer feature set, including FQDN policies, nodeSelectors and L7 rules.
See the [Antrea-native policy doc](antrea-network-policy.md) and [L7 policy doc](antrea-network-policy.md) for details.

Both the `ClusterNetworkPolicy` object and Antrea-native policy objects use a `priority` field to determine their
precedence compared to other policy objects. The following diagram describes the relative precedence between the
`ClusterNetworkPolicy` tiers and Antrea-native policy types:

```text
Antrea-native Policies (tier != baseline)  > 
ClusterNetworkPolicy (tier == Admin)        >
K8s NetworkPolicies                         >
Antrea-native Policies (tier == baseline)   >
ClusterNetworkPolicy (tier == Baseline)
```

In other words, any Antrea-native policies that are not created in the `baseline` tier will have higher precedence over,
and thus evaluated before, all Admin-tier ClusterNetworkPolicies at any `priority`. Effectively, the Admin-tier
ClusterNetworkPolicy objects are associated with a tier priority lower than Antrea-native policies, but higher than K8s
NetworkPolicies. Similarly, baseline-tier Antrea-native policies will have a higher precedence over Baseline-tier
ClusterNetworkPolicy objects. For more information on policy and rule precedence, refer to
[this section](antrea-network-policy.md#notes-and-constraints).
