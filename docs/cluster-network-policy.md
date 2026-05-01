# ClusterNetworkPolicy API Support in Antrea

This document describes Antrea support for the upstream Kubernetes
[`ClusterNetworkPolicy`](https://network-policy-api.sigs.k8s.io/) API (`policy.networking.k8s.io/v1alpha2`). It is
different from the Antrea-native `ClusterNetworkPolicy` CRD (`crd.antrea.io/v1beta1`), which is documented in
[Antrea Network Policy CRDs](antrea-network-policy.md#antrea-clusternetworkpolicy) as **Antrea ClusterNetworkPolicy
(ACNP)**.

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
  - [Install upstream CRDs](#install-upstream-crds)
- [Key differences from v1alpha1 AdminNetworkPolicy APIs](#key-differences-from-v1alpha1-adminnetworkpolicy-apis)
- [Usage](#usage)
  - [Sample ClusterNetworkPolicy specs](#sample-clusternetworkpolicy-specs)
  - [Relationship with Antrea-native Policies](#relationship-with-antrea-native-policies)
<!-- /toc -->

## Introduction

The [network-policy-api](https://github.com/kubernetes-sigs/network-policy-api) project defines cluster-wide policies for
cluster administrators. The v1alpha2 `ClusterNetworkPolicy` resource replaces the deprecated v1alpha1
`AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` types with a single API, an explicit **Admin** or **Baseline**
tier, and rule actions **Accept**, **Deny**, and **Pass**.

When the `ClusterNetworkPolicy` feature gate is enabled, the Antrea Controller translates each upstream
`ClusterNetworkPolicy` into Antrea's internal NetworkPolicy representation for enforcement in the dataplane.

## Prerequisites

`ClusterNetworkPolicy` was introduced as an Antrea Controller alpha feature in v2.7 and is disabled by default. Enable
the `ClusterNetworkPolicy` feature gate in `antrea-controller.conf` in the `antrea-config` ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-controller.conf: |
    featureGates:
      ClusterNetworkPolicy: true
```

Note: The `ClusterNetworkPolicy` feature requires the `AntreaPolicy` feature gate to be set to `true`, which is enabled by
default since Antrea v1.0.

### Install upstream CRDs

Install the Custom Resource Definitions from the [network-policy-api documentation](https://network-policy-api.sigs.k8s.io/).

For the v0.2.0 released version of ClusterNetworkPolicy, install via

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.2.0/config/crd/experimental/policy.networking.k8s.io_clusternetworkpolicies.yaml
```

## Key differences from v1alpha1 AdminNetworkPolicy APIs

If you are familiar with the deprecated v1alpha1 APIs described in
[AdminNetworkPolicy API Support in Antrea (deprecated)](admin-network-policy.md), the v1alpha2 model differs in several
ways:

- **Single resource**: One `ClusterNetworkPolicy` object replaces separate `AdminNetworkPolicy` and
  `BaselineAdminNetworkPolicy` resources. Baseline posture is expressed with `spec.tier: Baseline` instead of a distinct
  kind and singleton name.
- **Tier field**: `spec.tier` is either `Admin` or `Baseline`, aligning with the upstream tier model.
- **Actions**: `Accept`, `Deny`, and `Pass` replace the v1alpha1 action sets; Antrea maps **Accept** to allow, **Deny**
  to drop, and **Pass** to pass-through for further evaluation in the Antrea pipeline.
- **Rule structure**: Ingress and egress rules use the v1alpha2 peer and `protocols` shapes (including TCP/UDP/SCTP
  destination ports, port ranges, and named ports). Egress peers can include pods, namespaces, nodes, CIDR
  **networks**, and **domain names** as defined upstream.

## Usage

### Sample ClusterNetworkPolicy specs

Refer to the [examples](https://network-policy-api.sigs.k8s.io/reference/examples/) published with network-policy-api.
Below are minimal illustrations analogous to the legacy v1alpha1 samples in
[AdminNetworkPolicy API Support in Antrea (deprecated)](admin-network-policy.md#sample-specs-for-adminnetworkpolicy-and-baselineadminnetworkpolicy).

Admin-tier deny ingress to Pods in selected Namespaces from all Namespaces:

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
      name: select-all-deny-all
      from:
        - namespaces: {}
```

Baseline-tier default deny (compare to the legacy `BaselineAdminNetworkPolicy` named `default`):

```yaml
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: default-baseline-deny
spec:
  tier: Baseline
  priority: 10
  subject:
    namespaces: {}
  ingress:
    - action: Deny
      name: default-deny-all
      from:
        - namespaces: {}
```

### Relationship with Antrea-native Policies

Upstream `ClusterNetworkPolicy` objects and Antrea-native policies can co-exist in the same cluster. Upstream policies
provide portable, CNI-agnostic guardrails; Antrea-native `AntreaClusterNetworkPolicy` and `AntreaNetworkPolicy` offer a
richer feature set (for example FQDN rules beyond upstream domain peer types, node selectors, and L7 rules). See
[Antrea Network Policy CRDs](antrea-network-policy.md) and [L7 policy](antrea-l7-network-policy.md) for details.

Both upstream `ClusterNetworkPolicy` and Antrea-native policies use a `priority` field within a tier to order rules.
The following diagram summarizes how Antrea orders **upstream** `ClusterNetworkPolicy` tiers relative to Antrea-native
tiers and Kubernetes `NetworkPolicy` (consistent with the legacy Admin/Baseline model):

```text
Antrea-native Policies (tier != baseline) >
ClusterNetworkPolicy (Admin tier)         >
K8s NetworkPolicies                       >
Antrea-native Policies (tier == baseline) >
ClusterNetworkPolicy (Baseline tier)
```

In other words, Antrea-native policies that are not in the `baseline` tier are evaluated before any upstream
`ClusterNetworkPolicy` in the **Admin** tier. Admin-tier upstream policies are evaluated before Kubernetes
`NetworkPolicy`. Baseline-tier Antrea-native policies are evaluated before upstream **Baseline** tier
`ClusterNetworkPolicy` objects. For more detail on Antrea-native ordering, see
[Antrea-native policy ordering based on priorities](antrea-network-policy.md#antrea-native-policy-ordering-based-on-priorities).
