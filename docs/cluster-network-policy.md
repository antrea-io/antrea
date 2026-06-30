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
- [Relationship with Antrea-native Policies](#relationship-with-antrea-native-policies)
- [Tier Priority Reservation and Conflict Handling](#tier-priority-reservation-and-conflict-handling)
  - [Reserved Tier Priority](#reserved-tier-priority)
  - [Enabling the Feature Gate When a Custom Tier Exists at Priority 220](#enabling-the-feature-gate-when-a-custom-tier-exists-at-priority-220)
- [Usage](#usage)
  - [Sample ClusterNetworkPolicy specs](#sample-clusternetworkpolicy-specs)
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

Install the Custom Resource Definitions from the [network-policy-api documentation](https://network-policy-api.sigs.k8s.io/getting-started/).

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

## Relationship with Antrea-native Policies

Upstream `ClusterNetworkPolicy` objects and Antrea-native policies can co-exist in the same cluster. Upstream policies
provide portable, CNI-agnostic guardrails; Antrea-native `AntreaClusterNetworkPolicy` and `AntreaNetworkPolicy` offer a
richer feature set (for example FQDN rules beyond upstream domain peer types, node selectors, user-defined tiers and
L7 rules). See [Antrea Network Policy CRDs](antrea-network-policy.md) and [L7 policy](antrea-l7-network-policy.md) for
details.

Both upstream `ClusterNetworkPolicy` and Antrea-native policies use a `priority` field within a tier to order rules.
The following diagram summarizes how Antrea orders **upstream** `ClusterNetworkPolicy` tiers relative to Antrea-native
Tiers and Kubernetes `NetworkPolicy`, in the order of precedence:

```text
Antrea-native Policies, Tier priority higher than 220 (smaller numeric value)  >
ClusterNetworkPolicy, Admin tier (inherent tier priority == 220)               >
Antrea-native Policies, Tier priority lower than 220 (bigger numeric value)    >
K8s NetworkPolicies                                                            >
Antrea-native Policies, Tier == baseline                                       >
ClusterNetworkPolicy, Baseline tier
```

This tiering model enables cluster admins to create upstream ClusterNetworkPolicies that cannot be overridden by any
Application Tier (priority 250) Antrea-native policies (which presumably can be created by namespace admins), while at
the same time ensuring higher priority Antrea Tiers like the Platform Tier (priority 200) remains authoritative compared
to the upstream ClusterNetworkPolicy resource.

For more detail on Antrea-native policy ordering, see [Antrea-native policy ordering based on priorities](antrea-network-policy.md#antrea-native-policy-ordering-based-on-priorities).

## Tier Priority Reservation and Conflict Handling

### Reserved Tier Priority

When the `ClusterNetworkPolicy` feature gate is enabled, Antrea reserves Antrea Tier priority **220** for upstream
ClusterNetworkPolicy's Admin tier. This priority places upstream CNPs between the Antrea-native Platform Tier
(priority 200) and the Application Tier (priority 250), as shown in the precedence diagram in
[Relationship with Antrea-native Policies](#relationship-with-antrea-native-policies) above.

Two enforcement mechanisms protect priority 220:

- **Tier creation**: the Antrea admission webhook rejects any new attempt to create a user-defined Antrea Tier at
  priority 220 while the feature gate is enabled.
- **ClusterNetworkPolicy creation**: if a conflicting Tier at priority 220 already exists in the cluster (see below),
  the Antrea admission webhook rejects all new ClusterNetworkPolicy `CREATE` requests with an error such as:

  ```text
  ClusterNetworkPolicy creation is blocked: a user-created Tier at priority 220 (cnpAdminTierPriority) already
  exists; the Tier and its associated policies must be deleted/migrated first before a ClusterNetworkPolicy can
  be created
  ```

### Enabling the Feature Gate When a Custom Tier Exists at Priority 220

If you already have a custom Antrea Tier at priority 220 when you enable the `ClusterNetworkPolicy` feature gate
(you can check via `kubectl get tier`, which will display all the current Tiers and their respective priorities),
Antrea detects the conflict on startup and immediately blocks all new ClusterNetworkPolicy `CREATE` requests (via the
webhook above). Existing Antrea-native policies (ACNPs/ANNPs) in that Tier are **unaffected** — they continue to be
enforced.

To resolve the conflict and unblock ClusterNetworkPolicy creation, you must migrate your custom Tier away from priority
220. Two constraints govern the migration:

- **Tier priority cannot be updated in-place**: the Antrea admission webhook rejects any change to a Tier's
  `spec.priority`.
- **A Tier with associated policies cannot be deleted**: the Antrea admission webhook blocks deletion of a Tier
  that still has ACNPs or ANNPs referencing it.

The migration procedure is therefore:

1. **Decide the new priority** for your custom Tier. Choose a value *lower* than 220 (e.g. 215) if you want your
   Tier to take precedence *over* upstream CNPs, or a value *higher* than 220 (e.g. 225) if you want upstream CNPs
   to take precedence.
2. **Delete all Antrea-native policies** (ACNPs and ANNPs) that reference that Tier currently at priority 220.
3. **Delete the Tier** (allowed once no policies reference it).
4. **Recreate the Tier** at the new priority.
5. **Recreate the policies** referencing the new Tier.

Once the conflicting Tier at priority 220 is removed, Antrea re-allows ClusterNetworkPolicy creation immediately.

If the `ClusterNetworkPolicy` feature gate is **not enabled**, priority 220 is not reserved and no restriction is
placed on creating or maintaining a custom Antrea Tier at that priority. However, if you plan to enable the feature
gate in the future and already have a Tier at priority 220, you should proactively migrate it (following the steps
above) to avoid the conflict when the gate is eventually enabled.

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
