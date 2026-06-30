# AdminNetworkPolicy API Support in Antrea (deprecated)

**DEPRECATED**: This page documents the legacy v1alpha1 `AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` APIs only.
Antrea support for these APIs is deprecated.

For the supported upstream cluster admin policy API, see
[ClusterNetworkPolicy API Support in Antrea](cluster-network-policy.md) (v1alpha2 `ClusterNetworkPolicy`, enabled by the
`ClusterNetworkPolicy` feature gate).

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Migration to ClusterNetworkPolicy](#migration-to-clusternetworkpolicy)
- [Legacy usage](#legacy-usage)
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

**The v1alpha1 APIs have been deprecated upstream and replaced with the v1alpha2 `ClusterNetworkPolicy` API.** Users
should migrate to the new API; see [ClusterNetworkPolicy API Support in Antrea](cluster-network-policy.md).

## Prerequisites

**Legacy configuration only.** AdminNetworkPolicy was introduced in v1.13 as an alpha feature and is disabled by default.
Feature gate `AdminNetworkPolicy` must be enabled in antrea-controller.conf in the `antrea-config` ConfigMap when Antrea
is deployed:

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

## Migration to ClusterNetworkPolicy

**Action Required**: Users should migrate from the deprecated v1alpha1 `AdminNetworkPolicy` and `BaselineAdminNetworkPolicy`
resources to the v1alpha2 `ClusterNetworkPolicy` resource. For prerequisites, sample policies, and precedence with
Antrea-native policies, read [ClusterNetworkPolicy API Support in Antrea](cluster-network-policy.md).

**No automatic migration**: Antrea does **not** automatically convert or migrate v1alpha1 `AdminNetworkPolicy` and
`BaselineAdminNetworkPolicy` objects to v1alpha2 `ClusterNetworkPolicy`. You must manually create the equivalent
`ClusterNetworkPolicy` resources and delete the old ones. The two feature gates (`AdminNetworkPolicy` and
`ClusterNetworkPolicy`) are independent; you can run both APIs simultaneously during a migration window to avoid a
policy enforcement gap.

To migrate:

1. **Enable the new feature gate**: Update your `antrea-controller.conf` to enable the `ClusterNetworkPolicy` feature
   gate. You may keep the `AdminNetworkPolicy` gate enabled during migration so that existing policies continue to be
   enforced while you create the equivalent `ClusterNetworkPolicy` resources.

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: antrea-config
     namespace: kube-system
   data:
     antrea-controller.conf: |
       featureGates:
         ClusterNetworkPolicy: true   # enable the new API
         AdminNetworkPolicy: true     # keep during migration; can be removed once migration is complete
   ```

2. **Install v1alpha2 CRDs**: Ensure the v1alpha2 `ClusterNetworkPolicy` CRDs are installed in your cluster.
   Refer to the [network-policy-api documentation](https://network-policy-api.sigs.k8s.io/getting-started/) for installation instructions.

3. **Ensure no custom Tiers are present at priority 220**: ClusterNetworkPolicies with `tier: Admin` are created in
   Antrea Tier priority 220, which must not be occupied by a custom Tier. See the
   [Tier Priority Reservation and Conflict Handling section](cluster-network-policy.md#tier-priority-reservation-and-conflict-handling)
   for more details.

4. **Rewrite your policies**: The v1alpha2 `ClusterNetworkPolicy` API unifies the functionality of `AdminNetworkPolicy`
   and `BaselineAdminNetworkPolicy`. Key differences include:
   - Single resource type for both admin and baseline policies: use `spec.tier: Admin` for admin posture and
     `spec.tier: Baseline` for baseline posture (replaces the singleton `BaselineAdminNetworkPolicy` named `default`).
   - Updated field names and structure; see the
     [Key differences section in the ClusterNetworkPolicy doc](cluster-network-policy.md#key-differences-from-v1alpha1-adminnetworkpolicy-apis).

   Refer to the [network-policy-api v1alpha2 specification](https://network-policy-api.sigs.k8s.io/reference/spec/)
   for the full API structure.

5. **Test and validate**: Create the equivalent `ClusterNetworkPolicy` resources and verify they behave as expected
   in a non-production environment before removing the old policies in production.

6. **Remove old policies and disable the deprecated gate**: Once you have verified the new `ClusterNetworkPolicy`
   resources work correctly:
   - Delete the old v1alpha1 `AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` resources.
   - [Optional] Remove or set `AdminNetworkPolicy: false` in your `antrea-controller.conf` and restart Antrea controller.

**Timeline**: The `AdminNetworkPolicy` feature gate will be removed in two releases after Antrea v2.7.

## Legacy usage

The following applies only if you still run the deprecated v1alpha1 APIs with the `AdminNetworkPolicy` feature gate
enabled.

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
