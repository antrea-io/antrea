# Antrea Network Policies

## Table of Contents

- [Summary](#summary)
- [Tier](#tier)
  - [Static Tiers](#static-tiers)
  - [Tier CRDs](#tier-crds)
- [ClusterNetworkPolicy](#clusternetworkpolicy)
  - [The ClusterNetworkPolicy resource](#the-clusternetworkpolicy-resource)
  - [Rule enforcement based on priorities](#rule-enforcement-based-on-priorities)
  - [Behavior of to and from selectors](#behavior-of-to-and-from-selectors)
  - [Key differences from K8s NetworkPolicy](#key-differences-from-k8s-networkpolicy)
- [Notes](#notes)

## Summary

Antrea supports standard K8s NetworkPolicies to secure traffic between Pods. These
NetworkPolicies are written from an application developer's perspective, hence they
lack the ability to gain a finer-grained control over the security policies that
a cluster administrator would require. This document describes a few new CRDs
supported by Antrea to provide the administrator with more control over
security within the cluster, and which are meant to co-exist with and complement the
K8s NetworkPolicy.

## Tier

Antrea supports grouping Antrea NetworkPolicies together in a tiered fashion
to provide a hierarchy of security policies. This is achieved by setting the `tier`
field when defining Antrea NetworkPolicies (e.g. a ClusterNetworkPolicy object) to
the appropriate tier name. Each tier has a priority associated with it, which
determines its relative order among all tiers.

**Note**: K8s NetworkPolicies will be enforced once all tiers have been enforced.

### Static tiers

Currently, we support 5 static tiers in Antrea. They are as follows in the
relative order of precedence:

```
    Emergency > SecurityOps > NetworkOps > Platform > Application  
```

Thus, all ClusterNetworkPolicies associated with "Emergency" tier will be
enforced before any other ClusterNetworkPolicy associated with any other tier,
until a match occurs, in which case the policy rule's `action` will be
applied. The "Application" tier carries the lowest precedence, and any
ClusterNetworkPolicy without a `tier` name set in its spec will be
associated with the "Application" tier. Even though the policies associated
with the "Application" tier carry the lowest precedence amongst all the tiers,
they are still enforced before K8s NetworkPolicies. Thus, admin created tiered
policies have a higher precedence over developer-created K8s NetworkPolicies.


### Tier CRDs

Although static tiers provide a way to organize security policies for different
use cases, they are not flexible i.e. admin cannot add/delete a new tier at
will. This can be made possible by the introduction of Tier as CRDs. Tier CRDs
will be available soon and will replace the existing static tiers.

## ClusterNetworkPolicy

ClusterNetworkPolicy is a specification of how workloads within a cluster
communicate with each other and other external endpoints.
The ClusterNetworkPolicy is supposed to aid cluster admins to configure
the security policy for the cluster, unlike K8s NetworkPolicy, which is
aimed towards developers to secure their apps and affects Pods within the
Namespace in which the K8s NetworkPolicy is created.
Rules belonging to ClusterNetworkPolicies are enforced before any rule
belonging to a K8s NetworkPolicy.

**Note**: ClusterNetworkPolicy is currently in "Alpha" stage. In order to
enable them, edit the Controller and Agent configuration in the `antrea`
ConfigMap as follows:
```yaml
   antrea-controller.conf: |
     featureGates:
       # Enable ClusterNetworkPolicy feature to complement K8s NetworkPolicy
       # for cluster admins to define security policies which apply to the
       # entire cluster.
       ClusterNetworkPolicy: true
```
```yaml
   antrea-agent.conf: |
     featureGates:
       # Enable ClusterNetworkPolicy feature to complement K8s NetworkPolicy
       # for cluster admins to define security policies which apply to the
       # entire cluster.
       ClusterNetworkPolicy: true
```

### The ClusterNetworkPolicy resource

An example ClusterNetworkPolicy might look like this:

```
apiVersion: security.antrea.tanzu.vmware.com/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: test-cnp
spec:
    priority: 5
    tier: SecurityOps
    appliedTo:
      - podSelector:
          matchLabels:
            role: db
      - namespaceSelector:
          matchLabels:
            env: prod
    ingress:
      - action: Allow
        from:
          - podSelector:
              matchLabels:
                role: frontend
          - podSelector:
              matchLabels:
                role: nondb
            namespaceSelector:
              matchLabels:
                role: db
        ports:
          - protocol: TCP
            port: 8080
    egress:
      - action: Drop
        to:
          - ipBlock:
            cidr: 10.0.10.0/24
        ports:
          - protocol: TCP
            port: 5978
```

**spec**: The ClusterNetworkPolicy `spec` has all the information needed to
define a cluster-wide security policy.

**appliedTo**: The `appliedTo` field specifies the grouping criteria of Pods to
which the policy applies to. Pods can be selected cluster-wide using
`podSelector`. If set with a `namespaceSelector`, all Pods from Namespaces
selected by the namespaceSelector will be selected. Specific Pods from
specific Namespaces can be selected by providing both a `podSelector` and a
`namespaceSelector` in the same `appliedTo` entry.
IPBlock cannot be set in the `appliedTo` field.
In the example, the policy applies to Pods, which either match the labels
"role=db" in all the Namespaces, or are from Namespaces which match the
labels "env=prod".

**priority**: The `priority` field determines the relative priority of the policy
among all ClusterNetworkPolicies in the given cluster. This field is mandatory.
A lower priority value indicates higher precedence. Priority values can range
from 1.0 to 10000.0.
**Note**: Policies with the same priorities will be enforced
indeterministically. Users should therefore take care to use priorities to
ensure the behavior they expect.

**tier**: The `tier` field associates a CNP to an existing tier. As of now, the
`tier` field can be set with "Emergency", "SecurityOps", "NetworkOps",
"Platform" or "Application" as value. If not set, the CNP is associated with
the lowest priority "Application" tier.

**ingress**: Each ClusterNetworkPolicy may consist of zero or more ordered
set of ingress rules. Each rule, depending on the `action` field of the rule,
allows or drops traffic which matches both the `from` and `ports` sections.
The example policy contains a single rule, which allows matched traffic on a
single port, from one of two sources: the first specified by a `podSelector`
and the second specified by a combination of a `podSelector` and a
`namespaceSelector`.
**Note**: The order in which the ingress rules are set matter, i.e. rules will be
enforced in the order in which they are written.

**egress**: Each ClusterNetworkPolicy may consist of zero or more ordered set of
egress rules. Each rule, depending on the `action` field of the rule, allows
or drops traffic which matches both the `to` and `ports` sections. The example
policy contains a single rule, which drops matched traffic on a single port,
to the 10.0.10.0/24 subnet specified by the `ipBlock` field.
**Note**: The order in which the egress rules are set matter, i.e. rules will be
enforced in the order in which they are written.

### Rule enforcement based on priorities

With the introduction of tiers, ClusterNetworkPolicies are first enforced
based on the tier to which they are associated with. i.e. all CNP belonging
to the "Emergency" tier are enforced first, followed by policies associated with
the "SecurityOps" tier and so on, until the "Application" tier policies are
enforced. Within a tier, rules belonging to Cluster NetworkPolicy CRDs are
associated with various priorities, such as the `priority` at the CNP level and
the priority at the rule level. Overall, the Cluster Policy with the highest
precedence (lowest priority number value) is enforced first. Within this policy,
rules are enforced in the order in which they are set. For example, consider the
following:

- CNP1{tier: Application, priority: 10, ingressRules: [ir1.1, ir1.2], egressRules: [er1.1, er1.2]}
- CNP2{tier: Application, priority: 15, ingressRules: [ir2.1, ir2.2], egressRules: [er2.1, er2.2]}
- CNP3{tier: Emergency, priority: 20, ingressRules: [ir3.1, ir3.2], egressRules: [er3.1, er3.2]}

This translates to the following order:

- Ingress rules: ir3.1 > ir3.2 > ir1.1 -> ir1.2 -> ir2.1 -> ir2.2
- Egress rules: er3.1 > er3.2 > er1.1 -> er1.2 -> er2.1 -> er2.2

Once a rule is matched, it is executed based on the action set. If none of the
CNP rules match, the packet is then enforced for rules created for K8s NP.
Hence, CNP take precedence over K8s NP.

### Behavior of `to` and `from` selectors

There are four kinds of selectors that can be specified in an ingress `from`
section or egress `to` section:

**podSelector**: This selects particular Pods from all Namespaces as "sources",
if set in `ingress` section, or as "destinations", if set in `egress` section.

**namespaceSelector**: This selects particular Namespaces for which all Pods are
grouped as `ingress` "sources" or `egress` "destinations".

**podSelector** and **namespaceSelector**:  A single to/from entry that specifies
both namespaceSelector and podSelector selects particular Pods within
particular Namespaces. 

**ipBlock**: This selects particular IP CIDR ranges to allow as `ingress` "sources"
or `egress` "destinations". These should be cluster-external IPs, since Pod IPs are
ephemeral and unpredictable.

### Key differences from K8s NetworkPolicy

- ClusterNetworkPolicy is at the cluster scope, hence a `podSelector` without any
  `namespaceSelector` selects Pods from all Namespaces.
- There is no automatic isolation of Pods on being selected in appliedTo.
- Ingress/Egress rules in ClusterNetworkPolicy has an `action` field which
  specifies whether the matched rule allows or drops the traffic.
- IPBlock field in the ClusterNetworkPolicy rules do not have the `except`
  field. A higher priority rule can be written to deny the specific CIDR range
  to simulate the behavior of IPBlock field with `cidr` and `except` set.
- Rules assume the priority in which they are written. i.e. rule set at top
  takes precedence over a rule set below it.

## Notes

- The v1alpha1 CNP CRD supports up to 10000 unique priority at policy level. In
  order to reduce the churn in the agent, it is recommended to set the priority
  within the range 1.0 to 100.0.
