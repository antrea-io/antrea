# Antrea Policy CRDs

## Table of Contents

- [Summary](#summary)
- [Tier](#tier)
  - [Static Tiers](#static-tiers)
  - [Tier CRDs](#tier-crds)
- [ClusterNetworkPolicy](#clusternetworkpolicy)
  - [The ClusterNetworkPolicy resource](#the-clusternetworkpolicy-resource)
  - [Behavior of to and from selectors](#behavior-of-to-and-from-selectors)
  - [Key differences from K8s NetworkPolicy](#key-differences-from-k8s-networkpolicy)
- [Antrea NetworkPolicy](#antrea-networkpolicy)
  - [The Antrea NetworkPolicy resource](#the-antrea-networkpolicy-resource)
  - [Key differences from ClusterNetworkPolicy](#key-differences-from-clusternetworkpolicy)
- [Antrea Policy ordering based on priorities](#antrea-policy-ordering-based-on-priorities)
  - [Ordering based on Tier priority](#ordering-based-on-tier-priority)
  - [Ordering based on policy priority](#ordering-based-on-policy-priority)
  - [Rule enforcement based on priorities](#rule-enforcement-based-on-priorities)
- [Notes](#notes)

## Summary

Antrea supports standard K8s NetworkPolicies to secure traffic between Pods.
These NetworkPolicies are written from an application developer's perspective,
hence they lack the ability to gain a finer-grained control over the security
policies that a cluster administrator would require. This document describes a
few new CRDs supported by Antrea to provide the administrator with more control
over security within the cluster, and which are meant to co-exist with and
complement the K8s NetworkPolicy.

## Tier

Antrea supports grouping Antrea Policy CRDs together in a tiered fashion
to provide a hierarchy of security policies. This is achieved by setting the
`tier` field when defining an Antrea Policy CRD (e.g. a ClusterNetworkPolicy
object) to the appropriate tier name. Each tier has a priority associated with
it, which determines its relative order among all tiers.

**Note**: K8s NetworkPolicies will be enforced once all tiers have been
enforced.

### Static tiers

Currently, we support 5 static tiers in Antrea. They are as follows in the
relative order of precedence:

```
    Emergency > SecurityOps > NetworkOps > Platform > Application  
```

Thus, all Antrea Policy resources associated with "Emergency" tier will be
enforced before any other Antrea Policy resource associated with any other
tier, until a match occurs, in which case the policy rule's `action` will be
applied. The "Application" tier carries the lowest precedence, and any Antrea
Policy resource without a `tier` name set in its spec will be associated with
the "Application" tier. Even though the policies associated with the
"Application" tier carry the lowest precedence amongst all the tiers, they are
still enforced before K8s NetworkPolicies. Thus, admin-created tiered Antrea
Policy CRDs have a higher precedence than developer-created K8s
NetworkPolicies.


### Tier CRDs

Although static tiers provide a way to organize security policies for different
use cases, they are not flexible i.e. admin cannot add/delete a new tier at
will. This can be made possible by the introduction of Tier as CRDs. Tier CRDs
will be available soon and will replace the existing static tiers.

## ClusterNetworkPolicy

ClusterNetworkPolicy, one of the two Antrea Policy CRDs introduced, is a
specification of how workloads within a cluster communicate with each other and
other external endpoints. The ClusterNetworkPolicy is supposed to aid cluster
admins to configure the security policy for the cluster, unlike K8s
NetworkPolicy, which is aimed towards developers to secure their apps and
affects Pods within the Namespace in which the K8s NetworkPolicy is created.
Rules belonging to ClusterNetworkPolicies are enforced before any rule
belonging to a K8s NetworkPolicy.

**Note**: ClusterNetworkPolicy is currently in "Alpha" stage. In order to
enable them, edit the Controller and Agent configuration in the `antrea`
ConfigMap as follows:
```yaml
   antrea-controller.conf: |
     featureGates:
       # Enable AntreaPolicy feature to complement K8s NetworkPolicy
       # for cluster admins to define security policies which apply to the
       # entire cluster.
       AntreaPolicy: true
```
```yaml
   antrea-agent.conf: |
     featureGates:
       # Enable AntreaPolicy feature to complement K8s NetworkPolicy
       # for cluster admins to define security policies which apply to the
       # entire cluster.
       AntreaPolicy: true
```

### The ClusterNetworkPolicy resource

An example ClusterNetworkPolicy might look like this:
```yaml
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

**priority**: The `priority` field determines the relative priority of the
policy among all ClusterNetworkPolicies in the given cluster. This field is
mandatory. A lower priority value indicates higher precedence. Priority values
can range from 1.0 to 10000.0.
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
**Note**: The order in which the ingress rules are set matter, i.e. rules will
be enforced in the order in which they are written.

**egress**: Each ClusterNetworkPolicy may consist of zero or more ordered set
of egress rules. Each rule, depending on the `action` field of the rule, allows
or drops traffic which matches both the `to` and `ports` sections. The example
policy contains a single rule, which drops matched traffic on a single port,
to the 10.0.10.0/24 subnet specified by the `ipBlock` field.
**Note**: The order in which the egress rules are set matter, i.e. rules will
be enforced in the order in which they are written.

### Behavior of `to` and `from` selectors

There are four kinds of selectors that can be specified in an ingress `from`
section or egress `to` section:

**podSelector**: This selects particular Pods from all Namespaces as "sources",
if set in `ingress` section, or as "destinations", if set in `egress` section.

**namespaceSelector**: This selects particular Namespaces for which all Pods
are grouped as `ingress` "sources" or `egress` "destinations".

**podSelector** and **namespaceSelector**:  A single to/from entry that
specifies both namespaceSelector and podSelector selects particular Pods within
particular Namespaces. 

**ipBlock**: This selects particular IP CIDR ranges to allow as `ingress`
"sources" or `egress` "destinations". These should be cluster-external IPs,
since Pod IPs are ephemeral and unpredictable.

### Key differences from K8s NetworkPolicy

- ClusterNetworkPolicy is at the cluster scope, hence a `podSelector` without
  any `namespaceSelector` selects Pods from all Namespaces.
- There is no automatic isolation of Pods on being selected in appliedTo.
- Ingress/Egress rules in ClusterNetworkPolicy has an `action` field which
  specifies whether the matched rule allows or drops the traffic.
- IPBlock field in the ClusterNetworkPolicy rules do not have the `except`
  field. A higher priority rule can be written to deny the specific CIDR range
  to simulate the behavior of IPBlock field with `cidr` and `except` set.
- Rules assume the priority in which they are written. i.e. rule set at top
  takes precedence over a rule set below it.

## Antrea NetworkPolicy

Antrea NetworkPolicy is another Policy CRD, which is similar to the
ClusterNetworkPolicy CRD, however its scope is limited to a Namespace.
The purpose of introducing this CRD is to allow admins to take advantage of
advanced NetworkPolicy features and apply them within a Namespace to
complement the K8s NetworkPolicies. Similar to the ClusterNetworkPolicy
resource, Antrea NetworkPolicy can also be associated with Tiers.

**Note**: Antrea NetworkPolicy is currently in "Alpha" stage and is enabled
along with Tiers and ClusterNetworkPolicy as part of the `AntreaPolicy`
feature gate.

### The Antrea NetworkPolicy resource

An example Antrea NetworkPolicy might look like this:
```yaml
apiVersion: security.antrea.tanzu.vmware.com/v1alpha1
kind: NetworkPolicy
metadata:
  name: test-anp
  namespace: default
spec:
    priority: 5
    tier: SecurityOps
    appliedTo:
      - podSelector:
          matchLabels:
            role: db
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

### Key differences from ClusterNetworkPolicy

Antrea NetworkPolicy shares it's spec with ClusterNetworkPolicy. However,
the following documents some of the key differences between the two Antrea
Policy CRDs.

- Antrea NetworkPolicy is Namespaced while ClusterNetworkPolicy operates at
  cluster scope.
- Unlike the `appliedTo` in a ClusterNetworkPolicy, setting a
  `namespaceSelector` in the `appliedTo` field is forbidden.
- `podSelector` without a `namespaceSelector`, set within a NetworkPolicy Peer
  of any rule, selects Pods from the Namespace in which the Antrea
  NetworkPolicy is created. This behavior is similar to the K8s NetworkPolicy.

## Antrea Policy ordering based on priorities

Antrea Policy CRDs are ordered based on priorities set at various levels.

### Ordering based on Tier priority

With the introduction of tiers, Antrea Policies, like ClusterNetworkPolicies,
are first enforced based on the tier to which they are associated. i.e. all
policies belonging to the "Emergency" tier are enforced first, followed by
policies belonging to the "SecurityOps" tier and so on, until the "Application"
tier policies are enforced.

### Ordering based on policy priority

Within a tier, Antrea Policy CRDs are ordered by the `priority` at the policy
level. Thus, the policy with the highest precedence (lowest priority number
value) is enforced first. This ordering is performed solely based on the
`priority` assigned as opposed to the "Kind" of the resource, i.e. the relative
ordering between a [ClusterNetworkPolicy resource](#clusternetworkpolicy) and an [Antrea NetworkPolicy
resource](#antrea-networkpolicy) within a Tier depends only on the `priority`
set in each of the two resources.

### Rule enforcement based on priorities

Within a policy, rules are enforced in the order in which they are set. For example,
consider the following:

- CNP1{tier: Application, priority: 10, ingressRules: [ir1.1, ir1.2], egressRules: [er1.1, er1.2]}
- ANP1{tier: Application, priority: 15, ingressRules: [ir2.1, ir2.2], egressRules: [er2.1, er2.2]}
- CNP3{tier: Emergency, priority: 20, ingressRules: [ir3.1, ir3.2], egressRules: [er3.1, er3.2]}

This translates to the following order:
- Ingress rules: ir3.1 > ir3.2 > ir1.1 -> ir1.2 -> ir2.1 -> ir2.2
- Egress rules: er3.1 > er3.2 > er1.1 -> er1.2 -> er2.1 -> er2.2

Once a rule is matched, it is executed based on the action set. If none of the
policy rules match, the packet is then enforced for rules created for K8s NP.
Hence, Antrea Policy CRDs take precedence over K8s NP.

## Notes

- The v1alpha1 Policy CRDs support up to 10000 unique priority at policy level.
  In order to reduce the churn in the agent, it is recommended to set the
  priority within the range 1.0 to 100.0.
