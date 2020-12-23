# Antrea Network Policy CRDs

## Table of Contents

<!-- toc -->
- [Summary](#summary)
- [Tier](#tier)
  - [Tier CRDs](#tier-crds)
  - [Static tiers](#static-tiers)
  - [kubectl commands for Tier](#kubectl-commands-for-tier)
- [Antrea ClusterNetworkPolicy](#antrea-clusternetworkpolicy)
  - [The Antrea ClusterNetworkPolicy resource](#the-antrea-clusternetworkpolicy-resource)
  - [Behavior of <em>to</em> and <em>from</em> selectors](#behavior-of-to-and-from-selectors)
  - [Key differences from K8s NetworkPolicy](#key-differences-from-k8s-networkpolicy)
  - [kubectl commands for Antrea ClusterNetworkPolicy](#kubectl-commands-for-antrea-clusternetworkpolicy)
- [Antrea NetworkPolicy](#antrea-networkpolicy)
  - [The Antrea NetworkPolicy resource](#the-antrea-networkpolicy-resource)
  - [Key differences from Antrea ClusterNetworkPolicy](#key-differences-from-antrea-clusternetworkpolicy)
  - [kubectl commands for Antrea NetworkPolicy](#kubectl-commands-for-antrea-networkpolicy)
- [Antrea-native Policy ordering based on priorities](#antrea-native-policy-ordering-based-on-priorities)
  - [Ordering based on Tier priority](#ordering-based-on-tier-priority)
  - [Ordering based on policy priority](#ordering-based-on-policy-priority)
  - [Rule enforcement based on priorities](#rule-enforcement-based-on-priorities)
- [RBAC](#rbac)
- [Notes](#notes)
- [Known Issues](#known-issues)
<!-- /toc -->

## Summary

Antrea supports standard K8s NetworkPolicies to secure traffic between Pods.
These NetworkPolicies are written from an application developer's perspective,
hence they lack the ability to gain a finer-grained control over the security
policies that a cluster administrator would require. This document describes a
few new CRDs supported by Antrea to provide the administrator with more control
over security within the cluster, and which are meant to co-exist with and
complement the K8s NetworkPolicy.

## Tier

Antrea supports grouping Antrea-native Policy CRDs together in a tiered fashion
to provide a hierarchy of security policies. This is achieved by setting the
`tier` field when defining an Antrea-native Policy CRD (e.g. an Antrea
ClusterNetworkPolicy object) to the appropriate tier name. Each tier has a
priority associated with it, which determines its relative order among all tiers.

**Note**: K8s NetworkPolicies will be enforced once all tiers have been
enforced.

### Tier CRDs

Creating Tiers as CRDs allows users the flexibility to create and delete
Tiers as per their preference i.e. not be bound to 5 static tiering options
as was the case initially.

An example Tier might look like this:

```yaml
apiVersion: security.antrea.tanzu.vmware.com/v1alpha1
kind: Tier
metadata:
  name: mytier
spec:
  priority: 10
  description: "my custom tier"
```

Tiers have the following characteristics:

- Policies can associate themselves with an existing Tier by setting the `tier`
  field in a Antrea NetworkPolicy CRD spec to the Tier's name.
- A Tier must exist before an Antrea-native policy can reference it.
- Policies associated with higher ordered (low `priority` value) Tiers are
  enforced first.
- No two Tiers can be created with the same priority.
- Updating the Tier's `priority` field is unsupported.
- Deleting Tier with existing references from policies is not allowed.

### Static tiers

Antrea release 0.9.x introduced support for 5 static tiers. These static tiers
have been removed in favor of Tier CRDs as mentioned in the previous section.
On startup, antrea-controller will create 5 Read-Only Tier resources
corresponding to the static tiers for default consumption, as well as a "baseline"
Tier CRD object, that will be enforced after developer-created K8s NetworkPolicies.
The details for these tiers are shown below:

```text
    Emergency   -> Tier name "emergency" with priority "50"
    SecurityOps -> Tier name "securityops" with priority "100"
    NetworkOps  -> Tier name "networkops" with priority "150"
    Platform    -> Tier name "platform" with priority "200"
    Application -> Tier name "application" with priority "250"
    Baseline    -> Tier name "baseline" with priority "253"
```

Any Antrea-native policy CRD referencing a static tier in its spec will now internally
reference the corresponding Tier resource, thus maintaining the order of enforcement.

The static tier resources are created as follows in the relative order of
precedence compared to K8s NetworkPolicies:

```text
    Emergency > SecurityOps > NetworkOps > Platform > Application > K8s NetworkPolicy > Baseline
```

Thus, all Antrea-native Policy resources associated with the "emergency" tier will be
enforced before any Antrea-native Policy resource associated with any other
tiers, until a match occurs, in which case the policy rule's `action` will be
applied. **Any Antrea-native Policy resource without a `tier` name set in its spec
will be associated with the "application" tier.** Policies associated with the first
5 static, read-only tiers, as well as with all the custom tiers created with a priority
value lower than 250 (priority values greater than or equal to 250 are not allowed
for custom tiers), will be enforced before K8s NetworkPolicies.
Policies created in the "baseline" tier, on the other hand, will have lower precedence
than developer-created K8s NetworkPolicies, which comes in handy when administrators
want to enforce baseline policies like "default-deny inter-namespace traffic" for some
specific Namespace, while still allowing individual developers to lift the restriction
if needed using K8s NetworkPolicies.
Note that baseline policies cannot counteract the isolated Pod behavior provided by
K8s NetworkPolicies. If a Pod becomes isolated because a K8s NetworkPolicy is applied
to it, and the policy does not explicitly allow communications with another Pod,
this behavior cannot be changed by creating an Antrea-native policy with an "allow"
action in the "baseline" tier. For this reason, it generally does not make sense to
create policies in the "baseline" tier with the "allow" action。

### kubectl commands for Tier

The following kubectl commands can be used to retrieve Tier resources:

```bash
    # Use long name
    kubectl get tiers

    # Use long name with API Group
    kubectl get tiers.security.antrea.tanzu.vmware.com

    # Use short name
    kubectl get tr

    # Use short name with API Group
    kubectl get tr.security.antrea.tanzu.vmware.com

    # Sort output by Tier priority
    kubectl get tiers --sort-by=.spec.priority
```

All of the above commands produce output similar to what is shown below:

```text
    NAME          PRIORITY   AGE
    emergency     50         27h
    securityops   100        27h
    networkops    150        27h
    platform      200        27h
    application   250        27h
```

## Antrea ClusterNetworkPolicy

Antrea ClusterNetworkPolicy (ACNP), one of the two Antrea-native Policy CRDs
introduced, is a specification of how workloads within a cluster communicate
with each other and other external endpoints. The ClusterNetworkPolicy is
supposed to aid cluster admins to configure the security policy for the
cluster, unlike K8s NetworkPolicy, which is aimed towards developers to secure
their apps and affects Pods within the Namespace in which the K8s NetworkPolicy
is created. Rules belonging to ClusterNetworkPolicies are enforced before any
rule belonging to a K8s NetworkPolicy.

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

### The Antrea ClusterNetworkPolicy resource

An example ClusterNetworkPolicy might look like this:

```yaml
apiVersion: security.antrea.tanzu.vmware.com/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: test-cnp
spec:
    priority: 5
    tier: securityops
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
            endPort: 9000
          - protocol: TCP
            port: 6379  
        name: AllowFromFrontend
        enableLogging: false
    egress:
      - action: Drop
        to:
          - ipBlock:
              cidr: 10.0.10.0/24
        ports:
          - protocol: TCP
            port: 5978
        name: DropToThirdParty
        enableLogging: true
```

**spec**: The ClusterNetworkPolicy `spec` has all the information needed to
define a cluster-wide security policy.

**appliedTo**: The `appliedTo` field at the policy level specifies the
grouping criteria of Pods to which the policy applies to. Pods can be
selected cluster-wide using `podSelector`. If set with a `namespaceSelector`,
all Pods from Namespaces selected by the namespaceSelector will be selected.
Specific Pods from specific Namespaces can be selected by providing both a
`podSelector` and a `namespaceSelector` in the same `appliedTo` entry.
IPBlock cannot be set in the `appliedTo` field.
This `appliedTo` field must not be set, if `appliedTo` per
rule is used.
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

**tier**: The `tier` field associates an ACNP to an existing Tier. The `tier`
field can be set with the name of the Tier CRD to which this policy must be
associated with. If not set, the ACNP is associated with the lowest priority
default tier i.e. the "application" Tier.

**ingress**: Each ClusterNetworkPolicy may consist of zero or more ordered
set of ingress rules. Each rule, depending on the `action` field of the rule,
allows or drops traffic which matches all `from`, `ports` sections.
Under `ports`, the optional field `endPort` can only be set when a numerical `port`
is set to represent a range of ports from `port` to `endPort` inclusive.
Also, each rule has an optional `name` field, which should be unique within
the policy describing the intention of this rule. If `name` is not provided for
a rule, it will be auto-generated by Antrea. The auto-generated name will be
of format `[ingress/egress]-[action]-[uid]`, e.g. ingress-allow-2f0ed6e,
where [uid] is the first 7 bits of hash value of the rule based on sha1 algorithm.
If a policy contains duplicate rules, or if a rule name is same as the auto-generated
name of some other rules in the same policy, it will cause a conflict,
and the policy will be rejected.
The example policy contains a single rule, which allows matched traffic on a
single port, from one of two sources: the first specified by a `podSelector`
and the second specified by a combination of a `podSelector` and a
`namespaceSelector`.
**Note**: The order in which the ingress rules are set matter, i.e. rules will
be enforced in the order in which they are written.

**egress**: Each ClusterNetworkPolicy may consist of zero or more ordered set
of egress rules. Each rule, depending on the `action` field of the rule, allows
or drops traffic which matches all `from`, `ports` sections.
Under `ports`, the optional field `endPort` can only be set when a numerical `port`
is set to represent a range of ports from `port` to `endPort` inclusive.
Also, each rule has an optional `name` field, which should be unique within
the policy describing the intention of this rule. If `name` is not provided for
a rule, it will be auto-generated by Antrea. The rule name auto-generation process
is the same as ingress rules.
The example policy contains a single rule, which drops matched traffic on a
single port, to the 10.0.10.0/24 subnet specified by the `ipBlock` field.
**Note**: The order in which the egress rules are set matter, i.e. rules will
be enforced in the order in which they are written.

**enableLogging**: A ClusterNetworkPolicy ingress or egress rule can be
audited by enabling its logging field. When `enableLogging` field is set to
true, the first packet of any connection that matches this rule will be logged
to a separate file (`/var/log/antrea/networkpolicy/np.log`) on the Node on
which the rule is applied. These log files can then be retrieved for further
analysis. By default, rules are not logged. The example policy logs all
traffic that matches the "DropToThirdParty" egress rule, while the rule
"AllowFromFrontend" is not logged. The rules are logged in the following
format:

```text
    <yyyy/mm/dd> <time> <ovs-table-name> <antrea-native-policy-reference> <action> <openflow-priority> SRC: <source-ip> DEST: <destination-ip> <packet-length> <protocol>

    Example:
    2020/11/02 22:21:21.148395 AntreaPolicyAppTierIngressRule AntreaNetworkPolicy:default/test-anp Allow 61800 SRC: 10.0.0.4 DEST: 10.0.0.5 60 TCP
```

**`appliedTo` per rule**: A ClusterNetworkPolicy ingress or egress rule may
optionally contain the `appliedTo` field. Semantically, the `appliedTo` field
per rule is similar to the `appliedTo` field at the policy level, except that
it is valid for that rule itself, as opposed to spanning over all the rules.
If used, the `appliedTo` field must be set for all the rules existing in the
policy and cannot be set along with `appliedTo` at the policy level.

### Behavior of *to* and *from* selectors

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

### kubectl commands for Antrea ClusterNetworkPolicy

The following kubectl commands can be used to retrieve ACNP resources:

```bash
    # Use long name
    kubectl get clusternetworkpolicies

    # Use long name with API Group
    kubectl get clusternetworkpolicies.security.antrea.tanzu.vmware.com

    # Use short name
    kubectl get acnp

    # Use short name with API Group
    kubectl get acnp.security.antrea.tanzu.vmware.com
```

All of the above commands produce output similar to what is shown below:

```text
    NAME       TIER        PRIORITY   AGE
    test-cnp   emergency   5          54s
```

## Antrea NetworkPolicy

Antrea NetworkPolicy (ANP) is another Policy CRD, which is similar to the
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
    tier: securityops
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
            endPort: 9000
        name: AllowFromFrontend
        enableLogging: false
    egress:
      - action: Drop
        to:
          - ipBlock:
              cidr: 10.0.10.0/24
        ports:
          - protocol: TCP
            port: 5978
        name: DropToThirdParty
        enableLogging: true
```

### Key differences from Antrea ClusterNetworkPolicy

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

### kubectl commands for Antrea NetworkPolicy

The following kubectl commands can be used to retrieve ANP resources:

```bash
    # Use long name with API Group
    kubectl get networkpolicies.security.antrea.tanzu.vmware.com

    # Use short name
    kubectl get anp

    # Use short name with API Group
    kubectl get anp.security.antrea.tanzu.vmware.com
```

All of the above commands produce output similar to what is shown below:

```text
    NAME       TIER          PRIORITY   AGE
    test-anp   securityops   5          5s
```

## Antrea-native Policy ordering based on priorities

Antrea-native Policy CRDs are ordered based on priorities set at various levels.

### Ordering based on Tier priority

With the introduction of tiers, Antrea Policies, like ClusterNetworkPolicies,
are first enforced based on the Tier to which they are associated. i.e. all
policies belonging to a high Tier are enforced first, followed by policies
belonging to the next Tier and so on, until the "application" Tier policies
are enforced. K8s NetworkPolicies are enforced next, and "baseline" Tier
policies will be enforced last.

### Ordering based on policy priority

Within a tier, Antrea-native Policy CRDs are ordered by the `priority` at the policy
level. Thus, the policy with the highest precedence (lowest priority number
value) is enforced first. This ordering is performed solely based on the
`priority` assigned, as opposed to the "Kind" of the resource, i.e. the relative
ordering between a [ClusterNetworkPolicy resource](#antrea-clusternetworkpolicy) and
an [Antrea NetworkPolicy resource](#antrea-networkpolicy) within a Tier depends only
on the `priority` set in each of the two resources.

### Rule enforcement based on priorities

Within a policy, rules are enforced in the order in which they are set. For example,
consider the following:

- ACNP1{tier: application, priority: 10, ingressRules: [ir1.1, ir1.2], egressRules: [er1.1, er1.2]}
- ANP1{tier: application, priority: 15, ingressRules: [ir2.1, ir2.2], egressRules: [er2.1, er2.2]}
- ACNP3{tier: emergency, priority: 20, ingressRules: [ir3.1, ir3.2], egressRules: [er3.1, er3.2]}

This translates to the following order:

- Ingress rules: ir3.1 > ir3.2 > ir1.1 -> ir1.2 -> ir2.1 -> ir2.2
- Egress rules: er3.1 > er3.2 > er1.1 -> er1.2 -> er2.1 -> er2.2

Once a rule is matched, it is executed based on the action set. If none of the
policy rules match, the packet is then enforced for rules created for K8s NP.
If the packet still does not match any rule for K8s NP, it will then be evaluated
against policies created in the "baseline" Tier.

The [antctl command](antctl.md#networkPolicy-commands) with 'sort-by=effectivePriority'
flag can be used to check the order of policy enforcement.
An example output will look like the following:

```text
antctl get netpol --sort-by=effectivePriority
NAME                                 APPLIED-TO                           RULES SOURCE                                 TIER-PRIORITY PRIORITY
4c504456-9158-4838-bfab-f81665dfae12 85b88ddb-b474-5b44-93d3-c9192c09085e 1     AntreaClusterNetworkPolicy:acnp-1      250           1
41e510e0-e430-4606-b4d9-261424184fba e36f8beb-9b0b-5b49-b1b7-5c5307cddd83 1     AntreaClusterNetworkPolicy:acnp-2      250           2
819b8482-ede5-4423-910c-014b731fdba6 bb6711a1-87c7-5a15-9a4a-71bf49a78056 2     AntreaNetworkPolicy:anp-10             250           10
4d18e031-f05a-48f6-bd91-0197b556ccca e216c104-770c-5731-bfd3-ff4ccbc38c39 2     K8sNetworkPolicy:default/test-1        <NONE>        <NONE>
c547002a-d8c7-40f1-bdd1-8eb6d0217a67 e216c104-770c-5731-bfd3-ff4ccbc38c39 1     K8sNetworkPolicy:default/test-2        <NONE>        <NONE>
aac8b8bc-f3bf-4c41-b6e0-2af1863204eb bb6711a1-87c7-5a15-9a4a-71bf49a78056 3     AntreaClusterNetworkPolicy:baseline    253           10
```

The [ovs-pipeline doc](design/ovs-pipeline.md) contains more information on how
policy rules are realized by OpenFlow, and how the priority of flows reflects the
order in which they are enforced.

## RBAC

Antrea-native Policy CRDs are meant for admins to manage the security of their
cluster. Thus, access to manage these CRDs must be granted to subjects which
have the authority to outline the security policies for the cluster and/or
Namespaces. On cluster initialization, Antrea grants the permissions to edit
these CRDs with `admin` and the `edit` ClusterRole. In addition to this, Antrea
also grants the permission to view these CRDs with the `view` ClusterRole.
Cluster admins can therefore grant these ClusterRoles to any subject who may
be responsible to manage the Antrea Policy CRDs. The admins may also decide to
share the `view` ClusterRole to a wider range of subjects to allow them to read
the policies that may affect their workloads.

## Notes

- There is a soft limit of 20 on the maximum number of Tier resources that are
  supported. But for optimal performance, it is recommended that the number of
  Tiers in a cluster be less than or equal to 10.
- In order to reduce the churn in the agent, it is recommended to set the policy
  priority within the range 1.0 to 100.0.
- The v1alpha1 Policy CRDs support up to 10,000 unique priorities at policy level,
  and up to 50,000 unique priorities at rule level, across all tiers except for
  the "baseline" tier. For any two policy rules, their rule level priorities are only
  considered equal if they share the same tier, and have the same policy priority
  as well as rule priority.
- For the "baseline" tier, the max supported unique priorities (at rule level）is 150.

## Known Issues

- Creating an Antrea NetworkPolicy with the same name as a K8s NetworkPolicy
  under the same Namespace creates a collision and causes unexpected behavior.
  See issue [1173](https://github.com/vmware-tanzu/antrea/issues/1173) for more details.
