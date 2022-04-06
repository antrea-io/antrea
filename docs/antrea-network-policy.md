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
    - [ACNP with stand-alone selectors](#acnp-with-stand-alone-selectors)
    - [ACNP with ClusterGroup reference](#acnp-with-clustergroup-reference)
    - [ACNP for complete Pod isolation in selected Namespaces](#acnp-for-complete-pod-isolation-in-selected-namespaces)
    - [ACNP for strict Namespace isolation](#acnp-for-strict-namespace-isolation)
    - [ACNP for default zero-trust cluster security posture](#acnp-for-default-zero-trust-cluster-security-posture)
    - [ACNP for toServices rule](#acnp-for-toservices-rule)
    - [ACNP for ICMP traffic](#acnp-for-icmp-traffic)
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
- [ClusterGroup](#clustergroup)
  - [The ClusterGroup resource](#the-clustergroup-resource)
  - [kubectl commands for ClusterGroup](#kubectl-commands-for-clustergroup)
- [Audit logging for Antrea-native policies](#audit-logging-for-antrea-native-policies)
- [Select Namespace by Name](#select-namespace-by-name)
  - [K8s clusters with version 1.21 and above](#k8s-clusters-with-version-121-and-above)
  - [K8s clusters with version 1.20 and below](#k8s-clusters-with-version-120-and-below)
- [FQDN based filtering](#fqdn-based-filtering)
- [Node Selector](#node-selector)
- [toServices instruction](#toservices-instruction)
- [ServiceAccount based selection](#serviceaccount-based-selection)
- [RBAC](#rbac)
- [Notes](#notes)
<!-- /toc -->

## Summary

Antrea supports standard K8s NetworkPolicies to secure traffic between Pods.
These NetworkPolicies are written from an application developer's perspective,
hence they lack the ability to gain a finer-grained control over the security
policies that a cluster administrator would require. This document describes a
few new CRDs supported by Antrea to provide the administrator with more control
over security within the cluster, and which are meant to co-exist with and
complement the K8s NetworkPolicy.

Starting with Antrea v1.0, Antrea-native policies are enabled by default, which
means that no additional configuration is required in order to use the
Antrea-native policy CRDs.

## Tier

Antrea supports grouping Antrea-native policy CRDs together in a tiered fashion
to provide a hierarchy of security policies. This is achieved by setting the
`tier` field when defining an Antrea-native policy CRD (e.g. an Antrea
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
apiVersion: crd.antrea.io/v1alpha1
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
create policies in the "baseline" tier with the "allow" action.

### kubectl commands for Tier

The following kubectl commands can be used to retrieve Tier resources:

```bash
    # Use long name
    kubectl get tiers

    # Use long name with API Group
    kubectl get tiers.crd.antrea.io

    # Use short name
    kubectl get tr

    # Use short name with API Group
    kubectl get tr.crd.antrea.io

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

Antrea ClusterNetworkPolicy (ACNP), one of the two Antrea-native policy CRDs
introduced, is a specification of how workloads within a cluster communicate
with each other and other external endpoints. The ClusterNetworkPolicy is
supposed to aid cluster admins to configure the security policy for the
cluster, unlike K8s NetworkPolicy, which is aimed towards developers to secure
their apps and affects Pods within the Namespace in which the K8s NetworkPolicy
is created. Rules belonging to ClusterNetworkPolicies are enforced before any
rule belonging to a K8s NetworkPolicy.

### The Antrea ClusterNetworkPolicy resource

Example ClusterNetworkPolicies might look like these:

#### ACNP with stand-alone selectors

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-with-stand-alone-selectors
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

#### ACNP with ClusterGroup reference

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-with-cluster-groups
spec:
  priority: 8
  tier: securityops
  appliedTo:
    - group: "test-cg-with-db-selector"  # defined separately with a ClusterGroup resource
  ingress:
    - action: Allow
      from:
        - group: "test-cg-with-frontend-selector"  # defined separately with a ClusterGroup resource
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
        - group: "test-cg-with-ip-block"  # defined separately with a ClusterGroup resource
      ports:
        - protocol: TCP
          port: 5978
      name: DropToThirdParty
      enableLogging: true
```

#### ACNP for complete Pod isolation in selected Namespaces

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: isolate-all-pods-in-namespace
spec:
  priority: 1
  tier: securityops
  appliedTo:
    - namespaceSelector:
        matchLabels:
          app: no-network-access-required
  ingress:
    - action: Drop              # For all Pods in those Namespaces, drop and log all ingress traffic from anywhere
      name: drop-all-ingress
      enableLogging: true
  egress:
    - action: Drop              # For all Pods in those Namespaces, drop and log all egress traffic towards anywhere
      name: drop-all-egress
      enableLogging: true
```

#### ACNP for strict Namespace isolation

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: strict-ns-isolation
spec:
  priority: 5
  tier: securityops
  appliedTo:
    - namespaceSelector: {}       # Selects all Namespaces in the cluster
  ingress:
    - action: Pass
      from:
        - namespaces:
            match: Self           # Skip ACNP evaluation for traffic from Pods in the same Namespace
      name: PassFromSameNS
      enableLogging: false
    - action: Drop
      from:
        - namespaceSelector: {}   # Drop from Pods from all other Namespaces
      name: DropFromAllOtherNS
      enableLogging: true
  egress:
    - action: Pass
      to:
        - namespaces:
            match: Self           # Skip ACNP evaluation for traffic to Pods in the same Namespace
      name: PassToSameNS
      enableLogging: false
    - action: Drop
      to:
        - namespaceSelector: {}   # Drop to Pods from all other Namespaces
      name: DropToAllOtherNS
      enableLogging: true
```

#### ACNP for default zero-trust cluster security posture

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: default-cluster-deny
spec:
  priority: 1
  tier: baseline
  appliedTo:
    - namespaceSelector: {}       # Selects all Namespaces in the cluster
  ingress:
    - action: Drop
  egress:
    - action: Drop
```

#### ACNP for toServices rule

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-drop-to-services
spec:
    priority: 5
    tier: securityops
    appliedTo:
      - podSelector:
          matchLabels:
            role: client
        namespaceSelector:
          matchLabels:
            env: prod
    egress:
      - action: Drop
        toServices:
          - name: svcName
            namespace: svcNamespace
        name: DropToServices
        enableLogging: true
```

#### ACNP for ICMP traffic

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-reject-ping-request
spec:
    priority: 5
    tier: securityops
    appliedTo:
      - podSelector:
          matchLabels:
            role: server
        namespaceSelector:
          matchLabels:
            env: prod
    egress:
      - action: Reject
        protocols:
          - icmp:
              icmpType: 8
              icmpCode: 0
        name: DropPingRequest
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
The `appliedTo` field can also reference a ClusterGroup resource by setting
the ClusterGroup's name in `group` field in place of the stand-alone selectors.
IPBlock cannot be set in the `appliedTo` field.
An IPBlock ClusterGroup referenced in an `appliedTo` field will be ignored,
and the policy will have no effect.
This `appliedTo` field must not be set, if `appliedTo` per
rule is used.
In the [first example](#acnp-with-stand-alone-selectors), the policy applies to Pods, which either match the labels
"role=db" in all the Namespaces, or are from Namespaces which match the
labels "env=prod".
The [second example](#acnp-with-clustergroup-reference) policy applies to all network endpoints selected by the
"test-cg-with-db-selector" ClusterGroup.
The [third example](#acnp-for-complete-pod-isolation-in-selected-namespaces) policy applies to all Pods in the
Namespaces that matches label "app=no-network-access-required".
`appliedTo' also supports ServiceAccount based selection. This allows users using ServiceAccount to select Pods.
More details can be found in the [ServiceAccountSelector](#serviceaccount-based-selection) section.

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

**action**: Each ingress or egress rule of a ClusterNetworkPolicy must have the
`action` field set. As of now, the available actions are ["Allow", "Drop", "Reject", "Pass"].
When the rule action is "Allow" or "Drop", Antrea will allow or drop traffic which
matches both `from/to`, `ports` and `protocols` sections of that rule, given that traffic does not
match a higher precedence rule in the cluster (ACNP rules created in higher order
Tiers or policy instances in the same Tier with lower priority number). If a "Reject"
rule is matched, the client initiating the traffic will receive `ICMP host administratively
prohibited` code for ICMP, UDP and SCTP request, or an explicit reject response for
TCP request, instead of timeout. A "Pass" rule, on the other hand, skips this packet
for further ACNP rule evaluations (all ACNP rules that has lower priority than the
current "Pass" rule will be skipped, except for the Baseline Tier rules), and delegates
the decision to developer created namespaced NetworkPolicies. If no NetworkPolicy matches
this traffic, then the Baseline Tier rules will still be matched against. Note that the
"Pass" action does not make sense when configured in Baseline Tier ACNP rules, and such
configurations will be rejected by the admission controller.

**ingress**: Each ClusterNetworkPolicy may consist of zero or more ordered set of
ingress rules. Under `ports`, the optional field `endPort` can only be set when a
numerical `port` is set to represent a range of ports from `port` to `endPort` inclusive.
`protocols` defines additional protocols that are not supported by `ports`. Currently, only
ICMP protocol is under `protocols`. `icmpType` and `icmpCode` could be used to specify the ICMP
traffic that this rule matches. 
Also, each rule has an optional `name` field, which should be unique within
the policy describing the intention of this rule. If `name` is not provided for
a rule, it will be auto-generated by Antrea. The auto-generated name will be
of format `[ingress/egress]-[action]-[uid]`, e.g. ingress-allow-2f0ed6e,
where [uid] is the first 7 bits of hash value of the rule based on sha1 algorithm.
If a policy contains duplicate rules, or if a rule name is same as the auto-generated
name of some other rules in the same policy, it will cause a conflict,
and the policy will be rejected.
A ClusterGroup name can be set in the `group` field of an ingress `from` section in place
of stand-alone selectors to allow traffic from workloads/ipBlocks set in the ClusterGroup.
The [first example](#acnp-with-stand-alone-selectors) policy contains a single rule, which allows matched traffic on a
single port, from one of two sources: the first specified by a `podSelector`
and the second specified by a combination of a `podSelector` and a
`namespaceSelector`.
The [second example](#acnp-with-clustergroup-reference) policy contains a single rule, which allows matched traffic on
multiple TCP ports (8000 through 9000 included, plus 6379) from all network endpoints
selected by the "test-cg-with-frontend-selector" ClusterGroup.
The [third example](#acnp-for-complete-pod-isolation-in-selected-namespaces) policy contains a single rule,
which drops all ingress traffic towards any Pod in Namespaces that have label `app` set to
`no-network-access-required`. Note that an empty `From` in the ingress rule means that
this rule matches all ingress sources.
Ingress `From` section also supports ServiceAccount based selection. This allows users to use ServiceAccount
to select Pods. More details can be found in the [ServiceAccountSelector](#serviceaccount-based-selection) section.
**Note**: The order in which the ingress rules are specified matters, i.e., rules will
be enforced in the order in which they are written.

**egress**: Each ClusterNetworkPolicy may consist of zero or more ordered set
of egress rules. Each rule, depending on the `action` field of the rule, allows
or drops traffic which matches all `from`, `ports` sections.
Under `ports`, the optional field `endPort` can only be set when a numerical `port`
is set to represent a range of ports from `port` to `endPort` inclusive.
`protocols` defines additional protocols that are not supported by `ports`. Currently, only
ICMP protocol is under `protocols`. `icmpType` and `icmpCode` could be used to specify the ICMP
traffic that this rule matches.
Also, each rule has an optional `name` field, which should be unique within
the policy describing the intention of this rule. If `name` is not provided for
a rule, it will be auto-generated by Antrea. The rule name auto-generation process
is the same as ingress rules.
A ClusterGroup name can be set in the `group` field of a egress `to` section in place
of stand-alone selectors to allow traffic to workloads/ipBlocks set in the ClusterGroup.
`toServices` field contains a list of combinations of Service Namespace and Service Name to match traffic to this Service.
More details can be found in the [toServices](#toservices-instruction) section.
The [first example](#acnp-with-stand-alone-selectors) policy contains a single rule, which drops matched traffic on a
single port, to the 10.0.10.0/24 subnet specified by the `ipBlock` field.
The [second example](#acnp-with-clustergroup-reference) policy contains a single rule, which drops matched traffic on
TCP port 5978 to all network endpoints selected by the "test-cg-with-ip-block"
ClusterGroup.
The [third example](#acnp-for-complete-pod-isolation-in-selected-namespaces) policy contains a single rule,
which drops all egress traffic initiated by any Pod in Namespaces that have `app` set to
`no-network-access-required`.
The [sixth example](#acnp-for-toservices-rule) policy contains a single rule,
which drops traffic from "role: client" labeled Pods from "env: prod" labeled Namespaces to Service svcNamespace/svcName
via ClusterIP.
Note that an empty `to` + an empty `toServices` in the egress rule means that
this rule matches all egress destinations.
Egress `To` section also supports FQDN based filtering. This can be applied to exact FQDNs or
wildcard expressions. More details can be found in the [FQDN](#fqdn-based-filtering) section.
Egress `To` section also supports ServiceAccount based selection. This allows users to use ServiceAccount
to select Pods. More details can be found in the [ServiceAccountSelector](#serviceaccount-based-selection) section.
**Note**: The order in which the egress rules are specified matters, i.e., rules will
be enforced in the order in which they are written.

**enableLogging**: A ClusterNetworkPolicy ingress or egress rule can be
audited by enabling its logging field. When `enableLogging` field is set to
true, the first packet of any connection that matches this rule will be logged
to a separate file (`/var/log/antrea/networkpolicy/np.log`) on the Node on
which the rule is applied. These log files can then be retrieved for further
analysis. By default, rules are not logged. The example policy logs all
traffic that matches the "DropToThirdParty" egress rule, while the rule
"AllowFromFrontend" is not logged. Specifically for drop and reject rules,
deduplication is applied to simplify multiple logs. Duplication buffer length is set as 1 second.
The rules are logged in the following format:

```text
    <yyyy/mm/dd> <time> <ovs-table-name> <antrea-native-policy-reference> <action> <openflow-priority> <source-ip> <source-port> <destination-ip> <destination-port> <protocol> <packet-length>
    Deduplication:
    <yyyy/mm/dd> <time> <ovs-table-name> <antrea-native-policy-reference> <action> <openflow-priority> <source-ip> <source-port> <destination-ip> <destination-port> <protocol> <packet-length> [<num of packets> packets in <duplicate duration>]

    Example:
    2020/11/02 22:21:21.148395 AntreaPolicyAppTierIngressRule AntreaNetworkPolicy:default/test-anp Allow 61800 10.10.1.65 35402 10.0.0.5 80 TCP 60
    2021/06/24 23:56:41.346165 AntreaPolicyEgressRule AntreaNetworkPolicy:default/test-anp Drop 44900 10.10.1.65 35402 10.0.0.5 80 TCP 60 [3 packets in 1.011379442s]
```

**`appliedTo` per rule**: A ClusterNetworkPolicy ingress or egress rule may
optionally contain the `appliedTo` field. Semantically, the `appliedTo` field
per rule is similar to the `appliedTo` field at the policy level, except that
it is valid for that rule itself, as opposed to spanning over all the rules.
If used, the `appliedTo` field must be set for all the rules existing in the
policy and cannot be set along with `appliedTo` at the policy level.

**Note**: In a given ClusterNetworkPolicy, all rules/`appliedTo` fields must
either contain stand-alone selectors or references to ClusterGroup.
Usage of ClusterGroups along with stand-alone selectors is not allowed.

### Behavior of *to* and *from* selectors

There are seven kinds of selectors that can be specified in an ingress `from`
section or egress `to` section:

**podSelector**: This selects particular Pods from all Namespaces as "sources",
if set in `ingress` section, or as "destinations", if set in `egress` section.

**namespaceSelector**: This selects particular Namespaces for which all Pods
are grouped as `ingress` "sources" or `egress` "destinations". Cannot be set
with `namespaces` field.

**podSelector** and **namespaceSelector**:  A single to/from entry that
specifies both namespaceSelector and podSelector selects particular Pods within
particular Namespaces.

**nodeSelector**: This selects particular Nodes in cluster. The selected Node's
IPs will be set as "sources" if `nodeSelector` set in `ingress` section, or as
"destinations" if is set in the `egress` section.

**namespaces**: A `namespaces` field allows users to perform advanced matching on
Namespace objects which cannot be done via label selectors. Currently, the
`namespaces` field has only one matching strategy, `Self`. If set to `Self`, it indicates
that the corresponding `podSelector` (or all Pods if `podSelector` is not set)
should only select Pods belonging to the same Namespace as the workload targeted
(either through a policy-level AppliedTo or a rule-level Applied-To) by the current
ingress or egress rule. This enables policy writers to create per-Namespace rules within a
single policy. See the [example](#acnp-for-strict-namespace-isolation) YAML above. This field is
optional and cannot be set along with a `namespaceSelector` within the same peer.

**group**: A `group` refers to a ClusterGroup to which this ingress/egress peer, or
an `appliedTo` must resolve to. More information on ClusterGroups can be found [here](#clustergroup).

**ipBlock**: This selects particular IP CIDR ranges to allow as `ingress`
"sources" or `egress` "destinations". These should be cluster-external IPs,
since Pod IPs are ephemeral and unpredictable.

**fqdn**: This selector is applicable only to the `to` section in an `egress` block. It is used to
select Fully Qualified Domain Names (FQDNs), specified either by exact name or wildcard
expressions, when defining `egress` rules.

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
    kubectl get clusternetworkpolicies.crd.antrea.io

    # Use short name
    kubectl get acnp

    # Use short name with API Group
    kubectl get acnp.crd.antrea.io
```

All of the above commands produce output similar to what is shown below:

```text
    NAME       TIER        PRIORITY   AGE
    test-cnp   emergency   5          54s
```

## Antrea NetworkPolicy

Antrea NetworkPolicy (ANP) is another policy CRD, which is similar to the
ClusterNetworkPolicy CRD, however its scope is limited to a Namespace.
The purpose of introducing this CRD is to allow admins to take advantage of
advanced NetworkPolicy features and apply them within a Namespace to
complement the K8s NetworkPolicies. Similar to the ClusterNetworkPolicy
resource, Antrea NetworkPolicy can also be associated with Tiers.

### The Antrea NetworkPolicy resource

An example Antrea NetworkPolicy might look like this:

```yaml
apiVersion: crd.antrea.io/v1alpha1
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

Antrea NetworkPolicy shares its spec with ClusterNetworkPolicy. However,
the following documents some of the key differences between the two Antrea
policy CRDs.

- Antrea NetworkPolicy is Namespaced while ClusterNetworkPolicy operates at
  cluster scope.
- Unlike the `appliedTo` in a ClusterNetworkPolicy, setting a
  `namespaceSelector` in the `appliedTo` field is forbidden.
- `podSelector` without a `namespaceSelector`, set within a NetworkPolicy Peer
  of any rule, selects Pods from the Namespace in which the Antrea
  NetworkPolicy is created. This behavior is similar to the K8s NetworkPolicy.
- Antrea NetworkPolicy only supports stand-alone selectors. i.e. no support for
  ClusterGroup references.
- Antrea NetworkPolicy does not support `namespaces` field within a peer, as ANP
  themselves are scoped to a single Namespace.

### kubectl commands for Antrea NetworkPolicy

The following kubectl commands can be used to retrieve ANP resources:

```bash
    # Use long name with API Group
    kubectl get networkpolicies.crd.antrea.io

    # Use short name
    kubectl get anp

    # Use short name with API Group
    kubectl get anp.crd.antrea.io
```

All of the above commands produce output similar to what is shown below:

```text
    NAME       TIER          PRIORITY   AGE
    test-anp   securityops   5          5s
```

## Antrea-native Policy ordering based on priorities

Antrea-native policy CRDs are ordered based on priorities set at various levels.

### Ordering based on Tier priority

With the introduction of tiers, Antrea Policies, like ClusterNetworkPolicies,
are first enforced based on the Tier to which they are associated. i.e. all
policies belonging to a high Tier are enforced first, followed by policies
belonging to the next Tier and so on, until the "application" Tier policies
are enforced. K8s NetworkPolicies are enforced next, and "baseline" Tier
policies will be enforced last.

### Ordering based on policy priority

Within a tier, Antrea-native policy CRDs are ordered by the `priority` at the policy
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

## ClusterGroup

A ClusterGroup (CG) CRD is a specification of how workloads are grouped together.
It allows admins to group Pods using traditional label selectors, which can then
be referenced in ACNP in place of stand-alone `podSelector` and/or `namespaceSelector`.
In addition to `podSelector` and `namespaceSelector`, ClusterGroup also supports the
following ways to select endpoints:

- Pod grouping by `serviceReference`. ClusterGroup specified by `serviceReference` will
  contain the same Pod members that are currently selected by the Service's selector.
- `ipBlock` or `ipBlocks` to share IPBlocks between ACNPs.
- `childGroups` to select other ClusterGroups by name.

ClusterGroups allow admins to separate the concern of grouping of workloads from
the security aspect of Antrea-native policies.
It adds another level of indirection allowing users to update group membership
without having to update individual policy rules.

### The ClusterGroup resource

An example ClusterGroup might look like this:

```yaml
apiVersion: crd.antrea.io/v1alpha3
kind: ClusterGroup
metadata:
  name: test-cg-sel
spec:
  podSelector:
    matchLabels:
      role: db
  namespaceSelector:
    matchLabels:
      env: prod
status:
  conditions:
    - type: "GroupMembersComputed"
      status: "True"
      lastTransitionTime: "2021-01-29T19:59:39Z"
---
apiVersion: crd.antrea.io/v1alpha3
kind: ClusterGroup
metadata:
  name: test-cg-ip-block
spec:
  # IPBlocks cannot be set along with PodSelector, NamespaceSelector or serviceReference.
  ipBlocks:
  - cidr: 10.0.10.0/24
status:
  conditions:
    - type: "GroupMembersComputed"
      status: "True"
      lastTransitionTime: "2021-01-29T19:59:39Z"
---
apiVersion: crd.antrea.io/v1alpha3
kind: ClusterGroup
metadata:
  name: test-cg-svc-ref
spec:
  # ServiceReference cannot be set along with PodSelector, NamespaceSelector or ipBlocks.
  serviceReference:
    name: test-service
    namespace: default
status:
  conditions:
    - type: "GroupMembersComputed"
      status: "True"
      lastTransitionTime: "2021-01-29T20:21:46Z"
---
apiVersion: crd.antrea.io/v1alpha3
kind: ClusterGroup
metadata:
  name: test-cg-nested
spec:
  childGroups: [test-cg-sel, test-cg-ip-blocks, test-cg-svc-ref]
status:
  conditions:
    - type: "GroupMembersComputed"
      status: "True"
      lastTransitionTime: "2021-01-29T20:21:48Z"
```

There are a few **restrictions** on how ClusterGroups can be configured:

- A ClusterGroup is a cluster-scoped resource and therefore can only be set in an Antrea
  ClusterNetworkPolicy's `appliedTo` and `to`/`from` peers.
- For the `childGroup` field, currently only one level of nesting is supported:
  If a ClusterGroup has childGroups, it cannot be selected as a childGroup by other ClusterGroups.
- ClusterGroup must exist before another ClusterGroup can select it by name as its childGroup.
  A ClusterGroup cannot be deleted if it is referred to by other ClusterGroup as childGroup.
  This restriction may be lifted in future releases.
- At most one of `podSelector`, `serviceReference`, `ipBlock`, `ipBlocks` or `childGroups`
  can be set for a ClusterGroup, i.e. a single ClusterGroup can either group workloads,
  represent IP CIDRs or select other ClusterGroups. A parent ClusterGroup can select different
  types of ClusterGroups (Pod/Service/CIDRs), but as mentioned above, it cannot select a
  ClusterGroup that has childGroups itself.

**spec**: The ClusterGroup `spec` has all the information needed to define a
cluster-wide group.

**podSelector**: Pods can be grouped cluster-wide using `podSelector`.
If set with a `namespaceSelector`, all matching Pods from Namespaces selected
by the `namespaceSelector` will be grouped.

**namespaceSelector**: All Pods from Namespaces selected by the namespaceSelector
will be grouped.
If set with a `podSelector`, all matching Pods from Namespaces selected by the
`namespaceSelector` will be grouped.

**ipBlock**: This selects a particular IP CIDR range to allow as `ingress`
"sources" or `egress` "destinations".
A ClusterGroup with `ipBlock` referenced in an ACNP's `appliedTo` field will be
ignored, and the policy will have no effect.
For a same ClusterGroup, `ipBlock` and `ipBlocks` cannot be set concurrently.
ipBlock will be deprecated for ipBlocks in future versions of ClusterGroup.

**ipBlocks**: This selects a list of IP CIDR ranges to allow as `ingress`
"sources" or `egress` "destinations".
A ClusterGroup with `ipBlocks` referenced in an ACNP's `appliedTo` field will be
ignored, and the policy will have no effect.
For a same ClusterGroup, `ipBlock` and `ipBlocks` cannot be set concurrently.

**serviceReference**: Pods that serve as the backend for the specified Service
will be grouped. Services without selectors are currently not supported, and will
be ignored if referred by `serviceReference` in a ClusterGroup.
When ClusterGroups with `serviceReference` are used in ACNPs as `appliedTo` or
`to`/`from` peers, no Service port information will be automatically assumed for
traffic enforcement. `ServiceReference` is merely a mechanism to group Pods and
ensure that a ClusterGroup stays in sync with the set of Pods selected by a given
Service.

**childGroups**: This selects existing ClusterGroups by name. The effective members
of the "parent" ClusterGrup will be the union of all its childGroups' members.
See the section above for restrictions.

**status**: The ClusterGroup `status` field determines the overall realization
status of the group.

**groupMembersComputed**: The "GroupMembersComputed" condition is set to "True"
when the controller has calculated all the corresponding workloads that match the
selectors set in the group.

### kubectl commands for ClusterGroup

The following kubectl commands can be used to retrieve CG resources:

```bash
    # Use long name with API Group
    kubectl get clustergroups.crd.antrea.io

    # Use short name
    kubectl get cg

    # Use short name with API Group
    kubectl get cg.crd.antrea.io
```

## Audit logging for Antrea-native policies

Logs are recorded in `/var/log/antrea/networkpolicy` when `enableLogging` is configured.
Fluentd can be used to assist with analyzing the logs. Refer to the
[Fluentd cookbook](cookbooks/fluentd) for documentation.

## Select Namespace by Name

Kubernetes NetworkPolicies and Antrea-native policies allow selecting
workloads from Namespaces with the use of a label selector (i.e. `namespaceSelector`).
However, it is often desirable to be able to select Namespaces directly by their `name`
as opposed to using the `labels` associated with the Namespaces.

### K8s clusters with version 1.21 and above

Starting with K8s v1.21, all Namespaces are labeled with the `kubernetes.io/metadata.name: <namespaceName>` [label](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/#automatic-labelling)
provided that the `NamespaceDefaultLabelName` feature gate (enabled by default) is not disabled in K8s.
K8s NetworkPolicy and Antrea-native policy users can take advantage of this reserved label
to select Namespaces directly by their `name` in `namespaceSelectors` as follows:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: NetworkPolicy
metadata:
  name: test-anp-by-name
  namespace: default
spec:
    priority: 5
    tier: application
    appliedTo:
      - podSelector: {}
    egress:
      - action: Allow
        to:
          - podSelector:
              matchLabels:
                app: core-dns
            namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: kube-system
        ports:
          - protocol: TCP
            port: 53
          - protocol: UDP
            port: 53
        name: AllowToCoreDNS
```

**Note**: `NamespaceDefaultLabelName` feature gate is scheduled to be removed in K8s v1.24, thereby
ensuring that labeling Namespaces by their name cannot be disabled.

### K8s clusters with version 1.20 and below

In order to select Namespaces by name, Antrea labels Namespaces with a reserved label `antrea.io/metadata.name`,
whose value is set to the Namespace's name. Users can then use this label in the
`namespaceSelector` field, in both K8s NetworkPolicies and Antrea-native policies to
select Namespaces by name. By default, Namespaces are not labeled with the reserved name label.
In order for the Antrea controller to label the Namespaces, the `labelsmutator.antrea.io`
`MutatingWebhookConfiguration` must be enabled. This can be done by applying the following
webhook configuration YAML:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  # Do not edit this name.
  name: "labelsmutator.antrea.io"
webhooks:
  - name: "namelabelmutator.antrea.io"
    clientConfig:
      service:
        name: "antrea"
        namespace: "kube-system"
        path: "/mutate/namespace"
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["namespaces"]
        scope: "Cluster"
    admissionReviewVersions: ["v1", "v1beta1"]
    sideEffects: None
    timeoutSeconds: 5
```

**Note**: `antrea-controller` Pod must be restarted after applying this YAML.

Once the webhook is configured, Antrea will start labeling all new and updated
Namespaces with the `antrea.io/metadata.name: <namespaceName>` label. Users may now
use this reserved label to select Namespaces by name as follows:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: NetworkPolicy
metadata:
  name: test-anp-by-name
  namespace: default
spec:
    priority: 5
    tier: application
    appliedTo:
      - podSelector: {}
    egress:
      - action: Allow
        to:
          - podSelector:
              matchLabels:
                app: core-dns
            namespaceSelector:
              matchLabels:
                antrea.io/metadata.name: kube-system
        ports:
          - protocol: TCP
            port: 53
          - protocol: UDP
            port: 53
        name: AllowToCoreDNS
```

The above example allows all Pods from Namespace "default" to connect to all "core-dns"
Pods from Namespace "kube-system" on TCP port 53.

## FQDN based filtering

Antrea-native policy accepts a `fqdn` field to select Fully Qualified Domain Names (FQDNs),
specified either by exact name or wildcard expressions, when defining `egress` rules.

The standard `Allow`, `Drop` and `Reject` actions apply to FQDN egress rules.

An example policy using FQDN based filtering could look like this:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-fqdn-all-foobar
spec:
  priority: 1
  appliedTo:
  - podSelector:
      matchLabels:
        app: client
  egress:
  - action: Drop
    to:
      - fqdn: "*foobar.com"
```

The above example drops all traffic destined to any FQDN that matches the wildcard
expression `*foobar.com` originating from any Pod with label `app` set to `client`
across any Namespace. This feature only works at the L3/L4 level.

Note that FQDN based policies do not work for [Service DNS names created by
Kubernetes](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#services)
(e.g. `kubernetes.default.svc` or `antrea.kube-system.svc`), except for headless
Services. The reason is that Antrea will use the information included in A or
AAAA DNS records to implement FQDN based policies. In the case of "normal" (not
headless) Services, the DNS name resolves to the ClusterIP for the Service, but
policy rules are enforced after AntreaProxy Service Load-Balancing and at that
stage the destination IP address has already been rewritten to the address of an
endpoint backing the Service. For headless Services, a ClusterIP is not
allocated and, assuming the Service has a selector, the DNS server returns A /
AAAA records that point directly to the endpoints. In that case, FQDN based
policies can be used successfully. For example, the following policy, which
specifies an exact match on a DNS name, will drop all egress traffic destined to
headless Service `svcA` defined in the `default` Namespace:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-fqdn-headless-service
spec:
  priority: 1
  appliedTo:
  - podSelector:
      matchLabels:
        app: client
  egress:
  - action: Drop
    to:
      - fqdn: "svcA.default.svc.cluster.local"
```

## Node Selector

NodeSelector selects certain Nodes which match the label selector.
When used in the `to` field of an egress rule, it adds the Node IPs to the rule's destination address group;
when used in the `from` field of an ingress rule, it adds the Node IPs to the rule's source address group.

Notice that when a rule with a nodeSelector applies to a Node, it only restricts the traffic to/from certain IPs of the Node.
The IPs include:  

1. The Node IP (the IP address in the Node API object)
2. The Antrea gateway IP (the IP address of the interface antrea-agent will create and use for Node-to-Pod communication)
3. The transport IP (the IP address of the interface used for tunneling or routing the traffic across Nodes) if it's different from Node IP

Traffic to/from other IPs of the Node will be ignored.
Meanwhile, `NodeSelector` doesn’t affect the traffic from Node to Pods running on that Node. Such traffic will always
be allowed to make sure that [agents on a Node (e.g. system daemons, kubelet) can communicate with all Pods on
that Node](https://kubernetes.io/docs/concepts/services-networking/#the-kubernetes-network-model) to perform liveness
and readiness probes. For more information, see [https://github.com/antrea-io/antrea/pull/104](https://github.com/antrea-io/antrea/pull/104).

For example, the following rule applies to Pods with label `app=antrea-test-app` and will `Drop` egress traffic to
Nodes on TCP port 6443 which have the labels `node-role.kubernetes.io/control-plane`.

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: egress-control-plane
spec:
  priority: 1
  appliedTo:
    - podSelector:
        matchLabels:
          app: antrea-test-app
  egress:
    - action: Drop
      to:
        - nodeSelector:
            matchLabels:
              node-role.kubernetes.io/control-plane: ""
      ports:
        - protocol: TCP
          port: 6443
```

## toServices instruction

A combination of Service name and Service Namespace can be used in `toServices` to refer to a Service.
`toServices` match traffic based on the clusterIP, port and protocol of Services. So headless Service is not supported.
Since `toServices` represents a combination of IP+port, it can't be used with `to` or `ports`. Also, this match process
relies on the groupID assigned to the Service by AntreaProxy. So it can only be used when AntreaProxy is enabled.
This clusterIP based match has one caveat: directly access to the Endpoints of this Service is not controlled by
`toServices`. To control the access to the backend Endpoints, you could use `ClusterGroup` with `ServiceReference`.
Because `ClusterGroup` with `ServiceReference` is equivalent to a podSelector that selects all backend Endpoints Pods of
the Service referred in `ServiceReference`.

## ServiceAccount based selection

Antrea ClusterNetworkPolicy accepts a `serviceAccount` field to select all Pods that have been assigned the
ServiceAccount selected by this field. This field could be used in `appliedTo`, ingress `from` and egress `to` section.
No matter `serviceAccount` is used in which sections, it cannot be used with any other fields.

`serviceAccount` uses `namespace` + `name` to select the ServiceAccount with a specific name under a specific namespace.

An example policy using `serviceAccount` could look like this:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: acnp-service-account
spec:
    priority: 5
    tier: securityops
    appliedTo:
      - serviceAccount:
          name: sa-1
          namespace: ns-1
    egress:
      - action: Drop
        to:
          - serviceAccount:
              name: sa-2
              namespace: ns-2
        name: ServiceAccountEgressRule
        enableLogging: false
```

In this example, the policy will be applied to all Pods whose ServiceAccount is in `ns-1` namespace and name as `sa-1`.
Let's call those Pods "appliedToPods".
The egress `to` section will select all Pods whose ServiceAccount is in `ns-2` namespace and name as `sa-2`.
Let's call those Pods "egressPods".

So after this policy is applied, traffic from "appliedToPods" to "egressPods" will be dropped.

There is a CAVEAT after introducing `serviceAccount`:

Antrea will use a reserved label key for internal processing `serviceAccount`.
The reserved label looks like: `internal.antrea.io/service-account:[ServiceAccountName]`. Users should avoid using
this label key in any entities whether a policy with `serviceAccount` is applied in the cluster.

## RBAC

Antrea-native policy CRDs are meant for admins to manage the security of their
cluster. Thus, access to manage these CRDs must be granted to subjects which
have the authority to outline the security policies for the cluster and/or
Namespaces. On cluster initialization, Antrea grants the permissions to edit
these CRDs with `admin` and the `edit` ClusterRole. In addition to this, Antrea
also grants the permission to view these CRDs with the `view` ClusterRole.
Cluster admins can therefore grant these ClusterRoles to any subject who may
be responsible to manage the Antrea policy CRDs. The admins may also decide to
share the `view` ClusterRole to a wider range of subjects to allow them to read
the policies that may affect their workloads.
Similar RBAC is applied to the ClusterGroup resource.

## Notes

- There is a soft limit of 20 on the maximum number of Tier resources that are
  supported. But for optimal performance, it is recommended that the number of
  Tiers in a cluster be less than or equal to 10.
- In order to reduce the churn in the agent, it is recommended to set the policy
  priority within the range 1.0 to 100.0.
- The v1alpha1 policy CRDs support up to 10,000 unique priorities at policy level,
  and up to 50,000 unique priorities at rule level, across all tiers except for
  the "baseline" tier. For any two policy rules, their rule level priorities are only
  considered equal if they share the same tier, and have the same policy priority
  as well as rule priority.
- For the "baseline" tier, the max supported unique priorities (at rule level）is 150.
