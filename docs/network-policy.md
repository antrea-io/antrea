# Cluster Network Policy

ClusterNetworkPolicy is a specification of how workloads within a cluster
communicate with each other and other external endpoints.
The ClusterNetworkPolicy is supposed to aid cluster admins to configure
the security policy for the cluster, unlike K8s NetworkPolicy, which is
aimed towards developers to secure their apps and affects Pods within the
Namespace in which the K8s NetworkPolicy is created.
Rules belonging to ClusterNetworkPolicies are evaluated before any rule
belonging to a K8s NetworkPolicy.

**Note**: ClusterNetworkPolicy is currently in "Alpha" stage. In order to
enable them, edit the Controller configuration in the `antrea` ConfigMap
as follows:
```yaml
   antrea-controller.conf: |
     featureGates:
       # Enable ClusterNetworkPolicy feature to complement K8s NetworkPolicy
       # for cluster admins to define security policies which apply to the
       # entire cluster.
       ClusterNetworkPolicy: true
```

## The ClusterNetworkPolicy resource

An example ClusterNetworkPolicy might look like this:
```
apiVersion: security.antrea.tanzu.vmware.com/v1alpha1
kind: ClusterNetworkPolicy
metadata:
  name: test-cnp
spec:
    priority: 5
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
IPBlock is not allowed to be set in the `appliedTo` field.
In the example, the policy applies to Pods, which either match the labels
"role=db" in all the Namespaces, or are from Namespaces which match the
labels "env=prod".

**priority**: The `priority` field determines the relative priority of the policy
among all ClusterNetworkPolicies in the given cluster. This field is mandatory.
A lower priority value indicates higher precedence. Priority values can range
from 1.0 to 10000.0.
**Note**: Policies with the same priorities will be evaluated
indeterministically. Users should therefore take care to use priorities to
ensure the behavior they expect.

**ingress**: Each ClusterNetworkPolicy may consist of zero or more ordered
set of ingress rules. Each rule, depending on the `action` field of the rule,
allows or drops traffic which matches both the `from` and `ports` sections.
The example policy contains a single rule, which allows matched traffic on a
single port, from one of two sources: the first specified by a `podSelector`
and the second specified by a combination of a `podSelector` and a
`namespaceSelector`.
**Note**: The order in which the ingress rules are set matter, i.e. rules will be
evaluated in the order in which they are written.

**egress**: Each ClusterNetworkPolicy may consist of zero or more ordered set of
egress rules. Each rule, depending on the `action` field of the rule, allows
or drops traffic which matches both the `to` and `ports` sections. The example
policy contains a single rule, which drops matched traffic on a single port,
to the 10.0.10.0/24 subnet specified by the `ipBlock` field.
**Note**: The order in which the egress rules are set matter, i.e. rules will be
evaluated in the order in which they are written.

## Rule evaluation based on priorities

Rules belonging to Cluster NetworkPolicy CRDs are associated with various
priorities, such as the `priority` at the CNP level and the priority at rule
level. Overall, Cluster Policy with highest precedence (lowest priority number
value) is evaluated first. Within this policy, rules are evaluated in the order
in which they are set. For example, consider the following:

- CNP1{priority: 10, ingressRules: [ir1.1, ir1.2], egressRules: [er1.1, er1.2]}
- CNP2{priority: 15, ingressRules: [ir2.1, ir2.2], egressRules: [er2.1, er2.2]}

This translates to the following order:
- Ingress rules: ir1.1 -> ir1.2 -> ir2.1 -> ir2.2
- Egress rules: er1.1 -> er1.2 -> er2.1 -> er2.2

Once a rule is matched, it is executed based on the action set. If none of the
CNP rules match, the packet is then evaluated for rules created for K8s NP.
Hence, CNP take precedence over K8s NP.

## Behavior of `to` and `from` selectors

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

## Key differences from K8s NetworkPolicy

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
  order to reduce churn in the agent, it is recommended to set the priority
  within the range 1.0 to 100.0.
