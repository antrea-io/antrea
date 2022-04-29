# Security Recommendations

This document describes some security recommendations when deploying Antrea in a
cluster, and in particular a [multi-tenancy
cluster](https://cloud.google.com/kubernetes-engine/docs/concepts/multitenancy-overview#what_is_multi-tenancy).

To report a vulnerability in Antrea, please refer to
[SECURITY.md](../SECURITY.md).

For information about securing Antrea control-plane communications, refer to
this [document](securing-control-plane.md).

## Protecting Your Cluster Against Privilege Escalations

### Antrea Agent

Like all other K8s Network Plugins, Antrea runs an agent (the Antrea Agent) on
every Node on the cluster, using a K8s DaemonSet. And just like for other K8s
Network Plugins, this agent requires a specific set of permissions which grant
it access to the K8s API using
[RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/). These
permissions are required to implement the different features offered by
Antrea. If any Node in the cluster happens to become compromised (e.g., by an
escaped container) and the token for the `antrea-agent` ServiceAccount is
harvested by the attacker, some of these permissions can be leveraged to
negatively affect other workloads running on the cluster. In particular, the
Antrea Agent is granted the following permissions:

* `patch` the `pods/status` resources: a successful attacker could abuse this
  permission to re-label Pods to facilitate [confused deputy
  attacks](https://en.wikipedia.org/wiki/Confused_deputy_problem) against
  built-in controllers. For example, making a Pod match a Service selector in
  order to man-in-the-middle (MITM) the Service traffic, or making a Pod match a
  ReplicaSet selector so that the ReplicaSet controller deletes legitimate
  replicas.
* `patch` the `nodes/status` resources: a successful attacker could abuse this
  permission to affect scheduling by modifying Node fields like labels,
  capacity, and conditions.

In both cases, the Antrea Agent only requires the ability to mutate the
annotations field for all Pods and Nodes, but with K8s RBAC, the lowest
permission level that we can grant the Antrea Agent to satisfy this requirement
is the `patch` verb for the `status` subresource for Pods and Nodes (which also
provides the ability to mutate labels).

To mitigate the risk presented by these permissions in case of a compromised
token, we suggest that you use
[Gatekeeper](https://github.com/open-policy-agent/gatekeeper), with the
appropriate policy. We provide the following Gatekeeper policy, consisting of a
`ConstraintTemplate` and the corresponding `Constraint`. When using this policy,
it will no longer be possible for the `antrea-agent` ServiceAccount to mutate
anything besides annotations for the Pods and Nodes resources.

```yaml
# ConstraintTemplate
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: antreaagentstatusupdates
  annotations:
    description: >-
      Disallows unauthorized updates to status subresource by Antrea Agent
      Only annotations can be mutated
spec:
  crd:
    spec:
      names:
        kind: AntreaAgentStatusUpdates
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package antreaagentstatusupdates
        username := object.get(input.review.userInfo, "username", "")
        targetUsername := "system:serviceaccount:kube-system:antrea-agent"

        allowed_mutation(object, oldObject) {
            object.status == oldObject.status
            object.metadata.labels == oldObject.metadata.labels
        }

        violation[{"msg": msg}] {
          username == targetUsername
          input.review.operation == "UPDATE"
          input.review.requestSubResource == "status"
          not allowed_mutation(input.review.object, input.review.oldObject)
          msg := "Antrea Agent is not allowed to mutate this field"
        }
```

```yaml
# Constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: AntreaAgentStatusUpdates
metadata:
  name: antrea-agent-status-updates
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod", "Node"]
```

***Please ensure that the `ValidatingWebhookConfiguration` for your Gatekeeper
   installation enables policies to be applied on the `pods/status` and
   `nodes/status` subresources, which may not be the case by default.***

As a reference, the following `ValidatingWebhookConfiguration` rule will cause
policies to be applied to all resources and their subresources:

```yaml
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*/*'
    scope: '*'
```

while the following rule will cause policies to be applied to all resources, but
not their subresources:

```yaml
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*'
    scope: '*'
```

### Antrea Controller

The Antrea Controller, which runs as a single-replica Deployment, enjoys higher
level permissions than the Antrea Agent. We recommend for production clusters
running Antrea to schedule the `antrea-controller` Pod on a "secure" Node, which
could for example be the Node (or one of the Nodes) running the K8s
control-plane.

## Protecting Access to Antrea Configuration Files

Antrea relies on persisting files on each K8s Node's filesystem, in order to
minimize disruptions to network functions across Antrea Agent restarts, in
particular during an upgrade. All these files are located under
`/var/run/antrea/`. The most notable of these files is
`/var/run/antrea/openvswitch/conf.db`, which stores the Open vSwitch
database. Prior to Antrea v0.10, any user had read access to the file on the
host (permissions were set to `0644`). Starting with v0.10, this is no longer
the case (permissions are now set to `0640`). Starting with v0.13, we further
remove access to the `/var/run/antrea/` directory for non-root users
(permissions are set to `0750`).

If a malicious Pod can gain read access to this file, or, prior to Antrea v0.10,
if an attacker can gain access to the host, they can potentially access
sensitive information stored in the database, most notably the Pre-Shared Key
(PSK) used to configure [IPsec tunnels](traffic-encryption.md), which is stored
in plaintext in the database. If a PSK is leaked, an attacker can mount a
man-in-the-middle attack and intercept tunnel traffic.

If a malicious Pod can gain write access to this file, it can modify the
contents of the database, and therefore impact network functions.

Administrators of multi-tenancy clusters running Antrea should take steps to
restrict the access of Pods to `/var/run/antrea/`. One way to achieve this is to
use a
[PodSecurityPolicy](https://kubernetes.io/docs/concepts/policy/pod-security-policy)
and restrict the set of allowed
[volumes](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)
to exclude `hostPath`. **This guidance applies to all multi-tenancy clusters and
is not specific to Antrea.** To quote the K8s documentation:

> There are many ways a container with unrestricted access to the host
  filesystem can escalate privileges, including reading data from other
  containers, and abusing the credentials of system services, such as Kubelet.

An alternative solution to K8s PodSecurityPolicies is to use
[Gatekeeper](https://github.com/open-policy-agent/gatekeeper) to constrain usage
of the host filesystem by Pods.
