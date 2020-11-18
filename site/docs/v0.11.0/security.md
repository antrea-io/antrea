# Security Recommendations

This document describes some security recommendations when deploying Antrea in a
cluster, and in particular a [multi-tenancy
cluster](https://cloud.google.com/kubernetes-engine/docs/concepts/multitenancy-overview#what_is_multi-tenancy).

To report a vulnerability in Antrea, please refer to
[SECURITY.md](../SECURITY.md).

For information about securing Antrea control-plane communications, refer to
this [document](securing-control-plane.md).

## Protecting Access to Antrea Configuration Files

Antrea relies on persisting files on each K8s Node's filesystem, in order to
minimize disruptions to network functions across Antrea Agent restarts, in
particular during an upgrade. All these files are located under
`/var/run/antrea/`. The most notable of these files is
`/var/run/antrea/openvswitch/conf.db`, which stores the Open vSwitch
database. Prior to Antrea v0.10, any user had read access to the file on the
host (permissions were set to `0644`). Starting with v0.10, this is no longer
the case (permissions are now set to `0640`).

If a malicious Pod can gain read access to this file, or, prior to Antrea v0.10,
if an attacker can gain access to the host, they can potentially access
sensitive information stored in the database, most notably the Pre-Shared Key
(PSK) used to configure [IPsec tunnels](ipsec-tunnel.md), which is stored in
plaintext in the database. If a PSK is leaked, an attacker can mount a
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
