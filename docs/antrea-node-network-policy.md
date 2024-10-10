# Antrea Node NetworkPolicy

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Logs](#logs)
- [Limitations](#limitations)
<!-- /toc -->

## Introduction

Node NetworkPolicy is designed to secure the Kubernetes Nodes traffic. It is supported by Antrea starting with Antrea
v1.15. This guide demonstrates how to configure Node NetworkPolicy.

## Prerequisites

Node NetworkPolicy was introduced in v1.15 as an alpha feature and is disabled by default. A feature gate,
`NodeNetworkPolicy`, must be enabled in antrea-agent.conf in the `antrea-config` ConfigMap.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      NodeNetworkPolicy: true
```

Alternatively, you can use the following helm installation command to enable the feature gate:

```bash
helm install antrea antrea/antrea --namespace kube-system --set featureGates.NodeNetworkPolicy=true
```

## Usage

Node NetworkPolicy is an extension of Antrea ClusterNetworkPolicy (ACNP). By specifying a `nodeSelector` in the
policy-level `appliedTo` without other selectors, an ACNP is applied to the selected Kubernetes Nodes.

An example Node NetworkPolicy applied to Nodes with label `kubernetes.io/hostname: k8s-node-control-plane`, selectively
blocking all incoming traffic to port 80 on the Nodes, except for traffic originating from CIDR `10.10.0.0/16`.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: restrict-http-to-node
spec:
  priority: 5
  tier: application
  appliedTo:
    - nodeSelector:
        matchLabels:
          kubernetes.io/hostname: k8s-node-control-plane
  ingress:
    - name: allow-cidr
      action: Allow
      from:
        - ipBlock:
            cidr: 10.10.0.0/16
      ports:
        - protocol: TCP
          port: 80
      enableLogging: true
      logLabel: allow-http
    - name: drop-other
      action: Drop
      ports:
        - protocol: TCP
          port: 80
      enableLogging: true
      logLabel: default-drop-others
```

An example Node NetworkPolicy that blocks egress traffic from Nodes with label
`kubernetes.io/hostname: k8s-node-control-plane` to Nodes with label `kubernetes.io/hostname: k8s-node-worker-1`
and some IP blocks:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: egress-drop-node-to-node
spec:
  priority: 5
  tier: application
  appliedTo:
    - nodeSelector:
        matchLabels:
          kubernetes.io/hostname: k8s-node-control-plane
  egress:
    - name: drop-22
      action: Drop
      to:
        - nodeSelector:
            matchLabels:
              kubernetes.io/hostname: k8s-node-worker-1
        - ipBlock:
            cidr: 192.168.77.0/24
        - ipBlock:
            cidr: 10.10.0.0/24
      ports:
        - protocol: TCP
          port: 22
```

## Logs

The `enableLogging` and `logLabel` options provide limited support for Node NetworkPolicies. Since Node NetworkPolicies
are implemented using iptables, enabling `enableLogging` causes the Linux kernel to log information about all matching
packets via the kernel log. However, Antrea cannot process these logs directly. Instead, these logs can be accessed
through syslog, allowing you to filter and direct them to specific files using syslog syntax.

By default, `enableLogging` is unsupported in KinD clusters. To enable it, set the host’s
`/proc/sys/net/netfilter/nf_log_all_netns` to 1. Antrea uses the iptables `LOG` target to log packet information,
but by default, `/proc/sys/net/netfilter/nf_log_all_netns` is 0, preventing containers from logging to the kernel to
avoid clutter. If logging is required, you can enable it by setting the value to 1, but please be cautious to do so
unless you are clear about the impact.

For example, consider the Node NetworkPolicy `restrict-http-to-node` above. It could generate the following logs:

```text
Sep  2 10:31:07 k8s-node-control-plane kernel: [6657320.789675] Antrea:I:Allow:allow-http:IN=ens224 OUT= MAC=00:50:56:a7:fb:18:00:50:56:a7:23:47:08:00 SRC=10.10.0.10 DST=192.168.240.200 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=52813 DF PROTO=TCP SPT=57658 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0
Sep  2 10:31:11 k8s-node-control-plane kernel: [6657324.899219] Antrea:I:Drop:default-drop:IN=ens224 OUT= MAC=00:50:56:a7:fb:18:00:50:56:a7:23:47:08:00 SRC=192.168.240.201 DST=192.168.240.200 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=27486 DF PROTO=TCP SPT=33152 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0
```

In these logs, prefixes like `Antrea:I:Allow:allow-http:` and `Antrea:I:Drop:default-drop:` are added by iptables using
the `--log-prefix` parameter. The iptables log prefix is limited to 29 characters, as described in the
[iptables-extensions manual](https://ipset.netfilter.org/iptables-extensions.man.html).

The log prefix format includes essential information of a Node NetworkPolicy rule, and consists of four parts,
formatted as follows:

```text
|---1--| |2| |---3--| |----------4--------|
|Antrea|:|I|:|Reject|:|user-provided label|:|
|6     |1|1|1|4-6   |1|1-12               |1|
```

- Part 1: Fixed, "Antrea"
- Part 2: Direction, "I" (In) or "O" (Out)
- Part 3: Action, "Allow", "Drop", or "Reject"
- Part 4: User-provided `logLabel`, up to 12 characters

Due to iptables' 29-character prefix limitation, the user-provided `logLabel` is restricted to a maximum of 12 characters.
To manage these logs effectively, you can configure rsyslog on each Node as follows:

```text
# Example rsyslog configuration to filter Antrea logs
:msg, contains, "Antrea:I:Allow:allow-http" /var/log/antrea-node-netpol-allow.log
:msg, contains, "Antrea:I:Drop:default-drop" /var/log/antrea-node-netpol-drop.log
& stop
```

This configuration directs logs with the prefix `Antrea:I:Allow:allow-http` to `/var/log/antrea-node-netpol-allow.log`
and logs with the prefix `Antrea:I:Drop:default-drop` to `/var/log/antrea-node-netpol-drop.log`. The `& stop` command
ensures that these logs are not processed further.

## Limitations

- This feature is currently only supported for Linux Nodes.
- Be cautious when you configure policies to Nodes, in particular, when configuring a default-deny policy applied to
  Nodes. You should ensure Kubernetes and Antrea control-plane communication is exempt from the deny rules, otherwise
  the cluster may go out-of-service and you may lose connectivity to the Nodes.
- Only ACNPs can be applied to Nodes. ANPs cannot be applied to Nodes.
- `nodeSelector` can only be specified in the policy-level `appliedTo` field, not in the rule-level `appliedTo`, and not
  in a `Group` or `ClusterGroup`.
- ACNPs applied to Nodes cannot be applied to Pods at the same time.
- FQDN is not supported for ACNPs applied to Nodes.
- Layer 7 NetworkPolicy is not supported yet.
- For UDP or SCTP, when the `Reject` action is specified in an egress rule, it behaves identical to the `Drop` action.
- Limited support for traffic logging for ACNPs applied to Nodes.
