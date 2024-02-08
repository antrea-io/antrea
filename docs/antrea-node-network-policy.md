# Antrea Node NetworkPolicy

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
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
    - name: drop-other
      action: Drop
      ports:
        - protocol: TCP
          port: 80
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
