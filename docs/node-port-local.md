# NodePortLocal (NPL)

## Table of Contents

<!-- toc -->
- [What is NodePortLocal?](#what-is-nodeportlocal)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Usage pre Antrea v1.2](#usage-pre-antrea-v12)
- [Limitations](#limitations)
<!-- /toc -->

## What is NodePortLocal?

`NodePortLocal` (NPL) is a feature that runs as part of the Antrea Agent,
through which each port of a Service backend Pod can be reached from the
external network using a port of the Node on which the Pod is running. NPL
enables better integration with external Load Balancers which can take advantage
of the feature: instead of relying on NodePort Services implemented by
kube-proxy, external Load-Balancers can consume NPL port mappings published by
the Antrea Agent (as K8s Pod annotations) and load-balance Service traffic
directly to backend Pods.

## Prerequisites

NodePortLocal was introduced in v0.13 as an alpha feature, and was graduated to
beta in v1.4, at which time it was enabled by default. Prior to v1.4, a feature
gate, `NodePortLocal`, must be enabled on the antrea-agent for the feature to
work.

## Usage

In addition to enabling the NodePortLocal feature gate (if needed), the value of
`nplPortRange` can be set in the Antrea Agent configuration through the
ConfigMap. Ports from a Node will be allocated from the range of ports specified
in `nplPortRange`. If the value of `nplPortRange` is not specified, the range
`61000-62000` will be used by default.

Pods can be selected for `NodePortLocal` by tagging a Service with annotation:
`nodeportlocal.antrea.io/enabled: "true"`. Consequently, `NodePortLocal` is
enabled for all the Pods which are selected by the Service through a selector,
and the ports of these Pods will be reachable through Node ports allocated from
the `nplPortRange`. The selected Pods will be annotated with the details about
allocated Node port(s) for the Pod.

For example, given the following Service and Deployment definitions:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    nodeportlocal.antrea.io/enabled: "true"
spec:
  ports:
  - name: web
    port: 80
    protocol: TCP
    targetPort: 80
  selector:
    app: nginx
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 3
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
```

If the NodePortLocal feature gate is enabled, then all the Pods in the
Deployment will be annotated with the `nodeportlocal.antrea.io` annotation. The
value of this annotation is a serialized JSON array. In our example, a given Pod
in the `nginx` Deployment may look like this:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-6799fc88d8-9rx8z
  labels:
    app: nginx
  annotations:
    nodeportlocal.antrea.io: '[{"podPort":8080,"nodeIP":"10.10.10.10","nodePort":61002}]'
...
```

This annotation indicates that port 8080 of the Pod can be reached through port
61002 of the Node with IP Address 10.10.10.10.

### Usage pre Antrea v1.2

Prior to the Antrea v1.2 minor release, the NodePortLocal feature suffered from
a known [issue](https://github.com/antrea-io/antrea/issues/1912). In order to
use the feature, the correct list of ports exposed by each container had to be
provided in the Pod specification (`.spec.containers[*].Ports`). The
NodePortLocal implementation would then use this information to decide which
ports to map for each Pod. In the above example, the Deployment definition would
need to be changed to:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 3
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
```

This was error-prone because providing this list of ports is typically optional
in K8s and omitting it does not prevent ports from being exposed, which means
that many user may omit this information and expect NPL to work. Starting with
Antrea v1.2, we instead rely on the `service.spec.ports[*].targetPort`
information, for each NPL-enabled Service, to determine which ports need to be
mapped.

## Limitations

This feature is currently only supported for Nodes running Linux with IPv4
addresses. Only TCP & UDP Service ports are supported (not SCTP).
