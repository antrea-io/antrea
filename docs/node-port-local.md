# NodePortLocal (NPL)

## Table of Contents

<!-- toc -->
- [What is NodePortLocal?](#what-is-nodeportlocal)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Usage pre Antrea v1.4](#usage-pre-antrea-v14)
  - [Usage pre Antrea v1.2](#usage-pre-antrea-v12)
- [Limitations](#limitations)
- [Integrations with External Load Balancers](#integrations-with-external-load-balancers)
  - [AVI](#avi)
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

In addition to enabling the NodePortLocal feature gate (if needed), you need to
ensure that the `nodePortLocal.enable` flag is set to true in the Antrea Agent
configuration. The `nodePortLocal.portRange` parameter can also be set to change
the range from which Node ports will be allocated. Otherwise, the default range
of `61000-62000` will be used by default. When using the NodePortLocal feature,
your `antrea-agent` ConfigMap should look like this:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config-dcfb6k2hkm
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      # True by default starting with Antrea v1.4
      # NodePortLocal: true
    nodePortLocal:
      enable: true
      # Uncomment if you need to change the port range.
      # portRange: 61000-62000
```

Pods can be selected for `NodePortLocal` by tagging a Service with annotation:
`nodeportlocal.antrea.io/enabled: "true"`. Consequently, `NodePortLocal` is
enabled for all the Pods which are selected by the Service through a selector,
and the ports of these Pods will be reachable through Node ports allocated from
the port range. The selected Pods will be annotated with the details about
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

NodePortLocal can only be used with Services of type `ClusterIP` or
`LoadBalancer`. The `nodeportlocal.antrea.io` annotation has no effect for
Services of type `NodePort` or `ExternalName`. The annotation also has no effect
for Services with an empty or missing Selector.

### Usage pre Antrea v1.4

Prior to the Antrea v1.4 minor release, the `nodePortLocal` option group in the
Antrea Agent configuration did not exist. To enable the NodePortLocal feature,
one simply needed to enable the feature gate, and the port range could be
configured using the (now deprecated) `nplPortRange` parameter.

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

## Integrations with External Load Balancers

### AVI

When using AVI and the AVI Kubernetes Operator (AKO), the AKO `serviceType`
configuration parameter can be set to `NodePortLocal`. After that, annotating
Services manually with `nodeportlocal.antrea.io` is no longer required. AKO will
automatically annotate Services of type `LoadBalancer`, along with backend
ClusterIP Services used by Ingress resources (for which AVI is the Ingress
class). For more information refer to the [AKO
documentation](https://avinetworks.com/docs/ako/1.5/handling-objects/).
