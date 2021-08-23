# Antrea Feature Gates

This page contains an overview of the various features an administrator can turn
on or off for Antrea components. We follow the same convention as the
[Kubernetes feature
gates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/).

In particular:

* a feature in the Alpha stage will be disabled by default but can be enabled by
  editing the appropriate `.conf` entry in the Antrea manifest.
* a feature in the Beta stage will be enabled by default but can be disabled by
  editing the appropriate `.conf` entry in the Antrea manifest.
* a feature in the GA stage will be enabled by default and cannot be disabled.

Some features are specific to the Agent, others are specific to the Controller,
and some apply to both and should be enabled / disabled consistently in both
`.conf` entries.

To enable / disable a feature, edit the Antrea manifest appropriately. For
example, to enable `AntreaProxy` on Linux, edit the Agent configuration in the
`antrea` ConfigMap as follows:

```yaml
  antrea-agent.conf: |
    # FeatureGates is a map of feature names to bools that enable or disable experimental features.
    featureGates:
    # Enable antrea proxy which provides ServiceLB for in-cluster Services in antrea agent.
    # It should be enabled on Windows, otherwise NetworkPolicy will not take effect on
    # Service traffic.
      AntreaProxy: true
```

## List of Available Features

| Feature Name            | Component          | Default | Stage | Alpha Release | Beta Release | GA Release | Extra Requirements | Notes |
| ----------------------- | ------------------ | ------- | ----- | ------------- | ------------ | ---------- | ------------------ | ----- |
| `AntreaProxy`           | Agent              | `true`  | Beta  | v0.8          | v0.11        | N/A        | Yes                | Must be enabled for Windows. |
| `EndpointSlice`         | Agent              | `false` | Alpha | v0.13.0       | N/A          | N/A        | Yes                |       |
| `AntreaPolicy`          | Agent + Controller | `true`  | Beta  | v0.8          | v1.0         | N/A        | No                 | Agent side config required from v0.9.0+. |
| `Traceflow`             | Agent + Controller | `true`  | Beta  | v0.8          | v0.11        | N/A        | Yes                |       |
| `FlowExporter`          | Agent              | `false` | Alpha | v0.9          | N/A          | N/A        | Yes                |       |
| `NetworkPolicyStats`    | Agent + Controller | `true`  | Beta  | v0.10         | v1.2         | N/A        | No                 |       |
| `NodePortLocal`         | Agent              | `false` | Alpha | v0.13         | N/A          | N/A        | Yes                | Important user-facing change in v1.2.0 |
| `Egress`                | Agent + Controller | `false` | Alpha | v1.0          | N/A          | N/A        | Yes                |       |

## Description and Requirements of Features

### AntreaProxy

`AntreaProxy` implements Service load-balancing for ClusterIP Services as part
of the OVS pipeline, as opposed to relying on kube-proxy. This only applies to
traffic originating from Pods, and destined to ClusterIP Services. In
particular, it does not apply to NodePort Services. Please note that due to
some restrictions on the implementation of Services in Antrea, the maximum
number of Endpoints that Antrea can support at the moment is 800. If the
number of Endpoints for a given Service exceeds 800, extra Endpoints will
be dropped.

Note that this feature must be enabled for Windows. The Antrea Windows YAML
manifest provided as part of releases enables this feature by default. If you
edit the manifest, make sure you do not disable it, as it is needed for correct
NetworkPolicy implementation for Pod-to-Service traffic.

### EndpointSlice

`EndpointSlice` enables Service EndpointSlice support in AntreaProxy. The
EndpointSlice API was introduced in Kubernetes 1.16 (alpha) and it is enabled
by default in Kubernetes 1.17 (beta). The EndpointSlice feature gate will take no
effect if AntreaProxy is not enabled. The endpoint conditions of `Serving` and
`Terminating` are not supported currently. ServiceTopology is not supported either.
Refer to this [link](https://kubernetes.io/docs/tasks/administer-cluster/enabling-endpointslices/)
for more information. The EndpointSlice API version that AntreaProxy supports is v1beta1
currently, and other EndpointSlice API versions are not supported. If EndpointSlice is
enabled in AntreaProxy, but EndpointSlice API is disabled in Kubernetes or EndpointSlice
API version v1beta1 is not supported in Kubernetes, Antrea Agent will log an error message
and will not implement Cluster IP functionality as expected.

#### Requirements for this Feature

When using the OVS built-in kernel module (which is the most common case), your
kernel version must be >= 4.6 (as opposed to >= 4.4 without this feature).

### AntreaPolicy

`AntreaPolicy` enables Antrea ClusterNetworkPolicy and Antrea NetworkPolicy CRDs to be
handled by Antrea controller. `ClusterNetworkPolicy` is an Antrea-specific extension to K8s
NetworkPolicies, which enables cluster admins to define security policies which
apply to the entire cluster. `Antrea NetworkPolicy` also complements K8s NetworkPolicies
by supporting policy priorities and rule actions.
Refer to this [document](antrea-network-policy.md) for more information.

#### Requirements for this Feature

None

### Traceflow

`Traceflow` enables a CRD API for Antrea that supports generating tracing
requests for traffic going through the Antrea-managed Pod network. This is
useful for troubleshooting connectivity issues, e.g. determining if a
NetworkPolicy is responsible for traffic drops between two Pods. Refer to
this [document](traceflow-guide.md) for more information.

#### Requirements for this Feature

Until Antrea v0.11, this feature could only be used in "encap" mode, with the
Geneve tunnel type (default configuration for both Linux and Windows). In v0.11,
this feature was graduated to Beta (enabled by default) and this requirement was
lifted.

In order to support cluster Services as the destination for tracing requests,
`AntreaProxy` should be enabled, which is the default starting with Antrea
v0.11.

### Flow Exporter

`Flow Exporter` is a feature that runs as part of the Antrea Agent, and enables
network flow visibility into a Kubernetes cluster. Flow exporter sends
IPFIX flow records that are built from observed connections in Conntrack module
to a flow collector. Refer to this [document](network-flow-visibility.md) for more information.

#### Requirements for this Feature

This feature is currently only supported for Nodes running Linux.
Windows support will be added in the future.

### NetworkPolicyStats

`NetworkPolicyStats` enables collecting NetworkPolicy statistics from
antrea-agents and exposing them through Antrea Stats API, which can be accessed
by kubectl get commands, e.g. `kubectl get networkpolicystats`. The statistical
data includes total number of sessions, packets, and bytes allowed or denied by
a NetworkPolicy. It is collected asynchronously so there may be a delay of up to
1 minute for changes to be reflected in API responses. The feature supports K8s
NetworkPolicies and Antrea native policies, the latter of which requires
`AntreaPolicy` to be enabled. Usage examples:

```bash
# List stats of all K8s NetworkPolicies.
> kubectl get networkpolicystats -A
NAMESPACE     NAME                  SESSIONS   PACKETS   BYTES   CREATED AT
default       access-nginx          3          36        5199    2020-09-07T13:19:38Z
kube-system   access-dns            1          12        1221    2020-09-07T13:22:42Z

# List stats of all Antrea ClusterNetworkPolicies.
> kubectl get antreaclusternetworkpolicystats
NAME                  SESSIONS   PACKETS   BYTES   CREATED AT
cluster-deny-egress   3          36        5199    2020-09-07T13:19:38Z
cluster-access-dns    10         120       12210   2020-09-07T13:22:42Z

# List stats of all Antrea NetworkPolicies.
> kubectl get antreanetworkpolicystats -A
NAMESPACE     NAME                  SESSIONS   PACKETS   BYTES   CREATED AT
default       access-http           3          36        5199    2020-09-07T13:19:38Z
foo           bar                   1          12        1221    2020-09-07T13:22:42Z
```

#### Requirements for this Feature

None

### NodePortLocal

`NodePortLocal` (NPL) is a feature that runs as part of the Antrea Agent,
through which each port of a Pod can be reached from external network using a
port in the Node on which the Pod is running. In addition to enabling the
NodePortLocal feature gate, the value of `nplPortRange` can be set in the Antrea
Agent configuration through the ConfigMap. Ports from a Node will be allocated
from the range of ports specified in `nplPortRange`. If the value of
`nplPortRange` is not specified, the range `61000-62000` will be used by
default.

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

#### NodePortLocal pre Antrea v1.2

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

#### Requirements for this Feature

This feature is currently only supported for Nodes running Linux with IPv4
addresses. Only TCP Service ports are supported.

### Egress

`Egress` enables a CRD API for Antrea that supports specifying which egress
(SNAT) IP the traffic from the selected Pods to the external network should use.
When a selected Pod accesses the external network, the egress traffic will be
tunneled to the Node that hosts the egress IP if it's different from the Node
that the Pod runs on and will be SNATed to the egress IP when leaving that Node.
Refer to this [document](egress.md) for more information.

#### Requirements for this Feature

This feature is currently only supported for Nodes running Linux and "encap"
mode. The support for Windows and other traffic modes will be added in the
future.
