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
| `NodePortLocal`         | Agent              | `true`  | Beta  | v0.13         | v1.4         | N/A        | Yes                | Important user-facing change in v1.2.0 |
| `Egress`                | Agent + Controller | `false` | Alpha | v1.0          | N/A          | N/A        | Yes                |       |
| `NodeIPAM`              | Controller         | `false` | Alpha | v1.4          | N/A          | N/A        | Yes                |       |
| `AntreaIPAM`            | Agent + Controller | `false` | Alpha | v1.4          | N/A          | N/A        | Yes                |       |
| `Multicast`             | Agent              | `false` | Alpha | v1.5          | N/A          | N/A        | Yes                |       |
| `SecondaryNetwork`      | Agent              | `false` | Alpha | v1.5          | N/A          | N/A        | Yes                |       |
| `ServiceExternalIP`     | Agent + Controller | `false` | Alpha | v1.5          | N/A          | N/A        | Yes                |       |

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

# List per-rule statistics for Antrea ClusterNetworkPolicy cluster-access-dns.
# Both Antrea NetworkPolicy and Antrea ClusterNetworkPolicy support per-rule statistics.
> kubectl get antreaclusternetworkpolicystats cluster-access-dns -o json
{
    "apiVersion": "stats.antrea.io/v1alpha1",
    "kind": "AntreaClusterNetworkPolicyStats",
    "metadata": {
        "creationTimestamp": "2022-02-24T09:04:53Z",
        "name": "cluster-access-dns",
        "uid": "940cf76a-d836-4e76-b773-d275370b9328"
    },
    "ruleTrafficStats": [
        {
            "name": "rule1",
            "trafficStats": {
                "bytes": 392,
                "packets": 4,
                "sessions": 1
            }
        },
        {
            "name": "rule2",
            "trafficStats": {
                "bytes": 111,
                "packets": 2,
                "sessions": 1
            }
        }
    ],
    "trafficStats": {
        "bytes": 503,
        "packets": 6,
        "sessions": 2
    }
}
```

#### Requirements for this Feature

None

### NodePortLocal

`NodePortLocal` (NPL) is a feature that runs as part of the Antrea Agent,
through which each port of a Service backend Pod can be reached from the
external network using a port of the Node on which the Pod is running. NPL
enables better integration with external Load Balancers which can take advantage
of the feature: instead of relying on NodePort Services implemented by
kube-proxy, external Load-Balancers can consume NPL port mappings published by
the Antrea Agent (as K8s Pod annotations) and load-balance Service traffic
directly to backend Pods.
Refer to this [document](node-port-local.md) for more information.

#### Requirements for this Feature

This feature is currently only supported for Nodes running Linux with IPv4
addresses. Only TCP & UDP Service ports are supported (not SCTP).

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

### NodeIPAM

`NodeIPAM` runs a Node IPAM Controller similar to the one in Kubernetes that
allocates Pod CIDRs for Nodes.  Running Node IPAM Controller with Antrea is
useful in environments where Kubernetes Controller Manager does not run the
Node IPAM Controller, and Antrea has to handle the CIDR allocation.

#### Requirements for this Feature

This feature requires the Node IPAM Controller to be disabled in Kubernetes
Controller Manager. When Antrea and Kubernetes both run Node IPAM Controller
there is a risk of conflicts in CIDR allocation between the two.

### AntreaIPAM

`AntreaIPAM` feature allows flexible control over Pod IP addressing. This can be
achieved by configuring `IPPool` CRD with a desired set of IP ranges and VLANs. The
`IPPool` can be annotated to Namespace, Pod and PodTemplate of StatefulSet/Deployment.
Antrea will manage IP address assignment for corresponding Pods according to `IPPool`
spec. Refer to this [document](antrea-ipam.md) for more information.

#### Requirements for this Feature

As of now, this feature is supported on Linux Nodes, with IPv4, `system` OVS datapath
type, and `noEncap`, `noSNAT` traffic mode.

The IPs in the `IPPools` without VLAN must be in the same underlay subnet as the Node
IP, because inter-Node traffic of AntreaIPAM Pods is forwarded by the Node network.
`IPPools` with VLAN must not overlap with other network subnets, and the underlay network
router should provide the network connectivity for these VLANs. Only a single IP pool can
be included in the Namespace annotation. In the future, annotation of up to two pools for
IPv4 and IPv6 respectively will be supported.

### Multicast

The `Multicast` feature enables forwarding multicast traffic within the cluster
network (i.e., between Pods) and between the external network and the cluster
network.

More documentation will be coming in the future.

#### Requirements for this Feature

This feature is only supported:

* on Linux Nodes
* for IPv4 traffic
* in `noEncap` mode

### SecondaryNetwork

The `SecondaryNetwork` feature enables support for provisioning secondary
network interfaces for Pods, by annotating them appropriately.

More documentation will be coming in the future.

#### Requirements for this Feature

At the moment, Antrea can only create secondary network interfaces using SR-IOV
VFs on baremetal Linux Nodes.

### ServiceExternalIP

The `ServiceExternalIP` feature enables a controller which can allocate external
IPs for Services with type `LoadBalancer`. External IPs are allocated from an
`ExternalIPPool` resource and each IP gets assigned to a Node selected by the
`nodeSelector` of the pool automatically. That Node will receive Service traffic
destined to that IP and distribute it among the backend Endpoints for the
Service (through kube-proxy). To enable external IP allocation for a
`LoadBalancer` Service, you need to annotate the Service with
`"service.antrea.io/external-ip-pool": "<externalIPPool name>"` and define the
appropriate `ExternalIPPool` resource.

More documentation will be coming in the future.

#### Requirements for this Feature

This feature is currently only supported for Nodes running Linux. At the moment,
it only works with kube-proxy and it requires Antrea ProxyAll to be disabled
(which is the default Antrea configuration).
