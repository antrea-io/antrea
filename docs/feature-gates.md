# Antrea Feature Gates

This page contains an overview of the various features an administrator can turn
on or off for Antrea components. We follow the same convention as the
[Kubernetes feature
gates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/).

In particular:
 * a feature in the Alpha stage will be disabled by default but can be enabled
 by editing the appropriate `.conf` entry in the Antrea manifest.
 * a feature in the Beta stage will be enabled by default but can be disabled
 by editing the appropriate `.conf` entry in the Antrea manifest.
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
    # Enable antrea proxy which provides ServiceLB for in-cluster services in antrea agent.
    # It should be enabled on Windows, otherwise NetworkPolicy will not take effect on
    # Service traffic.
      AntreaProxy: true
```

## List of Available Features

| Feature Name            | Component          | Default | Stage | Alpha Release | Beta Release | GA Release | Extra Requirements | Notes |
| ----------------------- | ------------------ | ------- | ----- | ------------- | ------------ | ---------- | ------------------ | ----- |
| `AntreaProxy`           | Agent              | `false` | Alpha | v0.8.0        | N/A          | N/A        | Yes                | Must be enabled for Windows. |
| `ClusterNetworkPolicy`  | Controller         | `false` | Alpha | v0.8.0        | N/A          | N/A        | No                 |       |
| `Traceflow`             | Agent + Controller | `false` | Alpha | v0.8.0        | N/A          | N/A        | Yes                |       |

## Description and Requirements of Features

### AntreaProxy

`AntreaProxy` implements Service load-balancing for ClusterIP Services as part
of the OVS pipeline, as opposed to relying on kube-proxy. This only applies to
traffic originating from Pods, and destined to ClusterIP Services. In
particular, it does not apply to NodePort Services.

Note that this feature must be enabled for Windows. The Antrea Windows YAML
manifest provided as part of releases enables this feature by default. If you
edit the manifest, make sure you do not disable it, as it is needed for correct
NetworkPolicy implementation for Pod-to-Service traffic.

#### Requirements for this Feature

When using the OVS built-in kernel module (which is the most common case), your
kernel version must be >= 4.6 (as opposed to >= 4.4 without this feature).

### ClusterNetworkPolicy

`ClusterNetworkPolicy` is an Antrea-specific extension to K8s NetworkPolicies,
which enables cluster admins to define security policies which apply to the
entire cluster. Refer to this [document](network-policy.md) for more
information.

#### Requirements for this Feature

None

### Traceflow

`Traceflow` enables a CRD API for Antrea that supports generating tracing
requests for traffic going through the Antrea-managed Pod network. This is
useful for troubleshooting connectivity issues, e.g. determining if a
NetworkPolicy is responsible for traffic drops between two Pods.

We are currently working on adding documentation for this feature.

#### Requirements for this Feature

This feature can only be used in "encap" mode when the Geneve tunnel type is
being used. Note that this is the default configuration for both Linux and
Windows.
