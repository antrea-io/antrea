# Antrea API

This document lists all the API resource versions currently or previously
supported by Antrea, along with information related to their deprecation and
removal when appropriate. It is kept up-to-date as we evolve the Antrea API.

Starting with the v1.0 release, we decided to group all the Custom Resource
Definitions (CRDs) defined by Antrea in a single API group, `crd.antrea.io`,
instead of grouping CRDs logically in different API groups based on their
purposes. The rationale for this change was to avoid proliferation of API
groups. As a result, all resources in the `crd.antrea.io` are versioned
individually, while before the v1.0 release, we used to have a single version
number for all the CRDs in a given group: when introducing a new version of the
API group, we would "move" all CRDs from the earlier version to the new version
together. This explains why the tables below are presented differently for
`crd.antrea.io` and for other API groups.

For information about the Antrea API versioning policy, please refer to this
[document](versioning.md).

## Currently-supported

### CRDs in `crd.antrea.io`

These are the CRDs currently available in `crd.antrea.io`.

| CRD | CRD version | Introduced in | Deprecated in / Planned Deprecation | Planned Removal |
|---|---|---|---|---|
| `AntreaAgentInfo` | v1beta1 | v1.0.0 | N/A | N/A |
| `AntreaControllerInfo` | v1beta1 | v1.0.0 | N/A | N/A |
| `ClusterGroup` | v1alpha3 | v1.1.0 | v1.13.0 | N/A |
| `ClusterGroup` | v1beta1 | v1.13.0 | N/A | N/A |
| `ClusterNetworkPolicy` | v1alpha1 | v1.0.0 | v1.13.0 | N/A |
| `ClusterNetworkPolicy` | v1beta1 | v1.13.0 | N/A | N/A |
| `Egress` | v1alpha2 | v1.0.0 | N/A | N/A |
| `Egress` | v1beta1 | v1.13.0 | N/A | N/A |
| `ExternalEntity` | v1alpha2 | v1.0.0 | N/A | N/A |
| `ExternalIPPool` | v1alpha2 | v1.2.0 | v1.13.0 | N/A |
| `ExternalIPPool` | v1beta1 | v1.13.0 | N/A | N/A |
| `ExternalNode`   | v1alpha1 | v1.8.0 | N/A | N/A |
| `IPPool`| v1alpha2 | v1.4.0 | N/A | N/A |
| `Group` | v1alpha3 | v1.8.0 | v1.13.0 | N/A |
| `Group` | v1beta1 | v1.13.0 | N/A | N/A |
| `NetworkPolicy` | v1alpha1 | v1.0.0 | v1.13.0 | N/A |
| `NetworkPolicy` | v1beta1 | v1.13.0 | N/A | N/A |
| `SupportBundleCollection` | v1alpha1 | v1.10.0 | N/A | N/A |
| `Tier` | v1alpha1 | v1.0.0 | v1.13.0 | v2.0.0 |
| `Tier` | v1beta1 | v1.13.0 | N/A | N/A |
| `Traceflow` | v1alpha1 | v1.0.0 | v1.13.0 | N/A |
| `Traceflow` | v1beta1 | v1.13.0 | N/A | N/A |

### Other API groups

These are the API group versions which are currently available when using Antrea.

| API group | API version | API Service? | Introduced in | Deprecated in / Planned Deprecation | Planned Removal |
|---|---|---|---|---|---|
| `controlplane.antrea.io` | `v1beta2` | Yes | v1.0.0 | N/A | N/A |
| `stats.antrea.io` | `v1alpha1` | Yes | v1.0.0 | N/A | N/A |
| `system.antrea.io` | `v1beta1` | Yes | v1.0.0 | N/A | N/A |

## Previously-supported

### Previously-supported API groups

| API group | API version | API Service? | Introduced in | Deprecated in | Removed in |
|---|---|---|---|---|---|
| `core.antrea.tanzu.vmware.com` | `v1alpha1` | No | v0.8.0 | v0.11.0 | v0.11.0 |
| `networking.antrea.tanzu.vmware.com` | `v1beta1` | Yes | v0.3.0 | v0.10.0 | v1.2.0 |
| `controlplane.antrea.tanzu.vmware.com` | `v1beta1` | Yes | v0.10.0 | v0.11.0 | v1.3.0 |
| `clusterinformation.antrea.tanzu.vmware.com` | `v1beta1` | No | v0.3.0 | v1.0.0 | v1.6.0 |
| `core.antrea.tanzu.vmware.com` | `v1alpha2` | No | v0.11.0 | v1.0.0 | v1.6.0 |
| `controlplane.antrea.tanzu.vmware.com` | `v1beta2` | Yes | v0.11.0 | v1.0.0 | v1.6.0 |
| `ops.antrea.tanzu.vmware.com` | `v1alpha1` | No | v0.8.0 | v1.0.0 | v1.6.0 |
| `security.antrea.tanzu.vmware.com` | `v1alpha1` | No | v0.8.0 | v1.0.0 | v1.6.0 |
| `stats.antrea.tanzu.vmware.com` | `v1alpha1` | Yes | v0.10.0 | v1.0.0 | v1.6.0 |
| `system.antrea.tanzu.vmware.com` | `v1beta1` | Yes | v0.5.0 | v1.0.0 | v1.6.0 |

### Previously-supported CRDs

| CRD | CRD version | Introduced in | Deprecated in | Removed in |
|---|---|---|---|---|
| `ClusterGroup` | v1alpha2 | v1.0.0 | v1.1.0 | v2.0.0 |
