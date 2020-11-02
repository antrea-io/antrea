# Antrea API

This document lists all the API group versions currently or previously supported
by Antrea, along with information related to their deprecation and removal when
appropriate. it is kept up-to-date as we evolve the Antrea API.

For information about the Antrea API versioning policy, please refer to this
[document](versioning.md).

## Currently-supported

These are the API group versions which are curently available when using Antrea.

| API group | API version | API Service? | Introduced in | Deprecated in / Planned Deprecation | Planned Removal |
|---|---|---|---|---|---|
| `clusterinformation.antrea.tanzu.vmware.com` | `v1beta1` | No | v0.3.0 | N/A | N/A |
| `core.antrea.tanzu.vmware.com` | `v1alpha2` | No | v0.11.0 | N/A | N/A |
| `controlplane.antrea.tanzu.vmware.com` | `v1beta1` | Yes | v0.10.0 | v0.11.0 | Aug 2021 |
| `controlplane.antrea.tanzu.vmware.com` | `v1beta2` | Yes | v0.11.0 | N/A | N/A |
| `networking.antrea.tanzu.vmware.com` | `v1beta1` | Yes | v0.3.0 | v0.10.0 | Jun 2021 |
| `ops.antrea.tanzu.vmware.com` | `v1alpha1` | No | v0.8.0 | N/A | N/A |
| `security.antrea.tanzu.vmware.com` | `v1alpha1` | No | v0.8.0 | N/A | N/A |
| `stats.antrea.tanzu.vmware.com` | `v1alpha1` | Yes | v0.10.0 | N/A | N/A |
| `system.antrea.tanzu.vmware.com` | `v1beta1` | Yes | v0.5.0 | N/A | N/A |

## Previously-supported

| API group | API version | API Service? | Introduced in | Deprecated in | Removed in |
|---|---|---|---|---|---|
| `core.antrea.tanzu.vmware.com` | `v1alpha1` | No | v0.8.0 | v0.11.0 | v0.11.0 |
