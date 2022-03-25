# Antrea Multi-cluster API

This document lists all the API resource versions currently supported by Antrea Mulit-cluster.

Antrea Multi-cluster is supported since v1.5.0. Most Custom Resource Definitions (CRDs)
used by Antrea Multi-cluster are in the API group `multicluster.crd.antrea.io`, and
two CRDs from [mcs-api](https://github.com/kubernetes-sigs/mcs-api) are in group `multicluster.x-k8s.io`
which is defined by Kubernetes upstream [KEP-1645](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api).

## CRDs in `multicluster.crd.antrea.io`

| CRD                      | CRD version | Introduced in | Deprecated in / Planned Deprecation | Planned Removal |
| ------------------------ | ----------- | ------------- | ----------------------------------- | --------------- |
| `ClusterClaims`          | v1alpha1    | v1.5.0        | N/A                                 | N/A             |
| `ClusterSets`            | v1alpha1    | v1.5.0        | N/A                                 | N/A             |
| `MemberClusterAnnounces` | v1alpha1    | v1.5.0        | N/A                                 | N/A             |
| `ResourceExports`        | v1alpha1    | v1.5.0        | N/A                                 | N/A             |
| `ResourceImports`        | v1alpha1    | v1.5.0        | N/A                                 | N/A             |

## CRDs in `multicluster.x-k8s.io`

| CRD              | CRD version | Introduced in | Deprecated in / Planned Deprecation | Planned Removal |
| ---------------- | ----------- | ------------- | ----------------------------------- | --------------- |
| `ServiceExports` | v1alpha1    | v1.5.0        | N/A                                 | N/A             |
| `ServiceImports` | v1alpha1    | v1.5.0        | N/A                                 | N/A             |
