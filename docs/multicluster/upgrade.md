# Antrea Multi-cluster Upgrade Guide

The Antrea Multi-cluster feature is introduced from v1.5.0. There is no data-plane
related changes from release v1.5.0, so Antrea deployment and Antrea Multi-cluster
deployment are indenpendent. However, we suggest to keep Antrea and Antrea Multi-cluster
in the same version considering there will be data-plane change involved in the future.
Please refer to [Antrea upgrade and supported version skew](../versioning.md#antrea-upgrade-and-supported-version-skew)
to learn the requirement of Antrea upgrade. This doc focuses on Multi-cluster deployment only.

The goal is to support 'graceful' upgrade. Multi-cluster upgrade will not have disruption
to data-plane of member clusters, but there can be downtime of processing new configurations
when individual components restart:

- During Leader Controller restart, new member cluster, ClusterSet, ClusterClaim or
  ResourceExport will not be processed. This is because the Controller also runs the validation
  webhooks for MemberClusterAnnounce, ClusterSet, ClusterClaim and ResourceExport.
- During Member Controller restart, new ClusterSet or ClusterClaim will not be processed.
  This is because the Controller runs the validation webhooks for ClusterSet and ClusterClaim.

Our goal is to support version skew for different Antrea Multi-cluster components, but the
Multi-cluster feature is still in Alpha version, and the API is not stable yet. Our recommendation
is always to upgrade Antrea Multi-cluster to the same version for a ClusterSet.

- **Antrea Leader Controller**: must be upgraded first
- **Antrea Member Controller**: must the same version as the **Antrea Leader Controller**.
- **Antctl**: must not be newer than the **Antrea Leader/Member Controller**. Please
  notice Antctl for Multi-cluster is added since v1.6.0.

## Upgrade in one ClusterSet

In one ClusterSet, We recommend all member and leader clusters deployed with the same version.
During Leader controller upgrade, resource export/import between member clusters is not
supported. Before all member clusters are upgraded to the same version as Leader controller,
the feature introduced in old version should still work cross clusters, but no guarantee
for the feature in new version.

It should have no impact during upgrade to those imported resources like Service, Endpoints
or AntreaClusterNetworkPolicy.

## APIs deprecation policy

The Antrea Multi-cluster APIs are built using K8s CustomResourceDefinitions and we
follow the same versioning scheme as the K8s APIs and the same [deprecation policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/).

Other than the most recent API versions in each track, older API versions must be
supported after their announced deprecation for a duration of no less than:

- GA: 12 months
- Beta: 9 months
- Alpha: N/A (can be removed immediately)

K8s has a [moratorium](https://github.com/kubernetes/kubernetes/issues/52185) on the
removal ofAPI object versions that have been persisted to storage. We adopt the following
rules for the CustomResources which are persisted by the K8s apiserver.

- Alpha API versions may be removed at any time.
- The [`deprecated` field](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#version-deprecation) must be used for CRDs to indicate that a particular version of
  the resource has been deprecated.
- Beta and GA API versions must be supported after deprecation for the respective
  durations stipulated above before they can be removed.
- For deprecated Beta and GA API versions, a [conversion webhook](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion) must be provided along with
  each Antrea release, until the API version is removed altogether.

## Supported K8s versions

Please refer to [Supported K8s versions](../versioning.md#supported-k8s-versions)
to learn the details.

## Feature list

Following is the Antrea Multi-cluster feature list. For the details of each feature,
please refer to [Antrea Multi-cluster Architecture](./architecture.md).

| Feature                          | Supported in |
| -------------------------------- | ------------ |
| Service Export/Import            | v1.5.0       |
| ClusterNetworkPolicy Replication | v1.6.0       |

## Known Issues

When you are trying to directly apply a newer Antrea Multi-cluster YAML manifest, as
provided with [an Antrea release](https://github.com/antrea-io/antrea/releases), you will
probably meet an issue like below if you are upgrading Multi-cluster components
from v1.5.0 to a newer one:

```log
label issue:The Deployment "antrea-mc-controller" is invalid: spec.selector: Invalid value: v1.LabelSelector{MatchLabels:map[string]string{"app":"antrea", "component":"antrea-mc-controller"}, MatchExpressions:[]v1.LabelSelectorRequirement(nil)}: field is immutable
```

The issue is caused by the label change introduced by [PR3266](https://github.com/antrea-io/antrea/pull/3266).
The reason is mutation of label selectors on Deployments is not allowed in `apps/v1beta2`
and forward. You need to delete the Deployment "antrea-mc-controller" first, then run
`kubectl apply -f` with the manifest of the newer version.
