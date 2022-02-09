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
| `ClusterGroup` | v1alpha2 | v1.0.0 | v1.1.0 | Feb 2022 |
| `ClusterGroup` | v1alpha3 | v1.1.0 | N/A | N/A |
| `ClusterNetworkPolicy` | v1alpha1 | v1.0.0 | N/A | N/A |
| `Egress` | v1alpha2 | v1.0.0 | N/A | N/A |
| `ExternalEntity` | v1alpha2 | v1.0.0 | N/A | N/A |
| `ExternalIPPool` | v1alpha2 | v1.2.0 | N/A | N/A |
| `NetworkPolicy` | v1alpha1 | v1.0.0 | N/A | N/A |
| `Tier` | v1alpha1 | v1.0.0 | N/A | N/A |
| `Traceflow` | v1alpha1 | v1.0.0 | N/A | N/A |

### Other API groups

These are the API group versions which are curently available when using Antrea.

| API group | API version | API Service? | Introduced in | Deprecated in / Planned Deprecation | Planned Removal |
|---|---|---|---|---|---|
| `controlplane.antrea.io` | `v1beta2` | Yes | v1.0.0 | N/A | N/A |
| `stats.antrea.io` | `v1alpha1` | Yes | v1.0.0 | N/A | N/A |
| `system.antrea.io` | `v1beta1` | Yes | v1.0.0 | N/A | N/A |

## Previously-supported

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

## API renaming from `*.antrea.tanzu.vmware.com` to `*.antrea.io`

For the v1.0 release, we undertook to rename all Antrea APIs to use the
`antrea.io` suffix instead of the `antrea.tanzu.vmware.com` suffix. For more
information about the motivations behind this undertaking, please refer to
[Github issue #1715](https://github.com/antrea-io/antrea/issues/1715).

From the v1.6 release, all legacy APIs (ending with the
`antrea.tanzu.vmware.com` suffix) have been completely removed. If you are
running an Antrea version older than v1.0 and you want to upgrade to Antrea v1.6
or greater and migrate your API resources, you will first need to do an
intermediate upgrade to an Antrea version >= v1.0 and <= v1.5. You will then be
able to migrate all your API resources to the new (`*.antrea.io`) API, by
following the steps below. Finally, you will be able to upgrade to your desired
Antrea version (>= v1.6).

As part of the API renaming, and to avoid proliferation of API groups, we have
decided to group all the Custom Resource Definitions (CRDs) defined by Antrea in
a single API group: `crd.antrea.io`.

To avoid disruptions to existing Antrea users, our requirements for this
renaming process were as follows:

1. As per our [upgrade
   policy](versioning.md#antrea-upgrade-and-supported-version-skew), older
   Agents need to be able to communicate with a new upgraded Controller, using
   the old `controlplane.antrea.tanzu.vmware.com` API. Once both the Controller
   and the Agent are upgraded, they communicate using `controlplane.antrea.io`.
2. API Services can be accessed using either API version.
3. After upgrade, Custom Resources can be managed using either API
   version. Resources created using the old API (before or after upgrade) can be
   accessed using the new API (or the old one).
4. For each resource in each API group, the new resource type should be
   backward-compatible with the old resource type, and, whenever possible,
   forward-compatible. This simplifies the upgrade of existing client
   applications which leverage the Antrea API. These applications can be easily
   upgraded to use the new API version, with no change to the business
   logic. Custom Resources created before upgrading the application can be
   accessed through the new API with no loss of information.

To achieve our 3rd goal, we introduced a new Kubernetes controller in the Antrea
Controller, in charge of mirroring "old" Custom Resources (created using the
`*.antrea.tanzu.vmware.com` API groups) to the new (`*.antrea.io`) API. This new
mirroring controller is enabled by default, but can be disabled by setting
`legacyCRDMirroring` to `false` in the `antrea-controller` configuration
options. Thanks to this controller, the Antrea components (Agent and Controller)
only need to watch Custom Resources created with the new API group. If any
client still uses the old (or "legacy") API groups, these Custom Resources will
be mirrored to the new API group and handled as expected.

The mirroring controller behaves as follows:

* If a Custom Resource is created with the legacy API, it will create a new
  Custom Resource with the same `Spec` and `Labels` as the legacy one.
* Any update to the `Spec` and / or `Labels` of the legacy Custom Resource will
  be reflected identically in the new Custom Resource.
* Any update to the `Status` of the new mirrored Custom Resource (assuming it
  has a `Status` field) will be reflected back identically in the legacy Custom
  Resource.
* If the legacy Custom Resource is deleted, the mirrored one will be deleted
  automatically as well.
* Manual updates to new mirrored Custom Resources will be overwritten by the
  controller.
* If a legacy Custom Resource is annotated with `"crd.antrea.io/stop-mirror"`,
  it will then be ignored, and updates to the corresponding new Custom
  Resource will no longer be overwritten.

This gives us the following upgrade sequence for a client application which uses
the legacy Antrea CRDs:

1. Ensure that Antrea has been upgraded in the cluster to a version greater than
   or equal to v1.0, and that legacy CRD mirroring is enabled (this is the case
   by default).

2. Check that all Custom Resources have been mirrored. All the new ones should
   be annotated with `"crd.antrea.io/managed-by":
   "crdmirroring-controller"`. The first command below will display all the
   legacy AntreaNetworkPolicies (ANPs). The second one will display all the ones
   which exist in the new `crd.antrea.io` API group. You can then compare the
   two lists.

   ```bash
   kubectl get lanp.security.antrea.tanzu.vmware.com -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
   kubectl get anp.crd.antrea.io -o jsonpath='{range .items[?(@.metadata.annotations.crd\.antrea\.io/managed-by=="crdmirroring-controller")]}{.metadata.name}{"\n"}{end}'
   ```

3. Stop the old version of the application, which uses the legacy CRDs.

4. Annotate all existing Custom Resources managed by the application with
   `"crd.antrea.io/stop-mirror"`. From now on, the mirroring controller will
   ignore these legacy resources: updates to the legacy resources (including
   deletions) are not applied to the corresponding new resource any more, and
   changes to the new resources are now possible (they will not be overwritten
   by the controller). As an example, the command below will annotate *all* ANPs
   in the current Namespace with `"crd.antrea.io/stop-mirror"`.

   ```bash
   kubectl annotate lanp.security.antrea.tanzu.vmware.com --all crd.antrea.io/stop-mirror=''
   ```

5. Check that none of the new Custom Resources still have the
   `"crd.antrea.io/managed-by": "crdmirroring-controller"` annotation. Running
   the same command as before should return an empty list:

   ```bash
   kubectl get anp.crd.antrea.io -o jsonpath='{range .items[?(@.metadata.annotations.crd\.antrea\.io/managed-by=="crdmirroring-controller")]}{.metadata.name}{"\n"}{end}'
   ```

   If you remove the filter, all your ANPs should still exist:

   ```bash
   kubectl get anp.crd.antrea.io -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
   ```

6. Safely delete all legacy CRDs previously managed by the application. As an
   example, the command below will delete *all* legacy ANPs in the current
   Namespace:

   ```bash
   kubectl delete lanp.security.antrea.tanzu.vmware.com
   ```

   Once again, all new ANPs should still exist, which can be confirmed with:

   ```bash
   kubectl get anp.crd.antrea.io -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
   ```

7. Start the new version of the application, which uses the new CRDs. All
   mirrored Custom Resources should be available for the application to access.

8. At this stage, if all applications have been updated, legacy CRD mirroring
   can be disabled in the Antrea Controller configuration.

Note that for CRDs which are "owned" by Antrea, `AntreaAgentInfo` and
`AntreaControllerInfo`, resources are automatically created by the Antrea
components using both API versions.

### Deleting legacy Kubernetes resources after an upgrade

After a successful upgrade from Antrea < v1.6 to Antrea >= v1.6, you may want to
manually clean up legacy Kubernetes resources which were created by an old
Antrea version but are no longer needed. Note that keeping these resource will
not impact any Antrea functions.

To delete these legacy resources (CRDs and webhooks), run:

```bash
kubectl get crds -o=name --no-headers=true | grep "antrea\.tanzu\.vmware\.com" | xargs  kubectl delete
kubectl get mutatingwebhookconfigurations -o=name --no-headers=true | grep "antrea\.tanzu\.vmware\.com" | xargs  kubectl delete
kubectl get validatingwebhookconfigurations -o=name --no-headers=true | grep "antrea\.tanzu\.vmware\.com" | xargs  kubectl delete
```
