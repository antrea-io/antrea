# Antrea Multi-cluster Upgrade Guide

The Antrea Multi-cluster feature is introduced from v1.5.0. There is no data-plane
related changes from release v1.5.0, so Antrea deployment and Antrea Multi-cluster
deployment are independent. However, we suggest to keep Antrea and Antrea Multi-cluster
in the same version considering there will be data-plane change involved in the future.
Please refer to [Antrea upgrade and supported version skew](../versioning.md#antrea-upgrade-and-supported-version-skew)
to learn the requirement of Antrea upgrade. This doc focuses on Multi-cluster deployment only.

The goal is to support 'graceful' upgrade. Multi-cluster upgrade will not have disruption
to data-plane of member clusters, but there can be downtime of processing new configurations
when individual components restart:

- During Leader Controller restart, a new member cluster, ClusterSet or ResourceExport will
  not be processed. This is because the Controller also runs the validation webhooks for
  MemberClusterAnnounce, ClusterSet and ResourceExport.
- During Member Controller restart, a new ClusterSet will not be processed, this is because
  the Controller runs the validation webhooks for ClusterSet.

Our goal is to support version skew for different Antrea Multi-cluster components, but the
Multi-cluster feature is still in Alpha version, and the API is not stable yet. Our recommendation
is always to upgrade Antrea Multi-cluster to the same version for a ClusterSet.

- **Antrea Leader Controller**: must be upgraded first
- **Antrea Member Controller**: must be the same version as the **Antrea Leader Controller**.
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

## Upgrade to v2.7 or later

Starting with v2.7, Antrea Multi-cluster introduces strict identity binding for member clusters.
The `MemberClusterAnnounce` API now enforces that a member cluster's ServiceAccount is explicitly
authorized to announce its `ClusterID`.

**Breaking Changes & Migration Steps:**

Previously, it was possible for all member clusters to use a single shared ServiceAccount
(`antrea-mc-member-access-sa`). This is no longer supported because a ServiceAccount can only be
bound to a single `ClusterID`. Operators must migrate to per-member credentials before upgrading
the leader.

The binding check applies to all operations, including the heartbeat `Update` that
`SendMemberAnnounce` issues every 10 seconds to refresh the `touch-ts` annotation. If a member
cluster is not properly migrated, the leader webhook denies its `MemberClusterAnnounce` on the
first heartbeat after the leader is upgraded. Once `touch-ts` stops refreshing, the stale cleanup
controller deletes the `MemberClusterAnnounce` after 24 hours, which in turn makes
`StaleResCleanupController` delete every `ResourceExport` belonging to that member — breaking
cross-cluster Services and AntreaClusterNetworkPolicies across the whole ClusterSet.
This is why steps 1-3 must be completed for all members before upgrading the leader.

1. **Create Per-Member Credentials**: On the leader cluster, create a ServiceAccount, RoleBinding,
   and token Secret for each member, each annotated with its `ClusterID`. You can do this
   automatically using `antctl`:

   ```bash
   antctl mc create membertoken --cluster-id <cluster-id> <secret-name> -n antrea-multicluster
   ```

   If the ServiceAccount already exists but is bound to a different `ClusterID` (for example to
   correct a mistyped one), `antctl` re-binds it to the `--cluster-id` you provide. The existing
   token Secret then authenticates as the new `ClusterID`, so you should rotate that credential
   if it must not keep that identity.

2. **Apply the Token in Each Member**: Export each new token Secret from the leader and apply it
   in the corresponding member cluster. For example:

   ```bash
   # Extract the Secret created by antctl (replacing <secret-name> with the actual name)
   kubectl get secret <secret-name> -n antrea-multicluster -o yaml | grep -w -e '^apiVersion' -e '^data' -e '^metadata' -e '^ *name:' -e '^kind' -e '  ca.crt' -e '  token:' -e '^type' -e '  namespace' | sed -e 's/kubernetes.io\/service-account-token/Opaque/g' -e 's/antrea-multicluster/kube-system/g' > member-token.yml

   # Apply it to the member cluster
   kubectl apply -f member-token.yml --kubeconfig=/path/to/kubeconfig-of-member-cluster
   ```

3. **Update Member ClusterSets**: In each member cluster, update the `ClusterSet`'s
   `spec.leaders[].secret` field to reference its new token Secret.

4. **Upgrade the Leader**: Only after steps 1-3 are completed for all members should you upgrade
   the leader cluster.

5. **Delete the Shared Credential**: Once every member has been migrated to its own token and is
   reporting connected, delete the shared credential on the leader. This step is **mandatory**:
   the shared credential has no `ClusterID` annotation, so the `ResourceExport` validation webhook
   treats it as fully trusted (see below), and the `MemberClusterAnnounce` binding only bounds -
   but does not close - that bypass once an unmigrated member's announce ages out. Leaving it in
   place keeps a live, webhook-exempt member credential on the leader indefinitely. You can
   verify that a member is connected by checking that its `MemberClusterAnnounce` object is being
   refreshed periodically (every 10 seconds) with a recent `touch-ts` timestamp:

   ```bash
   kubectl get memberclusterannounce -n antrea-multicluster -o custom-columns='NAME:.metadata.name,CLUSTER-ID:.clusterID,LAST-SEEN:.metadata.annotations.touch-ts'
   ```

   Once confirmed, delete the shared credential:

   ```bash
   kubectl delete serviceaccount antrea-mc-member-access-sa -n antrea-multicluster
   kubectl delete rolebinding antrea-mc-member-cluster-rolebinding -n antrea-multicluster
   kubectl delete secret antrea-mc-member-access-token -n antrea-multicluster
   ```

**Removed `--create-token` flag**: The `--create-token` flag has been removed from `antctl mc init`.
Tokens must be created separately using `antctl mc create membertoken`.

**New `ResourceExport` validation webhook**: The leader now validates every
`ResourceExport` write (create/update/delete) from member clusters:

- The webhook allowlists the kinds a member may export: `Service`, `Endpoints`,
  `ClusterInfo` and `LabelIdentity`. The member controllers only ever generate these
  kinds, so this is not a new restriction; `AntreaClusterNetworkPolicy` exports are
  reserved to cluster admins on the leader (see [ClusterNetworkPolicy
  replication](https://github.com/antrea-io/antrea/blob/main/docs/multicluster/user-guide.md#clusternetworkpolicy-replication)).
- Every `ResourceExport` a member writes is bound to that member's identity: the
  `Spec.ClusterID`, the export's source labels and name must all match the member's
  `ClusterID` and the exported resource's metadata, and a member can only modify or
  delete its own exports. The member controllers set all these fields automatically, so
  no manual action is needed beyond steps 1-3.
- The `MemberClusterAnnounce` webhook and `antctl mc create membertoken` refuse to
  register a member whose `ClusterID` forms a dash-delimited prefix pair with an
  existing member's (e.g. `east` vs `east-1`), since `Service`/`Endpoints` export
  names embed the ClusterID as their first dash-delimited component; see
  [Resolve ClusterID naming conflicts](#resolve-clusterid-naming-conflicts)
  below for pre-existing pairs.

These checks only apply to ServiceAccounts annotated with their `ClusterID` (steps 1-3
above), so the token migration is what actually turns the webhook on for a member. A
ServiceAccount without the annotation - in particular the shared
`antrea-mc-member-access-sa` - is fully trusted by the webhook, which is why deleting
it in step 5 is mandatory.

**Member controllers must be upgraded to the same version as the leader controller**
once the leader runs the webhook. Until a member controller is upgraded, its
`ClusterInfo` export updates are rejected (the old member controller does not set the
source labels the webhook requires), so its Gateway information (Gateway IPs, PodCIDRs)
is not refreshed; this self-heals as soon as the member controller is upgraded, since
the upgraded controller adds the missing labels on the next Gateway reconciliation. No
manual cleanup of existing `ClusterInfo` exports is needed. The other export kinds
(`Service`, `Endpoints`, `LabelIdentity`) already carried the required labels in
earlier versions and are unaffected.

### Resolve ClusterID naming conflicts

`Service` and `Endpoints` ResourceExport names embed the ClusterID as their first
dash-delimited component (`<cluster-id>-<namespace>-<name>-service`). If two member
ClusterIDs form a *dash-delimited prefix pair* — one is the other followed by
`-<suffix>`, e.g. `east` and `east-1` — the member with the shorter ID can craft a
Namespace/Name combination whose export name collides with the longer-ID member's
exports and deny its imported Service. New pairs cannot be registered: the
`MemberClusterAnnounce` webhook and `antctl mc create membertoken` both refuse a
`ClusterID` that forms such a pair with an existing member's. Pre-existing pairs are a
known limitation: the shorter-ID member could still deny one of the longer-ID member's
Service exports (a targeted denial, not a hijack), so resolve any such pair to
eliminate the exposure.

Run this preflight check and resolve every pair it reports. List the ClusterIDs
claimed by the member clusters' `MemberClusterAnnounce` objects, which also covers
members still using the shared credential (they have no per-member ServiceAccount to
carry a `ClusterID` annotation):

```bash
kubectl get memberclusterannounce -n antrea-multicluster \
  -o custom-columns='CLUSTER-ID:.clusterID' | sort -u
```

Inspect the output for pairs where one ID is the other followed by `-`. In this
example, the `east`/`east-1` pair should be resolved:

```text
east
east-1
west
```

To resolve a pair, rename one of the two members: leave the ClusterSet with
`antctl mc leave` (which also removes the member's exports from the leader), re-bind
its ServiceAccount to a new ClusterID and create a new token with `antctl mc create
membertoken --cluster-id <new-id>`, then join again with `antctl mc join`. Pick the
new ID so that it does not form a dash-delimited prefix pair with any remaining member
ID. Removing the dash from the boundary is enough: renaming `east-1` → `east1`
resolves the pair with `east`, while `east-1` → `east-1b` does not, because `east` is
still a dash-delimited prefix of it.

### ResourceImport name collisions

ResourceImport names are derived from the concatenated `(Namespace, Name, Kind)`
tuple of the export (`<namespace>-<name>-<kind>`), so two members exporting
different tuples can resolve to the same ResourceImport name. For example, one
member exporting `prod/web-api` and another exporting `prod-web/api` both
resolve to `prod-web-api-service`. The leader refuses to overwrite or delete a
ResourceImport whose tuple belongs to another member's export, so the first
writer owns the import: the second member's export is stamped with a permanent
`ResourceExportFailure` and its Service is never imported. This is a denial of
that single Service — no injection and no cross-member data flow — and nothing
reports it beyond the losing member's own export status. To resolve the
collision, rename the Service or the Namespace in the losing member so its
tuple no longer concatenates to the same import name.

### ResourceExport name collisions within a member

The same ambiguity exists within a single member: the `ResourceExport` name
is derived as `<cluster-id>-<namespace>-<name>-<kind>`, so two
`ServiceExport`s in the same cluster — e.g. `prod/web-api` and `prod-web/api`
— derive the same export name. The leader webhook refuses the second export's
`Update` (its tuple differs from the stored one), and the losing
`ServiceExport` keeps failing with an error naming the colliding pair; rename
one of the two Services to resolve.

## Upgrade from a version prior to v1.13

Prior to Antrea v1.13, the `ClusterClaim` CRD is used to define both the local Cluster ID and
the ClusterSet ID. Since Antrea v1.13, the `ClusterClaim` CRD is removed, and the `ClusterSet`
CRD solely defines a ClusterSet. The name of a `ClusterSet` CR must match the ClusterSet ID,
and a new `clusterID` field specifies the local Cluster ID.

After upgrading Antrea Multi-cluster Controller from a version older than v1.13, the new version
Multi-cluster Controller can still recognize and work with the old version `ClusterClaim` and
`ClusterSet` CRs. However, we still suggest updating the `ClusterSet` CR to the new version after
upgrading Multi-cluster Controller. You just need to update the existing `ClusterSet` CR and add the
right `clusterID` to the spec. An example `ClusterSet` CR is like the following:

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha2
kind: ClusterSet
metadata:
  name: test-clusterset # This value must match the ClusterSet ID.
  namespace: kube-system
spec:
  clusterID: test-cluster-north # The new added field since v1.13.
  leaders:
    - clusterID: test-cluster-north
      secret: "member-north-token"
      server: "https://172.18.0.1:6443"
  namespace: antrea-multicluster
```

You may also delete the `ClusterClaim` CRD after the upgrade, and then all existing `ClusterClaim`
CRs will be removed automatically after the CRD is deleted.

```bash
kubectl delete crds clusterclaims.multicluster.crd.antrea.io
```

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
