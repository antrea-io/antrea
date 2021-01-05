# Antrea Versioning

## Table of Contents

- [Versioning scheme](#versioning-scheme)
  - [Minor releases and patch releases](#minor-releases-and-patch-releases)
  - [Feature stability](#feature-stability)
- [Release cycle](#release-cycle)
- [Antrea upgrade and supported version skew](#antrea-upgrade-and-supported-version-skew)
- [Supported K8s versions](#supported-k8s-versions)
- [Deprecation policies](#deprecation-policies)
  - [Prometheus metrics deprecation policy](#prometheus-metrics-deprecation-policy)
  - [APIs deprecation policy](#apis-deprecation-policy)

## Versioning scheme

Antrea versions are expressed as `x.y.z`, where `x` is the major version, `y` is
the minor version, and `z` is the patch version, following [Semantic Versioning]
terminology.

The major version for Antrea is currently 0. In particular, this means that the
Antrea APIs are still evolving at a pretty fast pace and that some features
which we consider important for a K8s network plugin have not been implemented
yet or have not reached the *General Availability* (GA) stability level. We have
not yet established a definitive list of features that should be GA before we
switch to a major version number of 1, but here are a few important features
that are likely to be included.

* Antrea-native policies (in particular, `security.antrea.tanzu.vmware.com` API
  group should be stable and in version `v1`)
* Antrea Proxy
* IPv6 and dual-stack support

### Minor releases and patch releases

Unlike minor releases, patch releases should not contain miscellaneous feature
additions or improvements. No incompatibilities should ever be introduced
between patch versions of the same minor version. API groups / versions must not
be introduced or removed as part of patch releases.

Patch releases are intended for important bug fixes to recent minor versions,
such as addressing security vulnerabilities, fixes to problems preventing Antrea
from being deployed & used successfully by a significant number of users, severe
problems with no workaround, and blockers for products (including commercial
products) which rely on Antrea.

When it comes to dependencies, the following rules are observed between patch
versions of the same Antrea minor versions:

* the same minor OVS version should be used
* the same minor version should be used for all Go dependencies, unless
  updating to a new minor / major version is required for an important bug fix
* for Antrea Docker images shipped as part of a patch release, the same version
  must be used for the base Operating System (Linux distribution / Windows
  server), unless an update is required to fix a critical bug. If important
  updates are available for a given Operating System version (e.g. which address
  security vulnerabilities), they should be included in Antrea patch releases.

### Feature stability

For every Antrea minor release, the stability level of supported features may be
updated (from `Alpha` to `Beta` or from `Beta` to `GA`). Refer to the the
[CHANGELOG] for information about feature stability level for each release. For
features controlled by a feature gate, this information is also present in a
more structured way in [feature-gates.md](feature-gates.md).

## Release cycle

New Antrea minor releases are currently shipped every 6 to 8 weeks. This fast
release cadence enables us to ship new features quickly and frequently. It may
change in the future. Compared to deploying the top-of-tree of the Antrea master
branch, using a released version should provide more stability
guarantees:

* despite our CI pipelines, some bugs can sneak into the branch and be fixed
  shortly after
* merge conflicts can break the top-of-tree temporarily
* some CI jobs are run periodically and not for every pull request before merge;
  as much as possible we run the entire test suite for each release candidate

Antrea maintains release branches for the two most recent minor releases
(e.g. the `release-0.10` and `release-0.11` branches are maintained until Antrea
0.12 is released). As part of this maintenance process, patch versions are
released as frequently as needed, following these
[guidelines](#minor-releases-and-patch-releases). With the current release
cadence, this means that each minor release receives approximately 3 months of
patch support. This may seem short, but was done on purpose to encourage users
to upgrade Antrea often and avoid potential incompatibility issues. In the
future, we may reduce our release cadence for minor releases and simultaneously
increase the support window for each release.

## Antrea upgrade and supported version skew

Our goal is to support "graceful" upgrades for Antrea. By "graceful", we notably
mean that there should be no significant disruption to data-plane connectivity
nor to policy enforcement, beyond the necessary disruption incurred by the
restart of individual components:

* during the Antrea Controller restart, new policies will not be
  processed. Because the Controller also runs the validation webhook for
  [Antrea-native policies](antrea-network-policy.md), an attempt to create an
  Antrea-native policy resource before the restart is complete may return an
  error.
* during an Antrea Agent restart, the Node's data-plane will be impacted: new
  connections to & from the Node will not be possible, and existing connections
  may break.

In particular, it should be possible to upgrade Antrea without compromising
enforcement of existing network policies for both new and existing Pods.

In order to achieve this, the different Antrea components need to support
version skew.

* **Antrea Controller**: must be upgraded first
* **Antrea Agent**: must not be newer than the **Antrea Controller**, and may be
  up to 4 minor versions older
* **Antctl**: must not be newer than the **Antrea Controller**, and may be up to
  4 minor versions older

The supported version skew means that we only recommend Antrea upgrades to a new
release up to 4 minor versions newer. For example, a cluster using 0.10 can be
upgraded to one of 0.11, 0.12, 0.13 or 0.14, but we discourage direct upgrades
to 0.15 and beyond. With the current release cadence, this provides a 6-month
window of compatibility. If we reduce our release cadence in the future, we may
revisit this policy as well.

When directly applying a newer Antrea YAML manifest, as provided for each
[release](https://github.com/vmware-tanzu/antrea/releases), there is no
guarantee that the Antrea Controller will be upgraded first. In practice, the
Controller would be upgraded simultaneously with the first Agent(s) to be
upgraded by the rolling update of the Agent DaemonSet. This may create some
transient issues and compromise the "graceful" upgrade. For upgrade scenarios,
we therefore recommend that you "split-up" the manifest to ensure that the
Controller is upgraded first.

## Supported K8s versions

Each Antrea minor release should support [maintained K8s
releases](https://kubernetes.io/docs/setup/release/version-skew-policy/#supported-versions)
at the time of release (3 up to K8s 1.19, 4 after that). For example, at the
time that Antrea 0.10 was released, the latest K8s version was 1.19; as a result
we guarantee that 0.10 supports at least 1.19, 1.18 and 1.17 (in practice it
also supports K8s 1.16).

In addition, we strive to support the K8s versions used by default in
cloud-managed K8s services ([EKS], [AKS] and [GKE] regular channel).

## Deprecation policies

### Prometheus metrics deprecation policy

Antrea follows a similar policy as
[Kubernetes](https://kubernetes.io/docs/concepts/cluster-administration/system-metrics/#metric-lifecycle)
for metrics deprecation.

Alpha metrics have no stability guarantees; as such they can be modified or
deleted at any time.

Stable metrics are guaranteed to not change; specifically, stability means:

* the metric itself will not be renamed
* the type of metric will not be modified

Eventually, even a stable metric can be deleted. In this case, the metric must
be marked as deprecated first and the metric must stay deprecated for at least
one minor release. The [CHANGELOG] must announce both metric deprecations and
metric deletions.

Before deprecation:

```bash
# HELP some_counter this counts things
# TYPE some_counter counter
some_counter 0
```

After deprecation:

```bash
# HELP some_counter (Deprecated since 0.10.0) this counts things
# TYPE some_counter counter
some_counter 0
```

In the future, we may introduce the same concept of [hidden
metric](https://kubernetes.io/docs/concepts/cluster-administration/system-metrics/#show-hidden-metrics)
as K8s, as an additional part of the metric lifecyle.

### APIs deprecation policy

The Antrea APIs are built using K8s (they are a combination of
CustomResourceDefinitions and aggregation layer APIServices) and we follow the
same versioning scheme as the K8s APIs and the same [deprecation
policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/).

Other than the most recent API versions in each track, older API versions must
be supported after their announced deprecation for a duration of no less than:

* GA: 12 months
* Beta: 9 months
* Alpha: N/A (can be removed immediately)

This also applies to the `controlplane` API. In particular, introduction and
removal of new versions for this API must respect the ["graceful" upgrade
guarantee](#antrea-upgrade-and-supported-version-skew). The `controlplane` API
(which is exposed using the aggregation layer) is often referred to as an
"internal" API as it is used by the Antrea components to communicate with each
other, and is usually not consummed by end users, e.g. cluster admins. However,
this API may also be used for integration with other software, which is why we
abide to the same deprecation policy as for other more "user-facing" APIs
(e.g. Antrea-native policy CRDs).

K8s has a [moratorium](https://github.com/kubernetes/kubernetes/issues/52185) on
the removal of API object versions that have been persisted to storage. At the
moment, none of Antrea APIServices (which use the aggregation layer) persist
objects to storage. So the only objects we need to worry about are
CustomResources, which are persisted by the K8s apiserver. For them, we adopt
the following rules:

* Alpha API versions may be removed at any time.
* The [`deprecated` field] must be used for CRDs to indicate that a particular
  version of the resource has been deprecated.
* Beta and GA API versions must be supported after deprecation for the
  respective durations stipulated above before they can be removed.
* For deprecated Beta and GA API versions, a [conversion webhook] must be
  provided along with each Antrea release, until the API version is removed
  altogether.

[Semantic Versioning]: https://semver.org/
[CHANGELOG]: ../CHANGELOG.md
[EKS]: https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html
[AKS]: https://docs.microsoft.com/en-us/azure/aks/supported-kubernetes-versions
[GKE]: https://cloud.google.com/kubernetes-engine/docs/release-notes
[`deprecated` field]: https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#version-deprecation
[conversion webhook]: https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion
