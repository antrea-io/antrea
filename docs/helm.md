# Installing Antrea with Helm

## Table of Contents

<!-- toc -->
- [Prerequisites](#prerequisites)
- [Charts](#charts)
  - [Antrea chart](#antrea-chart)
    - [Installation](#installation)
    - [Upgrade](#upgrade)
    - [An important note on CRDs](#an-important-note-on-crds)
  - [Flow Aggregator chart](#flow-aggregator-chart)
    - [Installation](#installation-1)
    - [Upgrade](#upgrade-1)
  - [Theia chart](#theia-chart)
<!-- /toc -->

Starting with Antrea v1.8, Antrea can be installed and updated using
[Helm](https://helm.sh/).

We provide the following Helm charts:

* `antrea/antrea`: the Antrea network plugin.
* `antrea/flow-aggregator`: the Antrea Flow Aggregator; see
  [here](network-flow-visibility.md) for more details.
* `antrea/theia`: Theia, the Antrea network observability solution; refer to the
  [Theia](https://github.com/antrea-io/theia) sub-project for more details.

Note that these charts are the same charts that we use to generate the YAML
manifests for the `kubectl apply` installation method.

## Prerequisites

* Ensure that the necessary
  [requirements](getting-started.md#ensuring-requirements-are-satisfied) for
  running Antrea are met.
* Ensure that Helm 3 is [installed](https://helm.sh/docs/intro/install/). We
  recommend using a recent version of Helm if possible. Refer to the [Helm
  documentation](https://helm.sh/docs/topics/version_skew/) for compatibility
  between Helm and Kubernetes versions.
* Add the Antrea Helm chart repository:

  ```bash
  helm repo add antrea https://charts.antrea.io
  helm repo update
  ```

## Charts

### Antrea chart

#### Installation

To install the Antrea Helm chart, use the following command:

```bash
helm install antrea antrea/antrea --namespace kube-system
```

This will install the latest available version of Antrea. You can also install a
specific version of Antrea (>= v1.8.0) with `--version <TAG>`.

#### Upgrade

To upgrade the Antrea Helm chart, use the following commands:

```bash
# Upgrading CRDs requires an extra step; see explanation below
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-crds.yml
helm upgrade antrea antrea/antrea --namespace kube-system --version <TAG>
```

#### An important note on CRDs

Helm 3 introduces "special treatment" for
[CRDs](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/),
with the ability to place CRD definitions (as plain YAML, not templated) in a
special crds/ directory. When CRDs are defined this way, they will be installed
before other resources (in case these other resources include CRs corresponding
to these CRDs). CRDs defined this way will also never be deleted (to avoid
accidental deletion of user-defined CRs) and will also never be upgraded (in
case the chart author didn't ensure that the upgrade was
backwards-compatible). The rationale for all of this is described in details in
this [Helm community
document](https://github.com/helm/community/blob/main/hips/hip-0011.md).

Even though Antrea follows a [strict versioning policy](versioning.md), which
reduces the likelihood of a serious issue when upgrading Antrea, we have decided
to follow Helm best practices when it comes to CRDs. It means that an extra step
is required for upgrading the chart:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-crds.yml
```

When upgrading CRDs in production, it is recommended to make a backup of your
Custom Resources (CRs) first.

### Flow Aggregator chart

The Flow Aggregator is on the same release schedule as Antrea. Please ensure
that you use the same released version for the Flow Aggregator chart as for the
Antrea chart.

#### Installation

To install the Flow Aggregator Helm chart, use the following command:

```bash
helm install flow-aggregator antrea/flow-aggregator --namespace flow-aggregator --create-namespace
```

This will install the latest available version of the Flow Aggregator. You can
also install a specific version (>= v1.8.0) with `--version <TAG>`.

#### Upgrade

To upgrade the Flow Aggregator Helm chart, use the following command:

```bash
helm upgrade flow-aggregator antrea/flow-aggregator --namespace flow-aggregator --version <TAG>
```

### Theia chart

Refer to the [Theia
documentation](https://github.com/antrea-io/theia/blob/main/docs/getting-started.md).
