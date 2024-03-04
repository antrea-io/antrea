# Antrea

![Antrea Logo](docs/assets/logo/antrea_logo.svg)

![Build Status](https://github.com/antrea-io/antrea/workflows/Go/badge.svg?branch=main)
[![Go Report Card](https://goreportcard.com/badge/antrea.io/antrea)](https://goreportcard.com/report/antrea.io/antrea)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/4173/badge)](https://bestpractices.coreinfrastructure.org/projects/4173)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![GitHub release](https://img.shields.io/github/v/release/antrea-io/antrea?display_name=tag&sort=semver)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fantrea-io%2Fantrea.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fantrea-io%2Fantrea?ref=badge_shield)

## Overview

Antrea is a [Kubernetes](https://kubernetes.io) networking solution intended
to be Kubernetes native. It operates at Layer 3/4 to provide networking and
security services for a Kubernetes cluster, leveraging
[Open vSwitch](https://www.openvswitch.org/) as the networking data plane.

<p align="center">
<img src="docs/assets/antrea_overview.svg.png" width="500" alt="Antrea Overview">
</p>

Open vSwitch is a widely adopted high-performance programmable virtual
switch; Antrea leverages it to implement Pod networking and security features.
For instance, Open vSwitch enables Antrea to implement Kubernetes
Network Policies in a very efficient manner.

## Prerequisites

Antrea has been tested with Kubernetes clusters running version 1.16 or later.

* `NodeIPAMController` must be enabled in the Kubernetes cluster.\
  When deploying a cluster with kubeadm the `--pod-network-cidr <cidr>`
  option must be specified.
  Alternately, NodeIPAM feature of Antrea Controller should be enabled and
  configured.
* Open vSwitch kernel module must be present on every Kubernetes node.

## Getting Started

Getting started with Antrea is very simple, and takes only a few minutes.
See how it's done in the [Getting started](docs/getting-started.md) document.

## Contributing

The Antrea community welcomes new contributors. We are waiting for your PRs!

* Before contributing, please get familiar with our
[Code of Conduct](CODE_OF_CONDUCT.md).
* Check out the Antrea [Contributor Guide](CONTRIBUTING.md) for information
about setting up your development environment and our contribution workflow.
* Learn about Antrea's [Architecture and Design](docs/design/architecture.md).
Your feedback is more than welcome!
* Check out [Open Issues](https://github.com/antrea-io/antrea/issues).
* Join the Antrea [community](#community) and ask us any question you may have.

### Community

* Join the [Kubernetes Slack](http://slack.k8s.io/) and look for our
[#antrea](https://kubernetes.slack.com/messages/CR2J23M0X) channel.
* Check the [Antrea Team Calendar](https://calendar.google.com/calendar/embed?src=uuillgmcb1cu3rmv7r7jrhcrco%40group.calendar.google.com)
  and join the developer and user communities!
  + The [Antrea community meeting](https://broadcom.zoom.us/j/91668049513?pwd=WHpaYTE2eWhja0xUN21MRU1BWllYdz09),
every two weeks on Tuesday at 5AM GMT+1 (United Kingdom time). See Antrea team calendar for localized times.
    - [Meeting minutes](https://github.com/antrea-io/antrea/wiki/Community-Meetings)
    - [Meeting recordings](https://www.youtube.com/playlist?list=PLuzde2hYeDBdw0BuQCYbYqxzoJYY1hfwv)
  + [Antrea live office hours](https://antrea.io/live) archives.
* Join our mailing lists to always stay up-to-date with Antrea development:
  + [projectantrea-announce](https://groups.google.com/forum/#!forum/projectantrea-announce)
for important project announcements.
  + [projectantrea](https://groups.google.com/forum/#!forum/projectantrea)
for updates about Antrea or provide feedback.
  + [projectantrea-dev](https://groups.google.com/forum/#!forum/projectantrea-dev)
to participate in discussions on Antrea development.

Also check out [@ProjectAntrea](https://twitter.com/ProjectAntrea) on Twitter!

## Features

* **Kubernetes-native**: Antrea follows best practices to extend the Kubernetes
  APIs and provide familiar abstractions to users, while also leveraging
  Kubernetes libraries in its own implementation.
* **Powered by Open vSwitch**: Antrea relies on Open vSwitch to implement all
  networking functions, including Kubernetes Service load-balancing, and to
  enable hardware offloading in order to support the most demanding workloads.
* **Run everywhere**: Run Antrea in private clouds, public clouds and on bare
  metal, and select the appropriate traffic mode (with or without overlay) based
  on your infrastructure and use case.
* **Comprehensive policy model**: Antrea provides a comprehensive network policy
  model, which builds upon Kubernetes Network Policies with new features such as
  policy tiering, rule priorities, cluster-level policies, and Node policies.
  Refer to the [Antrea Network Policy documentation](docs/antrea-network-policy.md)
  for a full list of features.
* **Windows Node support**: Thanks to the portability of Open vSwitch, Antrea
  can use the same data plane implementation on both Linux and Windows
  Kubernetes Nodes.
* **Multi-cluster networking**: Federate multiple Kubernetes clusters and
  benefit from a unified data plane (including multi-cluster Services) and a
  unified security posture. Refer to the [Antrea Multi-cluster documentation](docs/multicluster/user-guide.md)
  to get started.
* **Troubleshooting and monitoring tools**: Antrea comes with CLI and UI tools
  which provide visibility and diagnostics capabilities (packet tracing, policy
  analysis, flow inspection). It exposes Prometheus metrics and supports
  exporting network flow information to collectors and analyzers.
* **Network observability and analytics**: Antrea + [Theia](https://github.com/antrea-io/theia)
  enable fine-grained visibility into the communication among Kubernetes
  workloads. Theia provides visualization for Antrea network flows in Grafana
  dashboards, and recommends Network Policies to secure the workloads.
* **Network Policies for virtual machines**: Antrea-native policies can be
  enforced on non-Kubernetes Nodes including VMs and baremetal servers. Project
  [Nephe](https://github.com/antrea-io/nephe) implements security policies for
  VMs across clouds, leveraging Antrea-native policies.
* **Encryption**: Encryption of inter-Node Pod traffic with IPsec or WireGuard
  tunnels.
* **Easy deployment**: Antrea is deployed by applying a single YAML manifest
  file.

To explore more Antrea features and their usage, check the [Getting started](docs/getting-started.md#features)
document and user guides in the [Antrea documentation folder](docs/). Refer to
the [Changelogs](CHANGELOG/README.md) for a detailed list of features
introduced for each version release.

## Adopters

For a list of Antrea Adopters, please refer to [ADOPTERS.md](ADOPTERS.md).

## Roadmap

We are adding features very quickly to Antrea. Check out the list of features we
are considering on our [Roadmap](ROADMAP.md) page. Feel free to throw your ideas
in!

## License

Antrea is licensed under the [Apache License, version 2.0](LICENSE)

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fantrea-io%2Fantrea.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fantrea-io%2Fantrea?ref=badge_large)
