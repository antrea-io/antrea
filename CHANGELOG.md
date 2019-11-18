# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

Features in Alpha or Beta stage are tagged as such. We try to follow the same conventions as
Kubernetes for [feature development
stages](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api_changes.md#alpha-beta-and-stable-versions).

## Unreleased

## 0.1.0 - 2019-11-18

### Added

- Support for configuring and cleaning-up Pod networking as per the [CNI spec]. VXLAN or GENEVE tunnels are used for Pod connectivity across Nodes. [Beta]
- Support for [Kubernetes Network Policies]. [Alpha]
- Monitoring [CRDs] published by both the Antrea Agent and Controller to expose monitoring information. [Alpha]
- [Octant] plugin for visualizing the monitoring CRDs published by the Antrea Agent and Controller. [Alpha]

[CRDs]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[CNI spec]: https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md
[Kubernetes Network Policies]: https://kubernetes.io/docs/concepts/services-networking/network-policies/
[Octant]: https://github.com/vmware-tanzu/octant
