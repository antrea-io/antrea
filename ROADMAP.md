# Antrea Roadmap

This document lists the new features being considered for the future. The
intention is for Antrea contributors and users to know what features could come
in the near future, and to share feedback and ideas. Priorities for the project
may change over time and so this roadmap is likely to evolve. A feature that is
not listed now does not mean it will not be considered for Antrea. We definitely
welcome suggestions and ideas from everyone about the roadmap and Antrea
features. Reach us through Issues, Slack and / or Google Group!

## Roadmap Items

### Antrea v2

Antrea [version 2](https://github.com/antrea-io/antrea/issues/4832) is coming in
2024. We are graduating some popular features to Beta or GA, deprecating some
legacy APIs, dropping support for old K8s versions (< 1.19) to improve support
for newer ones, and more! This is a big milestone for the project, stay tuned!

### Quality of life improvements for installation and upgrade

We have a few things planned to improve basic usability:

* provide separate container images for the Agent and Controller: this will
  reduce image size and speed up deployment of new Antrea versions.
* support for installation and upgrade using the antctl CLI: this will provide
  an alternative installation method and antctl will ensure that Antrea
  components are upgraded in the right order to minimize workload disruption.
* CLI tools to facilitate migration from another CNI: we will take care of
  provisioning the correct network resources for your existing workloads.

### Core networking features

We are working on adding BGP support to the Antrea Agent, as it has been a much
requested feature. Take a look at [#5948](https://github.com/antrea-io/antrea/issues/5948)
if this is something you are interested in.

### Windows support improvements

Antrea [supports Windows K8s Nodes](docs/windows.md). However, a few features
including: Egress, NodePortLocal, IPsec encryption are not supported for Windows
yet. We will continue to add more features for Windows (starting with Egress)
and aim for feature parity with Linux. We encourage users to reach out if they
would like us to prioritize a specific feature. While the installation procedure
has improved significantly since we first added Windows support, we plan to keep
on streamlining the procedure (more automation) and on improving the user
documentation.

### More robust FQDN support in Antrea NetworkPolicy

Antrea provides a comprehensive network policy model, which builds upon K8s
Network Policies and provides many additional capabilities. One of them is the
ability to define policy rules using domain names (FQDNs). We think there is
some room to improve user experience with this feature, and we are working on
making it more stable.

### Implementation of new upstream NetworkPolicy APIs

[SIG Network](https://github.com/kubernetes/community/tree/master/sig-network)
is working on [new standard APIs](https://network-policy-api.sigs.k8s.io/) to
extend the base K8s NetworkPolicy resource. We are closely monitoring the
upstream work and implementing these APIs as their development matures.

### Better network troubleshooting with packet capture

Antrea comes with many tools for network diagnostics and observability. You may
already be familiar with Traceflow, which lets you trace a single packet through
the Antrea network. We plan on also providing users with the ability to capture
live traffic and export it in PCAP format. Think tcpdump, but for K8s and
through a dedicated Antrea API!

### Multi-network support for Pods

We recently added the SecondaryNetwork feature, which supports provisioning
additional networks for Pods, using the same constructs made popular by
[Multus](https://github.com/k8snetworkplumbingwg/multus-cni). However, at the
moment, options for network "types" are limited. We plan on supporting new use
cases (e.g., secondary network overlays, network acceleration with DPDK), as
well as on improving user experience for this feature (with some useful
documentation).

### L7 security policy

Support for L7 NetworkPolicies was added in version 1.10, providing the ability
to select traffic based on the application-layer context. However, the feature
currently only supports HTTP and TLS traffic, and we plan to extend support to
other protocols, such as DNS.

### Multi-cluster networking

Antrea can federate multiple K8s clusters, but this feature (introduced in
version 1.7) is still considered Alpha today. Most of the functionality is
already there (multi-cluster Services, cross-cluster connectivity,
and multi-cluster NetworkPolicies), but we think there is some room for
improvement when it comes to stability and usability.

### NetworkPolicy scale and performance tests

We are working on a framework to empower contributors and users to benchmark the
performance of Antrea at scale.

### Investigate better integration with service meshes

As service meshes start introducing alternatives to the sidecar approach,
we believe there is an opportunity to improve the synergy between the K8s
network plugin and the service mesh provider. In particular, we are looking at
how Antrea can integrate with the new Istio ambient data plane mode. Take a look
at [#5682](https://github.com/antrea-io/antrea/issues/5682) for more
information.

### Investigate multiple replicas for the Controller

While today the Antrea Controller can scale to 1000s of K8s Nodes and 100,000
Pods, and failover to a new replica in case of failure can happen in under a
minute, we believe we should still investigate the possibility of deploying
multiple replicas for the Controller (Active-Active or Active-Standby), to
enable horizontal scaling and achieve high-availability with very quick
failover. Horizontal scaling could help reduce the memory footprint of each
Controller instance for very large K8s clusters.
