# Antrea Roadmap

This document lists the new features being considered for the future. The
intention is for Antrea contributors and users to know what features could come
in the near future, and to share feedback and ideas. Priorities for the project
may change over time and so this roadmap is likely to evolve. A feature that is
not listed now does not mean it will not be considered for Antrea. We definitely
welcome suggestions and ideas from everyone about the roadmap and Antrea
features. Reach us through Issues, Slack and / or Google Group!

# Planned Features
The following features are considered for the near future:

* **No-encapsulation mode**
Route Pod traffic across Nodes without overlay tunneling.

* **Windows Kubernetes Node**
Support Windows Kubernetes Nodes. At the moment Antrea supports only Linux Nodes.

* **IPv6 Pod network**
Support IPv6 and IPv4/IPv6 dual-stack for Pod network. Right now Antrea supports
only IPv4.

* **Network and NetworkPolicy troubleshooting**
We want to focus on troubleshooting, and will add more mechanisms to simplify
troubleshooting Antrea network and the NetworkPolicy implementation.

* **Prometheus integration**
Export metrics to [Prometheus](https://prometheus.io) from both Antrea Controller and Agents.

* **Kubernetes Service by OVS**
Implement Kubernetes ClusterIP Services with OVS. Right now Antrea relies on
`kube-proxy` to serve ClusterIP Services. The OVS implementation could perform
better than the `kube-proxy` iptables mode.

* **Export OVS flow information**
Export OVS flow information using protocols like IPFix, NetFlow, sFlow. This is
for enabling visibility into the Antrea network from a flow analyzer.

* **NetworkPolicy scale and performance tests**
Evaluate and benchmark the NetworkPolicy implementation performance at a large
scale, including the policy computation performance of Antrea Controller and the
OVS datapath performance.

* **OVS with DPDK or AF_XDP**
Leverage OVS with DPDK or AF_XDP for high performance.

* **OVS hardware offloading**
Enable hardware accelaration of the NICs that support OVS offloading.

