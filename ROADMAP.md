# Antrea Roadmap

This document lists the features under development (the exact items are also
tracked in Issues), and the new features being considered for the future. The
intention is for Antrea contributors and users to know what features are coming,
and what could come in the near future, and to share feedback and ideas.

Priorities for the project may change over time and so this roadmap is likely to
evolve. This document lists some features as the potential features of future
Antrea releases, but the list is not finalized. A feature that is not listed now
does not  mean it will not be considered for Antrea. We definitely welcome
suggestions and ideas from everyone about the roadmap and Antrea features. Reach
us through Issues, Slack and / or Google Group!

# Features under Development
The following features are being actively developed and will be available soon:

* **Kubernetes NetworkPolicy**
Antrea already supports Kubernetes NetworkPolicy, but we are still stablizing
the implementation, improving the policy computation performance, and adding
end-to-end tests.

* **libOpenflow and ofnet for Openflow programming**
The current Antrea implementation uses the `ovs-ofctl` command to manipulate OVS
flows, which is inefficient. We plan to leverage [libOpenflow](https://github.com/contiv/libOpenflow) and [ofnet](https://github.com/contiv/ofnet) for
the Openflow client and controller implementation, and are enhancing the two
projects to support the OVS Openflow extensions.

* **CLI**
Both Antrea Controller and Agent will support a CLI, which will be mainly for
debugging purposes in the first version. The Controller CLI can be executed from
a remote host and can also be executed through `kubectl`. The Agent CLI can just
be executed locally on the Agent's Node.

* **Octant UI plugin**
Antrea will have an [Octant](https://github.com/vmware-tanzu/octant) plugin
which shows the Antrea information obtained from the Antrea Controller and Agent
monitoring CRDs. Right now an Octant plugin that shows some basic Antrea
Controller and Agent information is already implemented, but we are still working
on the installation guide and support for displaying more information.

* **IPSec encryption**
Enable IPSec (ESP) on the OVS VXLAN or Geneve tunnels to encrypt Pod traffic
across Nodes.

# Planned Features
The following features are considered for the near future:

* **IPv6 Pod network**
Support IPv6 and IPv4/IPv6 dual-stack for Pod network. Right now Antrea supports
only IPv4.

* **Windows Kubernetes Node**
Support Windows Kubernetes Nodes. At the moment Antrea supports only Linux Nodes.

* **Network and NetworkPolicy troubleshooting**
We want to focus on troubleshooting, and will add more mechanisms to simplify
troubleshooting Antrea network and the NetworkPolicy implementation.

* **No-encapsulation mode**
Route Pod traffic across Nodes without overlay tunneling.

* **Kubernetes Service by OVS**
Implement Kubernetes ClusterIP Services with OVS. Right now Antrea relies on
`kube-proxy` to serve ClusterIP Services. The OVS implementation could perform
better than the `kube-proxy` iptables mode.

* **NetworkPolicy scale and performance tests**
Evaluate and benchmark the NetworkPolicy implementation performance at a large
scale, including the policy computation performance of Antrea Controller and the
OVS datapath performance.

* **OVS with DPDK or AF_XDP**
Leverage OVS with DPDK or AF_XDP for high performance.

* **Prometheus integration**
Export metrics to [Prometheus](https://prometheus.io) from both Antrea Controller and Agents.

* **Export OVS flow information**
Export OVS flow information using protocols like IPFix, NetFlow, sFlow. This is
for enabling visibility into the Antrea network from a flow analyzer.
