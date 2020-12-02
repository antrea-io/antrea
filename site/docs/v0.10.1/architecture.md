# Antrea Architecture

Antrea is designed to be Kubernetes-centric and Kubernetes-native. It focuses on
and is optimized for networking and security of a Kubernetes cluster. Its
implementation leverages Kubernetes and Kubernetes native solutions as much as
possible.

Antrea leverages Open vSwitch as the networking data plane. Open vSwitch is a
high-performance programmable virtual switch that supports both Linux and
Windows. Open vSwitch enables Antrea to implement Kubernetes Network Policies
in a high-performance and efficient manner. Thanks to the "programmable"
characteristic of Open vSwitch, Antrea is able to implement an extensive set
of networking and security features and services on top of Open vSwitch.

Some information in this document and in particular when it comes to the Antrea
Agent is specific to running Antrea on Linux Nodes. For information about how
Antrea is run on Windows Nodes, please refer to [windows-design.md](windows-design.md).

## Components

In a Kubernetes cluster, Antrea creates a Deployment that runs Antrea
Controller, and a DaemonSet that includes two containers to run Antrea Agent
and OVS daemons respectively, on every Node. The DaemonSet also includes an
init container that installs the CNI plugin - `antrea-cni` - on the Node and
ensures that the OVS kernel module is loaded and it is chained with the portmap
CNI plugin. All Antrea Controller, Agent, OVS daemons, and `antrea-cni` bits
are included in a single Docker image. Antrea also has a command-line tool
called `antctl`, and an [Octant](https://github.com/vmware-tanzu/octant) UI plugin.

<img src="/docs/assets/arch.svg.png" width="600" alt="Antrea Architecture Overview">

### Antrea Controller

Antrea Controller watches NetworkPolicy, Pod, and Namespace resources from the
Kubernetes API, computes NetworkPolicies and distributes the computed policies
to all Antrea Agents. Right now Antrea Controller supports only a single
replica. At the moment, Antrea Controller mainly exists for NetworkPolicy
implementation. If you only care about connectivity between Pods but not
NetworkPolicy support, you may choose not to deploy Antrea Controller at all.
However, in the future, Antrea might support more features that require Antrea
Controller.

Antrea Controller leverages the [Kubernetes apiserver library](https://github.com/kubernetes/apiserver)
to implement the communication channel to Antrea Agents. Each Antrea Agent
connects to the Controller API server and watches the computed NetworkPolicy
objects. Controller also exposes a REST API for `antctl` on the same HTTP
endpoint. See more information about the Controller API server implementation
in the [Controller API server section](#Controller-API-server).

#### Controller API server

Antrea Controller leverages the Kubernetes apiserver library to implement its
own API server. The API server implementation is customized and optimized for
publishing the computed NetworkPolicies to Agents:
- The API server keeps all the state in in-memory caches and does not require a
datastore to persist the data.
- It sends the NetworkPolicy objects to only those Nodes that need to apply the
NetworkPolicies locally. A Node receives a NetworkPolicy if and only if the
NetworkPolicy is applied to at least one Pod on the Node.
- It supports sending incremental updates to the NetworkPolicy objects to
Agents.
- Messages between Controller and Agent are serialized using the Protobuf format
for reduced size and higher efficiency.

The Antrea Controller API server also leverages Kubernetes Service for:
- service discovery, and
- authentication and authorization.

The Controller API endpoint is exposed through a Kubernetes ClusterIP type
Service. Antrea Agent gets the Service's ClusterIP from the Service environment
variable and connects to the Controller API server using the ClusterIP. The
Controller API server delegates authentication and authorization to the
Kubernetes API - the Antrea Agent uses a Kubernetes ServiceAccount token to
authenticate to the Controller, and the Controller API server validates the
token and whether the ServiceAccount is authorized for the API request with the
Kubernetes API.

Antrea Controller also exposes a REST API for `antctl` using the API server HTTP
endpoint. It leverages [Kubernetes API aggregation](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/)
to enable `antctl` to reach the Antrea Controller API through the Kubernetes
API - `antctl` connects and authenticates to the Kubernetes API, which will
proxy the `antctl` API requests to the Antrea Controller. In this way, `antctl`
can be executed on any machine that can reach the Kubernetes API, and it can
also leverage the `kubectl` configuration (`kubeconfig` file) to discover the
Kubernetes API and authentication information. See also the [`antctl` section](#antctl).

### Antrea Agent

Antrea Agent manages the OVS bridge and Pod interfaces and implements Pod
networking with OVS on every Kubernetes Node.

Antrea Agent exposes a gRPC service (`Cni` service) which is invoked by the
`antrea-cni` binary to perform CNI operations. For each new Pod to be created on
the Node, after getting the CNI `ADD` call from `antrea-cni`, the Agent creates
the Pod's network interface, allocates an IP address, connects the interface to
the OVS bridge and installs the necessary flows in OVS. To learn more about the
OVS flows check out the [OVS pipeline doc](ovs-pipeline.md).

Antrea Agent includes two Kubernetes controllers:
- The Node controller watches the Kubernetes API server for new Nodes, and
creates an OVS (Geneve / VXLAN / GRE / STT) tunnel to each remote Node.
- The NetworkPolicy controller watches the computed NetworkPolicies from the
Antrea Controller API, and installs OVS flows to implement the NetworkPolicies
for the local Pods.

Antrea Agent also exposes a REST API on a local HTTP endpoint for `antctl`.

### OVS daemons

The two OVS daemons - `ovsdb-server` and `ovs-vswitchd` run in a separate
container, called `antrea-ovs`, of the Antrea Agent DaemonSet.

### `antrea-cni`

`antrea-cni` is the [CNI](https://github.com/containernetworking/cni) plugin
binary of Antrea. It is executed by `kubelet` for each CNI command. It is a
simple gRPC client which issues an RPC to Antrea Agent for each CNI command. The
Agent performs the actual work (sets up networking for the Pod) and returns the
result or an error to `antrea-cni`.

### `antctl`

`antctl` is a command-line tool for Antrea. At the moment, it can show basic
runtime information for both Antrea Controller and Antrea Agent, for debugging
purposes.

When accessing the Controller, `antctl` invokes the Controller API to query the
required information. As described earlier, `antctl` can reach the Controller
API through the Kubernetes API, and have the Kubernetes API authenticate,
authorize, and proxy the API requests to the Controller. `antctl` can be
executed through `kubectl` as a `kubectl` plugin as well.

When accessing the Agent, `antctl` connects to the Agent's local REST endpoint,
and can only be executed locally in the Agent's container.

### Octant UI plugin

Antrea also implements an Octant plugin which can show the Controller and
Agent's health and basic runtime information in the Octant UI. The Octant plugin
gets the Controller and Agent's information from the `AntreaControllerInfo` and
`AntreaAgentInfo` CRDs (Custom Resource Definition) in the Kubernetes API. The
CRDs are created by the Antrea Controller and each Antrea Agent to populate
their health and runtime information.

## Pod Networking

### Pod interface configuration and IPAM

On every Node, Antrea Agent creates an OVS bridge (named `br-int` by default),
and creates a veth pair for each Pod, with one end being in the Pod's network
namespace and the other connected to the OVS bridge. On the OVS bridge, Antrea
Agent also creates an internal port - `antrea-gw0` by default - to be the gateway of
the Node's subnet, and a tunnel port `antrea-tun0` which is for creating overlay
tunnels to other Nodes.

<img src="/docs/assets/node.svg.png" width="300" alt="Antrea Node Network">

Each Node is assigned a single subnet, and all Pods on the Node get an IP from
the subnet. Antrea leverages Kubernetes' `NodeIPAMController` for the Node
subnet allocation, which sets the `podCIDR` field of the Kubernetes Node spec
to the allocated subnet. Antrea Agent retrieves the subnets of Nodes from the
`podCIDR` field. It reserves the first IP of the local Node's subnet to be the
gateway IP and assigns it to the `antrea-gw0` port, and invokes the
[host-local IPAM plugin](https://github.com/containernetworking/plugins/tree/master/plugins/ipam/host-local)
to allocate IPs from the subnet to all local Pods. A local Pod is assigned an IP
when the CNI ADD command is received for that Pod.

For every remote Node, Antrea Agent adds an OVS flow to send the traffic to that
Node through the appropriate tunnel. The flow matches the packets' destination
IP against each Node's subnet.

### Traffic walk

<img src="/docs/assets/traffic_walk.svg.png" width="600" alt="Antrea Traffic Walk">

* ***Intra-node traffic*** Packets between two local Pods will be forwarded by
the OVS bridge directly.

* ***Inter-node traffic*** Packets to a Pod on another Node will be first
forwarded to the `antrea-tun0` port, encapsulated, and sent to the destination Node
through the tunnel; then they will be decapsulated, injected through the `antrea-tun0`
port to the OVS bridge, and finally forwarded to the destination Pod.

* ***Pod to external traffic*** Packets sent to an external IP or the Nodes'
network will be forwarded to the `antrea-gw0` port (as it is the gateway of the local
Pod subnet), and will be routed (based on routes configured on the Node) to the
appropriate network interface of the Node (e.g. a physical network interface for
a baremetal Node) and sent out to the Node network from there. Antrea Agent
creates an iptables (MASQUERADE) rule to perform SNAT on the packets from Pods,
so their source IP will be rewritten to the Node's IP before going out.

### ClusterIP Service

<img src="/docs/assets/service_walk.svg.png" width="600" alt="Antrea Service Traffic Walk">

At the moment, Antrea leverages `kube-proxy` to serve traffic for ClusterIP and
NodePort type Services. The packets from a Pod to a Service's ClusterIP will be
forwarded through the `antrea-gw0` port, then `kube-proxy` will select one Service
backend Pod to be the connection's destination and DNAT the packets to the Pod's
IP and port. If the destination Pod is on the local Node the packets will be
forwarded to the Pod directly; if it is on another Node the packets will be sent
to that Node via the tunnel.

`kube-proxy` can be used in any supported mode: user-space iptables, or IPVS.
See the [Kubernetes Service documentation](https://kubernetes.io/docs/concepts/services-networking/service)
for more details.

In the future, Antrea will also implement ClusterIP Service with OVS, and make
it a configurable option. This should help achieve better performance than
`kube-proxy` when `kube-proxy` is used in the user-space or iptables modes.

### NetworkPolicy

An important design choice Antrea took regarding the NetworkPolicy
implementation is centralized policy computation. Antrea Controller watches
NetworkPolicy, Pod, and Namespace resources from the Kubernetes API. It
processes podSelectors, namespaceSelectors, and ipBlocks as follows:
- PodSelectors directly under the NetworkPolicy spec (which define the Pods to
which the NetworkPolicy is applied) will be translated to member Pods.
- Selectors (podSelectors and namespaceSelectors) and ipBlocks in rules (which
define the ingress and egress traffic allowed by this policy) will be mapped to
Pod IP addresses / IP address ranges.

Antrea Controller also computes which Nodes need to receive a NetworkPolicy.
Each Antrea Agent receives only the computed policies which affect Pods running
locally on its Node, and directly uses the IP addresses computed by the
Controller to create OVS flows enforcing the specified NetworkPolicies.

We see the following major benefits of the centralized computation approach:

* Only one Antrea Controller instance needs to receive and process all
NetworkPolicy, Pod, and Namespace updates, and compute podSelectors and
namespaceSelectors. This has a much lower overall cost compared to watching
these updates and performing the same complex policy computation on all Nodes.

* It could enable scale-out of Controllers, with multiple Controllers working
together on the NetworkPolicy computation, each one being responsible for a
subset of NetworkPolicies (though at the moment Antrea supports only a single
Controller instance).

* Antrea Controller is the single source of NetworkPolicy computation. It is
much easier to achieve consistency among Nodes and easier to debug the
NetworkPolicy implementation.

As described earlier, Antrea Controller leverages the Kubernetes apiserver
library to build the API and communication channel to Agents.

### IPsec encryption

Antrea supports encrypting GRE tunnel traffic with IPsec ESP. The IPsec
implementation leverages [OVS IPsec](http://docs.openvswitch.org/en/latest/tutorials/ipsec)
and leverages [strongSwan](https://www.strongswan.org) as the IKE daemon.

To enable IPsec, an extra container -`antrea-ovs-ipsec` - must be added to the
Antrea Agent DaemonSet, which runs the `ovs-monitor-ipsec` and strongSwan
daemons. Antrea now supports only using pre-shared key (PSK) for IKE
authentication, and the PSK string must be passed to Antrea Agent using an
environment variable - `ANTREA_IPSEC_PSK`. The PSK string can be specified in
the [Antrea IPsec deployment yaml](/build/yamls/antrea-ipsec.yml), which creates
a Kubernetes Secret to save the PSK value and populates it to the
`ANTREA_IPSEC_PSK` environment variable of the Antrea Agent container.

When IPsec is enabled, Antrea Agent will create a separate GRE tunnel port on
the OVS bridge for each remote Node, and write the PSK string and the remote Node
IP address to two OVS interface options of the tunnel interface. Then
`ovs-monitor-ipsec` can detect the tunnel and create IPsec Security Policies
with PSK for the remote Node, and strongSwan can create the IPsec Security
Associations based on the Security Policies. These additional tunnel ports are
not used to send traffic to a remote Node - the tunnel traffic is still output
to the default tunnel port (`antrea-tun0`) with OVS flow based tunneling. However, the
traffic from a remote Node will be received from the Node's IPsec tunnel port.

### Hybrid, NoEncap, NetworkPolicyOnly TrafficEncapMode
Besides the default `Encap` mode, which always creates overlay tunnels among
Nodes and encapsulates inter-Node Pod traffic, Antrea also supports other
TrafficEncapModes including `Hybrid`, `NoEncap`, `NetworkPolicyOnly` modes. This
section introduces these modes.

* ***Hybrid*** When two Nodes are in two different subnets, Pod traffic between
the two Nodes is encapsulated; when the two Nodes are in the same subnet, Pod
traffic between them is not encapsulated, instead the traffic is routed from on3e
Node to another. Antrea Agent adds routes on the Node to enable the routing
within the same Node subnet. For every remote Node in the same subnet as the
local Node, Agent adds a static route entry that uses the remote Node IP as the
next hop of its Pod subnet.

`Hybrid` mode requires the Node network to allow packets with Pod IPs to be sent
out from the Nodes' NICs.

* ***NoEncap*** Pod traffic is never encapsulated. Antrea just assumes the Node
network can handle routing of Pod traffic across Nodes. Typically this is
achieved by the Kubernetes Cloud Provider implementation which adds routes for
Pod subnets to the Node network routers. Antrea Agent still creates static
routes on each Node for remote Nodes in the same subnet, which is an optimization
that routes Pod traffic directly to the destination Node without going through
the extra hop of the Node network router. Antrea Agent also creates the iptables
(MASQUERADE) rule for SNAT of Pod-to-external traffic.

[Antrea supports GKE](gke-installation.md) with `NoEncap` mode.

* ***NetworkPolicyOnly*** Inter-Node Pod traffic is neither tunneled nor routed
by Antrea. Antrea just implements NetworkPolicies for Pod traffic, but relies on
another cloud CNI and cloud network to implement Pod IPAM and cross-Node traffic
forwarding. Refer to the [NetworkPolicyOnly mode design doc](policy-only.md)
for more information.

[Antrea for AKS
Engine](https://github.com/Azure/aks-engine/blob/master/docs/topics/features.md#feat-antrea)
and [Antrea EKS support](eks-installation.md) work in `NetworkPolicyOnly` mode.
