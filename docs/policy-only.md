# Running Antrea In Policy Only Mode

Antrea supports chaining with routed CNI implementations such as EKS CNI. In this mode, Antrea
enforces Kubernetes NetworkPolicy, and delegates Pod IP management and network connectivity to the
primary CNI.

## Design

Antrea is designed to work as NetworkPolicy plug-in to work together with a routed CNIs.
For as long as a CNI implementation fits into this model, Antrea may be inserted to enforce
NetworkPolicy in that CNI's environment using Open VSwitch(OVS).

In addition, Antrea working as NetworkPolicy plug-in automatically enables Antrea-proxy, because
it requires Antrea-proxy to load balance Pod-to-Service traffic.

<img src="/docs/assets/policy-only-cni.svg" width="600" alt="Antrea Switched CNI">

The above diagram depicts a routed CNI network topology on the left, and what it looks like 
after Antrea inserts the OVS bridge into the data path.

The diagram on the left illustrates a routed CNI network topology such as AWS EKS.
In this topology a Pod connects to the host network via a
point-to-point(PtP) like device, such as (but not limited to) a veth-pair. On the host network, a
host route with corresponding Pod's IP address as destination is created on each PtP device. Within
each Pod, routes are configured to ensure all outgoing traffic is sent over this PtP device, and
incoming traffic is received on this PtP device. This is a spoke-and-hub model, where to/from Pod
traffic, even within the same worker Node must traverse first to the host network and be
routed by it.

When the container runtime instantiates a Pod, it first calls the primary CNI to configure Pod's
IP, route table, DNS etc, and then connects Pod to host network with a PtP device such as a 
veth-pair. When Antrea is chained with this primary CNI, container runtime then calls
Antrea Agent, and the Antrea Agent attaches Pod's PtP device to the OVS bridge, and moves the host
route to the Pod to local host gateway(``antrea-gw0``) interface from the PtP device. This is
illustrated by the diagram on the right.

Antrea needs to satisfy that 
1. All IP packets, sent on ``antrea-gw0`` in the host network, are received by the Pods exactly the same
as if the OVS bridge had not been inserted. 
1. All IP packets, sent by Pods, are received by other Pods or the host network exactly
the same as if OVS bridge had not been inserted.
1. There are no requirements on Pod MAC addresses as all MAC addresses stays within the OVS bridge.

To satisfy the above requirements, Antrea needs no knowledge of Pod's network configurations nor
of underlying CNI network, it simply needs to program the following OVS flows on the OVS bridge:
1. A default ARP responder flow that answers any ARP request. Its sole purpose is so that a Pod can
resolve its neighbors, and the Pod therefore can generate traffic to these neighbors.
1. A L3 flow for each local Pod that routes IP packets to that Pod if packets' destination IP
 matches that of the Pod.
1. A L3 fow that routes all other IP packets to host network via ``antrea-gw0
`` interface.

These flows together handle all Pod traffic patterns.
