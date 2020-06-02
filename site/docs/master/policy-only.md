# Running Antrea In Policy Only Mode

Antrea supports chaining with routed CNI implementations such as EKS CNI. In this mode, Antrea
enforces Kubernetes NetworkPolicy, and delegates Pod IP management and network connectivity to the
primary CNI.

## Design

Antrea is designed to work as NetworkPolicy plug-in to work together with a routed CNIs. 
For as long as a CNI implementation fits into this model, Antrea may be inserted to enforce
NetworkPolicy in that CNI's environment using Open VSwitch(OVS).

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

When a Pod is instantiated, the container runtime first calls the primary CNI to configure Pod's
IP, route table, DNS etc, and then connects Pod to host network with a PtP device such as a 
veth-pair. When Antrea is chained with this primary CNI, container runtime then calls
Antrea Agent, and the Antrea Agent attaches Pod's PtP device to the OVS bridge, and moves the host
route to the Pod to local host gateway(``gw0``) interface from the PtP device. This is
illustrated by the diagram on the right.

Antrea needs to satisfy that 
1. All IP packets, sent on ``gw0`` in the host network, are received by the Pods exactly the same
as if the OVS bridge had not been inserted. 
1. Similarly all IP packets, sent by Pods, are received by other Pods or the host network exactly
the same as if OVS bridge had not been inserted.
1. There are no requirements on Pod MAC addresses as all MAC addresses stays within the OVS bridge.

To satisfy the above requirements, Antrea needs no knowledge of Pod's network configurations nor
of underlying CNI network, it simply needs to program the following OVS flows on the OVS bridge:
1. A default ARP responder flow that answers any ARP request. Its sole purpose is so that a Pod's
neighbor may be resolved, and packets may be sent by that Pod to that neighbor.
1. IP packets are routed based on their destination IP if it matches any local Pod's IP.
1. All other IP packets are routed to host network via ``gw0`` interface.

These flows together handle all Pod traffic patterns with exception of Pod-to-Service traffic
that we will address next.

## Handling Pod-To-Service
The discussion in this section is relevant also to Pod-to-Service traffic in NoEncap traffic
mode. Antrea applies the same principle to handle Pod-to-Service traffic in all traffic modes where
traffic requires no encapsulation.

Antrea uses kube-proxy for load balancing. At the same time, it also supports Pod level
NetworkPolicy enforcement.

This means that a Pod-to-Service traffic flow needs to  
1. first traverse to the host network for load balancing (DNAT), then
1. come back to OVS bridge for Pod Egress NetworkPolicy processing, and
1. go back to the host network yet again to be forwarded, if DNATed destination in 1) is an 
inter-Node Pod or external network entity. 

We refer to the last traffic pattern as re-entrance traffic because in this pattern, a traffic flow
enters host network twice -- first time for load balancing, and second time for forwarding.

Denote
- VIP as cluster IP of a service
- SP_IP/DP_IP as respective client and server Pod IP
- VPort as service port of a service
- TPort as target port of server Pod
- SPort as original source port

The service request's 5-tuples upon first and second entrance to the host network, and
its reply's 5-tuples would be like

```
request/service:   
-- Entering Host Network(via gw0):     SP_IP/SPort->VIP/VPort 
-- After LB(DNAT):                     SP_IP/SPort->DP_IP/TPort
-- After Route(to gw0):                SP_IP/SPort->DP_IP/TPort

request/forwarding:
-- Entering Host Network(via gw0):     SP_IP/SPort->DP_IP/TPort
-- After route(to uplink):             SP_IP/SPort->DP_IP/TPort

reply:
-- Entering Host Network(via uplink):  DP_IP/TPort -> SP_IP/SPort
-- After LB(DNAT):                     VIP/VPort->SP_IP/Sport
-- After route(to gw0):                VIP/VPort->SP_IP/Sport
```

#### Routing 
Note that the request with destination IP DP_IP needs to be routed differently in LB and 
forwarding cases.(This differs from encap traffic where all traffic flows including post LB
service traffic share the same ``main`` route table.) Antrea creates a customized
``antrea_service`` route table, it is used in conjunction with ip-rule and ip-tables to handle
service traffic. Together they work as follows
1. At Antrea initialization, an ip-tables rule is created in ``mangle table`` that marks IP packets
with service IP as destination IP and are from ``gw0``.
1. At Antrea initialization, an ip-rule is added to select ``antrea_service`` route table as routing
table if traffic is marked in 1).
1. At Antrea initialization, a default route entry is added to ``antrea_service`` route table to
forward all traffic to ``gw0``.

The outcome may be something like this
```bash
ip neigh | grep gw0
169.254.253.1 dev gw0 lladdr 12:34:56:78:9a:bc PERMANENT

ip route show table 300 #tbl_idx=300 is antrea_service
default via 169.254.253.1 dev gw0 onlink 

ip rule | grep gw0
300:	from all fwmark 0x800/0x800 iif gw0 lookup 300 

iptables -t mangle  -L ANTREA-MANGLE 
Chain ANTREA-MANGLE (1 references)
target     prot opt source               destination         
MARK       all  --  anywhere             10.0.0.0/16          /* Antrea: mark service traffic */ MARK or 0x800
MARK       all  --  anywhere            !10.0.0.0/16          /* Antrea: unmark post LB service traffic */ MARK and 0x0
```

The above configuration allows Pod-to-Service traffic to use ``antrea_service`` route table after
load balancing, and to be steered back to OVS bridge for Pod NetworkPolicy processing.

#### Conntrack
Note also that with re-entrance traffic, a service request, after being load balanced and routed
back to OVS bridge via ``gw0``, has exactly the same 5-tuple as when it re-enters the host network
for forwarding.

When a service request with same 5-tuples re-enters the host network, it confuses Linux conntrack. 
The Linux considers the re-entrance IP packet from a new connection flow that uses same source port
that has been allocated in the DNAT connection. In turn, the re-entrance packet triggers
another SNAT connection. The overall effect is that the service's DNAT connection is not
discovered by the service reply, and no Un-DNAT takes place. As a result, the reply is not
recognized, and therefore dropped by the source Pod.
   
Antrea uses the following mechanisms to handle Pod-to-Service traffic re-entrance to the host
network, and bypasses conntrack in host network.
1. In OVS bridge, adds flow that marks any re-entrance traffic with a special source MAC.
1. In OVS bridge, adds flow that causes any re-entrance traffic to bypasses conntrack in OVS zone.
1. In the host network' ip-tables, adds a rule in ``raw`` table that if matching the special
source MAC in 1), bypass conntrack in host zone.

#### NetworkPolicy Considerations
Note that when a traffic flow is re-entrance, the original reply packets do not make it into OVS,
as it is un-DNATted in the host network before reaching OVS. This, however, does not have any
impact on NetworkPolicy enforcement.
 
Antrea enforces NetworkPolicy by allowing or disallowing initial connection packets (e.g. TCP
 SYN) to go through and to establish connection. Once a connection is
established, Antrea relies on conntrack to admit or reject packets for that connection. This still 
holds true for re-entrance traffic flows, except that conntrack takes place not within OVS conntrack
zone, but instead is in the host network's default conntrack zone. Hence NetworkPolicy
enforcement is not impacted. 

It has some effects on statistics collection. If original reply traffic reaches OVS bridge as is
the case of encap traffic flows, the OVS bridge knows about any reply packets dropped by OVS zone
conntrack, and can record them accordingly. With re-entrance traffic, the reply traffic with
original server Pod IPs does not reach OVS bridge, and any dropped traffic by host network
conntrack is unknown to the OVS bridge.

## Future Work
1. Smoother transition in/out of Antrea in policy mode, Kubernetes deployment shall be easily
scaled up and down after/before Antrea insertion to allow Pods be added to Antrea after
installation, and reconnect to old CNI topology after Antrea is uninstalled.
1. NetworkPolicy for external services is not working. 
See https://github.com/vmware-tanzu/antrea/issues/538.
