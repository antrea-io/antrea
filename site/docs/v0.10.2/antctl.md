# Antctl

Antctl is the command-line tool for Antrea. At the moment, antctl supports
running in two different modes:
 * "controller mode": when run out-of-cluster or from within the Antrea
 Controller Pod, antctl can connect to the Antrea Controller and query
 information from it (e.g. the set of computed NetworkPolicies).
 * "agent mode": when run from within an Antrea Agent Pod, antctl can connect to
 the Antrea Agent and query information local to that Agent (e.g. the set of
 computed NetworkPolicies received by that Agent from the Antrea Controller, as
 opposed to the entire set of computed policies).

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Collecting support information](#collecting-support-information)
  - [`controllerinfo` and `agentinfo` commands](#controllerinfo-and-agentinfo-commands)
  - [NetworkPolicy commands](#networkpolicy-commands)
  - [Dumping Pod network interface information](#dumping-pod-network-interface-information)
  - [Dumping OVS flows](#dumping-ovs-flows)
  - [OVS packet tracing](#ovs-packet-tracing)
  - [Traceflow](#traceflow)

## Installation

The antctl binary is included in the Antrea Docker image
(`antrea/antrea-ubuntu`) which means that there is no need to install anything
to connect to the Antrea Agent. Simply exec into the antrea-agent container for
the appropriate antrea-agent Pod and run `antctl`:

```bash
kubectl exec -it <antrea-agent Pod name> -n kube-system -c antrea-agent bash
> antctl help
```

Starting with Antrea release v0.5.0, we publish the antctl binaries for
different OS / CPU Architecture combinations. Head to the [releases
page](https://github.com/vmware-tanzu/antrea/releases) and download the
appropriate one for your machine. For example:

On Mac & Linux:

```bash
curl -Lo ./antctl "https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antctl-$(uname)-x86_64"
chmod +x ./antctl
mv ./antctl /some-dir-in-your-PATH/antctl
antctl version
```

For Linux, we also publish binaries for Arm-based systems.

On Windows, using PowerShell:

```powershell
Invoke-WebRequest -Uri https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antctl-windows-x86_64.exe -Outfile antctl.exe
Move-Item .\antctl.exe c:\some-dir-in-your-PATH\antctl.exe
antctl version
```

## Usage

To see the list of available commands and options, run `antctl help`. The list
will be different based on whether you are connecting to the Antrea Controller
or Agent.

When running out-of-cluster ("controller mode" only), antctl will look for your
kubeconfig file at `$HOME/.kube/config` by default. You can select a different
one by setting the `KUBECONFIG` environment variable or with `--kubeconfig`
(the latter taking precedence over the former).

The following sub-sections introduce a few commands which are useful for
troubleshooting the Antrea system.

### Collecting support information

Starting with version 0.7.0, Antrea supports the `antctl supportbundle` command,
which can collect information from the cluster, the Antrea Controller and all
Antrea agents. This information is useful when trying to troubleshoot issues in
Kubernetes clusters using Antrea. In particular, when running the command
out-of-cluster, all the information can be collected under one single directory,
which you can upload and share when reporting issues on Github. Simply run the
command as follows:

```bash
antctl supportbundle [-d <TARGET_DIR>]
```

If you omit to provide a directory, antctl will create one in the current
working directory, using the current timestamp as a suffix. The command also
provides additional flags to filter the results: run `antctl supportbundle
--help` for the full list.

The collected support bundle will include the following (more information may be
included over time):
 * cluster information: description of the different K8s resources in the
   cluster (Nodes, Deployments, etc.).
 * Antrea Controller information: all the available logs (contents will vary
   based on the verbosity selected when running the controller) and state stored
   at the controller (e.g. computed NetworkPolicy objects).
 * Antrea Agent information: all the available logs from the agent and the OVS
   daemons, network configuration of the Node (e.g. routes, iptables rules, OVS
   flows) and state stored at the agent (e.g. computed NetworkPolicy objects
   received from the controller).

**Be aware that the generated support bundle includes a lot of information,
  including logs, so please review the contents of the directory before sharing
  it on Github and ensure that you do not share anything sensitive.**

The `antctl supportbundle` command can also be run inside a Controller or Agent
Pod, in which case only local information will be collected.

### `controllerinfo` and `agentinfo` commands

`antctl` controller command `get controllerinfo` (or `get ci`) and agent command
`get agentinfo` (or `get ai`) print the runtime information of
`antrea-controller` and `antrea-agent` respectively.

```bash
antctl get controllerinfo
antctl get agentinfo
```

### NetworkPolicy commands

Both Antrea Controller and Agent support querying NetworkPolicy objects.
- `antctl` `get networkpolicy` (or `get netpol`) command can print all
NetworkPolicies, a specified NetworkPolicy, or NetworkPolicies in a specified
Namespace.
- `get appliedtogroup` (or `get atg`) command can print all NetworkPolicy
AppliedToGroups (AppliedToGroup includes the Pods to which a NetworkPolicy is
applied), or a specified AppliedToGroup.
- `get addressgroup` (or `get ag`) command can print all NetworkPolicy
AddressGroups (AddressGroup defines source or destination addresses of
NetworkPolicy rules), or a specified AddressGroup.

Using the `json` or `yaml` antctl output format can print more information of
NetworkPolicy, AppliedToGroup, and AddressGroup, than using the default `table`
output format.

```bash
antctl get networkpolicy [name] [-n namespace] [-o yaml]
antctl get appliedtogroup [name] [-o yaml]
antctl get addressgroup [name] [-o yaml]
```

Antrea Agent additionally supports printing NetworkPolicies applied to a
specified local Pod using this `antctl` command:

```bash
antctl get networkpolicy -p pod -n namespace
```

#### Mapping endpoints to NetworkPolicies

`antctl` supports mapping a specific Pod to the NetworkPolicies which "select"
this Pod, either because they apply to the Pod directly or because one of their
policy rules selects the Pod.

```bash
antctl query endpoint -p pod [-n namespace]
```

If no Namespace is provided with `-n`, the command will default to the "default"
Namespace.

This command only works in "controller mode" and **as of now it can only be run
from inside the Antrea Controller Pod, and not from out-of-cluster**.

### Dumping Pod network interface information

`antctl` agent command `get podinterface` (or `get pi`) can dump network
interface information of all local Pods, or a specified local Pod, or local Pods
in the specified Namespace, or local Pods matching the specified Pod name.

```bash
antctl get podinterface [name] [-n namespace]
```

### Dumping OVS flows

Starting from version 0.6.0, Antrea Agent supports dumping Antrea OVS flows. The
`antctl` `get ovsflows` (or `get of`) command can dump all OVS flows, flows
added for a specified Pod, or flows added to realize a specified NetworkPolicy,
or flows in a specified OVS flow table.

```bash
antctl get ovsflows
antctl get ovsflows -p pod -n namespace
antctl get ovsflows --networkpolicy networkpolicy -n namespace
antctl get ovsflows -T table
```

An OVS flow table can be specified using the table name or the table number.
`antctl get ovsflow --help` lists all Antrea flow tables. For more information
about Antrea OVS pipeline and flows, please refer to the [OVS pipeline doc](ovs-pipeline.md).

Example outputs of dumping Pod and NetworkPolicy OVS flows:

```bash
# Dump OVS flows of Pod "coredns-6955765f44-zcbwj"
$ antctl get of -p coredns-6955765f44-zcbwj -n kube-system
FLOW
table=classification, n_packets=513122, n_bytes=42615080, priority=190,in_port="coredns--d0c58e" actions=load:0x2->NXM_NX_REG0[0..15],resubmit(,10)
table=10, n_packets=513122, n_bytes=42615080, priority=200,ip,in_port="coredns--d0c58e",dl_src=52:bd:c6:e0:eb:c1,nw_src=172.100.1.7 actions=resubmit(,30)
table=10, n_packets=0, n_bytes=0, priority=200,arp,in_port="coredns--d0c58e",arp_spa=172.100.1.7,arp_sha=52:bd:c6:e0:eb:c1 actions=resubmit(,20)
table=80, n_packets=556468, n_bytes=166477824, priority=200,dl_dst=52:bd:c6:e0:eb:c1 actions=load:0x5->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],resubmit(,90)
table=70, n_packets=0, n_bytes=0, priority=200,ip,dl_dst=aa:bb:cc:dd:ee:ff,nw_dst=172.100.1.7 actions=set_field:62:39:b4:e8:05:76->eth_src,set_field:52:bd:c6:e0:eb:c1->eth_dst,dec_ttl,resubmit(,80)

# Get NetworkPolicies applied to Pod "coredns-6955765f44-zcbwj"
$ antctl get netpol -p coredns-6955765f44-zcbwj -n kube-system
NAMESPACE   NAME     APPLIED-TO                           RULES
kube-system kube-dns 160ea6d7-0234-5d1d-8ea0-b703d0aa3b46 1

# Dump OVS flows of NetworkPolicy "kube-dns"
$ antctl get of --networkpolicy kube-dns -n kube-system
FLOW
table=90, n_packets=0, n_bytes=0, priority=190,conj_id=1,ip actions=resubmit(,105)
table=90, n_packets=0, n_bytes=0, priority=200,ip actions=conjunction(1,1/3)
table=90, n_packets=0, n_bytes=0, priority=200,ip,reg1=0x5 actions=conjunction(2,2/3),conjunction(1,2/3)
table=90, n_packets=0, n_bytes=0, priority=200,udp,tp_dst=53 actions=conjunction(1,3/3)
table=90, n_packets=0, n_bytes=0, priority=200,tcp,tp_dst=53 actions=conjunction(1,3/3)
table=90, n_packets=0, n_bytes=0, priority=200,tcp,tp_dst=9153 actions=conjunction(1,3/3)
table=100, n_packets=0, n_bytes=0, priority=200,ip,reg1=0x5 actions=drop
```

### OVS packet tracing

Starting from version 0.7.0, Antrea Agent supports tracing the OVS flows that a
specified packet traverses, leveraging the [OVS packet tracing tool](http://docs.openvswitch.org/en/latest/topics/tracing).

`antctl trace-packet` command starts a packet tracing operation.
`antctl help trace-packet` shows the usage of the command. This section lists a
few trace-packet command examples.

```bash
# Trace an IP packet between two Pods
antctl trace-packet -S ns1/pod1 -D ns2/pod2
# Trace a Service request from a local Pod
antctl trace-packet -S ns1/pod1 -D ns2/srv2 -f "tcp,tcp_dst=80"
# Trace the Service reply packet (assuming "ns2/pod2" is the Service backend Pod)
antctl trace-packet -D ns1/pod1 -S ns2/pod2 -f "tcp,tcp_src=80"
# Trace an IP packet from a Pod to gateway port
antctl trace-packet -S ns1/pod1 -D antrea-gw0
# Trace a UDP packet from a Pod to an IP address
antctl trace-packet -S ns1/pod1 -D 10.1.2.3 -f udp,udp_dst=1234
# Trace a UDP packet from an IP address to a Pod
antctl trace-packet -D ns1/pod1 -S 10.1.2.3 -f udp,udp_src=1234
# Trace an ARP request from a local Pod
antctl trace-packet -p ns1/pod1 -f arp,arp_spa=10.1.2.3,arp_sha=00:11:22:33:44:55,arp_tpa=10.1.2.1,dl_dst=ff:ff:ff:ff:ff:ff
```

Example outputs of tracing a UDP (DNS request) packet from a remote Pod to a
local (coredns) Pod:

```bash
$ antctl trace-packet -S default/web-client -D kube-system/coredns-6955765f44-zcbwj -f udp,udp_dst=53
result: |
  Flow: udp,in_port=1,vlan_tci=0x0000,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=aa:bb:cc:dd:ee:ff,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=53

  bridge("br-int")
  ----------------
   0. in_port=1, priority 200, cookie 0x5e000000000000
      load:0->NXM_NX_REG0[0..15]
      resubmit(,30)
  30. ip, priority 200, cookie 0x5e000000000000
      ct(table=31,zone=65520)
      drop
       -> A clone of the packet is forked to recirculate. The forked pipeline will be resumed at table 31.
       -> Sets the packet to an untracked state, and clears all the conntrack fields.

  Final flow: unchanged
  Megaflow: recirc_id=0,eth,udp,in_port=1,nw_frag=no,tp_src=0x0/0xfc00
  Datapath actions: ct(zone=65520),recirc(0x53)

  ===============================================================================
  recirc(0x53) - resume conntrack with default ct_state=trk|new (use --ct-next to customize)
  ===============================================================================

  Flow: recirc_id=0x53,ct_state=new|trk,ct_zone=65520,eth,udp,in_port=1,vlan_tci=0x0000,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=aa:bb:cc:dd:ee:ff,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=53

  bridge("br-int")
  ----------------
      thaw
          Resuming from table 31
  31. priority 0, cookie 0x5e000000000000
      resubmit(,40)
  40. priority 0, cookie 0x5e000000000000
      resubmit(,50)
  50. priority 0, cookie 0x5e000000000000
      resubmit(,60)
  60. priority 0, cookie 0x5e000000000000
      resubmit(,70)
  70. ip,dl_dst=aa:bb:cc:dd:ee:ff,nw_dst=172.100.1.7, priority 200, cookie 0x5e030000000000
      set_field:62:39:b4:e8:05:76->eth_src
      set_field:52:bd:c6:e0:eb:c1->eth_dst
      dec_ttl
      resubmit(,80)
  80. dl_dst=52:bd:c6:e0:eb:c1, priority 200, cookie 0x5e030000000000
      load:0x5->NXM_NX_REG1[]
      load:0x1->NXM_NX_REG0[16]
      resubmit(,90)
  90. conj_id=2,ip, priority 190, cookie 0x5e050000000000
      resubmit(,105)
  105. ct_state=+new+trk,ip, priority 190, cookie 0x5e000000000000
      ct(commit,table=110,zone=65520)
      drop
       -> A clone of the packet is forked to recirculate. The forked pipeline will be resumed at table 110.
       -> Sets the packet to an untracked state, and clears all the conntrack fields.

  Final flow: recirc_id=0x53,eth,udp,reg0=0x10000,reg1=0x5,in_port=1,vlan_tci=0x0000,dl_src=62:39:b4:e8:05:76,dl_dst=52:bd:c6:e0:eb:c1,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=63,tp_src=0,tp_dst=53
  Megaflow: recirc_id=0x53,ct_state=+new-est-inv+trk,ct_mark=0,eth,udp,in_port=1,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=aa:bb:cc:dd:ee:ff,nw_src=192.0.0.0/2,nw_dst=172.100.1.7,nw_ttl=64,nw_frag=no,tp_dst=53
  Datapath actions: set(eth(src=62:39:b4:e8:05:76,dst=52:bd:c6:e0:eb:c1)),set(ipv4(ttl=63)),ct(commit,zone=65520),recirc(0x54)

  ===============================================================================
  recirc(0x54) - resume conntrack with default ct_state=trk|new (use --ct-next to customize)
  ===============================================================================

  Flow: recirc_id=0x54,ct_state=new|trk,ct_zone=65520,eth,udp,reg0=0x10000,reg1=0x5,in_port=1,vlan_tci=0x0000,dl_src=62:39:b4:e8:05:76,dl_dst=52:bd:c6:e0:eb:c1,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=63,tp_src=0,tp_dst=53

  bridge("br-int")
  ----------------
      thaw
          Resuming from table 110
  110. ip,reg0=0x10000/0x10000, priority 200, cookie 0x5e000000000000
      output:NXM_NX_REG1[]
       -> output port is 5

  Final flow: unchanged
  Megaflow: recirc_id=0x54,eth,ip,in_port=1,nw_frag=no
  Datapath actions: 3
```

### Traceflow

`antctl traceflow` command is used to start a traceflow and retrieve its result. After the
result is collected, the traceflow will be deleted. Users can also create a traceflow with
`kubectl`, but `antctl traceflow` offers a simpler approach.

The required options for this command
are `source` and `destination`, which consist of namespace and pod, service or IP. The command supports
yaml and json output. If users want a non blocking operation, an option: `--wait=false` can
be added to start the traceflow without waiting for result. Then, the deletion operation
will not be conducted. Besides, users can specify header protocol (ICMP, TCP and UDP),
source/destination ports and TCP flags.

e.g.
```bash
$ antctl traceflow -S busybox0 -D busybox1
name: default-busybox0-to-default-busybox1-fpllngzi
phase: Succeeded
source: default/busybox0
destination: default/busybox1
results:
- node: antrea-linux-testbed7-1
  timestamp: 1596435607
  observations:
  - component: SpoofGuard
    action: Forwarded
  - component: Forwarding
    componentInfo: Output
    action: Delivered
```
