# Antctl

antctl is the command-line tool for Antrea. At the moment, antctl supports
running in three different modes:

* "controller mode": when run out-of-cluster or from within the Antrea
  Controller Pod, antctl can connect to the Antrea Controller and query
  information from it (e.g. the set of computed NetworkPolicies).
* "agent mode": when run from within an Antrea Agent Pod, antctl can connect to
  the Antrea Agent and query information local to that Agent (e.g. the set of
  computed NetworkPolicies received by that Agent from the Antrea Controller, as
  opposed to the entire set of computed policies).
* "flowaggregator mode": when run from within a Flow Aggregator Pod, antctl can
  connect to the Flow Aggregator and query information from it (e.g. flow records
  related statistics).

## Table of Contents

<!-- toc -->
- [Installation](#installation)
- [Usage](#usage)
  - [Showing or changing log verbosity level](#showing-or-changing-log-verbosity-level)
  - [Showing feature gates status](#showing-feature-gates-status)
  - [Performing checks to facilitate installation process](#performing-checks-to-facilitate-installation-process)
    - [Pre-installation checks](#pre-installation-checks)
    - [Post-installation checks](#post-installation-checks)
  - [Collecting support information](#collecting-support-information)
  - [controllerinfo and agentinfo commands](#controllerinfo-and-agentinfo-commands)
  - [NetworkPolicy commands](#networkpolicy-commands)
    - [Mapping endpoints to NetworkPolicies](#mapping-endpoints-to-networkpolicies)
    - [Evaluating expected NetworkPolicy behavior](#evaluating-expected-networkpolicy-behavior)
  - [Dumping Pod network interface information](#dumping-pod-network-interface-information)
  - [Dumping OVS flows](#dumping-ovs-flows)
  - [OVS packet tracing](#ovs-packet-tracing)
  - [Traceflow](#traceflow)
  - [PacketCapture](#packetcapture)
  - [Antctl Proxy](#antctl-proxy)
  - [Flow Aggregator commands](#flow-aggregator-commands)
    - [Dumping flow records](#dumping-flow-records)
    - [Record metrics](#record-metrics)
  - [Multi-cluster commands](#multi-cluster-commands)
  - [Multicast commands](#multicast-commands)
  - [Showing memberlist state](#showing-memberlist-state)
  - [BGP commands](#bgp-commands)
  - [Upgrade existing objects of CRDs](#upgrade-existing-objects-of-crds)
<!-- /toc -->

## Installation

The antctl binary is included in the Antrea Docker images
(`antrea/antrea-agent-ubuntu`, `antrea/antrea-controller-ubuntu`) which means
that there is no need to install anything to connect to the Antrea Agent. Simply
exec into the antrea-agent container for the appropriate antrea-agent Pod and
run `antctl`:

```bash
kubectl exec -it ANTREA-AGENT_POD_NAME -n kube-system -c antrea-agent -- bash
> antctl help
```

Starting with Antrea release v0.5.0, we publish the antctl binaries for
different OS / CPU Architecture combinations. Head to the [releases
page](https://github.com/antrea-io/antrea/releases) and download the
appropriate one for your machine. For example:

On Mac & Linux:

```bash
curl -Lo ./antctl "https://github.com/antrea-io/antrea/releases/download/<TAG>/antctl-$(uname)-x86_64"
chmod +x ./antctl
mv ./antctl /some-dir-in-your-PATH/antctl
antctl version
```

For Linux, we also publish binaries for Arm-based systems.

On Windows, using PowerShell:

```powershell
Invoke-WebRequest -Uri https://github.com/antrea-io/antrea/releases/download/<TAG>/antctl-windows-x86_64.exe -Outfile antctl.exe
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

### Showing or changing log verbosity level

Starting from version 0.10.0, Antrea supports showing or changing the log
verbosity level of Antrea Controller or Antrea Agent using the `antctl log-level`
command. Starting from version 1.5, Antrea supports showing or changing the
log verbosity level of the Flow Aggregator using the `antctl log-level` command.
The command can only run locally inside the `antrea-controller`, `antrea-agent`
or `flow-aggregator` container.

The following command prints the current log verbosity level:

```bash
antctl log-level
```

This command updates the log verbosity level (the `LEVEL` argument must be an
integer):

```bash
antctl log-level LEVEL
```

### Showing feature gates status

The feature gates of Antrea Controller and Agent can be shown using the `antctl get featuregates` command.
The command can run locally inside the `antrea-controller` or `antrea-agent` container or out-of-cluster,
when it is running out-of-cluster or in Controller Pod, it will print both Controller and Agent's feature gates list.

The following command prints the current feature gates:

```bash
antctl get featuregates
```

### Performing checks to facilitate installation process

Antrea provides a utility command `antctl check` designed to perform checks
that verify whether a Kubernetes cluster is correctly configured for installing
Antrea, and also to confirm that Antrea has been installed correctly.

#### Pre-installation checks

Before installing Antrea, it can be helpful to ensure that the Kubernetes
cluster is configured properly. This can prevent potential issues that might
arise during the installation of Antrea. To perform these pre-installation
checks, simply run the command as follows:

```bash
antctl check cluster
```

Run the following command to discover more options:

```bash
antctl check cluster --help
```

#### Post-installation checks

Once Antrea is installed, you can verify that networking is functioning
correctly within your cluster. To perform post-installation checks, simply run
the command as follows:

```bash
antctl check installation
```

In case Antrea is installed in a custom namespace, You
can specify the namespace by adding the flag:

```bash
antctl check installation --namespace [NAMESPACE]
```

Run the following command to discover more options:

```bash
antctl check installation --help
```

### Collecting support information

Starting with version 0.7.0, Antrea supports the `antctl supportbundle` command,
which can collect information from the cluster, the Antrea Controller and all
Antrea agents. This information is useful when trying to troubleshoot issues in
Kubernetes clusters using Antrea. In particular, when running the command
out-of-cluster, all the information can be collected under one single directory,
which you can upload and share when reporting issues on Github. Simply run the
command as follows:

```bash
antctl supportbundle [-d TARGET_DIR]
```

If you omit to provide a directory, antctl will create one in the current
working directory, using the current timestamp as a suffix. The command also
provides additional flags to filter the results: run `antctl supportbundle
--help` for the full list.

The collected support bundle will include the following (more information may be
included over time):

* cluster information: description of the different K8s resources in the cluster
  (Nodes, Deployments, etc.).
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

Since v1.10.0, Antrea also supports collecting information by applying a
`SupportBundleCollection` CRD, you can refer to the [support bundle guide](./support-bundle-guide.md)
for more information.

### controllerinfo and agentinfo commands

`antctl` controller command `get controllerinfo` (or `get ci`) and agent command
`get agentinfo` (or `get ai`) print the runtime information of
`antrea-controller` and `antrea-agent` respectively.

```bash
antctl get controllerinfo
antctl get agentinfo
```

### NetworkPolicy commands

Both Antrea Controller and Agent support querying the NetworkPolicy objects in the Antrea
control plane API. The source of a control plane NetworkPolicy is the original policy resource
(K8s NetworkPolicy, Antrea-native Policy or AdminNetworkPolicy) from which the control plane
NetworkPolicy was derived.

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
output format. The `NAME` of a control plane NetworkPolicy is the UID of its source
NetworkPolicy.

```bash
antctl get networkpolicy [NAME] [-n NAMESPACE] [-T K8sNP|ACNP|ANNP|ANP|BANP] [-o yaml]
antctl get appliedtogroup [NAME] [-o yaml]
antctl get addressgroup [NAME] [-o yaml]
```

NetworkPolicy, AppliedToGroup, and AddressGroup also support `sort-by=''` option,
which can be used to sort these resources on the basis of a particular field. Any
valid json path can be passed as flag value. If no value is passed it will use a
default field to sort results. For NetworkPolicy, the default field is the name of
the source NetworkPolicy. For AppliedToGroup and AddressGroup, the default field is
the object name (which is a generated UUID).

```bash
antctl get networkpolicy --sort-by='.sourceRef.name'
antctl get appliedtogroup --sort-by='.metadata.name'
antctl get addressgroup --sort-by='.metadata.name'
```

NetworkPolicy also supports `sort-by=effectivePriority` option, which can be used to
view the effective order in which the NetworkPolicies are evaluated. Antrea-native
NetworkPolicy ordering is documented [here](
antrea-network-policy.md#antrea-native-policy-ordering-based-on-priorities).

```bash
antctl get networkpolicy --sort-by=effectivePriority
```

Antrea Agent supports some extra `antctl` commands.

* Printing NetworkPolicies applied to a specific local Pod.

  ```bash
  antctl get networkpolicy -p POD -n NAMESPACE
  ```

* Printing NetworkPolicies with a specific source NetworkPolicy type.

  ```bash
  antctl get networkpolicy -T (K8sNP|ACNP|ANNP|ANP)
  ```
  
* Printing NetworkPolicies with a specific source NetworkPolicy name.

  ```bash
  antctl get networkpolicy -S SOURCE_NAME [-n NAMESPACE]
  ```

#### Mapping endpoints to NetworkPolicies

`antctl` supports mapping a specific Pod to the NetworkPolicies which "select"
this Pod, either because they apply to the Pod directly or because one of their
policy rules selects the Pod.

```bash
antctl query endpoint -p POD [-n NAMESPACE]
```

If no Namespace is provided with `-n`, the command will default to the "default"
Namespace.

This command only works in "controller mode" and **as of now it can only be run
from inside the Antrea Controller Pod, and not from out-of-cluster**.

#### Evaluating expected NetworkPolicy behavior

`antctl` supports evaluating all the existing Antrea-native NetworkPolicies,
Kubernetes NetworkPolicies and AdminNetworkPolicies to predict the effective
policy rule for traffic between source and destination Pods.

```bash
antctl query networkpolicyevaluation -S NAMESPACE/POD -D NAMESPACE/POD
```

If only Pod name is provided, the command will default to the "default" Namespace.

This command only works in "controller mode".

### Dumping Pod network interface information

`antctl` agent command `get podinterface` (or `get pi`) can dump network
interface information of all local Pods, or a specified local Pod, or local Pods
in the specified Namespace, or local Pods matching the specified Pod name.

```bash
antctl get podinterface [NAME] [-n NAMESPACE]
```

### Dumping OVS flows

Starting from version 0.6.0, Antrea Agent supports dumping Antrea OVS flows. The
`antctl` `get ovsflows` (or `get of`) command can dump all OVS flows, flows
added for a specified Pod, or flows added for Service load-balancing of a
specified Service, or flows added to realize a specified NetworkPolicy, or flows
in the specified OVS flow tables, or all or the specified OVS groups.

```bash
antctl get ovsflows
antctl get ovsflows -p POD -n NAMESPACE
antctl get ovsflows -S SERVICE -n NAMESPACE
antctl get ovsflows [-n NAMESPACE] -N NETWORKPOLICY --type NETWORKPOLICY_TYPE
antctl get ovsflows -T TABLE_A,TABLE_B
antctl get ovsflows -T TABLE_A,TABLE_B_NUM
antctl get ovsflows -G all
antctl get ovsflows -G GROUP_ID1,GROUP_ID2
```

OVS flow tables can be specified using table names, or the table numbers.
`antctl get ovsflows --table-names-only` lists all Antrea flow tables. For more information
about Antrea OVS pipeline and flows, please refer to the [OVS pipeline doc](design/ovs-pipeline.md).

Example outputs of dumping Pod and NetworkPolicy OVS flows:

```bash
# Dump OVS flows of Pod "coredns-6955765f44-zcbwj"
$ antctl get of -p coredns-6955765f44-zcbwj -n kube-system
FLOW
table=classification, n_packets=513122, n_bytes=42615080, priority=190,in_port="coredns--d0c58e" actions=set_field:0x2/0xffff->reg0,resubmit(,10)
table=10, n_packets=513122, n_bytes=42615080, priority=200,ip,in_port="coredns--d0c58e",dl_src=52:bd:c6:e0:eb:c1,nw_src=172.100.1.7 actions=resubmit(,30)
table=10, n_packets=0, n_bytes=0, priority=200,arp,in_port="coredns--d0c58e",arp_spa=172.100.1.7,arp_sha=52:bd:c6:e0:eb:c1 actions=resubmit(,20)
table=80, n_packets=556468, n_bytes=166477824, priority=200,dl_dst=52:bd:c6:e0:eb:c1 actions=load:0x5->NXM_NX_REG1[],set_field:0x10000/0x10000->reg0,resubmit(,90)
table=70, n_packets=0, n_bytes=0, priority=200,ip,dl_dst=aa:bb:cc:dd:ee:ff,nw_dst=172.100.1.7 actions=set_field:62:39:b4:e8:05:76->eth_src,set_field:52:bd:c6:e0:eb:c1->eth_dst,dec_ttl,resubmit(,80)

# Get NetworkPolicies applied to Pod "coredns-6955765f44-zcbwj"
$ antctl get netpol -p coredns-6955765f44-zcbwj -n kube-system
NAMESPACE   NAME     APPLIED-TO                           RULES
kube-system kube-dns 160ea6d7-0234-5d1d-8ea0-b703d0aa3b46 1

# Dump OVS flows of NetworkPolicy "kube-dns"
$ antctl get of -N kube-dns -n kube-system
FLOW
table=IngressRule, n_packets=0, n_bytes=0, priority=190,conj_id=1,ip actions=set_field:0x1->reg5,ct(commit,table=IngressMetric,zone=65520,exec(set_field:0x1/0xffffffff->ct_label))
table=IngressRule, n_packets=0, n_bytes=0, priority=200,ip actions=conjunction(1,1/3)
table=IngressRule, n_packets=0, n_bytes=0, priority=200,ip,reg1=0x5 actions=conjunction(2,2/3),conjunction(1,2/3)
table=IngressRule, n_packets=0, n_bytes=0, priority=200,udp,tp_dst=53 actions=conjunction(1,3/3)
table=IngressRule, n_packets=0, n_bytes=0, priority=200,tcp,tp_dst=53 actions=conjunction(1,3/3)
table=IngressRule, n_packets=0, n_bytes=0, priority=200,tcp,tp_dst=9153 actions=conjunction(1,3/3)
table=IngressDefaultRule, n_packets=0, n_bytes=0, priority=200,ip,reg1=0x5 actions=drop

# Dump OVS flows of AntreaNetworkPolicy "test-annp"
$ antctl get ovsflows -N test-annp -n default --type ANNP
FLOW
table=AntreaPolicyIngressRule, n_packets=0, n_bytes=0, priority=14900,conj_id=6 actions=set_field:0x6->reg3,set_field:0x400/0x400->reg0,goto_table:IngressMetric
table=AntreaPolicyIngressRule, n_packets=0, n_bytes=0, priority=14900,ip,nw_src=10.20.1.8 actions=conjunction(6,1/3)
table=AntreaPolicyIngressRule, n_packets=0, n_bytes=0, priority=14900,ip,nw_src=10.20.2.8 actions=conjunction(6,1/3)
table=AntreaPolicyIngressRule, n_packets=0, n_bytes=0, priority=14900,reg1=0x3 actions=conjunction(6,2/3)
table=AntreaPolicyIngressRule, n_packets=0, n_bytes=0, priority=14900,tcp,tp_dst=443 actions=conjunction(6,3/3)
```

### OVS packet tracing

Starting from version 0.7.0, Antrea Agent supports tracing the OVS flows that a
specified packet traverses, leveraging the [OVS packet tracing tool](https://docs.openvswitch.org/en/latest/topics/tracing/).

`antctl trace-packet` command starts a packet tracing operation.
`antctl help trace-packet` shows the usage of the command. This section lists a
few trace-packet command examples.

```bash
# Trace an IP packet between two Pods
antctl trace-packet -S ns1/pod1 -D ns2/pod2
# Trace a Service request from a local Pod
antctl trace-packet -S ns1/pod1 -D ns2/svc2 -f "tcp,tcp_dst=80"
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
  Flow: udp,in_port=32768,vlan_tci=0x0000,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=aa:bb:cc:dd:ee:ff,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=53

  bridge("br-int")
  ----------------
   0. in_port=32768, priority 200, cookie 0x5e000000000000
      load:0->NXM_NX_REG0[0..15]
      resubmit(,30)
  30. ip, priority 200, cookie 0x5e000000000000
      ct(table=31,zone=65520)
      drop
       -> A clone of the packet is forked to recirculate. The forked pipeline will be resumed at table 31.
       -> Sets the packet to an untracked state, and clears all the conntrack fields.

  Final flow: unchanged
  Megaflow: recirc_id=0,eth,udp,in_port=32768,nw_frag=no,tp_src=0x0/0xfc00
  Datapath actions: ct(zone=65520),recirc(0x53)

  ===============================================================================
  recirc(0x53) - resume conntrack with default ct_state=trk|new (use --ct-next to customize)
  ===============================================================================

  Flow: recirc_id=0x53,ct_state=new|trk,ct_zone=65520,eth,udp,in_port=32768,vlan_tci=0x0000,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=aa:bb:cc:dd:ee:ff,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=53

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
      set_field:0x5->reg1
      set_field:0x10000/0x10000->reg0
      resubmit(,90)
  90. conj_id=2,ip, priority 190, cookie 0x5e050000000000
      resubmit(,105)
  105. ct_state=+new+trk,ip, priority 190, cookie 0x5e000000000000
      ct(commit,table=110,zone=65520)
      drop
       -> A clone of the packet is forked to recirculate. The forked pipeline will be resumed at table 110.
       -> Sets the packet to an untracked state, and clears all the conntrack fields.

  Final flow: recirc_id=0x53,eth,udp,reg0=0x10000,reg1=0x5,in_port=32768,vlan_tci=0x0000,dl_src=62:39:b4:e8:05:76,dl_dst=52:bd:c6:e0:eb:c1,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=63,tp_src=0,tp_dst=53
  Megaflow: recirc_id=0x53,ct_state=+new-est-inv+trk,ct_mark=0,eth,udp,in_port=32768,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=aa:bb:cc:dd:ee:ff,nw_src=192.0.0.0/2,nw_dst=172.100.1.7,nw_ttl=64,nw_frag=no,tp_dst=53
  Datapath actions: set(eth(src=62:39:b4:e8:05:76,dst=52:bd:c6:e0:eb:c1)),set(ipv4(ttl=63)),ct(commit,zone=65520),recirc(0x54)

  ===============================================================================
  recirc(0x54) - resume conntrack with default ct_state=trk|new (use --ct-next to customize)
  ===============================================================================

  Flow: recirc_id=0x54,ct_state=new|trk,ct_zone=65520,eth,udp,reg0=0x10000,reg1=0x5,in_port=32768,vlan_tci=0x0000,dl_src=62:39:b4:e8:05:76,dl_dst=52:bd:c6:e0:eb:c1,nw_src=172.100.2.11,nw_dst=172.100.1.7,nw_tos=0,nw_ecn=0,nw_ttl=63,tp_src=0,tp_dst=53

  bridge("br-int")
  ----------------
      thaw
          Resuming from table 110
  110. ip,reg0=0x10000/0x10000, priority 200, cookie 0x5e000000000000
      output:NXM_NX_REG1[]
       -> output port is 5

  Final flow: unchanged
  Megaflow: recirc_id=0x54,eth,ip,in_port=32768,nw_frag=no
  Datapath actions: 3
```

### Traceflow

`antctl traceflow` (or `antctl tf`) command is used to start a Traceflow and
retrieve its result. After the result is collected, the Traceflow will be
deleted. Users can also create a Traceflow with `kubectl`, but `antctl traceflow`
offers a simpler way. For more information about Traceflow, refer to the
[Traceflow guide](traceflow-guide.md).

To start a regular Traceflow, both `--source` (or `-S`) and `--destination` (or
`-D`) arguments must be specified, and the source must be a Pod. For example:

```bash
$ antctl tf -S busybox0 -D busybox1
name: busybox0-to-busybox1-fpllngzi
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

To start a live-traffic Traceflow, add the `--live-traffic` (or `-L`) flag. Add
the `--dropped-only` flag to indicate only the packet dropped by a NetworkPolicy
should be captured in the live-traffic Traceflow. A live-traffic Traceflow
just requires one of `--source` and `--destination` arguments to be specified,
and at least one of them must be a Pod.

The `--flow` (or `-f`) argument can be used to specify the Traceflow packet
headers with the [ovs-ofctl](http://www.openvswitch.org//support/dist-docs/ovs-ofctl.8.txt)
flow syntax. The supported flow fields include: IP family (`ipv6` to indicate an
IPv6 packet), IP protocol (`icmp`, `icmpv6`, `tcp`, `udp`), source and
destination ports (`tcp_src`, `tcp_dst`, `udp_src`, `udp_dst`), and TCP flags
(`tcp_flags`).

By default, the command will wait for the Traceflow to succeed or fail, or
timeout. The default timeout is 10 seconds, but can be changed with the
`--timeout` (or `-t`) argument. Add the `--no-wait` flag to start a Traceflow
without waiting for its results. In this case, the command will not delete the
Traceflow resource. The `traceflow` command supports yaml and json output.

More examples of `antctl traceflow`:

```bash
# Start a Traceflow from pod1 to pod2, both Pods are in Namespace default
$ antctl traceflow -S pod1 -D pod2
# Start a Traceflow from pod1 in Namepace ns1 to a destination IP
$ antctl traceflow -S ns1/pod1 -D 123.123.123.123
# Start a Traceflow from pod1 to Service svc1 in Namespace ns1
$ antctl traceflow -S pod1 -D ns1/svc1 -f tcp,tcp_dst=80
# Start a Traceflow from pod1 to pod2, with a UDP packet to destination port 1234
$ antctl traceflow -S pod1 -D pod2 -f udp,udp_dst=1234
# Start a Traceflow for live TCP traffic from pod1 to svc1, with 1 minute timeout
$ antctl traceflow -S pod1 -D svc1 -f tcp --live-traffic -t 1m
# Start a Traceflow to capture the first dropped TCP packet to pod1 on port 80, within 10 minutes
$ antctl traceflow -D pod1 -f tcp,tcp_dst=80 --live-traffic --dropped-only -t 10m
```

### PacketCapture

`antctl packetcapture` (or  `antctl pc`) command is used to start a `PacketCapture`
and retrieve the captured result. After the result packet file (in pcapng format)
is copied out, the PacketCapture will be deleted. The command will display the
local path to the pcapng file as it exits. Users can also create a PacketCapture
with `kubectl`, but `antctl` makes it easier. For more information about PacketCapture,
refer to [PacketCapture guide](packetcapture-guide.md).

To start a PacketCapture, users must provide the following arguments:

* `--source` (or `-S`)
* `--destination` (or `-D`)
* `--number` (or `-n`)

Note: one of `--source` and `--destination` must be a Pod.

The `--flow` (or `-f`) argument can be used to specify the PacketCapture packet
headers with the [ovs-ofctl](http://www.openvswitch.org//support/dist-docs/ovs-ofctl.8.txt)
flow syntax. This argument works the same way as the one for `antctl traceflow`. The supported flow fields
include: IP protocol (`icmp`, `tcp`, `udp`), source and destination ports
(`tcp_src`, `tcp_dst`, `udp_src`, `udp_dst`), TCP flags (`tcp_flags`) and ICMP messages (`icmp_type`, `icmp_code`).
The `icmp_type` value can be provided in either numeric or string type (`icmp-echo`, `icmp-echoreply`, `icmp-unreach`, `icmp-timxceed`),
and the `icmp_code` value can be provided in only numeric type.

By default, the command will wait for the PacketCapture to succeed or fail, or to
timeout. The default timeout is 60 seconds, but can be changed with the
`--timeout` (or `-t`) argument. Add the `--no-wait` flag to start a PacketCapture
without waiting for its results. In this case, the command will not delete the
PacketCapture resource.

More examples of `antctl packetcapture`:

```bash
# Start capturing packets from pod1 to pod2, both Pods are in Namespace default
$ antctl packetcapture -S pod1 -D pod2
# Start capturing packets from pod1 in Namespace ns1 to a destination IP
$ antctl packetcapture -S ns1/pod1 -D 192.168.123.123
# Start capturing TCP FIN packets from pod1 to pod2, with destination port 80
$ antctl packetcapture -S pod1 -D pod2 -f tcp,tcp_dst=80,tcp_flags=+fin
# Start capturing TCP SYNs that are not ACKs from pod1 to pod2, with destination port 80
$ antctl packetcapture -S pod1 -D pod2 -f tcp,tcp_dst=80,tcp_flags=+syn-ack
# Start capturing UDP packets from pod1 to pod2, with destination port 1234
$ antctl packetcapture -S pod1 -D pod2 -f udp,udp_dst=1234
# Start capturing ICMP destination unreachable (host unreachable) packets from pod1 to pod2
$ antctl packetcapture -S pod1 -D pod2 -f icmp,icmp_type=icmp-unreach,icmp_code=1
# Start capturing ICMP echo packets from pod1 to pod2
$ antctl packetcapture -S pod1 -D pod2 -f icmp,icmp_type=8
# Save the packets file to a specified directory
$ antctl packetcapture -S 192.168.123.123 -D pod2 -f tcp,tcp_dst=80 -o /tmp
```

### Antctl Proxy

antctl can run as a reverse proxy for the Antrea API (Controller or arbitrary
Agent). Usage is very similar to `kubectl proxy` and the implementation is
essentially the same.

To run a reverse proxy for the Antrea Controller API, use:

```bash
antctl proxy --controller
````

To run a reverse proxy for the Antrea Agent API for the antrea-agent Pod running
on Node <TARGET_NODE>, use:

```bash
antctl proxy --agent-node
```

You can then access the API at `127.0.0.1:8001`. To implement this
functionality, antctl retrieves the Node IP address and API server port for the
Antrea Controller or for the specified Agent from the K8s API, and it proxies
all the requests received on `127.0.0.1:8001` directly to that IP / port. One
thing to keep in mind is that the TLS connection between the proxy and the
Antrea Agent or Controller will not be secure (no certificate verification), and
the proxy should be used for debugging only.

To see the full list of supported options, run `antctl proxy --help`.

This feature is useful if one wants to use the Go
[pprof](https://golang.org/pkg/net/http/pprof/) tool to collect runtime
profiling data about the Antrea components. Please refer to this
[document](troubleshooting.md#profiling-antrea-components) for more information.

### Flow Aggregator commands

antctl supports dumping the flow records handled by the Flow Aggregator, and
printing metrics about flow record processing. These commands are only available
when you exec into the Flow Aggregator Pod.

#### Dumping flow records

antctl supports dumping flow records stored in the Flow Aggregator. The
`antctl get flowrecords` command can dump all matching flow records. It supports
the 5-tuple flow key or a subset of the 5-tuple as a filter. A 5-tuple flow key
contains Source IP, Destination IP, Source Port, Destination Port and Transport
Protocol. If the filter is empty, all flow records will be dumped.

The command provides a compact display of the flow records in the default table
output format, which contains the flow key, source pod name, destination pod name,
source pod namespace, destination pod namespace and destination service name for
each flow record. Using the `json` or `yaml` antctl output format will include
output flow record information in a structured format, and will include more
information about each flow record. `antctl get flowrecords --help` shows the
usage of the command. This section lists a few dumping flow records command
examples.

```bash
# Get the list of all flow records
antctl get flowrecords
# Get the list of flow records with a complete filter and output in json format
antctl get flowrecords --srcip 10.0.0.1 --dstip 10.0.0.2 --proto 6 --srcport 1234 --dstport 5678 -o json
# Get the list of flow records with a partial filter, e.g. source address and source port
antctl get flowrecords --srcip 10.0.0.1 --srcport 1234
```

Example outputs of dumping flow records:

```bash
$ antctl get flowrecords --srcip 10.10.1.4 --dstip 10.10.0.2
SRC_IP    DST_IP    SPORT DPORT PROTO SRC_POD                          DST_POD                  SRC_NS          DST_NS      SERVICE                 
10.10.1.4 10.10.0.2 38581 53    17    flow-aggregator-67dc8ddfc8-zx8sg coredns-78fcd69978-7vc6k flow-aggregator kube-system kube-system/kube-dns:dns
10.10.1.4 10.10.0.2 56505 53    17    flow-aggregator-67dc8ddfc8-zx8sg coredns-78fcd69978-7vc6k flow-aggregator kube-system kube-system/kube-dns:dns

$ antctl get flowrecords --srcip 10.10.0.1 --srcport 50497 -o json
[
  {
    "destinationClusterIPv4": "0.0.0.0",
    "destinationIPv4Address": "10.10.1.2",
    "destinationNodeName": "k8s-node-worker-1",
    "destinationPodName": "coredns-78fcd69978-x2twv",
    "destinationPodNamespace": "kube-system",
    "destinationServicePort": 0,
    "destinationServicePortName": "",
    "destinationTransportPort": 53,
    "egressNetworkPolicyName": "",
    "egressNetworkPolicyNamespace": "",
    "egressNetworkPolicyRuleAction": 0,
    "egressNetworkPolicyRuleName": "",
    "egressNetworkPolicyType": 0,
    "flowEndReason": 3,
    "flowEndSeconds": 1635546893,
    "flowStartSeconds": 1635546867,
    "flowType": 2,
    "ingressNetworkPolicyName": "",
    "ingressNetworkPolicyNamespace": "",
    "ingressNetworkPolicyRuleAction": 0,
    "ingressNetworkPolicyRuleName": "",
    "ingressNetworkPolicyType": 0,
    "octetDeltaCount": 99,
    "octetDeltaCountFromDestinationNode": 99,
    "octetDeltaCountFromSourceNode": 0,
    "octetTotalCount": 99,
    "octetTotalCountFromDestinationNode": 99,
    "octetTotalCountFromSourceNode": 0,
    "packetDeltaCount": 1,
    "packetDeltaCountFromDestinationNode": 1,
    "packetDeltaCountFromSourceNode": 0,
    "packetTotalCount": 1,
    "packetTotalCountFromDestinationNode": 1,
    "packetTotalCountFromSourceNode": 0,
    "protocolIdentifier": 17,
    "reverseOctetDeltaCount": 192,
    "reverseOctetDeltaCountFromDestinationNode": 192,
    "reverseOctetDeltaCountFromSourceNode": 0,
    "reverseOctetTotalCount": 192,
    "reverseOctetTotalCountFromDestinationNode": 192,
    "reverseOctetTotalCountFromSourceNode": 0,
    "reversePacketDeltaCount": 1,
    "reversePacketDeltaCountFromDestinationNode": 1,
    "reversePacketDeltaCountFromSourceNode": 0,
    "reversePacketTotalCount": 1,
    "reversePacketTotalCountFromDestinationNode": 1,
    "reversePacketTotalCountFromSourceNode": 0,
    "sourceIPv4Address": "10.10.0.1",
    "sourceNodeName": "",
    "sourcePodName": "",
    "sourcePodNamespace": "",
    "sourceTransportPort": 50497,
    "tcpState": ""
  }
]
```

#### Record metrics

Flow Aggregator supports printing record metrics. The `antctl get recordmetrics`
command can print all metrics related to the Flow Aggregator. The metrics include
the following:

* number of records received by the collector process in the Flow Aggregator
* number of records exported by the Flow Aggregator
* number of records dropped by the Flow Aggregator (Proxy mode)
* number of active flows that are being tracked (Aggregate mode)
* number of exporters connected to the Flow Aggregator

Example outputs of record metrics:

```bash
RECORDS-EXPORTED RECORDS-RECEIVED RECORDS-DROPPED FLOWS EXPORTERS-CONNECTED
46               118              0               7     2
```

### Multi-cluster commands

For information about Antrea Multi-cluster commands, please refer to the
[antctl Multi-cluster commands](./multicluster/antctl.md).

### Multicast commands

The `antctl get podmulticaststats [POD_NAME] [-n NAMESPACE]` command prints inbound
and outbound multicast statistics for each Pod. Note that IGMP packets are not counted.

Example output of podmulticaststats:

```bash
$ antctl get podmulticaststats

NAMESPACE              NAME                         INBOUND OUTBOUND
testmulticast-vw7gx5b9 test3-receiver-2             30      0
testmulticast-vw7gx5b9 test3-sender-1               0       10
```

### Showing memberlist state

`antctl` agent command `get memberlist` (or `get ml`) prints the state of memberlist
cluster of Antrea Agent.

```bash
$ antctl get memberlist

NODE    IP         STATUS
worker1 172.18.0.4 Alive 
worker2 172.18.0.3 Alive 
worker3 172.18.0.2 Dead
```

### BGP commands

`antctl` agent command `get bgppolicy` prints the effective BGP policy applied on the local Node.
It includes the name, local ASN, router ID, listen port and confederation identifier of the effective BGP policy.

```bash
$ antctl get bgppolicy

NAME               ROUTER-ID  LOCAL-ASN LISTEN-PORT CONFEDERATION-IDENTIFIER
example-bgp-policy 172.18.0.2 64512     179         65000
```

`antctl` agent command `get bgppeers` print the current status of all BGP peers
of effective BGP policy applied on the local Node. It includes Peer IP address with port,
ASN, and State of the BGP Peers.

```bash
# Get the list of all bgp peers
$ antctl get bgppeers

PEER                       ASN   STATE
192.168.77.200:179         65001 Established
[fec0::196:168:77:251]:179 65002 Active

# Get the list of IPv4 bgp peers only
$ antctl get bgppeers --ipv4-only

PEER               ASN   STATE
192.168.77.200:179 65001 Established
192.168.77.201:179 65002 Active

# Get the list of IPv6 bgp peers only
$ antctl get bgppeers --ipv6-only

PEER                       ASN   STATE
[fec0::196:168:77:251]:179 65001 Established
[fec0::196:168:77:252]:179 65002 Active
```

`antctl` agent command `get bgproutes` prints the advertised BGP routes on the local Node.
For more information about route advertisement, please refer to [Advertisements](./bgp-policy.md#advertisements).

```bash
# Get the list of all advertised bgp routes
$ antctl get bgproutes

ROUTE                    TYPE                  K8S-OBJ-REF
172.18.0.3/32            EgressIP              egress1
10.244.1.0/24            NodeIPAMPodCIDR       <NONE>
10.96.0.1/32             ServiceLoadBalancerIP default/svc1
fec0::192:168:77:100/128 EgressIP              egress2
fd00:10:244:1::/64       NodeIPAMPodCIDR       <NONE>
fec0::10:96:10:10/128    ServiceLoadBalancerIP default/svc2

# Get the list of advertised IPv4 bgp routes
$ antctl get bgproutes --ipv4-only

ROUTE         TYPE                  K8S-OBJ-REF
172.18.0.3/32 EgressIP              egress1
10.244.1.0/24 NodeIPAMPodCIDR       <NONE>
10.96.0.1/32  ServiceLoadBalancerIP default/svc1

# Get the list of advertised IPv6 bgp routes
$ antctl get bgproutes --ipv6-only

ROUTE                    TYPE                  K8S-OBJ-REF
fec0::192:168:77:100/128 EgressIP              egress2
fd00:10:244:1::/64       NodeIPAMPodCIDR       <NONE>
fec0::10:96:10:10/128    ServiceLoadBalancerIP default/svc2

# Get the list of all advertised routes of a specific type
$ antctl get bgproutes -T EgressIP

ROUTE                    TYPE     K8S-OBJ-REF
172.18.0.3/32            EgressIP egress1
fec0::192:168:77:100/128 EgressIP egress2
```

### Upgrade existing objects of CRDs

antctl supports upgrading existing objects of Antrea CRDs to the storage version.
The related sub-commands should be run out-of-cluster. Please ensure that the
kubeconfig file used by antctl has the necessary permissions. The required permissions
are listed in the following sample ClusterRole.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: antctl
rules:
  - apiGroups:
      - apiextensions.k8s.io
    resources:
      - customresourcedefinitions
    verbs:
      - get 
      - list
  - apiGroups:
      - apiextensions.k8s.io
    resources: 
      - customresourcedefinitions/status
    verbs:
      - update
  - apiGroups: 
      - crd.antrea.io
    resources:
      - "*"
    verbs: 
      - get
      - list 
      - update
```

This command performs a dry-run to upgrade all existing objects of Antrea CRDs to
the storage version:

```bash
antctl upgrade api-storage --dry-run
```

This command upgrades all existing objects of Antrea CRDs to the storage version:

```bash
antctl upgrade api-storage
```

This command upgrades existing AntreaAgentInfo objects to the storage version:

```bash
antctl upgrade api-storage --crds=antreaagentinfos.crd.antrea.io
```

This command upgrades existing Egress and Group objects to the storage version:

```bash
antctl upgrade api-storage --crds=egresses.crd.antrea.io,groups.crd.antrea.io
```

If you encounter any errors related to permissions while running the commands, double-check
the permissions of the kubeconfig used by antctl. Ensure that the ClusterRole has the
required permissions. The following sample errors are caused by insufficient permissions:

```bash
Error: failed to get CRD list: customresourcedefinitions.apiextensions.k8s.io is forbidden: User "user" cannot list resource "customresourcedefinitions" in API group "apiextensions.k8s.io" at the cluster scope

Error: externalippools.crd.antrea.io is forbidden: User "user" cannot list resource "externalippools" in API group "crd.antrea.io" at the cluster scope

Error: error upgrading object prod-external-ip-pool of CRD "externalippools.crd.antrea.io": externalippools.crd.antrea.io "prod-external-ip-pool" is forbidden: User "user" cannot update resource "externalippools" in API group "crd.antrea.io" at the cluster scope

Error: error updating CRD "externalippools.crd.antrea.io" status.storedVersion: customresourcedefinitions.apiextensions.k8s.io "externalippools.crd.antrea.io" is forbidden: User "user" cannot update resource "customresourcedefinitions/status" in API group "apiextensions.k8s.io" at the cluster scope
```
