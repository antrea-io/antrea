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

## Installation

The antctl binary is included in the Antrea Docker image
(`antrea/antrea-ubuntu`) which means that there is no need to install anything
to connect to the Antrea Agent. Simply exec into the antrea-agent container for
the appropriate antrea-agent Pod and run `antctl`:
```
kubectl exec -it <antrea-agent Pod name> -n kube-system -c antrea-agent bash
> antctl help
```

Starting with Antrea release v0.5.0, we publish the antctl binaries for
different OS / CPU Architecture combinations. Head to the [releases
page](https://github.com/vmware-tanzu/antrea/releases) and download the
appropriate one for your machine. For example:

On Mac & Linux:
```
curl -Lo ./antctl "https://github.com/vmware-tanzu/antrea/releases/download/v0.5.0/antctl-$(uname)-x86_64"
chmod +x ./antctl
mv ./antctl /some-dir-in-your-PATH/antctl
antctl version
```

For Linux, we also publish binaries for Arm-based systems.

On Windows, using PowerShell:
```
Invoke-WebRequest -Uri https://github.com/vmware-tanzu/antrea/releases/download/v0.5.0/antctl-windows-x86_64.exe -Outfile antctl.exe
Move-Item .\antctl.exe c:\some-dir-in-your-PATH\antctl.exe
antctl version
```

## Usage

To see the list of available commands and options, run `antctl help`. The list
will be different based on whether you are connecting to the Antrea Controller
or Agent.

When running out-of-cluster ("controller mode" only), antctl will look for your
kubeconfig file at `$HOME/.kube/config` by default. You can select a different
one with `--kubeconfig`.

The following sub-sections introduce a few commands which are useful for
troubleshooting the Antrea system.

### `controllerinfo` and `agentinfo` commands
`antctl` controller command `get controllerinfo` (or `get ci`) and agent command
`get agentinfo` (or `get ai`) print the runtime information of
`antrea-controller` and `antrea-agent` respectively.
```
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
```
antctl get networkpolicy [name] [-n namespace] [-o yaml]
antctl get appliedtogroup [name] [-o yaml]
antctl get addressgroup [name] [-o yaml]
```

Antrea Agent additionally supports printing NetworkPolicies applied to a
specified local Pod using this `antctl` command:
```
antctl get networkpolicy -p pod -n namespace
```

### Dumping Pod network interface information
`antctl` agent command `get podinterface` (or `get pi`) can dump network
interface information of all local Pods, or a specified local Pod, or local Pods
in the specified Namespace, or local Pods matching the specified Pod name.
```
antctl get podinterface [name] [-n namespace]
```

### Dumping OVS flows
Starting from version 0.6.0, Antrea Agent supports dumping Antrea OVS flows. The
`antctl` `get ovsflows` (or `get of`) command can dump all OVS flows, flows
added for a specified Pod, or flows added to realize a specified NetworkPolicy,
or flows in a specified OVS flow table.
```
antctl get ovsflows
antctl get ovsflows -p pod -n namespace
antctl get ovsflows --networkpolicy networkpolicy -n namespace
antctl get ovsflows -T table
```

An OVS flow table can be specified using the table name or the table number.
`antctl get ovsflow --help` lists all Antrea flow tables. For more information
about Antrea OVS pipeline and flows, please refer to the [OVS pipeline doc](/docs/ovs-pipeline.md).

Example outputs of dumping Pod and NetworkPolicy OVS flows:
```
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
