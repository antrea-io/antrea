# Antrea on Windows

## Overview
Antrea supports to run on Windows worker Node, and setups an overlay network
which uses VXLAN tunneling to route packets between nodes.

One HNS Network with [Transparent mode](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/network-drivers-topologies)
is created on a Windows worker Node, on which Open vSwitch Extension is enabled.
The HNS Network uses the network adapter which is used to join the Windows Node
into the cluster. An OVS bridge is created, and leverages the network adapter as
the uplink interface. The original IP and MAC address of the network adapter is
moved to the OVS bridge. 

One HNS Endpoint is created on this HNS Network and attached on all containers
in the Pod when the CNI ADD command is received. An internal OVS port is created
at the same time, which has the same name as the HNS Endpoint. OpenFlow entries
are installed on the OVS bridge to provide container networking.

Each Windows Node is assigned  with a single subnet, and 
[host-local IPAM plugin](https://github.com/containernetworking/plugins/tree/master/plugins/ipam/host-local)
is invoked to allocate IPs from the subnet to all local Pods.

### Components that run on Windows

The following components are configured and run on the Windows Node.
* [kubernetes components](https://kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/)
* Antrea Agent
* OVS daemons

Both Antrea Agent and OVS daemons support to run as process or Windows service.

### Traffic walk
* ***Intra-node traffic*** and ***Inter-node traffic*** On Windows Node, the
forwarding path for packets that are between two local Pods or to a Pod on
another Node is the same as Linux Node. Please refer to the [architecture](/docs/architecture.md).

* ***Pod to external traffic*** Antrea Agent creates OpenFlow rules to perform
SNAT on the packets sent from local Pod to an external IP or the Nodes' network,
and the source IP will be rewritten to the Node's IP. Then the packets are
forwarded to the OVS bridge. IP-Forwarding is enabled on the OVS bridge, and the
pacets will be sent out using host networking stack.

## Deploying Antrea on Windows Worker Node

### Prerequisite
* Obtain a Windows Server 2019 license (or higher) in order to configure the
Windows node that hosts Windows containers. 
* Build a Linux-based Kubernetes cluster.
* Install Windows [Kubernetes binaries](https://github.com/kubernetes/kubernetes/releases)
(kubeadm, kubectl, kubelet, and kube-proxy).
* [Install OVS](http://docs.openvswitch.org/en/latest/intro/install/windows/)
and configure the daemons as Windows service.

### Installation
* Download Antrea Windows binaries to a local path.
* Add OVS run path to environment variable `OVS_RUNDIR`. If this environment
variable is not provided, path `C:\openvswitch\var\run\openvswitch` is used by
default.
* Retrieve the Kubeconfig file and save it on the local Node. Add the file path 
to an environment variable `KUBECONFIG`.
* Create the kubeconfig files that contains both the K8s APIServer endpoint and
the `antrea-controller` APIServer endpoint. Update the file path into the
antrea-agentPlease refer to this [guide](/docs/manual-installation.md). The
configuration file should be created in a directory named as `conf` at where
the Antrea Agent binary is placed.
```shell script
clientConnection:
  kubeconfig: C:\antrea\antrea-agent.kubeconfig
antreaClientConnection:
  kubeconfig: C:\antrea\antrea-agent.antrea.kubeconfig
```
* Configure Kubernetes to use Antrea as the CNI plugin.
* Run kubelet to join the cluster.
* Add the hostname of current Node to the environment variable.
```shell script
PS > $env:NODE_NAME = $(hostname).ToLower()
```
* Run Antrea Agent.
```shell script
PS > antrea-agent.exe --config ./conf/antrea-agent.conf
```

#### Windows Service
Antrea Agent supports to run as Windows service. The instructions here assume that
the Antrea Windows binaries are downloaded, and the `KUBECONFIG` is added as an 
environment variable.

To start, add the path where the Antrea Agent binary is located to an environment
variable `Antrea_Home`. If the `Antrea_Home` is not provided, `C:\antrea\` is
used as the default path.

The logs for Antrea Agent is written to file `$Antrea_Home\logs\antrea-agent.log`
by default. If another path is wanted to place log files, add it to the
environment variable `Antrea_LogDir`.
```shell script
PS > $env:Antrea_Home="C:\antrea"
PS > [System.Environment]::SetEnvironmentVariable("Antrea_Home", "C:\antrea", "Machine") 
PS > $env:Antrea_LogDir="C:\antrea\logs"
PS > [System.Environment]::SetEnvironmentVariable("Antrea_LogDir", "C:\antrea\logs", "Machine") 
```
Create the antrea-agent service and start it
```shell script
PS > antrea-service.exe --service-control install
PS > Start-Service antrea-agent
```
Use the service command to stop Antrea Agent gracefully
```shell script
PS > Stop-Service antrea-agent
```

## Troubleshooting
1. HNS Network is not persistent on Windows. So after the Windows Node is restarted,
the HNS Network create by Antrea Agent is removed, and the Open vSwitch Extension is
disabled by default. In this case, the stale OVS bridge and ports should be removed
manually before running Antrea Agent.

