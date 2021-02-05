# Deploying Antrea on Windows

## Overview

Antrea supports Windows worker Node. On Windows Node, Antrea sets up an overlay
network to forward packets between Nodes and implements NetworkPolicies. Currently
Geneve, VXLAN, and STT tunnels are supported.

This page shows how to install antrea-agent on Windows Nodes and register the
Node to an existing Kubernetes cluster.

For the detailed design of how antrea-agent works on Windows, please refer to
the [design doc](design/windows-design.md).

### Components that run on Windows

The following components should be configured and run on the Windows Node.

* [kubernetes components](https://kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/)
* OVS daemons
* antrea-agent
* kube-proxy

antrea-agent and kube-proxy run as processes on host and are managed by
management Pods. It is recommended to run OVS daemons as Windows services.
If you don't want to run antrea-agent and kube-proxy from the management Pods
Antrea also provides scripts which help install and run these two components
directly without Pod, please see [Manually run kube-proxy and antrea-agent on Windows worker Nodes](#Manually-run-kube-proxy-and-antrea-agent-on-Windows-worker-Nodes)
section for details.

### Antrea Windows demo

Watch this [demo video](https://www.youtube.com/watch?v=NjeVPGgaNFU) of running
Antrea in a Kubernetes cluster with both Linux and Windows Nodes. The demo also
shows the Antrea OVS bridge configuration on a Windows Node, NetworkPolicy
enforcement for Windows Pods, and Antrea Traceflow from Octant. Note, OVS driver
and daemons are pre-installed on the Windows Nodes in the demo.

## Deploying Antrea on Windows Worker Node

### Prerequisites

* Obtain a Windows Server 2019 license (or higher) in order to configure the
  Windows Node that hosts Windows containers. And install the latest Windows
  updates.
* Deploy a Linux-based Kubernetes cluster.
* Install [Hyper-V](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-the-hyper-v-role-on-windows-server)
  with management tools. If your Nodes do not have the virtualization
  capabilities required by Hyper-V, you could try the workaround
  described in the [Known issues](#Known-issues) section.
* Install [Docker](https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server).
* [Install OVS](http://docs.openvswitch.org/en/latest/intro/install/windows/)
  and configure the daemons as Windows service.
  - The kernel driver of OVS should be [signed by Windows Hardware Dev Center](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing).
  - If OVS driver is not signed, please refer to the Windows doc about how to
    [install a test-signed driver package on the test computer](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-a-test-signed-driver-package-on-the-test-computer).
  - If you don't have a self-signed OVS package and just want to try the
    Antrea on Windows, Antrea provides a test-signed OVS package for you.
    See details in [Join Windows worker Nodes](#Join-Windows-worker-nodes)
    section.

### Installation

#### Download & Configure Antrea for Linux

Configure the Antrea for Linux on the control-plane Node following [Getting started](getting-started.md)
document.

```bash
# Example:
kubectl apply -f https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea.yml
```

#### Add Windows kube-proxy DaemonSet

Add Windows-compatible versions of kube-proxy by applying file `kube-proxy.yaml`.

Download `kube-proxy.yaml` from kubernetes official repository and set
kube-proxy version.

```bash
# Example:
curl -L https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/kube-proxy.yml | sed 's/VERSION/v1.18.0/g'  > kube-proxy.yml
```

Replace the content of `run-script.ps1` in configmap named `kube-proxy-windows`
as following:

```yaml
apiVersion: v1
data:
  run-script.ps1: |-
    $ErrorActionPreference = "Stop";
    mkdir -force /host/var/lib/kube-proxy/var/run/secrets/kubernetes.io/serviceaccount
    mkdir -force /host/k/kube-proxy

    cp -force /k/kube-proxy/* /host/k/kube-proxy
    cp -force /var/lib/kube-proxy/* /host/var/lib/kube-proxy
    cp -force /var/run/secrets/kubernetes.io/serviceaccount/* /host/var/lib/kube-proxy/var/run/secrets/kubernetes.io/serviceaccount

    wins cli process run --path /k/kube-proxy/kube-proxy.exe --args "--v=3 --config=/var/lib/kube-proxy/config.conf --proxy-mode=userspace --hostname-override=$env:NODE_NAME"

kind: ConfigMap
metadata:
  labels:
    app: kube-proxy
  name: kube-proxy-windows
  namespace: kube-system
```

Set the `hostNetwork` option as true in spec of kube-proxy-windows daemonset.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    k8s-app: kube-proxy
  name: kube-proxy-windows
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: kube-proxy-windows
  template:
    metadata:
      labels:
        k8s-app: kube-proxy-windows
    spec:
      hostNetwork: true
```

Then apply the `kube-proxy.yml`.

```bash
kubectl apply -f kube-proxy.yml
```

#### Add Windows antrea-agent DaemonSet

Now you can deploy antrea-agent Windows DaemonSet by applying file `antrea-windows.yml`.

Download and apply `antrea-windows.yml`.

```bash
# Example:
kubectl apply -f https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea-windows.yml
```

#### Join Windows worker Nodes

#### 1. (Optional, Test-Only) Install OVS provided by Antrea

Antrea provides a pre-built OVS package which contains test-signed OVS kernel
driver. If you don't have a self-signed OVS package and just want to try the
Antrea on Windows, this package can be used for testing. We also provide a help
script to install the OVS driver and register userspace binaries as services.

Firstly, please make sure to [enable test-signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
code on Windows Nodes.

```powershell
Bcdedit.exe -set TESTSIGNING ON
Restart-Computer
```

Then, install the OVS using the script.

```powershell
curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/main/hack/windows/Install-OVS.ps1
.\Install-OVS.ps1
```

Verify the OVS services are installed.

```powershell
get-service ovsdb-server
get-service ovs-vswitchd
```

#### 2. Disable Windows Firewall

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

#### 3. Install wins, kubelet, kubeadm and configure kubelet startup params

Firstly, install wins, kubelet, kubeadm using script `PrepareNode.ps1` provided
by kubernetes. The third component [`wins`](https://github.com/rancher/wins) is
used to run kube-proxy and antrea-agent on Windows host inside the Windows
container.

```powershell
# Example:
curl.exe -LO https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/PrepareNode.ps1
.\PrepareNode.ps1 -KubernetesVersion v1.18.0
```

#### 4. Prepare Node environment needed by antrea-agent

Run the following commands to prepare the Node environment needed by antrea-agent:

```powershell
mkdir c:\k\antrea
cd c:\k\antrea
curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/main/hack/windows/Clean-AntreaNetwork.ps1
curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/main/hack/windows/Prepare-ServiceInterface.ps1
curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/main/hack/windows/Prepare-AntreaAgent.ps1
.\Prepare-AntreaAgent.ps1
```

The script `Prepare-AntreaAgent.ps1` performs following tasks:

* Prepare network adapter for kube-proxy.

    kube-proxy needs a network adapter to configure Kubernetes Services IPs and
    uses the adapter for proxying connections to Service. Use following script
    to create the network adapter. The adapter will be deleted automatically by
    Windows after the Windows Node reboots.

* Remove stale network resources created by antrea-agent.

    After the Windows Node reboots, there will be stale network resources which
    need to be cleaned before starting antrea-agent.

As you know from the task details from above, the script must be executed every
time you restart the Node to prepare the environment for antrea-agent.

You could make the script be executed automatically after Windows startup by
using different methods. Here're two examples for your reference:

* Example1: Update kubelet service.

Insert following line in kubelet service script `c:\k\StartKubelet.ps1` to invoke
`Prepare-AntreaAgent.ps1` when starting kubelet service:

```powershell
& C:\k\Prepare-AntreaAgent.ps1
```

* Example2: Create a ScheduledJob that runs at startup.

```powershell
$trigger = New-JobTrigger -AtStartup
$options = New-ScheduledJobOption -RunElevated
Register-ScheduledJob -Name PrepareAntreaAgent -Trigger $trigger  -ScriptBlock { Invoke-Expression C:\k\antrea\Prepare-AntreaAgent.ps1 } -ScheduledJobOption $options
```

#### 5. Run kubeadm to join the Node

On Windows Node, run the `kubeadm join` command to join the cluster. The token
is provided by the control-plane Node.

If you forgot the token, or the token has expired, you can run
`kubeadm token create --print-join-command` (on the control-plane Node) to
generate a new token and join command.

```powershell
# Example:
kubeadm join 192.168.101.5:6443 --token tdp0jt.rshv3uobkuoobb4v  --discovery-token-ca-cert-hash sha256:84a163e57bf470f18565e44eaa2a657bed4da9748b441e9643ac856a274a30b9
```

Then, set the Node IP used by kubelet.
Open file `/var/lib/kubelet/kubeadm-flags.env`:

```text
KUBELET_KUBEADM_ARGS="--network-plugin=cni --pod-infra-container-image=mcr.microsoft.com/oss/kubernetes/pause:1.3.0"
```

Append `--node-ip=$NODE_IP` at the end of params. Replace `$NODE_IP` with
the address for kubelet. It should look like:

```text
KUBELET_KUBEADM_ARGS="--network-plugin=cni --pod-infra-container-image=mcr.microsoft.com/oss/kubernetes/pause:1.3.0 --node-ip=$NODE_IP"
```

Restart kubelet service for changes to take effect.

```powershell
restart-service kubelet
```

#### Verify your installation

There will be temporary network interruption on Windows worker Node on the
first startup of antrea-agent. It's because antrea-agent will set the OVS to
take over the host network. After that you should be able to view the Windows
Nodes and Pods in your cluster by running:

```bash
# Show Nodes
kubectl get nodes -o wide -n kube-system
NAME                           STATUS   ROLES                  AGE   VERSION   INTERNAL-IP     EXTERNAL-IP   OS-IMAGE                                  KERNEL-VERSION     CONTAINER-RUNTIME
control-plane                  Ready    control-plane,master   1h    v1.18.3   10.176.27.168   <none>        Ubuntu 18.04.3 LTS                        4.15.0-66-generic   docker://19.3.9
win-5akrf2tpq91                Ready    <none>                 1h    v1.18.0   10.176.27.150   <none>        Windows Server 2019 Standard Evaluation   10.0.17763.1158    docker://19.3.5
win-5akrf2tpq92                Ready    <none>                 1h    v1.18.0   10.176.27.197   <none>        Windows Server 2019 Standard Evaluation   10.0.17763.1158     docker://19.3.5

# Show antrea-agent and kube-proxy Pods
kubectl get pods -o wide -n kube-system | grep windows
antrea-agent-windows-6hvkw                             1/1     Running     0          100s
kube-proxy-windows-2d45w                               1/1     Running     0          102s
```

### Manually run kube-proxy and antrea-agent on Windows worker Nodes

Aside from starting kube-proxy and antrea-agent from the management Pods, Antrea
also provides powershell scripts which help install and run these two components
directly without Pod. Please complete the steps in [Installation](#Installation)
section, skip [Add Windows kube-proxy DaemonSet](#Add-Windows-kube-proxy-DaemonSet)
and [Add Windows antrea-agent DaemonSet](#Add-Windows-antrea-agent-DaemonSet)
steps. And then run the following commands in powershell.

```powershell
mkdir c:\k\antrea
cd c:\k\antrea
curl.exe -LO https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/Start.ps1
# $KubeConfigPath is the path of kubeconfig file
./Start.ps1 -kubeconfig $KubeConfigPath
```

> Note: Some features such as supportbundle collection are not supported in this
> way. It's recommended to start kube-proxy and antrea-agent through management
> Pods.

## Known issues

1. HNS Network is not persistent on Windows. So after the Windows Node reboots,
the HNS Network created by antrea-agent is removed, and the Open vSwitch
Extension is disabled by default. In this case, the stale OVS bridge and ports
should be removed. A help script [Clean-AntreaNetwork.ps1](https://raw.githubusercontent.com/vmware-tanzu/antrea/main/hack/windows/Clean-AntreaNetwork.ps1)
can be used to clean the OVS bridge.

2. Hyper-V feature cannot be installed on Windows Node due to the processor not
having the required virtualization capabilities.

    If the processor of the Windows Node does not have the required
    virtualization capabilities. The installation of Hyper-V feature will fail
    with the following error:

    ```powershell
    PS C:\Users\Administrator> Install-WindowsFeature Hyper-V

    Success Restart Needed Exit Code      Feature Result
    ------- -------------- ---------      --------------
    False   Maybe          Failed         {}
    Install-WindowsFeature : A prerequisite check for the Hyper-V feature failed.
    1. Hyper-V cannot be installed: The processor does not have required virtualization capabilities.
    At line:1 char:1
    + Install-WindowsFeature hyper-v
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : InvalidOperation: (Hyper-V:ServerComponentWrapper) [Install-WindowsFeature], Exception
        + FullyQualifiedErrorId : Alteration_PrerequisiteCheck_Failed,Microsoft.Windows.ServerManager.Commands.AddWindowsF
       eatureCommand
    ```

    The capabilities are required by the Hyper-V `hypervisor` components to
    support [Hyper-V isolation](https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container#hyper-v-isolation).
    If you only need [Process Isolation](https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container#process-isolation)
    on the Nodes. You could apply the following workaround to skip CPU check for
    Hyper-V feature installation.

    ```powershell
    # 1. Install containers feature
    Install-WindowsFeature containers

    # 2. Install Hyper-V management powershell module
    Install-WindowsFeature Hyper-V-Powershell

    # 3. Install Hyper-V feature without CPU check and disable the "hypervisor"
    dism /online /enable-feature /featurename:Microsoft-Hyper-V /all /NoRestart
    dism /online /disable-feature /featurename:Microsoft-Hyper-V-Online /NoRestart

    # 4. Restart-Computer to take effect
    Restart-Computer
    ```
