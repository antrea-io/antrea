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
* Some manifests are from [sig-windows-tool](https://github.com/kubernetes-sigs/sig-windows-tools)
  repo. Release version v0.1.5 has been verified.

### Installation as a Service (Containerd based runtimes)

First install Antrea (v0.13.0+ is required for Containerd).

```bash
# Example:
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/v0.13.0/antrea.yml
```

Then, you can run the following commands. [nssm](https://nssm.cc/) will install Antrea as a Windows service. Please ensure
`nssm` is on your machine, which is a handy tool to manage services on Windows. NOTE: `<KubernetesVersion>`, `<KubeconfigPath>`
`<KubeProxyKubeconfigPath>` and `<KubeletKubeconfigPath>` should be set by you. E.g.

```powershell
$KubernetesVersion="v1.20.4"
$KubeConfig="C:/Users/Administrator/.kube/config" # admin kubeconfig
$KubeletKubeconfigPath="C:/etc/kubernetes/kubelet.conf"
$KubeProxyKubeconfigPath="C:/Users/Administrator/kubeproxy.conf"
```

```powershell
$TAG="v0.13.0"
$KubernetesVersion="<KubernetesVersion>"
$KubeConfig="<KubeconfigPath>"
$KubeletKubeconfigPath="<KubeletKubeconfigPath>"
$KubeProxyKubeconfigPath="<KubeProxyKubeconfigPath>"
$KubernetesHome="c:/k"
$AntreaHome="c:/k/antrea"
$KubeProxyLogPath="c:/var/log/kube-proxy"

curl.exe -LO "https://raw.githubusercontent.com/antrea-io/antrea/${TAG}/hack/windows/Helper.psm1"
Import-Module ./Helper.psm1

Install-AntreaAgent -KubernetesVersion "$KubernetesVersion" -KubernetesHome "$KubernetesHome" -KubeConfig "$KubeConfig" -AntreaVersion "$TAG" -AntreaHome "$AntreaHome"
New-KubeProxyServiceInterface

New-DirectoryIfNotExist "${AntreaHome}/logs"
New-DirectoryIfNotExist "${KubeProxyLogPath}"
nssm install kube-proxy "${KubernetesHome}/kube-proxy.exe" "--proxy-mode=userspace --kubeconfig=${KubeProxyKubeconfigPath} --log-dir=${KubeProxyLogPath} --logtostderr=false --alsologtostderr"
nssm install antrea-agent "${AntreaHome}/bin/antrea-agent.exe" "--config=${AntreaHome}/etc/antrea-agent.conf --logtostderr=false --log_dir=${AntreaHome}/logs --alsologtostderr --log_file_max_size=100 --log_file_max_num=4"

nssm set antrea-agent DependOnService kube-proxy ovs-vswitchd
nssm set antrea-agent Start SERVICE_DELAYED_AUTO_START

Start-Service kube-proxy
Start-Service antrea-agent
```

### Installation via wins (Docker based runtimes)

Installing Antrea using [wins](https://github.com/rancher/wins) gives you a lot of flexibility to manage it as a Pod, but
currently this only works with Docker due to a bug in the way Containerd handles host networking for Windows Pods ([Issue](https://github.com/containerd/containerd/issues/4856)).
In any case, if you are using Docker on Windows, this is how you can run Antrea in a Pod.

#### Download & Configure Antrea for Linux

Configure the Antrea for Linux on the control-plane Node following [Getting started](getting-started.md)
document.

```bash
# Example:
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

#### Add Windows kube-proxy DaemonSet

Add Windows-compatible versions of kube-proxy by applying file `kube-proxy.yaml`.

Download `kube-proxy.yaml` from kubernetes official repository and set
kube-proxy version.

```bash
# Example:
curl -L "https://github.com/kubernetes-sigs/sig-windows-tools/releases/download/v0.1.5/kube-proxy.yml" | sed 's/VERSION/v1.18.0/g' > kube-proxy.yml
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

If the powershell version on your Window Node is earlier than v6.0,
change the command from `pwsh` to `powershell` in kube-proxy.yml.

```bash
sed -i 's/pwsh/powershell/g' kube-proxy.yml
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
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-windows.yml
```

#### Join Windows worker Nodes

#### 1. (Optional) Install OVS (provided by Antrea or your own)

Antrea provides a pre-built OVS package which contains test-signed OVS kernel
driver. If you don't have a self-signed OVS package and just want to try the
Antrea on Windows, this package can be used for testing. We also provide a helper
script `Install-OVS.ps1` to install the OVS driver and register userspace binaries
as services. If you want to use your own signed OVS package for production, you can
run `Install-OVS.ps1` like this:

```powershell
Install-OVS.ps1 -ImportCertificate $false -Local -LocalFile <PathToOVSPackage>
```

**[Test-only]** First, if you are using test-signed driver (such as the one provided with Antrea),
please make sure to [enable test-signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

```powershell
Bcdedit.exe -set TESTSIGNING ON
Restart-Computer
```

Then, install the OVS using the script.

```powershell
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Install-OVS.ps1
.\Install-OVS.ps1 # Test-only
.\Install-OVS.ps1 -ImportCertificate $false -Local -LocalFile <PathToOVSPackage> # Production
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
curl.exe -LO "https://github.com/kubernetes-sigs/sig-windows-tools/releases/download/v0.1.5/PrepareNode.ps1"
.\PrepareNode.ps1 -KubernetesVersion v1.18.0
```

#### 4. Prepare Node environment needed by antrea-agent

Run the following commands to prepare the Node environment needed by antrea-agent:

```powershell
mkdir c:\k\antrea
cd c:\k\antrea
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Clean-AntreaNetwork.ps1
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Prepare-ServiceInterface.ps1
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Prepare-AntreaAgent.ps1
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
& C:\k\antrea\Prepare-AntreaAgent.ps1
```

* Example2: Create a ScheduledJob that runs at startup.

```powershell
$trigger = New-JobTrigger -AtStartup -RandomDelay 00:00:30 
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
curl.exe -LO https://github.com/antrea-io/antrea/releases/download/<TAG>/Start.ps1
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
should be removed. A help script [Clean-AntreaNetwork.ps1](https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Clean-AntreaNetwork.ps1)
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
