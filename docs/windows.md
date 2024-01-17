# Deploying Antrea on Windows

## Table of Contents

<!-- toc -->
- [Overview](#overview)
  - [Components that run on Windows](#components-that-run-on-windows)
  - [Antrea Windows demo](#antrea-windows-demo)
- [Deploying Antrea on Windows worker Nodes](#deploying-antrea-on-windows-worker-nodes)
  - [Prerequisites](#prerequisites)
  - [Installation as a Pod](#installation-as-a-pod)
    - [Download &amp; Configure Antrea for Linux](#download--configure-antrea-for-linux)
    - [Add Windows antrea-agent DaemonSet](#add-windows-antrea-agent-daemonset)
    - [Join Windows worker Nodes](#join-windows-worker-nodes)
      - [1. (Optional) Install OVS (provided by Antrea or your own)](#1-optional-install-ovs-provided-by-antrea-or-your-own)
      - [2. Disable Windows Firewall](#2-disable-windows-firewall)
      - [3. Install kubelet, kubeadm and configure kubelet startup params](#3-install-kubelet-kubeadm-and-configure-kubelet-startup-params)
      - [4. Prepare Node environment needed by antrea-agent](#4-prepare-node-environment-needed-by-antrea-agent)
      - [5. Run kubeadm to join the Node](#5-run-kubeadm-to-join-the-node)
      - [Verify your installation](#verify-your-installation)
  - [Installation as a Service](#installation-as-a-service)
  - [Installation as a Pod using wins for Docker (DEPRECATED)](#installation-as-a-pod-using-wins-for-docker-deprecated)
    - [Add Windows antrea-agent DaemonSet](#add-windows-antrea-agent-daemonset-1)
    - [Join Windows worker Nodes](#join-windows-worker-nodes-1)
  - [Add Windows kube-proxy DaemonSet (only for Kubernetes versions prior to 1.26)](#add-windows-kube-proxy-daemonset-only-for-kubernetes-versions-prior-to-126)
    - [Common steps](#common-steps)
    - [For containerd](#for-containerd)
    - [For Docker](#for-docker)
  - [Manually run kube-proxy and antrea-agent on Windows worker Nodes](#manually-run-kube-proxy-and-antrea-agent-on-windows-worker-nodes)
- [Known issues](#known-issues)
<!-- /toc -->

## Overview

Antrea supports Windows worker Nodes. On Windows Nodes, Antrea sets up an overlay
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
We also support running OVS processes inside a container. If you don't want to
run antrea-agent and kube-proxy from the management Pods Antrea also provides
scripts which help to install and run these two components directly without Pod.
Please see [Manually run kube-proxy and antrea-agent on Windows worker Nodes](#manually-run-kube-proxy-and-antrea-agent-on-windows-worker-nodes)
section for details.

### Antrea Windows demo

Watch this [demo video](https://www.youtube.com/watch?v=NjeVPGgaNFU) of running
Antrea in a Kubernetes cluster with both Linux and Windows Nodes. The demo also
shows the Antrea OVS bridge configuration on a Windows Node, and NetworkPolicy
enforcement for Windows Pods. Note, OVS driver and daemons are pre-installed on
the Windows Nodes in the demo.

## Deploying Antrea on Windows worker Nodes

Running Antrea on Windows Nodes requires the containerd container runtime. The
recommended installation method is [Installation as a
Pod](#installation-as-a-pod), and it requires containerd 1.6 or higher. If you
prefer running the Antrea Agent as a Windows service, or if you are using
containerd 1.5, you can use the [Installation as a
Service](#installation-as-a-service) method.

Note that [Docker support](#installation-as-a-pod-using-wins-for-docker-deprecated)
is deprecated. We no longer test Antrea support with Docker on Windows, and the
installation method will be removed from the documentation in a later release.

### Prerequisites

* Create a Kubernetes cluster.
* Obtain a Windows Server 2019 license (or higher) in order to configure the
  Windows Nodes that will host Windows containers. And install the latest
  Windows updates.
* On each Windows Node, install the following:
  - [Hyper-V](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-the-hyper-v-role-on-windows-server)
    with management tools. If your Nodes do not have the virtualization
    capabilities required by Hyper-V, use the workaround described in the
    [Known issues](#known-issues) section.
  - [containerd](https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=containerd#windows-server-1).

### Installation as a Pod

This installation method requires Antrea 1.10 or higher, and containerd 1.6 or
higher (containerd 1.7 or higher is recommended). It relies on support for
[Windows HostProcess Pods](https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/),
which is generally available starting with K8s 1.26.

Starting with Antrea v1.13, Antrea will take over all the responsibilities of
kube-proxy for Windows nodes by default. Since Kubernetes 1.26, kube-proxy
should not be deployed on Windows Nodes with Antrea, as kube-proxy userspace
mode is deprecated. For Kubernetes versions prior to 1.26, Antrea can work
with userspace kube-proxy on Windows Nodes.
For more information refer to section [Add Windows kube-proxy DaemonSet (only for Kubernetes versions prior to 1.26)](#add-windows-kube-proxy-daemonset-only-for-kubernetes-versions-prior-to-126)

#### Download & Configure Antrea for Linux

Deploy Antrea for Linux on the control-plane Node following [Getting started](getting-started.md)
document. The following command deploys Antrea with the version specified by `<TAG>`:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

#### Add Windows antrea-agent DaemonSet

Starting from Antrea 1.13, you need to manually set the `kubeAPIServerOverride`
field in the YAML configuration file as the Antrea Proxy `proxyAll` mode is
enabled by default.

```yaml
    # Provide the address of Kubernetes apiserver, to override any value provided in kubeconfig or InClusterConfig.
    # Defaults to "". It must be a host string, a host:port pair, or a URL to the base of the apiserver.
    kubeAPIServerOverride: "10.10.1.1:6443"

    # Option antreaProxy contains AntreaProxy related configuration options.
    antreaProxy:
      # ProxyAll tells antrea-agent to proxy ClusterIP Service traffic, regardless of where they come from.
      # Therefore, running kube-proxy is no longer required. This requires the AntreaProxy feature to be enabled.
      # Note that this option is experimental. If kube-proxy is removed, option kubeAPIServerOverride must be used to access
      # apiserver directly.
      proxyAll: true
```

For earlier versions of Antrea, you will need to enable `proxyAll` manually.

Starting with Antrea 1.13, you can run both the Antrea Agent and the OVS daemons
on Windows Nodes using a single DaemonSet, by applying the file
`antrea-windows-containerd-with-ovs.yml`. This is the recommended installation
method. The following commands download the manifest, set
`kubeAPIServerOverride`, and create the DaemonSet:

```bash
KUBE_APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}') && \
curl -sL https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-windows-containerd-with-ovs.yml | \
sed "s|.*kubeAPIServerOverride: \"\"|    kubeAPIServerOverride: \"${KUBE_APISERVER}\"|g" | \
kubectl apply -f -
```

Alternatively, to deploy the antrea-agent Windows DaemonSet without the OVS
daemons, apply the file `antrea-windows-containerd.yml` with the following
commands:

```bash
KUBE_APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}') && \
curl -sL https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-windows-containerd.yml | \
sed "s|.*kubeAPIServerOverride: \"\"|    kubeAPIServerOverride: \"${KUBE_APISERVER}\"|g" | \
kubectl apply -f -
```

When using `antrea-windows-containerd.yml`, you will need to install OVS
userspace daemons as services when you prepare your Windows worker Nodes, in the
next section.

#### Join Windows worker Nodes

##### 1. (Optional) Install OVS (provided by Antrea or your own)

Depending on which method you are using to install Antrea on Windows, and
depending on whether you are using your own [signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
OVS kernel driver or you want to use the test-signed driver provided by Antrea,
you will need to invoke the `Install-OVS.ps1` script differently (or not at all).

| Containerized OVS daemons? | Test-signed OVS driver? | Run this command |
| -------------------------- | ----------------------- | ---------------- |
| Yes                        | Yes                     | `.\Install-OVS.ps1 -InstallUserspace $false` |
| Yes                        | No                      | N/A |
| No                         | Yes                     | `.\Install-OVS.ps1` |
| No                         | No                      | `.\Install-OVS.ps1 -ImportCertificate $false -Local -LocalFile <PathToOVSPackage>` |

If you used `antrea-windows-containerd-with-ovs.yml` to create the antrea-agent
Windows DaemonSet, then you are using "Containerized OVS daemons". For all other
methods, you are *not* using "Containerized OVS daemons".

Antrea provides a pre-built OVS package which contains a test-signed OVS kernel
driver. If you don't have a self-signed OVS package and just want to try Antrea
on Windows, this package can be used for testing.

**[Test-only]** If you are using test-signed driver (such as the one provided with Antrea),
please make sure to [enable test-signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option):

```powershell
Bcdedit.exe -set TESTSIGNING ON
Restart-Computer
```

As an example, if you are using containerized OVS
(`antrea-windows-containerd-with-ovs.yml`), and you want to use the test-signed
OVS kernel driver provided by Antrea (not recommended for production), you would
run the following commands:

```powershell
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Install-OVS.ps1
.\Install-OVS.ps1 -InstallUserspace $false
```

And, if you want to run OVS as Windows native services, and you are bringing
your own OVS package with a signed OVS kernel driver, you would run:

```powershell
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Install-OVS.ps1
.\Install-OVS.ps1 -ImportCertificate $false -Local -LocalFile <PathToOVSPackage>

# verify that the OVS services are installed
get-service ovsdb-server
get-service ovs-vswitchd
```

##### 2. Disable Windows Firewall

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

##### 3. Install kubelet, kubeadm and configure kubelet startup params

Firstly, install kubelet and kubeadm using the provided `PrepareNode.ps1`
script. Specify the Node IP, Kubernetes Version and container runtime while
running the script. The following command downloads and executes
`Prepare-Node.ps1`:

```powershell
# Example:
curl.exe -LO "https://raw.githubusercontent.com/antrea-io/antrea/main/hack/windows/Prepare-Node.ps1"
.\Prepare-Node.ps1 -KubernetesVersion v1.29.0 -NodeIP 192.168.1.10
```

##### 4. Prepare Node environment needed by antrea-agent

Run the following commands to prepare the Node environment needed by antrea-agent:

```powershell
mkdir c:\k\antrea
cd c:\k\antrea
$TAG="v1.14.0"
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/${TAG}/hack/windows/Clean-AntreaNetwork.ps1
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/${TAG}/hack/windows/Prepare-ServiceInterface.ps1
curl.exe -LO https://raw.githubusercontent.com/antrea-io/antrea/${TAG}/hack/windows/Prepare-AntreaAgent.ps1
# use -RunOVSServices $false for containerized OVS!
.\Prepare-AntreaAgent.ps1 -InstallKubeProxy $false [-RunOVSServices $false]
```

The script `Prepare-AntreaAgent.ps1` performs the following tasks:

* Remove stale network resources created by antrea-agent.

    After the Windows Node reboots, there will be stale network resources which
    need to be cleaned before starting antrea-agent.

* Ensure OVS services are running.

    This script starts OVS services on the Node if they are not running. This
    step needs to be skipped in case of OVS containerization. In that case, you
    need to specify the parameter `RunOVSServices` as false.

    ```powershell
    .\Prepare-AntreaAgent.ps1 -InstallKubeProxy $false -RunOVSServices $false
    ```

The script must be executed every time you restart the Node to prepare the
environment for antrea-agent.

You can ensure that the script is executed automatically after each Windows
startup by using different methods. Here are two examples for your reference:

* Example 1: Update kubelet service.

Insert following line in kubelet service script `c:\k\StartKubelet.ps1` to invoke
`Prepare-AntreaAgent.ps1` when starting kubelet service:

```powershell
& C:\k\antrea\Prepare-AntreaAgent.ps1 -InstallKubeProxy $false -RunOVSServices $false
```

* Example 2: Create a ScheduledJob that runs at startup.

```powershell
$trigger = New-JobTrigger -AtStartup -RandomDelay 00:00:30 
$options = New-ScheduledJobOption -RunElevated
Register-ScheduledJob -Name PrepareAntreaAgent -Trigger $trigger  -ScriptBlock { Invoke-Expression C:\k\antrea\Prepare-AntreaAgent.ps1 -InstallKubeProxy $false -RunOVSServices $false } -ScheduledJobOption $options
```

##### 5. Run kubeadm to join the Node

On Windows Nodes, run the `kubeadm join` command to join the cluster. The token
is provided by the control-plane Node. If you lost the token, or the token has
expired, you can run `kubeadm token create --print-join-command` (on the
control-plane Node) to generate a new token and join command. An example
`kubeadm join` command is like below:

```powershell
kubeadm join 192.168.101.5:6443 --token tdp0jt.rshv3uobkuoobb4v  --discovery-token-ca-cert-hash sha256:84a163e57bf470f18565e44eaa2a657bed4da9748b441e9643ac856a274a30b9
```

##### Verify your installation

There will be temporary network interruption on Windows worker Node on the
first startup of antrea-agent. It's because antrea-agent will set the OVS to
take over the host network. After that you should be able to view the Windows
Nodes and Pods in your cluster by running:

```bash
# Show Nodes
kubectl get nodes -o wide -n kube-system
NAME                           STATUS   ROLES           AGE   VERSION   INTERNAL-IP     EXTERNAL-IP   OS-IMAGE                         KERNEL-VERSION       CONTAINER-RUNTIME
control-plane                  Ready    control-plane   1h    v1.29.0   10.176.27.168   <none>        Ubuntu 22.04.3 LTS               6.2.0-1017-generic   containerd://1.6.26
win-5akrf2tpq91                Ready    <none>          1h    v1.29.0   10.176.27.150   <none>        Windows Server 2019 Datacenter   10.0.17763.5206      containerd://1.6.6
win-5akrf2tpq92                Ready    <none>          1h    v1.29.0   10.176.27.197   <none>        Windows Server 2019 Datacenter   10.0.17763.5206      containerd://1.6.6

# Show antrea-agent and kube-proxy Pods
kubectl get pods -o wide -n kube-system | grep windows
antrea-agent-windows-6hvkw                             1/1     Running     0          100s
kube-proxy-windows-2d45w                               1/1     Running     0          102s
```

### Installation as a Service

Install Antrea (v0.13.0+ is required for containerd) as usual. The following
command deploys Antrea with the version specified by `<TAG>`:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

When running the Antrea Agent as a Windows service, no DaemonSet is created for
Windows worker Nodes. You will need to ensure that [nssm](https://nssm.cc/) is
installed on all your Windows Nodes. `nssm` is a handy tool to manage services
on Windows.

To prepare your Windows worker Nodes, follow the steps in [Join Windows worker Nodes](#join-windows-worker-nodes).
With this installation method, OVS daemons are always run as services (not
containerized), and you will need to run `Install-OVS.ps1` to install them.

When your Nodes are ready, run the following scripts to install the antrea-agent
service. NOTE: `<KubernetesVersion>`, `<KubeconfigPath>` and
`<KubeletKubeconfigPath>` should be set by you. `<KubeProxyKubeconfigPath>` is
an optional parameter that is specific to kube-proxy mode. For example:

```powershell
# kube-proxy mode is no longer supported starting with K8s version 1.26
$InstallKubeProxy=$false
$KubernetesVersion="v1.23.5"
$KubeConfig="C:/Users/Administrator/.kube/config" # admin kubeconfig
$KubeletKubeconfigPath="C:/etc/kubernetes/kubelet.conf"
if ($InstallKubeProxy) { $KubeProxyKubeconfigPath="C:/Users/Administrator/kubeproxy.conf" }
```

```powershell
$TAG="v1.14.0"
$KubernetesVersion="<KubernetesVersion>"
$KubeConfig="<KubeconfigPath>"
$KubeletKubeconfigPath="<KubeletKubeconfigPath>"
if ($InstallKubeProxy) { $KubeProxyKubeconfigPath="<KubeProxyKubeconfigPath>" }
$KubernetesHome="c:/k"
$AntreaHome="c:/k/antrea"
$KubeProxyLogPath="c:/var/log/kube-proxy"

curl.exe -LO "https://raw.githubusercontent.com/antrea-io/antrea/${TAG}/hack/windows/Helper.psm1"
Import-Module ./Helper.psm1

Install-AntreaAgent -KubernetesVersion "$KubernetesVersion" -KubernetesHome "$KubernetesHome" -KubeConfig "$KubeConfig" -AntreaVersion "$TAG" -AntreaHome "$AntreaHome"
New-KubeProxyServiceInterface

New-DirectoryIfNotExist "${AntreaHome}/logs"
New-DirectoryIfNotExist "${KubeProxyLogPath}"
# Install kube-proxy service
if ($InstallKubeProxy) { nssm install kube-proxy "${KubernetesHome}/kube-proxy.exe" "--proxy-mode=userspace --kubeconfig=${KubeProxyKubeconfigPath} --log-dir=${KubeProxyLogPath} --logtostderr=false --alsologtostderr" }
nssm install antrea-agent "${AntreaHome}/bin/antrea-agent.exe" "--config=${AntreaHome}/etc/antrea-agent.conf --logtostderr=false --log_dir=${AntreaHome}/logs --alsologtostderr --log_file_max_size=100 --log_file_max_num=4"

nssm set antrea-agent DependOnService ovs-vswitchd
if ($InstallKubeProxy) { nssm set antrea-agent DependOnService kube-proxy ovs-vswitchd }
nssm set antrea-agent Start SERVICE_DELAYED_AUTO_START

if ($InstallKubeProxy) { Start-Service kube-proxy }
Start-Service antrea-agent
```

### Installation as a Pod using wins for Docker (DEPRECATED)

*Dockershim was deprecated in K8s 1.20, and removed in K8s version 1.24. These
 steps may work with [cri-dockerd](https://github.com/Mirantis/cri-dockerd) but
 this is not something we validated. Antrea is no longer tested with Docker on
 Windows, and we intend to remove these steps from the documentation in Antrea
 version 2.0.*

Running Antrea with Docker on Windows uses
[wins](https://github.com/rancher/wins), which lets you run services on the
Window hosts, while managing them as if they were Pods.

#### Add Windows antrea-agent DaemonSet

For example, these commands will download the antrea-agent manifest, set
`kubeAPIServerOverride`, and deploy the antrea-agent DaemonSet when using the
Docker container runtime:

```bash
KUBE_APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}') && \
curl -sL https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-windows.yml | \
sed "s|.*kubeAPIServerOverride: \"\"|    kubeAPIServerOverride: \"${KUBE_APISERVER}\"|g" | \
kubectl apply -f -
```

#### Join Windows worker Nodes

The steps to join Windows worker Nodes are similar to the ones for the
containerd runtime, with the following differences:

1. OVS containerization is not supported, so OVS userspace processes need to be
   run as Windows native services.
2. When running the `Prepare-Node.ps1` script, you will need to explicitly
   specify that you are using the Docker container runtime. The script will then
   take care of installing wins. For example:

   ```powershell
   .\Prepare-Node.ps1 -KubernetesVersion v1.23.5 -NodeIP 192.168.1.10 -ContainerRuntime docker
   ```

If you want to install and use userspace kube-proxy on the Node (no longer
supported since K8s version 1.26), follow instructions in [Add Windows
kube-proxy DaemonSet (only for Kubernetes versions prior to 1.26)](#add-windows-kube-proxy-daemonset-only-for-kubernetes-versions-prior-to-126).

### Add Windows kube-proxy DaemonSet (only for Kubernetes versions prior to 1.26)

Starting from Kubernetes 1.26, Antrea no longer supports Windows kube-proxy
because the kube-proxy userspace mode has been removed, and the kernel
implementation does not work with Antrea. Clusters using recent K8s versions
will need to follow the normal [installation guide](#deploying-antrea-on-windows-worker-nodes)
and use AntreaProxy with `proxyAll` enabled.

For older K8s versions, you can use kube-proxy userspace mode by following the
instructions below.

#### Common steps

When running `Prepare-Node.ps1`, make sure that you set `InstallKubeProxy` to
true. For example:

```powershell
.\Prepare-Node.ps1 -KubernetesVersion v1.25.0 -InstallKubeProxy:$true -NodeIP 192.168.1.10
```

When running `Prepare-AntreaAgent.ps1`, make sure that you set
`InstallKubeProxy` to true. For example:

```powershell
.\Prepare-AntreaAgent.ps1 -InstallKubeProxy $true`
```

This will take care of preparing the network adapter for kube-proxy. kube-proxy
needs a network adapter to configure Kubernetes Services IPs and uses the
adapter for proxying connections to Services. The adapter will be deleted
automatically by Windows after the Windows Node reboots
(`Prepare-AntreaAgent.ps1` needs to run at every startup).

After that, you will need to deploy a Windows-compatible version of
kube-proxy. You can download `kube-proxy.yml` from the Kubernetes github
repository to deploy kube-proxy. The kube-proxy version in the YAML file must be
set to a Windows compatible version. The following command downloads
`kube-proxy.yml`:

```bash
curl -L "https://github.com/kubernetes-sigs/sig-windows-tools/releases/download/v0.1.5/kube-proxy.yml" | sed 's/VERSION-nanoserver/v1.20.0/g' > kube-proxy.yml
```

Before applying the downloaded manifest, you will need to make some changes
(which depend on your container runtime).

#### For containerd

Replace the content of `run-script.ps1` in the `kube-proxy-windows` ConfigMap
with the following:

```yaml
apiVersion: v1
data:
  run-script.ps1: |-
    $mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
    $mountPath =  ($mountPath.Replace('\', '/')).TrimEnd('/') 
    New-Item -Path "c:/var/lib" -Name "kube-proxy" -ItemType "directory" -Force
    ((Get-Content -path $mountPath/var/lib/kube-proxy/kubeconfig.conf -Raw) -replace '/var',"$($mountPath)/var") | Set-Content -Path /var/lib/kube-proxy/kubeconfig.conf
    ((Get-Content -path /var/lib/kube-proxy/kubeconfig.conf -Raw) -replace '\/',"/") | Set-Content -Path /var/lib/kube-proxy/kubeconfig.conf
    sed -i 's/mode: iptables/mode: \"\"/g' $mountPath/var/lib/kube-proxy/config.conf
    & "$mountPath/k/kube-proxy/kube-proxy.exe" --config=$mountPath/var/lib/kube-proxy/config.conf --v=10 --proxy-mode=userspace --hostname-override=$env:NODE_NAME
kind: ConfigMap
metadata:
  labels:
    app: kube-proxy
  name: kube-proxy-windows
  namespace: kube-system
```

Set the `hostNetwork` option to `true` and add the following to the
kube-proxy-windows DaemonSet spec:

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
      securityContext:
        windowsOptions:
          hostProcess: true
          runAsUserName: "NT AUTHORITY\\SYSTEM"
      hostNetwork: true
      serviceAccountName: kube-proxy
      containers:
      - command:
        - pwsh
        args:
        - -file
        - $env:CONTAINER_SANDBOX_MOUNT_POINT/var/lib/kube-proxy-windows/run-script.ps1
```

#### For Docker

Replace the content of `run-script.ps1` in the `kube-proxy-windows` ConfigMap
with the following:

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

Set the `hostNetwork` option to `true` in the spec of kube-proxy-windows
DaemonSet spec:

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

### Manually run kube-proxy and antrea-agent on Windows worker Nodes

Aside from starting kube-proxy and antrea-agent from the management Pods, Antrea
also provides powershell scripts which help install and run these two components
directly without Pods. Please complete the steps in
[Installation](#installation-as-a-pod) section, and skip the
[Add Windows antrea-agent DaemonSet](#add-windows-antrea-agent-daemonset) step.
Then run the following commands in powershell.

```powershell
mkdir c:\k\antrea
cd c:\k\antrea
curl.exe -LO https://github.com/antrea-io/antrea/releases/download/<TAG>/Start-AntreaAgent.ps1
# Run antrea-agent without kube-proxy
# $KubeConfigPath is the path of kubeconfig file
./Start-AntreaAgent.ps1 -kubeconfig $KubeConfigPath -StartKubeProxy $false
# Run Antrea-Agent with kube-proxy (deprecated since Kubernetes 1.26)
# ./Start-AntreaAgent.ps1 -kubeconfig $KubeConfigPath -StartKubeProxy $true
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

    ```powershell
    # If OVS userspace processes were running as a Service on Windows host
    ./Clean-AntreaNetwork.ps1 -OVSRunMode "service"
    # If OVS userspace processes were running inside container in antrea-agent Pod
    ./Clean-AntreaNetwork.ps1 -OVSRunMode "container"
    ```  

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
