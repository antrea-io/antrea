# Deploying Antrea on Windows

## Overview
Antrea supports Windows worker Node. On Windows Node, Antrea sets up an overlay
network to forward packets between Nodes and implements NetworkPolicies. Currently
Geneve, VXLAN, and STT tunnels are supported.

This page shows how to install antrea-agent on Windows Nodes and register the
Node to an existing Kubernetes cluster.

For the detailed design of how antrea-agent works on Windows, please refer to
the [design doc](/docs/windows-design.md).

### Components that run on Windows

The following components should be configured and run on the Windows Node.
* [kubernetes components](https://kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/)
* OVS daemons
* antrea-agent
* kube-proxy

antrea-agent and kube-proxy run as processes on host and are managed by
management Pods. It is recommended to run OVS daemons as Windows services.

## Deploying Antrea on Windows Worker Node

### Prerequisites
* Obtain a Windows Server 2019 license (or higher) in order to configure the
  Windows Node that hosts Windows containers. And install the latest Windows
  updates.
* Deploy a Linux-based Kubernetes cluster.
* Install [Hyper-V](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-the-hyper-v-role-on-windows-server)
  with management tools.
* Install [Docker](https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server).
* [Install OVS](http://docs.openvswitch.org/en/latest/intro/install/windows/)
  and configure the daemons as Windows service.
    * The kernel driver of OVS should be [signed by Windows Hardware Dev Center](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing).
    * If OVS driver is not signed, please refer to the Windows doc about how to
      [install a test-signed driver package on the test computer](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-a-test-signed-driver-package-on-the-test-computer).
    * If you don't have a self-signed OVS package and just want to try the
      Antrea on windows, Antrea provides a test-signed OVS package for you.
      See details in [Join Windows worker Nodes](#Join-Windows-worker-nodes)
      section.

### Installation
#### Download & Configure Antrea for Linux
Configure the Antrea for Linux on master Node following [Getting started](/docs/getting-started.md)
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

    wins cli process run --path /k/kube-proxy/kube-proxy.exe --args "--v=4 --config=/var/lib/kube-proxy/config.conf --proxy-mode=userspace --hostname-override=$env:NODE_NAME"

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
```
# Example:
kubectl apply -f https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea-windows.yml
```

#### Join Windows worker Nodes
1. (Optional, Test-Only) Install OVS provided by Antrea

Antrea provides a pre-built OVS package which contains test-signed OVS kernel
driver. If you don't have a self-signed OVS package and just want to try the
Antrea on windows, this package can be used for testing. We also provide a help 
script to install the OVS driver and register userspace binaries as services.

Firstly, please make sure to [enable test-signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
code on Windows Nodes.

```powershell
Bcdedit.exe -set TESTSIGNING ON
Restart-Computer
```

Then, install the OVS using the script.

```powershell
curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/master/hack/windows/Install-OVS.ps1
.\Install-OVS.ps1
```

Verify the OVS services are installed.

```powershell
get-service ovsdb-server
get-service ovs-vswitchd
```

2. Disable Windows Firewall

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

3. Install wins, kubelet, kubeadm and configure kubelet startup params

Firstly, install wins, kubelet, kubeadm using script `PrepareNode.ps1` provided
by kubernetes. The third component [`wins`](https://github.com/rancher/wins) is
used to run kube-proxy and antrea-agent on Windows host inside the Windows
container.

```powershell
# Example:
curl.exe -LO https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/PrepareNode.ps1
.\PrepareNode.ps1 -KubernetesVersion v1.18.0
```

4. Prepare network adapter for kube-proxy

kube-proxy needs a network adapter to configure Kubernetes Service IPs and uses
the adapter for proxying connections to Service. Use following script to create the network
adapter.

```powershell
curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/master/hack/windows/Prepare-ServiceInterface.ps1
.\Prepare-ServiceInterface.ps1
```

> Note: The interface will be deleted automatically by Windows after Windows
> Node reboots. So the script needs to be executed after rebooting the Node.

5. Run kubeadm to join the Node

On Windows Node, run the `kubeadm join` command to join the cluster. The token 
is provided by the master Node.

If you forgot the token, or the token has expired, you can run
`kubeadm token create --print-join-command` (on the master Node) to
generate a new token and join command.

```bash
# Example:
kubeadm join 192.168.101.5:6443 --token tdp0jt.rshv3uobkuoobb4v  --discovery-token-ca-cert-hash sha256:84a163e57bf470f18565e44eaa2a657bed4da9748b441e9643ac856a274a30b9
```

Then, set the Node IP used by kubelet.
Open file `/var/lib/kubelet/kubeadm-flags.env`:

```bash
KUBELET_KUBEADM_ARGS="--cgroup-driver= --network-plugin=cni --pod-infra-container-image=k8s.gcr.io/pause:3.1"
```

Append `--node-ip=$NODE_IP` at the end of params. Replace `$NODE_IP` with
the address for kubelet. It should look like:

```bash
KUBELET_KUBEADM_ARGS="--cgroup-driver= --network-plugin=cni --pod-infra-container-image=k8s.gcr.io/pause:3.1 --node-ip=$NODE_IP"
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
# Show nodes
kubectl get nodes -o wide -nkube-system
NAME                           STATUS   ROLES    AGE    VERSION   INTERNAL-IP     EXTERNAL-IP   OS-IMAGE                                  KERNEL-VERSION     CONTAINER-RUNTIME
master                         Ready    master   1h   v1.18.3   10.176.27.168   <none>        Ubuntu 18.04.3 LTS                        4.15.0-66-generic   docker://19.3.9
win-5akrf2tpq91                Ready    <none>   1h   v1.18.0   10.176.27.150   <none>        Windows Server 2019 Standard Evaluation   10.0.17763.1158    docker://19.3.5
win-5akrf2tpq92                Ready    <none>   1h   v1.18.0   10.176.27.197   <none>        Windows Server 2019 Standard Evaluation   10.0.17763.1158     docker://19.3.5

# Show antrea-agent and kube-proxy pods
kubectl get pods -o wide -nkube-system | grep windows
antrea-agent-windows-6hvkw                             1/1     Running     0          100s
kube-proxy-windows-2d45w                               1/1     Running     0          102s
```


## Known issues
1. HNS Network is not persistent on Windows. So after the Windows Node reboots,
the HNS Network created by antrea-agent is removed, and the Open vSwitch
Extension is disabled by default. In this case, the stale OVS bridge and ports
should be removed. A help script [Clean-AntreaNetwork.ps1](https://raw.githubusercontent.com/tanzu/antrea/master/hack/windows/Clean-AntreaNetwork.ps1)
can be used to clean the OVS bridge.
