# Antrea Agent installation on VM

Antrea Agent can run on a Linux or Windows VM, and enforce Antrea NetworkPolicies on the VM. This document describes
the steps needed to configure and run `antrea-agent` on VMs.

## Prerequisites on Kubernetes cluster

1. Enable `ExternalNode` feature on the `antrea-controller`.
2. Create a NameSpace for `antrea-agent`. This document will use `vm-ns` as an example NameSpace for illustration.

```bash
kubectl create ns vm-ns
```

3. Create a ServiceAccount, ClusterRole and ClusterRoleBinding for `antrea-agent` as shown below. If you use a different
   Namespace other than `vm-ns`, you need to update the [VM RBAC manifest](../build/yamls/externalnode/vm-agent-rbac.yml)
   and change `vm-ns` to the right Namespace.

```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/feature/externalnode/build/yamls/externalnode/vm-agent-rbac.yml
```

4. Create `antrea-agent.kubeconfig` file for `antrea-agent` to access the K8S API server.

```bash
export CLUSTER_NAME="kubernetes"
export SERVICE_ACCOUNT="vm-agent"
APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")
TOKEN=$(kubectl -n vm-ns get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='$SERVICE_ACCOUNT')].data.token}"|base64 --decode)
kubectl config --kubeconfig=antrea-agent.kubeconfig set-cluster $CLUSTER_NAME --server=$APISERVER --insecure-skip-tls-verify=true
kubectl config --kubeconfig=antrea-agent.kubeconfig set-credentials antrea-agent --token=$TOKEN
kubectl config --kubeconfig=antrea-agent.kubeconfig set-context antrea-agent@$CLUSTER_NAME --cluster=$CLUSTER_NAME --user=antrea-agent
kubectl config --kubeconfig=antrea-agent.kubeconfig use-context antrea-agent@$CLUSTER_NAME
# Copy antrea-agent.kubeconfig to the VM
```

5. Create `antrea-agent.antrea.kubeconfig` file for `antrea-agent` to access the `antrea-controller` API server.

```bash
# Specify the antrea-controller API server endpoint. Antrea-Controller needs to be exposed via the Node IP or a
# public IP that is reachable from the VM
export ANTREA_API_SERVER="https://172.18.0.1:443"
export ANTREA_CLUSTER_NAME="antrea"
TOKEN=$(kubectl -n vm-ns get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='$SERVICE_ACCOUNT')].data.token}"|base64 --decode)
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-cluster $ANTREA_CLUSTER_NAME --server=$ANTREA_API_SERVER --insecure-skip-tls-verify=true
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-credentials antrea-agent --token=$TOKEN
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-context antrea-agent@$ANTREA_CLUSTER_NAME --cluster=$ANTREA_CLUSTER_NAME --user=antrea-agent
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig use-context antrea-agent@$ANTREA_CLUSTER_NAME
# Copy antrea-agent.antrea.kubeconfig to the VM
```

## Installation on Linux VM

### Prerequisites

OVS needs to be installed on the VM. For more information about OVS installation please refer to the [getting-started guide](getting-started.md#open-vswitch).

### Installation

1. Build `antrea-agent` binary in the root of the antrea code tree and copy the `antrea-agent` binary from the `bin`
   directory to the Linux VM.

```bash
make docker-bin
```

2. The `antrea-agent.conf` file specifies agent configuration parameters. Copy the [agent configuration file](../build/yamls/externalnode/conf/antrea-agent.conf)
   to the VM and edit the `antrea-agent.conf` file to set `clientConnection`, `antreaClientConnection` and
   `externalNodeNamespace` with the correct values. Copy `antrea-agent.antrea.kubeconfig` and `antrea-agent.kubeconfig`
   files to the VM, that were generated in the step 4 and step 5 of [Prerequisites on Kubernetes cluster](vm-installation.md#prerequisites-on-kubernetes-cluster).

```bash
AGENT_NAMESPACE="vm-ns"
AGENT_CONF_PATH="/etc/antrea"
mkdir -p $AGENT_CONF_PATH
# Copy antrea-agent kubeconfig files
cp ./antrea-agent.kubeconfig $AGENT_CONF_PATH
cp ./antrea-agent.antrea.kubeconfig $AGENT_CONF_PATH
# Update clientConnection and antreaClientConnection
sed -i "s|kubeconfig: |kubeconfig: $AGENT_CONF_PATH/|g" antrea-agent.conf
sed -i "s|#externalNodeNamespace: default|externalNodeNamespace: $AGENT_NAMESPACE|g" antrea-agent.conf
# Copy antrea-agent configuration file
cp ./antrea-agent.conf $AGENT_CONF_PATH
```

3. Create `antrea-agent` service. Below is a sample snippet to start `antrea-agent` as a service on Ubuntu 18.04 or
   later:

```bash
AGENT_BIN_PATH="/usr/sbin"
AGENT_LOG_PATH="/var/log/antrea"
mkdir -p $AGENT_BIN_PATH
mkdir -p $AGENT_LOG_PATH
cat << EOF > /etc/systemd/system/antrea-agent.service
Description="antrea-agent as a systemd service"
After=network.target
[Service]
ExecStart=$AGENT_BIN_PATH/antrea-agent \
--config=$AGENT_CONF_PATH/antrea-agent.conf \
--logtostderr=false \
--log_file=$AGENT_LOG_PATH/antrea-agent.log
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable antrea-agent
sudo systemctl start antrea-agent
```

## Installation on Windows VM

### Prerequisites

1. Enable the Windows Hyper-V optional feature on Windows VM.

```powershell
Install-WindowsFeature Hyper-V-Powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
```

2. OVS needs to be installed on the VM. For more information about OVS installation please refer to the [Antrea Windows documentation](windows.md#1-optional-install-ovs-provided-by-antrea-or-your-own).
3. Download [nssm](https://nssm.cc/download) which will be used to create the Windows service for `antrea-agent`.

Note: Only Windows Server 2019 is supported in the first release at the moment.

### Installation

1. Build `antrea-agent` binary in the root of the antrea code tree and copy the `antrea-agent` binary from the `bin`
   directory to the Windows VM.

```bash
#! /bin/bash
make docker-windows-bin
```

2. Copy `antrea-agent.conf`, `antrea-agent.kubeconfig` and `antrea-agent.antrea.kubeconfig` files to the VM. Please
   refer to the step 2 of [Installation on Linux VM](vm-installation.md#installation) section for more information.

```powershell
$WIN_AGENT_CONF_PATH="C:\antrea-agent\conf"
New-Item -ItemType Directory -Force -Path $WIN_AGENT_CONF_PATH
# Copy antrea-agent kubeconfig files
Copy-Item .\antrea-agent.kubeconfig $WIN_AGENT_CONF_PATH
Copy-Item .\antrea-agent.antrea.kubeconfig $WIN_AGENT_CONF_PATH
# Copy antrea-agent configuration file
Copy-Item .\antrea-agent.conf $WIN_AGENT_CONF_PATH
```

3. Create `antrea-agent` service using nssm. Below is a sample snippet to start `antrea-agent` as a service:

```powershell
$WIN_AGENT_BIN_PATH="C:\antrea-agent"
$WIN_AGENT_LOG_PATH="C:\antrea-agent\logs"
New-Item -ItemType Directory -Force -Path $WIN_AGENT_BIN_PATH
New-Item -ItemType Directory -Force -Path $WIN_AGENT_LOG_PATH
Copy-Item .\antrea-agent.exe $WIN_AGENT_BIN_PATH
nssm.exe install antrea-agent $WIN_AGENT_BIN_PATH\antrea-agent.exe --config $WIN_AGENT_CONF_PATH\antrea-agent.conf --log_file $WIN_AGENT_LOG_PATH\antrea-agent.log --logtostderr=false
nssm.exe start antrea-agent
```