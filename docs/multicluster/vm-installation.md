# Deploying antrea-agent on VM

Antrea-agent can be run on Linux/Windows VMs. Below are the steps needed to configure and run antrea-agent on VMs

## Prerequisites on cluster
1. Create a name-space for the antrea agent
2. Create a service account, cluster role and cluster role bindings for antrea agent.
```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/feature/externalnode/build/yamls/externalnode/vm-agent-rbac.yaml
```
2. Create antrea-agent.kubeconfig file to access K8S API service
```bash
export CLUSTER_NAME=<cluster-name>
export SERVICE_ACCOUNT=<service-account-name>
APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")
TOKEN=$(kubectl -n kube-system get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='$SERVICE_ACCOUNT')].data.token}"|base64 --decode)
kubectl config --kubeconfig=antrea-agent.kubeconfig set-cluster kubernetes --server=$APISERVER --insecure-skip-tls-verify=true
kubectl config --kubeconfig=antrea-agent.kubeconfig set-credentials antrea-agent --token=$TOKEN
kubectl config --kubeconfig=antrea-agent.kubeconfig set-context antrea-agent@kubernetes --cluster=kubernetes --user=antrea-agent
kubectl config --kubeconfig=antrea-agent.kubeconfig use-context antrea-agent@kubernetes
```
3. Create antrea-agent.antrea.kubeconfig file to access antrea controller API service
```bash
export ANTREA_API_SERVER=<Antrea API service endpoint>
TOKEN=$(kubectl -n kube-system get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='$SERVICE_ACCOUNT')].data.token}"|base64 --decode)
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-cluster antrea --server=$ANTREA_API_SERVER --insecure-skip-tls-verify=true
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-credentials antrea-agent --token=$TOKEN
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-context antrea-agent@antrea --cluster=antrea --user=antrea-agent
kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig use-context antrea-agent@antrea
```
4. The antrea-agent configuration file specifies the agent configuration parameters. For all the agent configuration parameters of VM, refer to this [base configuration file](https://raw.githubusercontent.com/antrea-io/antrea/feature/externalnode/build/yamls/externalnode/conf/antrea-agent.conf).
Update clientConnection and antreaClientConnection with corresponding kubeconfig file path.

## Prerequisites on Linux VM
1. OVS needs to be installed. Please refer [Openvswitch](https://github.com/antrea-io/antrea/blob/main/docs/getting-started.md#open-vswitch)

## Running antrea-agent on Linux VM
1. Compile antrea-agent for Linux
```bash
make docker-bin
make antctl
```
2. Create antrea-agent service. Below is a sample snippet to start antrea-agent as a service on Ubuntu
```bash
Description="antrea-agent as a systemd service"
After=network.target
[Service]
ExecStart=/usr/sbin/antrea-agent \
--config=/var/run/antrea/antrea-agent.conf \
--logtostderr=false \
--log_file=/var/log/antrea/antrea-agent.log
Restart=on-failure
[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reload
sudo systemctl enable antrea-agent
sudo systemclt start antrea-agent
```

## Prerequisites on Windows VM
1. OVS needs to be installed. Please refer [Install OVS](https://github.com/antrea-io/antrea/blob/main/docs/windows.md#1-optional-install-ovs-provided-by-antrea-or-your-own)
2. Enable Hyper-V on Windows VM.
```powershell
Install-WindowsFeature Hyper-V-Powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
```

## Running antrea-agent on Windows VM
1. Compile antrea-agent for Windows
```powershell
make docker-windows-bin
make antctl
```
2. Create antrea-agent service. Below is a sample snippet to start antrea-agent as a service on Windows
```powershell
nssm install antrea-agent --config C:\antrea-agent\antrea-agent.conf --log_file C:\cygwin\tmp\antrea-agent.log --logtostderr=false
nssm start antrea-agent
```