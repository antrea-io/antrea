# Deploying Antrea on AKS and AKS Engine

This document describes steps to deploy Antrea to an AKS cluster or an AKS
Engine cluster.

## Deploy Antrea to an AKS cluster

Antrea can be deployed to an AKS cluster either in `networkPolicyOnly` mode or
in `encap` mode.

In `networkPolicyOnly` mode, Antrea enforces NetworkPolicies and implements
other services for the AKS cluster, while the Azure CNI takes care of Pod IPAM
and traffic routing across Nodes. For more information about `networkPolicyOnly`
mode, refer to [this design document](design/policy-only.md).

In `encap` mode, Antrea is in charge of Pod IPAM and of all the networking
functions on the Nodes. Using `encap` mode provides access to additional Antrea
features, such as Multicast, as inter-Node Pod traffic is encapsulated, and is
not handled directly by the Azure Virtual Network. Note that the [caveats](eks-installation.md#deploying-antrea-in-encap-mode)
which apply when deploying Antrea in `encap` mode on EKS do *not* apply for AKS.

We recommend `encap` mode, as it will give you access to the most Antrea
features.

### AKS Prerequisites

Install the Azure Cloud CLI. Refer to [Azure CLI installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)

We recommend using the latest version available (use at least version 2.39.0).

### Deploying Antrea in `networkPolicyOnly` mode

#### Creating the cluster

You can use any method to create an AKS cluster. The example given here is using the Azure Cloud CLI.

1. Create an AKS cluster

    ```bash
    export RESOURCE_GROUP_NAME=aks-antrea-cluster
    export CLUSTER_NAME=aks-antrea-cluster
    export LOCATION=westus

    az group create --name $RESOURCE_GROUP_NAME --location $LOCATION
    az aks create \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $CLUSTER_NAME \
        --node-count 2 \
        --network-plugin azure
    ```

    **Note** Do not specify network-policy option.

2. Get AKS cluster credentials

   ```bash
   az aks get-credentials --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP_NAME
   ```

3. Access your cluster

    ```bash
    kubectl get nodes
    NAME                                STATUS   ROLES   AGE     VERSION
    aks-nodepool1-84330359-vmss000000   Ready    agent   6m21s   v1.16.10
    aks-nodepool1-84330359-vmss000001   Ready    agent   6m25s   v1.16.10
    ```

#### Deploying Antrea

1. Prepare the cluster Nodes

    Deploy ``antrea-node-init`` DaemonSet to enable ``azure cni`` to operate in transparent mode.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-aks-node-init.yml
    ```

2. Deploy Antrea

    To deploy a released version of Antrea, pick a deployment manifest from the
[list of releases](https://github.com/antrea-io/antrea/releases).
Note that AKS support was added in release 0.9.0, which means you cannot
pick a release older than 0.9.0. For any given release `<TAG>` (e.g. `v0.9.0`),
you can deploy Antrea as follows:

    ```bash
    kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-aks.yml
    ```

    To deploy the latest version of Antrea (built from the main branch), use the
checked-in [deployment yaml](../build/yamls/antrea-aks.yml):

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-aks.yml
    ```

    The command will deploy a single replica of Antrea controller to the AKS
cluster and deploy Antrea agent to every Node. After a successful deployment
you should be able to see these Pods running in your cluster:

    ```bash
    $ kubectl get pods --namespace kube-system  -l app=antrea
    NAME                                 READY   STATUS    RESTARTS   AGE
    antrea-agent-bpj72                   2/2     Running   0          40s
    antrea-agent-j2sjz                   2/2     Running   0          40s
    antrea-controller-6f7468cbff-5sk4t   1/1     Running   0          43s
    antrea-node-init-6twqg               1/1     Running   0          2m
    antrea-node-init-mqsqr               1/1     Running   0          2m
    ```

3. Restart remaining Pods

    Once Antrea is up and running, restart all Pods in all Namespaces (kube-system, etc) so they can be managed by Antrea.

    ```bash
    kubectl delete pods -n kube-system $(kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{ print $1 }')
    pod "coredns-544d979687-96xm9" deleted
    pod "coredns-544d979687-p7dfb" deleted
    pod "coredns-autoscaler-78959b4578-849k8" deleted
    pod "dashboard-metrics-scraper-5f44bbb8b5-5qkkx" deleted
    pod "kube-proxy-6qxdw" deleted
    pod "kube-proxy-h6d89" deleted
    pod "kubernetes-dashboard-785654f667-7twsm" deleted
    pod "metrics-server-85c57978c6-pwzcx" deleted
    pod "tunnelfront-649ff5fb55-5lxg7" deleted
    ```

### Deploying Antrea in `encap` mode

AKS now officially supports [Bring your own Container Network Interface (BYOCNI)](https://learn.microsoft.com/en-us/azure/aks/use-byo-cni).
Thanks to this, you can deploy Antrea on AKS in `encap` mode, and you will not
lose access to any functionality. Check the AKS BYOCNI documentation for
prerequisites, in particular for AKS version requirements.

#### Creating the cluster

You can use any method to create an AKS cluster. The example given here is using the Azure Cloud CLI.

1. Create an AKS cluster

    ```bash
    export RESOURCE_GROUP_NAME=aks-antrea-cluster
    export CLUSTER_NAME=aks-antrea-cluster
    export LOCATION=westus

    az group create --name $RESOURCE_GROUP_NAME --location $LOCATION
    az aks create \
        --resource-group $RESOURCE_GROUP_NAME \
        --name $CLUSTER_NAME \
        --node-count 2 \
        --network-plugin none
    ```

    Notice `--network-plugin none`, which tells AKS not to install any CNI plugin.

2. Get AKS cluster credentials

   ```bash
   az aks get-credentials --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP_NAME
   ```

3. Access your cluster

    ```bash
    kubectl get nodes
    NAME                                STATUS     ROLES   AGE   VERSION
    aks-nodepool1-40948307-vmss000000   NotReady   agent   18m   v1.27.7
    aks-nodepool1-40948307-vmss000001   NotReady   agent   17m   v1.27.7
    ```

    The Nodes are supposed to report a `NotReady` Status, since no CNI plugin is
    installed yet.

#### Deploying Antrea

You can use Helm to easily install Antrea (or any other supported installation
method). Just make sure that you configure Antrea NodeIPAM:

```bash
# you may not need this:
helm repo add antrea https://charts.antrea.io
helm repo update

cat <<EOF >> values-aks.yml
nodeIPAM:
  enable: true
  clusterCIDRs: ["10.10.0.0/16"]
EOF

helm install -n kube-system -f values-aks.yml antrea antrea/antrea
```

For more information about how to configure Antrea Node IPAM, please refer to
[Antrea Node IPAM guide](antrea-ipam.md#running-nodeipam-within-antrea-controller).

After a while, make sure that all your Nodes report a `Ready` Status and that
all your Pods are running correctly. Some Pods, and in particular the
`metrics-server` Pods, may restart once after installing Antrea; this is not an
issue.

After a successful installation, Pods should look like this:

```bash
NAMESPACE     NAME                                  READY   STATUS    RESTARTS   AGE
kube-system   antrea-agent-bpskv                    2/2     Running   0          7m34s
kube-system   antrea-agent-pfqrn                    2/2     Running   0          7m34s
kube-system   antrea-controller-555b8c799d-wk8zz    1/1     Running   0          7m34s
kube-system   cloud-node-manager-2nszz              1/1     Running   0          31m
kube-system   cloud-node-manager-wj68q              1/1     Running   0          31m
kube-system   coredns-789789675-2nwd7               1/1     Running   0          6m48s
kube-system   coredns-789789675-lbkfn               1/1     Running   0          31m
kube-system   coredns-autoscaler-649b947bbd-j5wqc   1/1     Running   0          31m
kube-system   csi-azuredisk-node-4bnnl              3/3     Running   0          31m
kube-system   csi-azuredisk-node-52nwd              3/3     Running   0          31m
kube-system   csi-azurefile-node-2h66l              3/3     Running   0          31m
kube-system   csi-azurefile-node-dhrf2              3/3     Running   0          31m
kube-system   konnectivity-agent-5fc7989878-6nhwl   1/1     Running   0          31m
kube-system   konnectivity-agent-5fc7989878-t2n6h   1/1     Running   0          30m
kube-system   kube-proxy-96c9p                      1/1     Running   0          31m
kube-system   kube-proxy-x8g8s                      1/1     Running   0          31m
kube-system   metrics-server-5955767688-2hjvn       2/2     Running   0          3m45s
kube-system   metrics-server-5955767688-vmcq7       2/2     Running   0          3m45s
```

## Deploy Antrea to an AKS Engine cluster

Antrea is an integrated CNI of AKS Engine, and can be installed in
`networkPolicyOnly` mode or `encap` mode to an AKS Engine cluster as part of the
AKS Engine cluster deployment. To learn basics of AKS Engine cluster deployment,
please refer to [AKS Engine Quickstart Guide](https://github.com/Azure/aks-engine/blob/master/docs/tutorials/quickstart.md).

### Deploying Antrea in `networkPolicyOnly` mode

To configure Antrea to enforce NetworkPolicies for the AKS Engine cluster,
`"networkPolicy": "antrea"` needs to be set in `kubernetesConfig` of the AKS
Engine cluster definition (Azure CNI will be used as the `networkPlugin`):

```json
  "apiVersion": "vlabs",
  "properties": {
    "orchestratorProfile": {
      "kubernetesConfig": {
        "networkPolicy": "antrea"
      }
    }
  }
```

You can use the deployment template
[`examples/networkpolicy/kubernetes-antrea.json`](https://github.com/Azure/aks-engine/blob/master/examples/networkpolicy/kubernetes-antrea.json)
to deploy an AKS Engine cluster with Antrea in `networkPolicyOnly` mode:

```bash
$ aks-engine deploy --dns-prefix <dns-prefix> \
    --resource-group <reource-group> \
    --location westus2 \
    --api-model examples/networkpolicy/kubernetes-antrea.json \
    --auto-suffix
```

### Deploying Antrea in `encap` mode

To deploy Antrea in `encap` mode for an AKS Engine cluster, both
`"networkPlugin": "antrea"` and `"networkPolicy": "antrea"` need to be set in
`kubernetesConfig` of the AKS Engine cluster definition:

```json
  "apiVersion": "vlabs",
  "properties": {
    "orchestratorProfile": {
      "kubernetesConfig": {
        "networkPlugin": "antrea",
        "networkPolicy": "antrea"
      }
    }
  }
```

You can add `"networkPlugin": "antrea"` to the deployment template
[`examples/networkpolicy/kubernetes-antrea.json`](https://github.com/Azure/aks-engine/blob/master/examples/networkpolicy/kubernetes-antrea.json),
and use the template to deploy an AKS Engine cluster with Antrea in `encap`
mode.
