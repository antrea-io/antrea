# Deploying Antrea on AKS and AKS Engine

This document describes steps to deploy Antrea to an AKS cluster or an AKS
Engine cluster.

## Deploy Antrea to an AKS cluster

Antrea can be deployed to an AKS cluster in `networkPolicyOnly` mode, in which
Antrea enforces NetworkPolicies and implements other services for the AKS
cluster, while Azure CNI takes care of Pod IPAM and traffic routing across Nodes.
For more information about `networkPolicyOnly` mode, refer to [this design document](design/policy-only.md).

### AKS Prerequisites

Install the Azure Cloud CLI. Refer to [Azure CLI installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)

### Creating the cluster

You can use any method to create an AKS cluster. The example given here is using the Azure Cloud CLI.

1. Create an AKS Cluster

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

2. Get AKS Cluster Credentials

   ```bash
   az aks get-credentials --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP_NAME
   ```

3. Access your Cluster

    ```bash
    kubectl get nodes
    NAME                                STATUS   ROLES   AGE     VERSION
    aks-nodepool1-84330359-vmss000000   Ready    agent   6m21s   v1.16.10
    aks-nodepool1-84330359-vmss000001   Ready    agent   6m25s   v1.16.10
    ```

### Deploying Antrea

1. Prepare the Cluster Nodes

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
checked-in [deployment yaml](/build/yamls/antrea-aks.yml):

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
