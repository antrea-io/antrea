# Antrea Multi-cluster Quick Start

In this quick start guide, we will set up an Antrea Multi-cluster ClusterSet
with two clusters. One cluster will serve as the leader of the ClusterSet, and
meanwhile also join as a member cluster; another cluster will be a member only.

The diagram below shows the two clusters and the ClusterSet to be created (for
simplicity, the diagram just shows two Nodes for each cluster).

<img src="assets/sample-clusterset.svg" width="800" alt="Antrea Multi-cluster Example ClusterSet">

## Preparation

We assume an Antrea version >= `v1.7.0` is used in this guide, and the Antrea
version is set to an environment variable `TAG`. For example, the following
command sets the Antrea version to `v1.7.0`.

```bash
export TAG=v1.7.0
```

To use the latest version of Antrea Multi-cluster from the Antrea main branch,
you can change the YAML manifest path to: `https://github.com/antrea-io/antrea/tree/main/multicluster/build/yamls/`
when applying or downloading an Antrea YAML manifest.

Antrea must be deployed in both cluster A and cluster B, and the `Multicluster`
feature of `antrea-agent` must be enabled to support multi-cluster Services. The
two clusters **must have non-overlapping Service CIDRs**. Set the following
configuration parameters in `antrea-agent.conf` of the Antrea deployment
manifest to enable the `Multicluster` feature:

```yaml
antrea-agent.conf: |
...
  featureGates:
...
    Multicluster: true
...
  multicluster:
    enable: true
    namespace: ""
```

At the moment, Multi-cluster Gateway only works with the Antrea `encap` traffic
mode, and all member clusters in a ClusterSet must use the same tunnel type.

## Set up Leader and Member in Cluster A

### Step 1 - deploy Antrea Multi-cluster Controllers for leader and member

Run the following commands to deploy Multi-cluster Controller for the leader
into Namespace `antrea-multicluster` (Namespace `antrea-multicluster` will be
created by the commands), and  Multi-cluster Controller for the member into
Namepsace `kube-system`.

```bash
$kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-leader-global.yml
$kubectl create ns antrea-multicluster
$kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-leader-namespaced.yml
$kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-member.yml
```

You can run the following command to verify the the leader and member
`antrea-mc-controller` Pods are deployed and running:

```bash
$kubectl get all -A -l="component=antrea-mc-controller"
NAMESPACE             NAME                                        READY   STATUS    RESTARTS   AGE
antrea-multicluster   pod/antrea-mc-controller-cd7bf8f68-kh4kz    1/1     Running   0          50s
kube-system           pod/antrea-mc-controller-85dbf58b75-pjj48   1/1     Running   0          48s

NAMESPACE             NAME                                   READY   UP-TO-DATE   AVAILABLE   AGE
antrea-multicluster   deployment.apps/antrea-mc-controller   1/1     1            1           50s
kube-system           deployment.apps/antrea-mc-controller   1/1     1            1           48s
```

### Step 2 - initialize ClusterSet

Antrea provides several template YAML manifests to set up a ClusterSet quicker.
You can run the following commands that use the template manifests to create a
ClusterSet named `test-clusteraset` in the leader cluster and get a
ServiceAccount token for the member clusters (both cluster A and B in our case)
to access the leader cluster (cluster A in our case) apiserver.

```bash
$kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/$TAG/multicluster/config/samples/clusterset_init/multicluster_clusterset_template.yaml
$kubectl apply -f  https://raw.githubusercontent.com/antrea-io/antrea/$TAG/multicluster/config/samples/clusterset_init/multicluster_leader_access_token_template.yaml
$kubectl get secret leader-access-token -n antrea-multicluster -o yaml | grep -w -e '^apiVersion' -e '^data' -e '^metadata' -e '^ *name:'  -e   '^kind' -e '  ca.crt' -e '  token:' -e '^type' -e '  namespace' | sed -e 's/kubernetes.io\/service-account-token/Opaque/g' -e 's/antrea-multicluster/kube-system/g' >  leader-access-token.yml
```

The last command saves the ServiceAccount token to `leader-access-token.yml`
which will be needed for member clusters to join the ClusterSet. Note, in this
guide, we use a shared default  ServiceAccount `antrea-mc-member-access-sa` for
all member clusters. If you want to create a separate ServiceAccount for each
member cluster for security considerations, you can follow the instructions in
the [Multi-cluster User Guide](user-guide.md#set-up-access-to-leader-cluster).

Next, run the following commands to make cluster A join the ClusterSet also as a
member:

```bash
$kubectl apply -f leader-access-token.yml
$curl -L https://raw.githubusercontent.com/antrea-io/antrea/v1.7.0/multicluster/config/samples/clusterset_init/multicluster_membercluster_template.yaml  > multicluster_membercluster.yaml
$sed -e 's/test-cluster-member/test-cluster-leader/g' -e 's/<LEADER_CLUSTER_IP>/172.10.0.11/g' multicluster_membercluster.yaml | kubectl apply -f -
```

Here, `172.10.0.11` is the `kube-apiserver` IP of cluster A. You should replace
it with the `kube-apiserver` IP of your leader cluster.

### Step 3 - specify Multi-cluster Gateway Node

Last, you need to choose a Node in cluster A to serve as the Multi-cluster
Gateway. The Node should have an IP that is reachable from the cluster B's
Gateway Node, so a tunnel can be created between the two Gateways. For more
information about Multi-cluster Gatweay, please refer to the [Multi-cluster
User Guide](user-guide.md#multi-cluster-gateway-configuration).

Assuming K8s Node `node-a1` is selected for the Multi-cluster Gateway, run
the following command to annotate the Node with:
`multicluster.antrea.io/gateway=true` (so Antrea can know it is the Gateway
Node from the annotation):

```bash
$kubectl annotate node node-a1 multicluster.antrea.io/gateway=true
```

## Set up Cluster B

Let us switch to cluster B. All the `kubectl` commands in the following steps
should be run with the `kubeconfig` for cluster B.

### Step 1 - deploy Antrea Multi-cluster Controller for member

Run the following command to deploy the member Multi-cluster Controller into
Namespace `kube-system`.

```bash
$kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-member.yml
```

You can run the following command to verify the `antrea-mc-controller` Pod is
deployed and running:

```bash
$kubectl get all -A -l="component=antrea-mc-controller"
NAMESPACE             NAME                                        READY   STATUS    RESTARTS   AGE
kube-system           pod/antrea-mc-controller-85dbf58b75-pjj48   1/1     Running   0          40s

NAMESPACE             NAME                                   READY   UP-TO-DATE   AVAILABLE   AGE
kube-system           deployment.apps/antrea-mc-controller   1/1     1            1           40s
```

### Step 2 - initialize ClusterSet

Run the following commands to make cluster B join the ClusterSet:

```bash
$kubectl apply -f leader-access-token.yml
$curl -L https://raw.githubusercontent.com/antrea-io/antrea/$TAG/multicluster/config/samples/clusterset_init/multicluster_membercluster_template.yaml  > multicluster_membercluster.yaml
$sed -e 's/<LEADER_CLUSTER_IP>/172.10.0.11/g' multicluster_membercluster.yaml | kubectl apply -f -
```

`leader-access-token.yml` saves the leader cluster ServiceAccount token which
was generated when initializing the ClusterSet in cluster A.

### Step 3 - specify Multi-cluster Gateway Node

Assuming K8s Node `node-b1` is chosen to be the Multi-cluster Gateway for cluster
B, run the following command to annotate the Node:

```bash
$kubectl annotate node node-b1 multicluster.antrea.io/gateway=true
```

## What is Next

So far, we set up an Antrea Multi-cluster ClusterSet with two clusters following
the above sections of this guide. Next, you can start to consume the Antrea
Multi-cluster features with the ClusterSet, including [Multi-cluster Services](user-guide.md#multi-cluster-service)
and [ClusterNetworkPolicy Replication](user-guide.md#multi-cluster-clusternetworkpolicy-replication).
Please check the relevant Antrea Multi-cluster User Guide sections to learn more.

If you want to add a new member cluster to your ClusterSet, you can follow the
steps for cluster B to do so. But note, you will need the following two changes:

1. You need to add the new mumber cluster to the `ClusterSet` in the leader
cluster (cluster A). You can do that by adding the cluster ID of the new member
to `multicluster_clusterset_template.yaml` and re-applying the manifest in
cluster A.

2. You need to update the member cluster ID in
`multicluster_membercluster_template.yaml` to the cluster ID of the new member
cluster in the step 2 of initializing ClusterSet. For example, you can run the
following commands to initialize the ClusterSet for a member cluster with ID
`test-cluster-member2`:

```bash
$kubectl apply -f leader-access-token.yml
$curl -L https://raw.githubusercontent.com/antrea-io/antrea/$TAG/multicluster/config/samples/clusterset_init/multicluster_membercluster_template.yaml  > multicluster_membercluster.yaml
$sed -e 's/<LEADER_CLUSTER_IP>/172.10.0.11/g' -e 's/test-cluster-member/test-cluster-member2/g' multicluster_membercluster.yaml | kubectl apply -f -
```
