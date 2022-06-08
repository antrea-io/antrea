# Antrea Multi-cluster User Guide

Antrea Multi-cluster implements [Multi-cluster Service API](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api),
which allows users to create multi-cluster Services that can be accessed cross clusters in a
ClusterSet. Antrea Multi-cluster also supports Antrea ClusterNetworkPolicy replication. A
multi-cluster ClusterSet admin can define ClusterNetworkPolicies to be replicated across the
entire ClusterSet and enforced in all member clusters. Antrea Multi-cluster is introduced in
Antrea v1.5.0, and the ClusterNetworkPolicy replication feature is supported since Antrea
v1.6.0. In Antrea v1.7.0, the Multi-cluster Gateway feature is added that supports routing
Multi-cluster Service traffic through tunnels among clusters.

## Quick Start

Please refer to the [Quick Start Guide](./quick-start.md) to learn how to build a ClusterSet
with two clusters quickly.

## Antrea Multi-cluster Installation

### Preparation

We assume an Antrea version >= `v1.7.0` is used in this guide, and the Antrea
version is set to an environment variable `TAG`. For example, the following
command sets the Antrea version to `v1.7.0`.

```bash
export TAG=v1.7.0
```

To use the latest version of Antrea Multi-cluster from the Antrea main branch,
you can change the YAML manifest path to: `https://github.com/antrea-io/antrea/tree/main/multicluster/build/yamls/`
when applying or downloading an Antrea YAML manifest.

Multi-cluster Services require an Antrea Multi-cluster Gateway to be set up in
each member cluster, so the Multi-cluster Service traffic can be routed across
clusters by the Gateways. To support Multi-cluster Gateways, `antrea-agent` must
be deployed with the `Multicluster` feature enabled in a member cluster. You can
set the following configuration parameters in `antrea-agent.conf` of the Antrea
deployment manifest to enable the `Multicluster` feature:

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

### Deploy Antrea Mulit-cluster Controller

A Multi-cluster ClusterSet is comprised of a single leader cluster and at least
two member clusters. Antrea Multi-cluster Controller needs to be deployed in the
leader and all member clusters. A cluster can serve as the leader, and meanwhile
also be a member cluster of the ClusterSet. To deploy Multi-cluster Controller
in a dedicated leader cluster, please refer to [Deploy in a Dedicated Leader
cluster](#deploy-in-a-dedicated-leader-cluster). To deploy Multi-cluster
Controller in a member cluster, please refer to [Deploy in a Member Cluster](#deploy-in-a-member-cluster).
To deploy Multi-cluster Controller in a dual-role cluster, please refer to
[Deploy Leader and Member in One Cluster](#deploy-leader-and-member-in-one-cluster).

#### Deploy in a Dedicated Leader Cluster

1. Run the following command to import Multi-cluster CRDs in the leader cluster:

     ```bash
     kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-leader-global.yml
     ```

2. Install Multi-cluster Controller in the leader cluster. Since Multi-cluster
   Controller runs as a namespaced Deployment, you should create the Namespace
   first, and then apply the deployment manifest with the Namespace.

  ```bash
  kubectl create ns antrea-multicluster
  curl -L https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-leader-namespaced.yml >   antrea-multicluster-leader-namespaced.yml
  sed 's/changeme/antrea-multicluster/g' antrea-multicluster-leader-namespaced.yml | kubectl apply -f -
  ```

#### Deploy in a Member Cluster

You can run the following command to install Multi-cluster Controller in a
member cluster. The command will run the controller in the "member" mode in the
`kube-system` Namespace. If you want to use a different Namespace other than
`kube-system`, you can edit `antrea-multicluster-member.yml` and change
`kube-system` to the desired Namespace.

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$TAG/antrea-multicluster-member.yml
```

#### Deploy Leader and Member in One Cluster

We need to run two instances of Multi-cluster Controller in the dual-role
cluster, one in leader mode and another in member mode.

1. Follow the steps in section [Deploy in a Dedicated Leader Cluster](#deploy-in-a-dedicated-leader-cluster)
   to deploy the leader controller and import the Multi-cluster CRDs.
2. Follow the steps in section [Deploy in a Member Cluster](#deploy-in-a-member-cluster)
   to deploy the member controller.

### Create ClusterSet

An Antrea Multi-cluster ClusterSet should include at least one leader cluster
and two member clusters. As an example, in the following sections we will create
a ClusterSet `test-clusterset` which has two member clusters with cluster ID
`test-cluster-east` and `test-cluster-west` respectively, and one leader cluster
with ID `test-cluster-north`.

#### Set up Access to Leader Cluster

We first need to set up access to the leader cluster's API server for all member
clusters. We recommend creating one ServiceAccount for each member for
fine-grained access control.

1. Apply the following YAML manifest in the leader cluster to set up access for
   `test-cluster-east`:

   ```yml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: member-east-access-sa
     namespace: antrea-multicluster
   ---
   apiVersion: v1
   kind: Secret
   metadata:
     name: member-east-access-token
     namespace: antrea-multicluster
     annotations:
       kubernetes.io/service-account.name: member-east-access-sa
   type: kubernetes.io/service-account-token
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata:
     name: member-east-access-rolebinding
     namespace: antrea-multicluster
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: Role
     name: antrea-mc-member-cluster-role
   subjects:
     - kind: ServiceAccount
       name: member-east-access-sa
       namespace: antrea-multicluster
   ```

2. Generate the access token file from the leader cluster, and create a Secret
   with the token in member cluster `test-cluster-east`, e.g.:

   ```bash
   # Generate the file 'member-east-access-token.yml' from your leader cluster
   kubectl get secret member-east-access-token -n antrea-multicluster -o yaml | grep -w -e '^apiVersion' -e '^data' -e '^metadata' -e '^ *name:'  -e   '^kind' -e '  ca.crt' -e '  token:' -e '^type' -e '  namespace' | sed -e 's/kubernetes.io\/service-account-token/Opaque/g' -e 's/antrea-multicluster/kube-system/g' >  member-east-access-token.yml
   # Apply 'member-east-access-token.yml' to the member cluster.
   kubectl apply -f member-east-access-token.yml --kubeconfig=/path/to/kubeconfig-of-member-test-cluster-east
   ```

3. Replace all `east` to `west` and repeat step 1/2 for the other member cluster
   `test-cluster-west`.

#### Initialize ClusterSet

In all clusters, a `ClusterSet` CR must be created to define the ClusterSet, and
two `ClusterClaim` CRs must be created to claim the ClusterSet and claim the
cluster is a member of the ClusterSet.

- Create `ClusterClaim` and `ClusterSet` in member cluster `test-cluster-east`
with the following YAML manifest (you can also refer to
[multicluster_membercluster_template.yaml](../../multicluster/config/samples/clusterset_init/multicluster_membercluster_template.yaml)):

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: id.k8s.io
  namespace: kube-system
name: id.k8s.io
value: test-cluster-east
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset.k8s.io
  namespace: kube-system
name: clusterset.k8s.io
value: test-clusterset
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
  name: test-clusterset
  namespace: kube-system
spec:
  leaders:
    - clusterID: test-cluster-north
      secret: "member-east-access-token"
      server: "https://172.18.0.1:6443"
  members:
    - clusterID: test-cluster-east
  namespace: antrea-multicluster
```

Note: update `server: "https://172.18.0.1:6443"` in the `ClusterSet` spec to the
correct leader cluster API server address.

- Create `ClusterClaim` and `ClusterSet` in member cluster `test-cluster-west`:

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: id.k8s.io
  namespace: kube-system
name: id.k8s.io
value: test-cluster-west
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset.k8s.io
  namespace: kube-system
name: clusterset.k8s.io
value: test-clusterset
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
  name: test-clusterset
  namespace: kube-system
spec:
  leaders:
    - clusterID: test-cluster-north
      secret: "member-west-access-token"
      server: "https://172.18.0.1:6443"
  members:
    - clusterID: test-cluster-west
  namespace: antrea-multicluster
```

- Create `ClusterClaim` and `ClusterSet` in the leader cluster
`test-cluster-north` with the following YAML manifest (you can also refer to
[multicluster_clusterset_template.yaml](../../multicluster/config/samples/clusterset_init/multicluster_clusterset_template.yaml)):

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: id.k8s.io
  namespace: antrea-multicluster
name: id.k8s.io
value: test-cluster-north
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset.k8s.io
  namespace: antrea-multicluster
name: clusterset.k8s.io
value: test-clusterset
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
  name: test-clusterset
  namespace: antrea-multicluster
spec:
  leaders:
    - clusterID: test-cluster-north
  members:
    - clusterID: test-cluster-east
      serviceAccount: "member-east-access-sa"
    - clusterID: test-cluster-west
      serviceAccount: "member-west-access-sa"
  namespace: antrea-multicluster
```

In the leader cluster, the `ClusterSet` spec should include all member clusters
of the ClusterSet.

#### Initialize ClusterSet for a Dual-role Cluster

If you want to make the leader cluster `test-cluster-north` also a member
cluster of the ClusterSet, make sure you follow the steps in [Deploy Leader and
Member in One Cluster](#deploy-leader-and-member-in-one-cluster) and repeat the
steps in [Set up Access to Leader Cluster](#set-up-access-to-leader-cluster) as
well (don't forget replace all `east` to `north` when you repeat the steps).

Then create the `ClusterClaim` and `ClusterSet` CRs in cluster
`test-cluster-north` in the `kube-system` Namespace (where the member
Multi-cluster Controller runs):

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: id.k8s.io
  namespace: kube-system
name: id.k8s.io
value: test-cluster-north
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset.k8s.io
  namespace: kube-system
name: clusterset.k8s.io
value: test-clusterset
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
  name: test-clusterset
  namespace: kube-system
spec:
  leaders:
    - clusterID: test-cluster-north
      secret: "member-north-access-token"
      server: "https://172.18.0.1:6443"
  members:
    - clusterID: test-cluster-north
  namespace: antrea-multicluster
```

Last, update the ClusterSet `test-clusterset` in Namepsace `antrea-multicluster`
(where the leader Multi-cluster Controller runs) to include `test-cluster-north`
as a member cluster of the ClusterSet:

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
  name: test-clusterset
  namespace: antrea-multicluster
spec:
  leaders:
    - clusterID: test-cluster-north
  members:
    - clusterID: test-cluster-east
      serviceAccount: "member-east-access-sa"
    - clusterID: test-cluster-west
      serviceAccount: "member-west-access-sa"
    - clusterID: test-cluster-north
      serviceAccount: "member-north-access-sa"
  namespace: antrea-multicluster
```

## Multi-cluster Gateway Configuration

After a member cluster joins a ClusterSet, and the `Multicluster` feature is
enabled for `antrea-agent`, one K8s Node in the member cluster can be specified
to serve as the Multi-cluster Gateway of the cluster. An annotation -
`multicluster.antrea.io/gateway=true` - should be added to the Node to tell
Antrea it is the Gateway Node. For example, you can run the following command to
annotate Node `node-1` as the Multi-cluster Gateway:

```bash
$kubectl annotate node node-1 multicluster.antrea.io/gateway=true
```

Multi-cluster Controller in the member cluster will detect the Gateway Node, and
create a `Gateway` CR with the same name as the Node. You can check the `Gateway`
with: `kubectl get gateway node-1 -o yaml`, which should show the Gateway
information like:

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: Gateway
metadata:
  name: node-1
  namespace: kube-system
gatewayIP: 10.17.27.55
internalIP: 10.17.27.55
```

`internalIP` of the Gateway is used for the tunnels between the Gateway Node and
other Nodes in the local cluster, while `gatewayIP` is used for the tunnels to
remote Gateways of other member clusters.  By default, Multi-cluster Controller
will use the K8s Node `InternalIP` of the Gateway Node as the `gatewayIP`. If
you want to use `ExternalIP` of the Gateway Node instead, you can change the
configuration option `gatewayIPPrecedence` in ConfigMap
`antrea-mc-controller-config-***` to value `public`, when you deploy the member
Multi-cluster Controller. When selecting the Multi-cluster Gateway Node, you
need to make sure the resulted `gatewayIP` can be reached from the remote
Gateways.

After the `Gateway` CR is created, Multi-cluster Controller will be responsible
for exporting the cluster's network information to the leader cluster including
the Gateway IPs and `serviceCIDR` (the cluster's Service ClusterIP range).
Multi-cluster Controller will try to discover `serviceCIDR` automatically, but
you can also define the `serviceCIDR` manually in the Antrea Multi-cluster
ConfigMap `antrea-mc-controller-config-***`.

The Multi-cluster resource export/import pipeline will replicate the exported
cluster network information to all member clusters in the ClusterSet. For
example, in other member clusters, you can see a `ClusterInfoImport` CR with
name `test-cluster-east-clusterinfo` is created for `test-cluster-east` with
its network information. You can check the `ClusterInfoImport` with command:
`kubectl get clusterinfoimport test-cluster-east-clusterinfo -o yaml`, which
should show information like:

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterInfoImport
metadata:
  name: test-cluster-east-clusterinfo
  namespace: kube-system
spec:
  clusterID: test-cluster-east
  gatewayInfos:
    - gatewayIP: 10.17.27.55
  serviceCIDR: 110.96.0.0/20
```

Make sure you repeat the same steps to assign a Gateway Node in all member
clusters, then `antrea-agent` will set up Geneve tunnels among the Gateway Nodes
of member clusters based on the local `Gateway` and the `ClusterInfoImport`
resources, and route Multi-cluster Service traffic across clusters through the
tunnels. `antrea-agent` on regular Nodes will route cross-cluster traffic from
local Pods to the Gateway Node of the member cluster.

Once you confirm that all `Gateway` and `ClusterInfoImport` resources are
created correctly, you can follow the [Multi-cluster Service](#multi-cluster-service)
section to create Multi-cluster Services and verify cross-cluster Service
access.

## Multi-cluster Service

After you set up a ClusterSet properly, you can simply create a `ServiceExport` resource
as below to export a `Service` from one member cluster to other members in the ClusterSet,
you can update the name and Namespace according to your local K8s Service.

```yaml
apiVersion: multicluster.x-k8s.io/v1alpha1
kind: ServiceExport
metadata:
  name: nginx
  namespace: kube-system
```

For example, once you export the `kube-system/nginx` Service in the member cluster
`test-cluster-west`, Antrea Multi-cluster Controller in the member cluster will create
two corresponding `ResourceExport` resources in the leader cluster, and the controller
in leader cluster will create two `ResourceImport` contains all exported Service and
Endpoints'. you can check the created resources in the leader cluster which should be
like below:

```sh
$kubectl get resourceexport
NAME                                        AGE
test-cluster-west-default-nginx-endpoints   7s
test-cluster-west-default-nginx-service     7s

$kubectl get resourceimport
NAME                      AGE
default-nginx-endpoints   99s
default-nginx-service     99s
```

Then you can go to the member cluster `test-cluster-east` to check the new created
Service and Endpoints with name `kube-system/antrea-mc-nginx` and a ServiceImport named
`kube-system/nginx`. If there is already an existing Service created by users in the
member cluster `test-cluster-east` also named `nginx` in Namespace `kube-system`, which
should have no Antrea Multi-cluster annotation, then Multi-cluster Controller will
simply skip the Service and Endpoints creation.

If there is any new change from the exported Service or Endpoints, the derived multi-cluster
resources will be updated accordingly. A few cases below are worth to note:

1. When there is only one Service ResourceExport, Antrea Multi-cluster Controller will converge
   the change and reflect the update in correspoding ResourceImport. Otherwise, controller will skip
   converging the update until users correct it to match the Service definition in correspoding
   ResourceImport.
2. When a member cluster has already exported a Service, e.g.: `default/nginx` with TCP
   Port `80`, then other member clusters can only export the same Service with the same Ports
   definition including port names. Otherwise, Antrea Multi-cluster Controller will skip converting
   the mismatched ResourceExport into the corresponding ResourceImport until users correct it.
3. When a member cluster's Service ResourceExport has not been converged successfully
   due to forementioned mismatch issue, Antrea Multi-cluster Controller will also skip converging
   the corresponding Endpoints ResourceExport until users correct it.

## Multi-cluster ClusterNetworkPolicy Replication

Since Antrea v1.6.0, Multi-cluster admins can specify certain ClusterNetworkPolicies to be replicated
across the entire ClusterSet. This is especially useful for ClusterSet admins who want all clusters in
the ClusterSet to be applied with a consistent security posture (for example, all Namespaces in all
clusters can only communicate with Pods in their own namespaces). For more information regarding
Antrea ClusterNetworkPolicy (ACNP), refer to [this document](../antrea-network-policy.md).

To achieve such ACNP replication across clusters, admins can, in the acting leader cluster of a
Multi-cluster deployment, create a ResourceExport of kind `AntreaClusterNetworkPolicy` which contains
the ClusterNetworkPolicy spec they wish to be replicated. The ResourceExport should be created in the
Namespace which implements the Common Area of the ClusterSet. In future releases, some additional tooling
may become available to automate the creation of such ResourceExport and make ACNP replication easier.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceExport
metadata:
  name: strict-namespace-isolation-for-test-clusterset
  namespace: antrea-multicluster # Namespace that implements Common Area of test-clusterset
spec:
  kind: AntreaClusterNetworkPolicy
  name: strict-namespace-isolation # In each importing cluster, an ACNP of name antrea-mc-strict-namespace-isolation will be created with the spec below
  clusternetworkpolicy:
    priority: 1
    tier: securityops
    appliedTo:
      - namespaceSelector: {} # Selects all Namespaces in the member cluster
    ingress:
      - action: Pass
        from:
          - namespaces:
              match: Self # Skip drop rule for traffic from Pods in the same Namespace
          - podSelector:
              matchLabels:
                k8s-app: kube-dns # Skip drop rule for traffic from the core-dns components
      - action: Drop
        from:
          - namespaceSelector: {} # Drop from Pods from all other Namespaces
```

The above sample spec will create an ACNP in each member cluster which implements strict namespace
isolation for that cluster.

Note that because the Tier that an ACNP refers to must exist before the ACNP is applied, an importing
cluster may fail to create the ACNP to be replicated, if the Tier in the ResourceExport spec cannot be
found in that particular cluster. If there are such failures, the ACNP creation status of failed member
clusters will be reported back to the Common Area as K8s Events, and can be checked by describing the
ResourceImport of the original ResourceExport:

```text
kubectl describe resourceimport -A
---
Name:         strict-namespace-isolation-antreaclusternetworkpolicy
Namespace:    antrea-multicluster
API Version:  multicluster.crd.antrea.io/v1alpha1
Kind:         ResourceImport
Spec:
  Clusternetworkpolicy:
    Applied To:
      Namespace Selector:
    Ingress:
      Action:          Pass
      Enable Logging:  false
      From:
        Namespaces:
          Match:  Self
        Pod Selector:
          Match Labels:
            k8s-app:   kube-dns
      Action:          Drop
      Enable Logging:  false
      From:
        Namespace Selector:
    Priority:  1
    Tier:      random
  Kind:        AntreaClusterNetworkPolicy
  Name:        strict-namespace-isolation
  ...
Events:
  Type    Reason               Age    From                       Message
  ----    ------               ----   ----                       -------
  Warning ACNPImportFailed     2m11s  resourceimport-controller  ACNP Tier random does not exist in the importing cluster test-cluster-west
```

## Build Antrea Multi-cluster Image

If you'd like to build Antrea Multi-cluster Docker image locally, you can follow
the following steps:

1. Go to your local `antrea` source tree, run `make antrea-mc-controller`, and you will get a new image
   named `antrea/antrea-mc-controller:latest` locally.
2. Run `docker save antrea/antrea-mc-controller:latest > antrea-mcs.tar` to save the image.
3. Copy the image file `antrea-mcs.tar` to the Nodes of your local cluster.
4. Run `docker load < antrea-mcs.tar` in each Node of your local cluster.

## Known Issue

We recommend user to reinstall or update Antrea Multi-cluster controllers through `kubectl apply`.
If you are using `kubectl delete -f *` and `kubectl create -f *` to reinstall CRDs and controller
in the leader cluster, you might encounter [a known issue](https://github.com/kubernetes/kubernetes/issues/60538)
during `ResourceExport` CRD cleanup. To avoid this issue, please clean up any `ResourceExport`
resources in the leader cluster first, and make sure `kubectl get resourceexport -A` returns
empty result before you can reinstall the CRDs and leader controller.

All `ResourceExport` can be deleted with the following command:

```sh
kubectl get resourceexport -A -o json | jq -r '.items[]|[.metadata.namespace,.metadata.name]|join(" ")' | xargs -n2 bash -c 'kubectl delete -n $0 resourceexport/$1'
```
