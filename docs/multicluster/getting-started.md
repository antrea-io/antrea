# Antrea Multi-cluster Installation

Antrea Multi-cluster allows users to export and import resources including Services and
Endpoints across multiple clusters within a ClusterSet, and enables inter-cluster Service
communication in the ClusterSet. This feature is introduced from Antrea v1.5.0.

## Prepare Antrea Multi-cluster Image

For Antrea Multi-cluster, there is only one image `antrea/antrea-mc-controller:latest`
you can pull the image from Docker Hub by default, or if you'd like to build image locally,
you can follow the following steps to get the image ready on your local clusters.

1. Go to `antrea` folder, run `make antrea-mc-controller`, and you will get a new image
  named `antrea/antrea-mc-controller:latest` locally.
2. Run `docker save antrea/antrea-mc-controller:latest > antrea-mcs.tar` to save the image.
3. Copy the image file `antrea-mcs.tar` to the Nodes of your local cluster.
4. Run `docker load < antrea-mcs.tar` in each Node of your local cluster.

## Deploy Mulit-cluster Controller

In a ClusterSet, there is one leader cluster and two or more member clusters. You can run the
leader controller in either a dedicated cluster or one of the member clusters. Please refer
to [Installation in Dedicated Leader Cluster](#installation-in-dedicated-leader-cluster)
and [Installation in the Member Cluster](#installation-in-the-member-cluster)
to deploy leader and member controllers in separate clusters, or you can refer to
[Installation in a Shared Cluster](#installation-in-a-shared-cluster) to learn how to
run both member and leader controllers in one cluster.

### Deployment in a Dedicated Leader Cluster

1. Run the following commands to apply Multi-cluster CRDs in the leader cluster.

   * For any given release `<TAG>` (e.g. `v1.5.0`).

     ```bash
     kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-multicluster-leader-global.yml
     ```

   * To deploy the latest version (checkout and built from the `feature/multi-cluster` branch).

     ```bash
     kubectl apply -f multicluster/build/yamls/antrea-multicluster-leader-global.yml
     ```

2. Install Multi-cluster Controller in the leader cluster. Since Multi-cluster Controller is
running as namespaced deployment, you should create a Namespace first, then apply the
manifest with new Namespace.

* For any given release `<TAG>` (e.g. `v1.5.0`).
  
  ```bash
  kubectl create ns antrea-mcs-ns
  curl -L https://github.com/antrea-io/antrea/releases/download/v1.5.0/antrea-multicluster-leader-namespaced.yml >   antrea-multicluster-leader-namespaced.yml
  sed 's/changeme/antrea-mcs-ns/g' antrea-multicluster-leader-namespaced.yml | kubectl apply -f -
  ```
  
* To deploy the latest version (checkout and built from the `feature/multi-cluster` branch).
  
  ```bash
  kubectl create ns antrea-mcs-ns
  multicluster/hack/generate-manifest.sh -l antrea-mcs-ns | kubectl apply -f -
  ```
  
### Deployment in the Member Cluster

You can run the following commands to install Multi-cluster Controller to all
member clusters. The command will run the controller in the "member" mode in the `kube-system`
Namespace by default.

* For any given release `<TAG>` (e.g. `v1.5.0`).

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-multicluster-member.yml
```

* To deploy the latest version (checkout and built from the `feature/multi-cluster` branch).

```bash
kubectl apply -f multicluster/build/yamls/antrea-multicluster-member.yml
```

### Deploy Leader and Member in one Cluster

There is no deployment dependency between member and leader clusters if you are using a cluster
as a dedicated leader cluster. But if you'd like to run both leader and member controllers in
one cluster, below is the required deployment sequence:

1. Follow the step in section [Installation in the Member Cluster](#deployment-in-the-member-cluster)
to install the member controller first.
2. Follow the step 2 only in section [Installation in Dedicated Leader Cluster](#deployment-in-dedicated-leader-cluster)
to install the leader controller. The global CRDs have been installed when you deploy the member controller.

## ClusterSet

An Antrea Multi-cluster ClusterSet should include at least one leader cluster
and two member clusters. As an example, in the following sections we will create a ClusterSet with
ID `test-clusterset` which has two member clusters with cluster ID `test-cluster-east`,
`test-cluster-west` and one leader cluster with ID `test-cluster-north`.

### Setting up Access to Leader Cluster

We first need to set up access to the leader cluster's API server for all member clusters.
We recommend creating one ServiceAccount for each member for fine-grained access control.

1. Apply the following yaml in the leader cluster to set up access for
`test-cluster-east`.

   ```yml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: member-east-access-sa
     namespace: antrea-mcs-ns
   ---
   apiVersion: v1
   kind: Secret
   metadata:
       name: member-east-access-token
       namespace: antrea-mcs-ns
       annotations:
         kubernetes.io/service-account.name: member-east-access-sa
   type: kubernetes.io/service-account-token
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata:
     name: member-east-access-rolebinding
     namespace: antrea-mcs-ns
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: Role
     name: antrea-mc-member-cluster-role
   subjects:
     - kind: ServiceAccount
       name: member-east-access-sa
       namespace: antrea-mcs-ns
   ```

2. Copy the access token into the member cluster `test-cluster-east`. E.g.

   ```bash
   kubectl get secret member-east-access-token -n antrea-mcs-ns -o yaml | grep -w -e '^apiVersion' -e '^data' -e '^metadata' -e '^ *name:'  -e   '^kind' -e '  ca.crt' -e '  token:' -e '^type' -e '  namespace' | sed -e 's/kubernetes.io\/service-account-token/Opaque/g' -e 's/ namespace:   antrea-mcs-ns/namespace: kube-system/g' >  member-east-access-token.yml
   ```

3. Replace all `east` to `west` and repeat step 1/2 for the other member cluster `test-cluster-west`
to create the token secret and copy the token.

### Setting up ClusterSet

All clusters in the ClusterSet need to use `ClusterClaim` to claim itself as a member
of a ClusterSet. A leader cluster will define `ClusterSet` which includes leader and
member clusters.

* Create below `ClusterClaim` and `ClusterSet` in the member cluster `test-cluster-east`.

Note: Update `server: "https://172.18.0.2:6443"` in `ClusterSet` resource to
the correct the leader cluster API address.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: east-membercluster-id
  namespace: kube-system
name: id.k8s.io
value: test-cluster-east
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: kube-system
name: clusterSet.k8s.io
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
        server: "https://172.18.0.2:6443"
    members:
      - clusterID: test-cluster-east
    namespace: antrea-mcs-ns
```

* Create `ClusterClaim` and `ClusterSet` in the member cluster `test-cluster-west`.

Note: Update `server: "https://172.18.0.2:6443"` in `ClusterSet` resource to
the correct leader cluster API address.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: west-membercluster-id
  namespace: kube-system
name: id.k8s.io
value: test-cluster-west
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: kube-system
name: clusterSet.k8s.io
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
        server: "https://172.18.0.2:6443"
    members:
      - clusterID: test-cluster-west
    namespace: antrea-mcs-ns
```

* Create `ClusterClaim` and `ClusterSet` in the leader cluster `test-cluster-north`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: leadercluster-id
  namespace: antrea-mcs-ns
name: id.k8s.io
value: test-cluster-north
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: antrea-mcs-ns
name: clusterSet.k8s.io
value: test-clusterset
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
    name: test-clusterset
    namespace: antrea-mcs-ns
spec:
    leaders:
      - clusterID: test-cluster-north
    members:
      - clusterID: test-cluster-east
        serviceAccount: "member-east-access-sa"
      - clusterID: test-cluster-west
        serviceAccount: "member-west-access-sa"
    namespace: antrea-mcs-ns
```

When you also want to make the leader cluster `test-cluster-north` as a member in the
ClusterSet, so it can export and import resources from other member clusters, make
sure you follow the steps in [Installation in a Shared Cluster](#installation-in-a-shared-cluster),
and repeat the step [Setting up Access to Leader Cluster](#setting-up-access-to-leader-cluster)
as well to create the token secret and copy the token first.

A sample yaml is like below:

```yml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: member-north-access-sa
  namespace: antrea-mcs-ns
---
apiVersion: v1
kind: Secret
metadata:
    name: member-north-access-token
    namespace: antrea-mcs-ns
    annotations:
      kubernetes.io/service-account.name: member-north-access-sa
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: member-north-access-rolebinding
  namespace: antrea-mcs-ns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: antrea-mc-member-cluster-role
subjects:
  - kind: ServiceAccount
    name: member-north-access-sa
    namespace: antrea-mcs-ns
```

Then create below `ClusterClaim` and `ClusterSet` in the cluster `test-cluster-north` in the
`kube-system` Namespace where the member controller is deployed.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: north-membercluster-id
  namespace: kube-system
name: id.k8s.io
value: test-cluster-north
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: kube-system
name: clusterSet.k8s.io
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
        server: "https://172.18.0.2:6443"
    members:
      - clusterID: test-cluster-north
    namespace: antrea-mcs-ns
```

Then update the ClusterSet `test-clusterset` definition as below to include itself
as a member cluster in the Namespace `antrea-mcs-ns` where the leader controller is
running in the cluster `test-cluster-north`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
    name: test-clusterset
    namespace: antrea-mcs-ns
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
    namespace: antrea-mcs-ns
```

## Export and Import Service

After you set up a cluster set properly, you can simply create a `ServiceExport` resource
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
