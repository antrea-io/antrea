# MCS Controller Installation

## Dependency
Before you start to install MCS controller in a local cluster, please make sure `cert-manager` is installed which is a dependency for now, we will remove this dependency in the future.
`kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml`

## Prepare Docker Image

For Antrea multi-cluster, there will be only one image `antrea/antrea-multicluster-controller:latest` for all controllers, you need to prepare a docker image before setup MCS component, you can follow below steps to get the image ready on your local cluster.

1. Go to `antrea/multi-cluster` folder, run `make docker-build`, you will get a new image named `antrea/antrea-multicluster-controller:latest` locally.
2. Run `docker save antrea/antrea-multicluster-controller:latest > antrea-mcs.tar` to save the image.
3. Copy the image file `antrea-mcs.tar` to the nodes of your local cluster
4. Run `docker load < antrea-mcs.tar` in each node of your local cluster.

## Install MCS

After you prepare MCS docker image, you can run below command to install MCS component:

```shell
kubectl apply -f multicluster/config/multi-cluster.yaml
```

## Setup ClusterSet

In an Antrea multi-cluster cluster set, there will be at least one leader cluster and one member cluster. At first, all clusters in the cluster set need to use `ClusterClaim` to claim itself as a member of a cluster set. A leader cluster will define `ClusterSet` which includes leader and member clusters. below is a sample to create a cluster set with a cluster set id `test-clusterset` which has two member clusters with cluster id `test-cluster-east` and `test-cluster-west`, one leader cluster with id `test-cluster-leader`, if you'd like to set up an MCS cluster set with two clusters, you can use one of member cluster `test-cluster-east` or `test-cluster-west` to replace `test-cluster-leader`.

* Create below `ClusterClaim` in the member cluster `test-cluster-east`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: east-membercluster-id
  namespace: antrea-mcs-ns
name: id.k8s.io
value: test-cluster-east
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: antrea-mcs-ns
name: clusterSet.k8s.io
value: test-clusterset
```

* Create below `ClusterClaim` in the member cluster `test-cluster-west`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: west-membercluster-id
  namespace: antrea-mcs-ns
name: id.k8s.io
value: test-cluster-west
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: antrea-mcs-ns
name: clusterSet.k8s.io
value: test-clusterset
```

* Create below `ClusterClaim` in the leader cluster `test-cluster-leader`.
 
```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: leadercluster-id
  namespace: antrea-mcs-ns
name: id.k8s.io
value: test-cluster-leader
---
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterClaim
metadata:
  name: clusterset-id
  namespace: antrea-mcs-ns
name: clusterSet.k8s.io
value: test-clusterset
```

* Create below `ClusterSet` in the leader cluster `test-cluster-leader`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ClusterSet
metadata:
    name: test-clusterset
    namespace: kube-system
spec:
    leaders:
      - clusterID: test-cluster-leader
        secret: "leader-access-token"
        server: "https://172.18.0.2:6443"
    members:
      - clusterID: test-cluster-east
      - clusterID: test-cluster-west
    namespace: antrea-mcs-ns
```

## Use MCS Customer Resource

Since there is no real reconcile logic in MCS controller code yet, you need to create some MCS resource manually if you need to do some testing again `ResourceExport`, `ResourceImport` etc. below lists a few sample yamls for you to create some MCS custom resources.


* A `ServiceExport` example which will expose a Service named `nginx` in namespace `kube-system` in a member cluster, let's create it in both `test-cluster-west` and `test-cluster-east` clusters.

```yaml
apiVersion: multicluster.x-k8s.io/v1alpha1
kind: ServiceExport
metadata:
  name: nginx
  namespace: kube-system
```

* Create two `ResourceExports` examples which wrap a `ServiceExport` named `nginx` to Service type of `ResourceExport` and Endpoint type of `ResourceExport` to represent the exposed `nginx` service for both `test-cluster-west` and `test-cluster-east` in the leader cluster `test-cluster-leader`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceExport
metadata:
  name: test-cluster-west-nginx-kube-system-service
  namespace: antrea-mcs-ns
spec:
  clusterID: test-cluster-west
  name: nginx
  namespace: kube-system
  kind: Service
  service:
    serviceSpec:
      ports: 
      - name: tcp80
        port: 80
        protocol: TCP
```

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceExport
metadata:
  name: test-cluster-west-nginx-kube-system-endpoints
  namespace: antrea-mcs-ns
spec:
  clusterID: test-cluster-west
  name: nginx
  namespace: kube-system
  kind: Endpoints
  endpoints:
    subsets:
    - addresses:
      - ip: 192.168.225.49
        nodeName: node-1
      - ip: 192.168.225.51
        nodeName: node-2
      ports:
      - name: tcp8080
        port: 8080
        protocol: TCP
```

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceExport
metadata:
  name: test-cluster-east-nginx-kube-system-service
  namespace: antrea-mcs-ns
spec:
  clusterID: test-cluster-east
  name: nginx
  namespace: kube-system
  kind: Service
  service:
    serviceSpec:
      ports: 
      - name: tcp80
        port: 80
        protocol: TCP
```

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceExport
metadata:
  name: test-cluster-east-nginx-kube-system-endpoints
  namespace: antrea-mcs-ns
spec:
  clusterID: test-cluster-east
  name: nginx
  namespace: kube-system
  kind: Endpoints
  endpoints:
    subsets:
    - addresses:
      - ip: 192.168.224.21
        nodeName: node-one
      - ip: 192.168.226.11
        nodeName: node-two
      ports:
      - name: tcp8080
        port: 8080
        protocol: TCP
```

* Create two `ResourceImport` examples which represent the `nginx` service in namespace `kube-system` in the leader cluster `test-cluster-leader`.

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceImport
metadata:
  name: nginx-kube-system-service
  namespace: antrea-mcs-ns
spec:
  name: nginx
  namespace: kube-system
  kind: ServiceImport
  serviceImport:
    spec:
      ports: 
      - name: tcp80
        port: 80
        protocol: TCP
      type: ClusterSetIP
```

```yaml
apiVersion: multicluster.crd.antrea.io/v1alpha1
kind: ResourceImport
metadata:
  name: nginx-kube-system-endpoints
  namespace: antrea-mcs-ns
spec:
  name: nginx
  namespace: kube-system
  kind: EndPoints
  endpoints:
    subsets:
    - addresses:
      - ip: 192.168.225.49
        nodeName: node-1
      - ip: 192.168.225.51
        nodeName: node-2
      ports:
      - name: tcp8080
        port: 8080
        protocol: TCP
    - addresses:
      - ip: 192.168.224.21
        nodeName: node-one
      - ip: 192.168.226.11
        nodeName: node-two
      ports:
      - name: tcp8080
        port: 8080
        protocol: TCP
```