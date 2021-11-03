# Deploying Antrea in AWS EKS

This document describes steps to deploy Antrea in `networkPolicyOnly` mode or `encap` mode to an
AWS EKS cluster.

## Deploying Antrea in `networkPolicyOnly` mode

In `networkPolicyOnly` mode, Antrea implements NetworkPolicy and other services for an EKS cluster,
while Amazon VPC CNI takes care of IPAM and Pod traffic routing across Nodes. Refer to
[the design document](design/policy-only.md) for more information about `networkPolicyOnly` mode.

This document assumes you already have an EKS cluster, and have ``KUBECONFIG`` environment variable
point to the kubeconfig file of that cluster. You can follow [the EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/create-cluster.html)
to create the cluster.

With Antrea >=v0.9.0 release, you should apply `antrea-eks-node-init.yaml` before deploying Antrea.
This will restart existing Pods (except those in host network), so that Antrea can also manage them
(i.e. enforce NetworkPolicies on them) once it is installed.

```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-eks-node-init.yml
```

To deploy a released version of Antrea, pick a deployment manifest from the
[list of releases](https://github.com/antrea-io/antrea/releases).
Note that EKS support was added in release 0.5.0, which means you cannot
pick a release older than 0.5.0. For any given release `<TAG>` (e.g. `v0.5.0`),
you can deploy Antrea as follows:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-eks.yml
```

To deploy the latest version of Antrea (built from the main branch), use the
checked-in [deployment yaml](/build/yamls/antrea-eks.yml):

```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-eks.yml
```

Now Antrea should be plugged into the EKS CNI and is ready to enforce NetworkPolicy.

## Deploying Antrea in `encap` mode

In `encap` mode, Antrea acts as the primary CNI of an EKS cluster, and
implements all Pod networking functionalities, including IPAM and routing across
Nodes. The major benefit of Antrea as the primary CNI is that it can get rid of
the Pods per Node limits with Amazon VPC CNI. For example, the default mode of
VPC CNI allocates a secondary IP for each Pod, and the maximum number of Pods
that can be created on a Node is decided by the maximum number of elastic
network interfaces and secondary IPs per interface that can be attached to an
EC2 instance type. When Antrea is the primary CNI, Pods are connected to the
Antrea overlay network and Pod IPs are allocated from the private CIDRs
configured for an EKS cluster, and so the number of Pods per Node is no longer
limited by the number of secondary IPs per instance.

Note: as a general limitation when using custom CNIs with EKS, Antrea cannot be
installed to the EKS control plane Nodes. As a result, EKS control plane
cannot initiate a connection to a Pod in Antrea overlay network, when Antrea
runs in `encap` mode, and so applications that require control plane to Pod
connections might not work properly. For example, [Kubernetes API aggregation](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation),
[apiserver proxy](https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#manually-constructing-apiserver-proxy-urls),
or [admission controller](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers),
will not work with `encap` mode on EKS, when the Services are provided
by Pods in overlay network. A workaround is to run such Pods in `hostNetwork`.

### 1. Create an EKS cluster without Nodes

This guide uses `eksctl` to create an EKS cluster, but you can also follow the
[EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/create-cluster.html)
to create an EKS cluster. `eksctl` can be installed following the [eksctl guide](https://docs.aws.amazon.com/eks/latest/userguide/eksctl.html).

Run the following `eksctl` command to create a cluster named `antrea-eks-cluster`:

```bash
eksctl create cluster --name antrea-eks-cluster --without-nodegroup
```

After the command runs successfully, you should be able to access the cluster
using `kubectl`, for example:

```bash
kubectl get node
```

Note, as the cluster does not have a node group configured yet, no Node will be
returned by the command.

### 2. Delete Amazon VPC CNI

As Antrea is the primary CNI in `encap` mode, the VPC CNI (`aws-node` DaemonSet)
installed with the EKS cluster needs to be deleted:

```bash
kubectl -n kube-system delete daemonset aws-node
```

### 3. Install Antrea

First, download the Antrea deployment yaml. Note that `encap` mode support for
EKS was added in release 1.4.0, which means you cannot pick a release older
than 1.4.0. For any given release `<TAG>` (e.g. `v1.4.0`), get the Antrea
deployment yaml at:

```text
https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

To deploy the latest version of Antrea (built from the main branch), get the
deployment yaml at:

```text
https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea.yml
```

`encap` mode on EKS requires Antrea's built-in Node IPAM feature to be enabled.
For information about how to configure Antrea Node IPAM, please refer to
[Antrea Node IPAM guide](antrea-ipam.md#running-nodeipam-within-antrea-controller).

After enabling Antrea Node IPAM in the deployment yaml, deploy Antrea with:

```bash
kubectl apply -f antrea.yml
```

### 4. Create a node group for the EKS cluster

For example, you can run the following command to create a node group of two
Nodes:

```bash
eksctl create nodegroup --cluster antrea-eks-cluster --nodes 2
```

### 5. Validate Antrea installation

After the EKS Nodes are successfully created and booted, you can verify that
Antrea Controller and Agent Pods are running on the Nodes:

```bash
$ kubectl get pods --namespace kube-system  -l app=antrea
NAME                                 READY   STATUS    RESTARTS   AGE
antrea-agent-bpj72                   2/2     Running   0          40s
antrea-agent-j2sjz                   2/2     Running   0          40s
antrea-controller-6f7468cbff-5sk4t   1/1     Running   0          43s
```
