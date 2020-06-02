# Deploying Antrea in AWS EKS

This document describes steps to deploy Antrea in NetworkPolicy only mode to an AWS EKS cluster.

Assuming you already have an EKS cluster, and have ``KUBECONFIG`` environment variable point to
the kubeconfig file of that cluster.

To deploy a released version of Antrea, pick a version from the
[list of releases](https://github.com/vmware-tanzu/antrea/releases).
Note that EKS support was added in release 0.5.0, which means you can not
pick a release older than 0.5.0. For any given release `<TAG>` (e.g. `v0.7.0`),
get the Antrea EKS deployment yaml at:

```
https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea-eks.yml
```

To deploy the latest version of Antrea (built from the master branch) to EKS, get the Antrea EKS
deployment yaml at:

```
https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea-eks.yml
```

Based on EKS worker Node MTU size and Kubernetes service cluster IP range, adjust
``defaultMTU`` and ``serviceCIDR`` values of antrea-agent.conf in antrea-eks.yml
 accordingly, and apply antrea-eks.yml to the EKS cluster.

```bash
kubectl apply -f antrea-eks.yaml 
```

Now Antrea should be plugged into the EKS CNI and is ready to enforce NetworkPolicy.

### Caveats

Some Pods may already be installed before Antrea deployment. Antrea cannot enforce NetworkPolicy
on these pre-installed Pods. This may be remedied by restarting the Pods. For example,

```bash
kubectl scale deployment coredns --replicas 0 -n kube-system
kubectl scale deployment coredns --replicas 2 -n kube-system
```
