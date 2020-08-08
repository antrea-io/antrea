# Deploying Antrea in AWS EKS

This document describes steps to deploy Antrea in NetworkPolicy only mode to an AWS EKS cluster.

Assuming you already have an EKS cluster, and have ``KUBECONFIG`` environment variable point to
the kubeconfig file of that cluster.

With Antrea >=v0.9.0 release, you should apply `antrea-eks-node-init.yaml` before deploying Antrea.
This would restart existing PODs (except in host network) so that Antrea can also manage it, once installed.
```
kubectl apply -f https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea-eks-node-init.yml
```

To deploy a released version of Antrea, pick a version from the
[list of releases](https://github.com/vmware-tanzu/antrea/releases).
Note that EKS support was added in release 0.5.0, which means you can not
pick a release older than 0.5.0. For any given release `<TAG>` (e.g. `v0.5.0`),
get the Antrea EKS deployment yaml at:
```
https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea-eks.yml
```

To deploy the latest version of Antrea (built from the master branch) to EKS, get the Antrea EKS
deployment yaml at:
```
https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea-eks.yml
```

```bash
kubectl apply -f antrea-eks.yaml
```
Now Antrea should be plugged into the EKS CNI and is ready to enforce NetworkPolicy.
