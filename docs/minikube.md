# Deploying Antrea on Minikube

<!-- toc -->
- [Install Minikube](#install-minikube)
- [Deploy Antrea](#deploy-antrea)
  - [Deploy Antrea to Minikube cluster](#deploy-antrea-to-minikube-cluster)
  - [Deploy a local build of Antrea to Minikube cluster (for developers)](#deploy-a-local-build-of-antrea-to-minikube-cluster-for-developers)
- [Verification](#verification)
<!-- /toc -->

## Install Minikube

Follow these [steps](https://minikube.sigs.k8s.io/docs/start) to install minikube and set its development environment.

## Deploy Antrea

### Deploy Antrea to Minikube cluster

```bash
# curl is required because --cni flag does not accept URL as a parameter
curl -Lo https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
minikube start --cni=antrea.yml --network-plugin=cni
```

### Deploy a local build of Antrea to Minikube cluster (for developers)

These instructions assume that you have built the Antrea Docker image locally
(e.g. by running `make` from the root of the repository, or in case of arm64 architecture by running
`./hack/build-antrea-linux-all.sh --platform linux/arm64`).

```bash
# load the Antrea Docker images in the minikube nodes
minikube image load antrea/antrea-controller-ubuntu:latest
minikube image load antrea/antrea-agent-ubuntu:latest
# deploy Antrea
kubectl apply -f antrea/build/yamls/antrea.yml
```

## Verification

After a few seconds you should be able to observe the following when running
`kubectl get pods -l app=antrea -n kube-system`:

```txt
NAME                                 READY   STATUS    RESTARTS   AGE
antrea-agent-9ftn9                   2/2     Running   0          66m
antrea-controller-56f97bbcff-zbfmv   1/1     Running   0          66m
```
