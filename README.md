# OKN

## Getting started

OKN components can be installed as Kubernetes DaemonSet and Deployment using Kubernetes manifests.

### Requirements

* A kubernetes cluster is created. See [Creating a cluster with kubeadm](
https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/) for details.

* `kube-controller-manager` is configured to enable `NodeIPAMController` by setting the following flags:
  - `--cluster-cidr=<CIDR Range for Pods>`
  - `--allocate-node-cidrs=true`

  If `kubeadm` is used, passing `--pod-network-cidr=<CIDR Range for Pods>` to `kubeadm init` will set the two flags.

* `kubelet` is configured to use `cni` network plugin. If `kubeadm` is used, `--network-plugin=cni` is set by default.

* Open vSwitch >= 2.8.0 kernel module is installed and loaded on all worker nodes, See [Installing Open vSwitch](
https://docs.openvswitch.org/en/latest/intro/install/#installation-from-packages) for details.

### Installation

To deploy OKN in your Kubernetes cluster, run the following command:
```
kubectl apply -f build/yamls/okn.yml
```

OKN components can also be run manually for development purpose. See [Manual Installation](docs/manual-installation.md)
for details.

## Building and testing

The OKN project uses the [Go modules
support](https://github.com/golang/go/wiki/Modules) which was introduced in Go
1.11. It facilitates dependency tracking and no longer requires projects to live
inside the `$GOPATH`.

To develop locally, you can follow these steps:

 1. [Install Go 1.12](https://golang.org/doc/install)

 2. Clone this repository anywhere on your machine and `cd` into it

 3. To build all Go files and install them under `bin`, run `make bin`

 4. To run all Go unit tests, run `make test-unit`
