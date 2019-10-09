# OKN

## Getting started

OKN is super easy to install. All the OKN components are containerized and can
be installed using the Kubernetes deployment manifest.

### Requirements

OKN requires that `NodeIPAMController` and `CNI` network plugin are enabled for
the Kubernetes cluster, and it also requires that the Open vSwitch kernel module
>= version 2.6.0 is installed on all the Kubernetes worker Nodes (which should
be the case for most popular Linux distributions). OKN packages the Open vSwitch
agents in the OKN Docker image and runs them in the OKN Agent DaemonSet, and
thus does not require the Open vSwitch agents to be installed on the worker
Nodes in advance.

* To enable `NodeIPAMController`, `kube-controller-manager` should be started
with the following flags:
  - `--cluster-cidr=<CIDR Range for Pods>`
  - `--allocate-node-cidrs=true`

  When using `kubeadm` to create the Kubernetes cluster, passing
  `--pod-network-cidr=<CIDR Range for Pods>` to `kubeadm init` will set the two
  required flags. Refer to [Creating a cluster with kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm) for more information
  about setting up a Kubernetes cluster with `kubeadm`.

* To enable `CNI` network plugin, `kubelet` should be started with the
`--network-plugin=cni` flag.

  If `kubeadm` is used, `CNI` network plugin is enabled by default.

* In case a Node does not have the Open vSwitch kernel module >= version 2.6.0
installed, you can install it following the instructions at: [Installing Open
vSwitch](https://docs.openvswitch.org/en/latest/intro/install).

### Installation

To deploy OKN in your Kubernetes cluster, run the following command:
```
kubectl apply -f build/yamls/okn.yml
```

OKN components can also be run manually for development purpose. See [Manual Installation](docs/manual-installation.md)
for information.

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
