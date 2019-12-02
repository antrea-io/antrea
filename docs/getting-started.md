# Getting started

Antrea is super easy to install. All the Antrea components are
containerized and can be installed using the Kubernetes deployment
manifest.

## Ensuring requirements are satisfied

When using `kubeadm` to create the Kubernetes cluster, passing
`--pod-network-cidr=<CIDR Range for Pods>` to `kubeadm init` will enable
`NodeIpamController`. Clusters created with kubeadm will always have
`CNI` plugins enabled. Refer to
[Creating a cluster with kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm)
for more information about setting up a Kubernetes cluster with `kubeadm`.

When the cluster is deployed by other means then:

* To enable `NodeIpamController`, `kube-controller-manager` should be started
with the following flags:
  - `--cluster-cidr=<CIDR Range for Pods>`
  - `--allocate-node-cidrs=true`

* To enable `CNI` network plugins, `kubelet` should be started with the
`--network-plugin=cni` flag.

As for OVS, when using the built-in kernel module, kernel version >= 4.4 is
required. On the other hand, when building it from OVS sources, OVS
version >= 2.6.0 is required.

Red Hat Enterprise Linux and CentOS 7.x use kernel 3.10, but as changes to
OVS kernel modules are regularly backported to these kernel versions, they
should work with Antrea, starting with version 7.4.

In case a node does not have a supported OVS module installed,
you can install it following the instructions at:
[Installing Open vSwitch](https://docs.openvswitch.org/en/latest/intro/install).

## Installation

To deploy a released version of Antrea, pick a deployment manifest from the
[list of releases](https://github.com/vmware-tanzu/antrea/releases). For any
given release `<TAG>` (e.g. `v0.1.0`), you can deploy Antrea as follows:
```bash
kubectl apply -f https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea.yml
```

To deploy the latest version of Antrea (built from the master branch), use the
checked-in [deployment yaml](/build/yamls/antrea.yml):
```bash
kubectl apply -f https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea.yml
```

To build the image locally, you can follow the instructions in the [Contributor
Guide](/CONTRIBUTING.md#building-and-testing-your-change).

Antrea components can also be run manually as processes for development
purposes. See [Manual Installation](/docs/manual-installation.md) for
information.

### Deploying Antrea in Kind

To deploy Antrea in a [Kind](https://github.com/kubernetes-sigs/kind) cluster,
please refer to this [guide](/docs/kind.md).
