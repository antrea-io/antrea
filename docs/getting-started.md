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

Antrea is deployed with the [deployment yaml](/build/yamls/antrea.yml).

You need to update the `image` field of the container specs in the yaml file
to point to the Antrea Docker image in your Docker registry, and run the
following command to apply the deployment yaml to your Kubernetes cluster:

```
kubectl apply -f antrea.yml
```

At the moment the Antrea Docker image is not published to a public registry.

You can follow the instructions in the
[Contributor Guide](/CONTRIBUTING.md#building-and-testing-your-change)
to build the image.

Antrea components can also be run manually for development purpose.
See [Manual Installation](/docs/manual-installation.md) for information.

### Deploying Antrea in Kind

To deploy Antrea in a [Kind](https://github.com/kubernetes-sigs/kind) cluster,
please refer to this [guide](/docs/kind.md).

## Features

The first version of Antrea will offer the following features and
functionalities:

* IPv4 overlay network for a Kubernetes cluster. Either VXLAN or Geneve can
be chosen as the encapsulation protocol.
* Kubernetes [Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies) (coming soon).
* Encryption of Pod traffic with [IPSec ESP](https://tools.ietf.org/html/rfc2406) (coming soon).
* CLI for debugging (coming soon).
* [Octant](https://github.com/vmware-tanzu/octant) UI plugin for monitoring
the Antrea components health status and runtime information (coming soon).

Some of these features are still under development now and will be available
soon. Check out [Antrea ROADMAP](/ROADMAP.md) for more information about the
features that are coming and the features planned for future releases.
