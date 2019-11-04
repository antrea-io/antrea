# Antrea

Antrea is a [Kubernetes](https://kubernetes.io) networking solution that is intended to be
Kubernetes-centric and Kubernetes-native. It implements and is highly optimized
for networking and security of a Kubernetes cluster, leveraging Kubernetes and
Kubernetes native solutions as much as possible. It supports any compute
platform that Kubernetes runs on and will support both Linux and Windows Nodes.

Antrea leverages [Open vSwitch](https://www.openvswitch.org/) as the networking data plane in every Kubernetes
Node. Open vSwitch is a high-performance programmable virtual switch. It is an
extensively adopted Linux vSwitch. As of Linux 3.3 the OVS kernel module is part
of the mainline kernel. It also works on Windows. Open vSwitch enables Antrea to
implement Kuberentes Network Policies in a high-performance and efficient
manner. Due to the "programmable" characteristic of Open vSwitch, Antrea is able
to implement an extensive set of networking and security features and services
on top of Open vSwitch for both Linux and Windows.

## Features

The first version of Antrea will offer the following features and
functionalities:

* IPv4 overlay network for a Kubernetes cluster. Either VXLAN or Geneve can
be chosen as the encapsulation protocol.
* Kubernetes [Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies) (coming soon).
* Encryption of Pod traffic with [IPSec ESP](https://tools.ietf.org/html/rfc2406) (coming soon).
* CLI for debugging (coming soon).
* [Octant](https://github.com/vmware-tanzu/octant) UI plugin for monitoring the Antrea components health status and runtime
information (coming soon).

Some of these features are still under development now and will be available
soon. Check out [Antrea ROADMAP](ROADMAP.md) for more information about the
features that are coming and the features planned for future releases.

## Getting started

Antrea is super easy to install. All the Antrea components are containerized and can
be installed using the Kubernetes deployment manifest.

### Requirements

Antrea requires that `NodeIPAMController` and `CNI` network plugin are enabled for
the Kubernetes cluster, and it also requires that the Open vSwitch kernel module
is installed on all the Kubernetes worker Nodes. Most popular Linux distros
should already include the OVS module good for Antrea. If the OVS module is from
the Linux upstream, a version >= 4.4 is required (Red Hat Enterprise Linux 7.x
and CentOS 7.x use kernel 3.10, but they back port OVS modules changes and
should work with Antrea since version 7.4); if the OVS module is built from the
OVS source tree, a version >= 2.6.0 is required.

Antrea packages the OVS daemons in the Antrea Docker image and runs them in the
Antrea Agent DaemonSet, and thus does not require the OVS daemons to be
installed on the worker Nodes in advance.

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

* In case a Node does not have the OVS module of a supported version installed,
you can install it following the instructions at: [Installing Open vSwitch](https://docs.openvswitch.org/en/latest/intro/install).

### Installation

Antrea is deployed with the [deployment yaml](build/yamls/antrea.yml). You need to update the `image` field
of the container specs in the yaml file to point to the Antrea Docker image in
your Docker registry, and run the following command to apply the deployment yaml
to your Kubernetes cluster:

```
kubectl apply -f antrea.yml
```

At the moment the Antrea Docker image is not published to a public registry yet.
You can follow the instructions in the [Contributor Guide](CONTRIBUTING.md#building-and-testing-your-change) to build the image.

Antrea components can also be run manually for development purpose. See [Manual Installation](docs/manual-installation.md)
for information.

### Contribute

The Antrea community welcomes new contributors. Please join our [slack channel](https://projectantrea.slack.com/)
and [mailing list](https://groups.google.com/forum/#!forum/antrea-dev) to stay updated, get help to get started, start conversations
and propose new ideas. We are waiting for your PRs!

Check out the [Contributor Guide](CONTRIBUTING.md) for detailed
information on how to effectively contribute to this project.

Also check the [Architecture document](/docs/architecture.md) for the Antrea architecture and design.
