# Deploying Antrea on a Kind cluster

<!-- toc -->
- [Create a Kind cluster and deploy Antrea in a few seconds](#create-a-kind-cluster-and-deploy-antrea-in-a-few-seconds)
  - [Using the kind-setup.sh script](#using-the-kind-setupsh-script)
    - [As an Antrea developer](#as-an-antrea-developer)
  - [Create a Kind cluster manually](#create-a-kind-cluster-manually)
  - [Deploy Antrea to your Kind cluster](#deploy-antrea-to-your-kind-cluster)
  - [Deploy a local build of Antrea to your Kind cluster (for developers)](#deploy-a-local-build-of-antrea-to-your-kind-cluster-for-developers)
  - [Check that everything is working](#check-that-everything-is-working)
- [Run the Antrea e2e tests](#run-the-antrea-e2e-tests)
- [FAQ](#faq)
  - [Why is the YAML manifest different when using Kind](#why-is-the-yaml-manifest-different-when-using-kind)
  - [Why do I need to run the <code>hack/kind-fix-networking.sh</code> script on my host](#why-do-i-need-to-run-the--script-on-my-host)
<!-- /toc -->

We support running Antrea inside of Kind clusters on both Linux and macOS
hosts. On macOS, support for Kind requires the use of Docker Desktop, instead of
the legacy [Docker
Toolbox](https://docs.docker.com/docker-for-mac/docker-toolbox/).

To deploy a released version of Antrea on an existing Kind cluster, you can use:

```bash
# "fix" the host's veth interfaces (for the different Kind Nodes)
kind get nodes | xargs ./hack/kind-fix-networking.sh
# deploy Antrea
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-kind.yml
```

## Create a Kind cluster and deploy Antrea in a few seconds

### Using the kind-setup.sh script

To create a simple two worker Node cluster and deploy a released version of
Antrea, use:

```bash
./ci/kind/kind-setup.sh create <CLUSTER_NAME>
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-kind.yml
```

Or, for the latest version of Antrea, use:

```bash
./ci/kind/kind-setup.sh create <CLUSTER_NAME>
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-kind.yml
```

The `kind-setup.sh` script may execute `kubectl` commands to set up the cluster,
and requires that `kubectl` be present in your `PATH`.

To specify a different number of worker Nodes, use `--num-workers <NUM>`. To
create an IPv6 Kind cluster, use `--ip-family ipv6`.

If you want to pre-load the Antrea image in each Node (to avoid having each Node
pull from the registry), you can use:

```bash
docker pull projects.registry.vmware.com/antrea/antrea-ubuntu:<TAG>
./ci/kind/kind-setup.sh --images projects.registry.vmware.com/antrea/antrea-ubuntu:<TAG> create <CLUSTER_NAME>
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-kind.yml
```

The `kind-setup.sh` is a convenience script typically used by developers for
testing. For more information on how to create a Kind cluster manually and
deploy Antrea, read the following sections.

#### As an Antrea developer

If you are an Antrea developer and you need to deploy Antrea with your local
changes and locally built Antrea image, use:

```bash
./ci/kind/kind-setup.sh --antrea-cni create <CLUSTER_NAME>
```

`kind-setup.sh` allows developers to specify the number of worker Nodes, the
docker bridge networks/subnets connected to the worker Nodes (to test Antrea in
different encap modes), and a list of docker images to be pre-loaded in each
Node. For more information on usage, run:

```bash
./ci/kind/kind-setup.sh help
```

As a developer, you do usually want to provide the `--antrea-cni` flag, so that
the `kind-setup.sh` can generate the appropriate Antrea YAML manifest for you on
the fly, and apply it to the created cluster directly.

### Create a Kind cluster manually

The only requirement is to use a Kind configuration file which disables the
Kubernetes default CNI (`kubenet`). For example, your configuration file may
look like this:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 10.10.0.0/16
nodes:
- role: control-plane
- role: worker
- role: worker
```

Once you have created your configuration file (let's call it `kind-config.yml`),
create your cluster with:

```bash
kind create cluster --config kind-config.yml
```

### Deploy Antrea to your Kind cluster

```bash
# "fix" the host's veth interfaces (for the different Kind Nodes)
kind get nodes | xargs ./hack/kind-fix-networking.sh
# pull the Antrea Docker image
docker pull projects.registry.vmware.com/antrea/antrea-ubuntu:<TAG>
# load the Antrea Docker image in the Nodes
kind load docker-image projects.registry.vmware.com/antrea/antrea-ubuntu:<TAG>
# deploy Antrea
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-kind.yml
```

### Deploy a local build of Antrea to your Kind cluster (for developers)

These instructions assume that you have built the Antrea Docker image locally
(e.g. by running `make` from the root of the repository).

```bash
# "fix" the host's veth interfaces (for the different Kind Nodes)
kind get nodes | xargs ./hack/kind-fix-networking.sh
# load the Antrea Docker image in the Nodes
kind load docker-image projects.registry.vmware.com/antrea/antrea-ubuntu:latest
# deploy Antrea
./hack/generate-manifest.sh --kind | kubectl apply -f -
```

### Check that everything is working

After a few seconds you should be able to observe the following when running
`kubectl get -n kube-system pods -l app=antrea`:

```bash
NAME                                 READY   STATUS    RESTARTS   AGE
antrea-agent-dgsfs                   2/2     Running   0          8m56s
antrea-agent-nzsmx                   2/2     Running   0          8m56s
antrea-agent-zsztq                   2/2     Running   0          8m56s
antrea-controller-775f4d79f8-6tksp   1/1     Running   0          8m56s
```

## Run the Antrea e2e tests

To run the Antrea e2e test suite on your Kind cluster, please refer to [this
document](../test/e2e/README.md#running-the-e2e-tests-on-a-kind-cluster).

## FAQ

### Why is the YAML manifest different when using Kind

By default Antrea uses the Open vSwitch (OVS) kernel datapath type to provide
connectivity between Pods, and each Kubernetes Node runs its own datapath
(named `br-int` by default). Because of the very nature of Kind (which uses
containers to run Kubernetes Nodes), it is not possible to use the kernel
datapath type for Kind clusters. Instead, we use OVS in [userspace
mode](http://docs.openvswitch.org/en/latest/intro/install/userspace/), which
requires some changes to the way Antrea is deployed. Most notably:

* the tun device driver needs to be mounted in the antrea-ovs container
* the Antrea agent's ConfigMap needs to be updated so that the userspace
  (`netdev`) OVS datapath type is used
* the Antrea agent's Init Container no longer needs to load the `openvswitch`
  kernel module
* the `start_ovs` script used by the `antrea-ovs` container needs to be replaced
  with the `start_ovs_netdev` script, which creates an additional bridge
  (`br-phy`) as required for [OVS userspace
  tunneling](http://docs.openvswitch.org/en/latest/howto/userspace-tunneling/)

### Why do I need to run the `hack/kind-fix-networking.sh` script on my host

The script is required for Antrea to work properly in a Kind cluster. It takes
care of disabling TX hardware checksum offload for the veth interface (in the
host's network namespace) of each Kind Node. This is required when using OVS in
userspace mode. Refer to this [Antrea Github issue
14](https://github.com/antrea-io/antrea/issues/14) for more information. For
Linux hosts, the script is equivalent to running `ethtool` directly on the Linux
host to disable TX checksum offload on each Node's veth interface. On macOS, the
script is equivalent to running `ethtool` in the Linux
[HyperKit](https://github.com/moby/hyperkit) VM which runs the Docker daemon,
and within which the Node's veth interfaces are created. The
`hack/kind-fix-networking.sh` script uses a Linux Docker container with host
networking to run `ethtool`, which means the script can be exactly the same for
both OSs.
