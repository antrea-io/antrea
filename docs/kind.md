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
  - [Antrea Agents are not starting on macOS, what could it be?](#antrea-agents-are-not-starting-on-macos-what-could-it-be)
  - [Antrea Agents are not starting on Windows, what could it be?](#antrea-agents-are-not-starting-on-windows-what-could-it-be)
<!-- /toc -->

We support running Antrea inside of Kind clusters on both Linux and macOS
hosts. On macOS, support for Kind requires the use of Docker Desktop, instead of
the legacy [Docker
Toolbox](https://docs.docker.com/docker-for-mac/docker-toolbox/).

To deploy a released version of Antrea on an existing Kind cluster, you can
simply use the same command as for other types of clusters:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

## Create a Kind cluster and deploy Antrea in a few seconds

### Using the kind-setup.sh script

To create a simple two worker Node cluster and deploy a released version of
Antrea, use:

```bash
./ci/kind/kind-setup.sh create <CLUSTER_NAME>
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

Or, for the latest version of Antrea, use:

```bash
./ci/kind/kind-setup.sh create <CLUSTER_NAME>
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea.yml
```

The `kind-setup.sh` script may execute `kubectl` commands to set up the cluster,
and requires that `kubectl` be present in your `PATH`.

To specify a different number of worker Nodes, use `--num-workers <NUM>`. To
specify the IP family of the kind cluster, use `--ip-family <ipv4|ipv6|dual>`.
To specify the Kubernetes version of the kind cluster, use
`--k8s-version <VERSION>`. To specify the Service Cluster IP range, use
`--service-cidr <CIDR>`.

If you want to pre-load the Antrea image in each Node (to avoid having each Node
pull from the registry), you can use:

```bash
tag=<TAG>
cluster=<CLUSTER_NAME>
docker pull antrea/antrea-controller-ubuntu:$tag
docker pull antrea/antrea-agent-ubuntu:$tag
./ci/kind/kind-setup.sh \
  --images "antrea/antrea-controller-ubuntu:$tag antrea/antrea-agent-ubuntu:$tag" \
  create $cluster
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/$tag/antrea.yml
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
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

### Deploy a local build of Antrea to your Kind cluster (for developers)

These instructions assume that you have built the Antrea Docker image locally
(e.g. by running `make` from the root of the repository).

```bash
# load the Antrea Docker images in the Nodes
kind load docker-image antrea/antrea-controller-ubuntu:latest antrea/antrea-agent-ubuntu:latest
# deploy Antrea
kubectl apply -f build/yamls/antrea.yml
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
document](https://github.com/antrea-io/antrea/blob/main/test/e2e/README.md#running-the-e2e-tests-on-a-kind-cluster).

## FAQ

### Antrea Agents are not starting on macOS, what could it be?

Some older versions of Docker Desktop did not include all the required Kernel
modules to run the Antrea Agent, and in particular the `openvswitch` Kernel
module. See [this issue](https://github.com/docker/for-mac/issues/4660) for more
information. This issue does not exist with recent Docker Desktop versions (`>=
2.5`).

### Antrea Agents are not starting on Windows, what could it be?

At this time, we do not officially support Antrea for Kind clusters running on
Windows hosts. In recent Docker Desktop versions, the default way of running
Linux containers on Windows is by using the [Docker Desktop WSL 2
backend](https://docs.docker.com/desktop/windows/wsl/). However, the Linux
Kernel used by default in WSL 2 does not include all the required Kernel modules
to run the Antrea Agent, and in particular the `openvswitch` Kernel
module. There are 2 different ways to work around this issue, which we will not
detail in this document:

* use the Hyper-V backend for Docker Desktop
* build a custom Kernel for WSL, with the required Kernel configuration:

  ```text
  CONFIG_NETFILTER_XT_MATCH_RECENT=y
  CONFIG_NETFILTER_XT_TARGET_CT=y
  CONFIG_OPENVSWITCH=y
  CONFIG_OPENVSWITCH_GRE=y
  CONFIG_OPENVSWITCH_VXLAN=y
  CONFIG_OPENVSWITCH_GENEVE=y
  ```
