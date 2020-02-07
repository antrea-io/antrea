# Deploying Antrea on a Kind cluster

We support running Antrea inside of Kind clusters on both Linux and macOS
hosts. On macOS, support for Kind requires the use of Docker Desktop, instead of
the legacy [Docker
Toolbox](https://docs.docker.com/docker-for-mac/docker-toolbox/).

## Create a Kind cluster and deploy Antrea in a few seconds

### Create a Kind cluster

The only requirement is to use a Kind configuration file which disables the
Kubernetes default CNI (`kubenet`). For example, your configuration file may
look like this:
```yaml
kind: Cluster
apiVersion: kind.sigs.k8s.io/v1alpha3
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

These instructions assume that you have built the `antrea/antrea-ubuntu` Docker
image locally (e.g. by running `make` from the root of the repository).

```bash
# "fix" the host's veth interfaces (for the different Kind Nodes)
kind get nodes | xargs ./hack/kind-fix-networking.sh
# load the Antrea Docker image in the Nodes
kind load docker-image antrea/antrea-ubuntu:latest
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

## FAQ

### Why is the YAML manifest different when using Kind?

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
 * the `start_ovs` script used by the `antrea-ovs` container needs to be
   replaced with the `start_ovs_netdev` script, which creates an additional
   bridge (`br-phy`) as required for [OVS userspace
   tunneling](http://docs.openvswitch.org/en/latest/howto/userspace-tunneling/)

### Why do I need to run the `hack/kind-fix-networking.sh` script on my host?

The script is required for Antrea to work properly in a Kind cluster. It takes
care of disabling TX hardware checksum offload for the veth interface (in the
host's network namespace) of each Kind Node. This is required when using OVS in
userspace mode. Refer to this [Antrea Github issue #14](https://github.com/vmware-tanzu/antrea/issues/14) for more information. For
Linux hosts, the script is equivalent to running `ethtool` directly on the Linux
host to disable TX checksum offload on each Node's veth interface. On macOS, the
script is equivalent to running `ethtool` in the Linux
[HyperKit](https://github.com/moby/hyperkit) VM which runs the Docker daemon,
and within which the Node's veth interfaces are created. The
`hack/kind-fix-networking.sh` script uses a Linux Docker container with host
networking to run `ethtool`, which means the script can be exactly the same for
both OSs.
