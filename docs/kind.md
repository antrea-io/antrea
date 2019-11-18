# Deploying Antrea on a Kind cluster

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
# load the Antrea Docker image in the Nodes
kind load docker-image antrea/antrea-ubuntu:latest
# deploy Antrea
./hack/generate-manifest.sh --kind | kubectl apply -f -
```

### Check that everything is working

After a few seconds you sould be able to observe the following when running
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
