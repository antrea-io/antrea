# NoEncap and Hybrid Traffic Modes of Antrea

Besides the default `Encap` mode, in which Pod traffic across Nodes will be
encapsulated and sent over tunnels, Antrea also supports `NoEncap` and `Hybrid`
traffic modes. In `NoEncap` mode, Antrea does not encapsulate Pod traffic, but
relies on the Node network to route the traffic across Nodes. In `Hybrid` mode,
Antrea encapsulates Pod traffic when the source Node and the destination Node
are in different subnets, but does not encapsulate when the source and the
destination Nodes are in the same subnet. This document describes how to
configure Antrea with the `NoEncap` and `Hybrid` modes.

## Hybrid Mode

Let us start from `Hybrid` mode which is simpler to configure. `Hybrid` mode
does not encapsulate Pod traffic when the source and the destination Nodes are
in the same subnet. Thus it requires the Node network to allow Pod IP addresses
to be sent out from the Nodes' NICs. This requirement is not supported in all
the networks and clouds, or in some cases it might require specific
configuration of the Node network. For example:

* On AWS, the source/destination checks must be disabled on the EC2 instances of
the Kubernetes Nodes, as described in the
[AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck).

* On Google Compute Engine, IP forwarding must be enabled on the VM instances as
described in the [Google Cloud documentation](https://cloud.google.com/vpc/docs/using-routes#canipforward).

* On Azure, there is no way to let VNet forward unknown IPs, hence Antrea
`Hybrid` mode cannot work on Azure.

If the Node network does allow Pod IPs sent out from the Nodes, you can
configure Antrea to run in the `Hybrid` mode by setting the `trafficEncapMode`
config option of `antrea-agent` to `hybrid`. The `trafficEncapMode` config
option is defined in `antrea-agent.conf` of the `antrea` ConfigMap in the
[Antrea deployment YAML](https://github.com/vmware-tanzu/antrea/blob/main/build/yamls/antrea.yml).

```yaml
  antrea-agent.conf: |
    ... ...
    trafficEncapMode: hybrid
    ... ...
```

After changing the config option, you can deploy Antrea in `Hybrid` mode with
the usual command:

```bash
kubectl apply -f antrea.yml
```

## NoEncap Mode

In `NoEncap` mode, Antrea never encapsulates Pod traffic. Just like `Hybrid`
mode, the Node network needs to allow Pod IP addresses sent out from Nodes. When
the Nodes are not in the same subnet, `NoEncap` mode additionally requires the
Node network be able to route the Pod traffic from the source Node to the
destination Node. There are two possibilities to enable this routing by Node
network:

* Leverage Route Controller of [Kubernetes Cloud Controller Manager](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller).
The Kubernetes Cloud Providers that implement Route Controller can add routes
to the cloud network routers for the Pod CIDRs of Nodes, and then the cloud
network is able to route Pod traffic between Nodes. This Route Controller
functionality is supported by the Cloud Provider implementations of the major
clouds, including: [AWS](https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/legacy-cloud-providers/aws),
[Azure](https://github.com/kubernetes-sigs/cloud-provider-azure),
[GCE](https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/legacy-cloud-providers/gce),
and [vSphere (with NSX-T)](https://github.com/kubernetes/cloud-provider-vsphere).

* Run a routing protocol or even manually configure routers to add routes to
the Node network routers. For example, Antrea can work with [kube-router](https://www.kube-router.io)
and leverage kube-router to advertise Pod CIDRs to routers using BGP. Section
[Using kube-router for BGP](#using-kube-router-for-bgp) describes how to
configure Antrea and kube-router to work together.

When the Node network can support forwarding and routing of Pod traffic, Antrea
can be configured to run in the `NoEncap` mode, by setting the `trafficEncapMode`
config option of `antrea-agent` to `noEncap`. By default, Antrea performs SNAT
(source network address translation) for the outbound connections from a Pod to
outside of the Pod network, using the Node's IP address as the SNAT IP. In the
`NoEncap` mode, as the Node network knows about Pod IP addresses, the SNAT by
Antrea might be unnecessary. In this case, you can disable it by setting the
`noSNAT` config option to `true`. The `trafficEncapMode` and `noSNAT` config
options are defined in `antrea-agent.conf` of the `antrea` ConfigMap in the
[Antrea deployment YAML](https://github.com/vmware-tanzu/antrea/blob/main/build/yamls/antrea.yml).

```yaml
  antrea-agent.conf: |
    ... ...
    trafficEncapMode: noEncap

    noSNAT: false # Set to true to disable Antrea SNAT for external traffic
    ... ...
```

After changing the options, you can deploy Antrea in `noEncap` mode by applying
the deployment YAML.

### Using kube-router for BGP

We can run kube-router in advertisement-only mode to advertise Pod CIDRs to the
peered routers, so the routers can know how to route Pod traffic to the Nodes.
To deploy kube-router in advertisement-only mode, first download the
[kube-router DaemonSet template](https://raw.githubusercontent.com/cloudnativelabs/kube-router/v0.4.0/daemonset/generic-kuberouter-only-advertise-routes.yaml):

```bash
curl -LO https://raw.githubusercontent.com/cloudnativelabs/kube-router/v0.4.0/daemonset/generic-kuberouter-only-advertise-routes.yaml
```

Then edit the YAML file and set the following kube-router arguments:

```yaml
- "--run-router=true"
- "--run-firewall=false"
- "--run-service-proxy=false"
- "--enable-cni=false"
- "--enable-ibgp=false"
- "--enable-overlay=false"
- "--enable-pod-egress=false"
- "--peer-router-ips=<CHANGE ME>"
- "--peer-router-asns=<CHANGE ME>"
```

The BGP peers should be configured by specifying the `--peer-router-asns` and
`--peer-router-ips` parameters. Note, the ASNs and IPs must match the
configuration on the peered routers. For example:

```yaml
- "--peer-router-ips=192.168.1.99,192.168.1.100
- "--peer-router-asns=65000,65000"
```

Then you can deploy the kube-router DaemonSet with:

```bash
kubectl apply -f generic-kuberouter-only-advertise-routes.yaml
```

You can verify that the kube-router Pods are running on the Nodes of your
Kubernetes cluster by (the cluster in the following example has only two Nodes):

```bash
$ kubectl -n kube-system get pods -l k8s-app=kube-router
NAME                READY     STATUS    RESTARTS   AGE
kube-router-rn4xc   1/1       Running   0          1m
kube-router-vhrf5   1/1       Running   0          1m
```

Antrea can be deployed either before or after kube-router, with the `NoEncap`
mode.
