# Service of type LoadBalancer

## Table of Contents

<!-- toc -->
- [Service external IP management by Antrea](#service-external-ip-management-by-antrea)
  - [Configuration](#configuration)
    - [Enable Service external IP management feature](#enable-service-external-ip-management-feature)
    - [Create an ExternalIPPool custom resource](#create-an-externalippool-custom-resource)
    - [Create a Service of type LoadBalancer](#create-a-service-of-type-loadbalancer)
    - [Validate Service external IP](#validate-service-external-ip)
  - [Limitations](#limitations)
- [Using MetalLB with Antrea](#using-metallb-with-antrea)
  - [Install MetalLB](#install-metallb)
  - [Configure MetalLB with layer 2 mode](#configure-metallb-with-layer-2-mode)
  - [Configure MetalLB with BGP mode](#configure-metallb-with-bgp-mode)
<!-- /toc -->

In Kubernetes, implementing Services of type LoadBalancer usually requires
an external load balancer. On cloud platforms (including public clouds
and platforms like NSX-T) that support load balancers, Services of type
LoadBalancer can be implemented by the Kubernetes Cloud Provider, which
configures the cloud load balancers for the Services. However, the load
balancer support is not available on all platforms, or in some cases, it is
complex or has extra cost to deploy external load balancers. This document
describes two options for supporting Services of type LoadBalancer with Antrea,
without an external load balancer:

1. Using Antrea's built-in external IP management for Services of type
LoadBalancer
2. Leveraging [MetalLB](https://metallb.universe.tf)

## Service external IP management by Antrea

Antrea supports external IP management for Services of type LoadBalancer
since version 1.5, which can work together with `AntreaProxy` or
`kube-proxy` to implement Services of type LoadBalancer, without requiring an
external load balancer. With the external IP management feature, Antrea can
allocate an external IP for a Service of type LoadBalancer from an
[ExternalIPPool](egress.md#the-externalippool-resource), and select a Node
based on the ExternalIPPool's NodeSelector to host the external IP. Antrea
configures the Service's external IP on the selected Node, and thus Service
requests to the external IP will get to the Node, and they are then handled by
`AntreaProxy` or `kube-proxy` on the Node and distributed to the Service's
Endpoints. Antrea also implements a Node failover mechanism for Service
external IPs. When Antrea detects a Node hosting an external IP is down, it
will move the external IP to another available Node of the ExternalIPPool.

### Configuration

#### Enable Service external IP management feature

At this moment, external IP management for Services is an alpha feature of
Antrea. The `ServiceExternalIP` feature gate of `antrea-agent` and
`antrea-controller` must be enabled for the feature to work. You can enable
the `ServiceExternalIP` feature gate in the `antrea-config` ConfigMap in
the Antrea deployment YAML:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config-dcfb6k2hkm
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
...
      ServiceExternalIP: true
...
  antrea-controller.conf: |
    featureGates:
...
      ServiceExternalIP: true
...
```

The feature works with both `AntreaProxy` and `kube-proxy`, including the
following configurations:

- `AntreaProxy` without `proxyAll` enabled - this is `antrea-agent`'s default
configuration, in which `kube-proxy` serves the request traffic for Services
of type LoadBalancer (while `AntreaProxy` handles Service requests from Pods).
- `AntreaProxy` with `proxyAll` enabled - in this case, `AntreaProxy` handles
all Service traffic, including Services of type LoadBalancer.
- `AntreaProxy` disabled - `kube-proxy` handles all Service traffic, including
Services of type LoadBalancer.

#### Create an ExternalIPPool custom resource

Service external IPs are allocated from an ExternalIPPool, which defines a pool
of external IPs and the set of Nodes to which the external IPs can be assigned.
To learn more information about ExternalIPPool, please refer to [the Egress
documentation](egress.md#the-externalippool-resource). The example below
defines an ExternalIPPool with IP range "10.10.0.2 - 10.10.0.10", and it
selects the Nodes with label "network-role: ingress-node" to host the external
IPs:

```yaml
- apiVersion: crd.antrea.io/v1alpha2
  kind: ExternalIPPool
  metadata:
    name: service-external-ip-pool
  spec:
    ipRanges:
    - start: 10.10.0.2
      end: 10.10.0.10
    - cidr: 10.10.1.0/28
    nodeSelector:
      matchLabels:
        network-role: ingress-node
```

#### Create a Service of type LoadBalancer

For Antrea to manage the externalIP for a Service of type LoadBalancer, the
Service should be annotated with `service.antrea.io/external-ip-pool`. For
example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    service.antrea.io/external-ip-pool: "service-external-ip-pool"
spec:
  selector:
    app: MyApp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
  type: LoadBalancer
```

You can also request a particular IP from an ExternalIPPool by setting
the loadBalancerIP field in the Service spec to that specific IP available
in the ExternalIPPool, Antrea will allocate the IP from the ExternalIPPool
for the Service. For example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    service.antrea.io/external-ip-pool: "service-external-ip-pool"
spec:
  selector:
    app: MyApp
  loadBalancerIP: "10.10.0.2"
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
  type: LoadBalancer
```

#### Validate Service external IP

Once Antrea allocates an external IP for a Service of type LoadBalancer, it
will set the IP to the `loadBalancer.ingress` field in the Service resource
`status`.  For example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    service.antrea.io/external-ip-pool: "service-external-ip-pool"
spec:
  selector:
    app: MyApp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 9376
  clusterIP: 10.96.0.11
  type: LoadBalancer
status:
  loadBalancer:
    ingress:
    - ip: 10.10.0.2
      hostname: node-1
```

You can validate that the Service can be accessed from the client using the
`<external IP>:<port>` (`10.10.0.2:80/TCP` in the above example).

### Limitations

As described above, the Service externalIP management by Antrea configures a
Service's external IP to a Node, so that the Node can receive Service requests.
However, this requires that the externalIP on the Node be reachable through the
Node network. The simplest way to achieve this is to reserve a range of IPs
from the Node network subnet, and define Service ExternalIPPools with the
reserved IPs, when the Nodes are connected to a layer 2 subnet. Or, another
possible way might be to manually configure Node network routing (e.g. by
adding a static route entry to the underlay router) to route the Service
traffic to the Node that hosts the Service's externalIP.

As of now, Antrea supports Service externalIP management only on Linux Nodes.
Windows Nodes are not supported yet.

## Using MetalLB with Antrea

MetalLB also implements external IP management for Services of type
LoadBalancer, and it can be deployed to a Kubernetes cluster with Antrea.
MetalLB supports two modes - layer 2 mode and BGP mode - to advertise an
Service external IP to the Node network. The layer 2 mode is similar to what
Antrea external IP management implements and has the same limitation that the
external IPs must be allocated from the Node network subnet. The BGP mode
leverages BGP to advertise external IPs to the Node network router. It does
not have the layer 2 subnet limitation, but requires the Node network to
support BGP.

MetalLB will automatically allocate external IPs for every Service of type
LoadBalancer, and it sets the allocated IP to the `loadBalancer.ingress` field
in the Service resource `status`. MetalLB also supports user specified `loadBalancerIP`
in the Service spec. For more information, please refer to the [MetalLB usage](https://metallb.universe.tf/usage).

To learn more about MetalLB concepts and functionalities, you can read the
[MetalLB concepts](https://metallb.universe.tf/concepts).

### Install MetalLB

You can run the following commands to install MetalLB using the YAML manifests:

```bash
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/metallb.yaml
```

The commands will deploy MetalLB of version 0.11.0 into Namespace
`metallb-system`. You can also refer to this [MetalLB installation guide](https://metallb.universe.tf/installation)
for other ways of installing MetalLB.

As MetalLB will allocate external IPs for all Services of type LoadBalancer,
once it is running, the Service external IP management feature of Antrea should
not be enabled to avoid conflicts with MetalLB. You can deploy Antrea with the
default configuration (in which the `ServiceExternalIP` feature gate of
`antrea-agent` is set to `false`). MetalLB can work with both `AntreaProxy` and
`kube-proxy` configurations of `antrea-agent`.

### Configure MetalLB with layer 2 mode

MetalLB is configured through a ConfigMap. To configure MetalLB to work in the
layer 2 mode, you just need to provide the IP ranges to allocate external IPs.
The IP ranges should be from the Node network subnet.

For example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 10.10.0.2-10.10.0.10
```

### Configure MetalLB with BGP mode

The BGP mode of MetalLB requires more configuration parameters to establish BGP
peering to the router. The example below configures MetalLB using AS number
64500 to connect to peer router 10.0.0.1 with AS number 64501:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    peers:
    - peer-address: 10.0.0.1
      peer-asn: 64501
      my-asn: 64500
    address-pools:
    - name: default
      protocol: bgp
      addresses:
      - 10.10.0.2-10.10.0.10
```

In addition to the basic layer 2 and BGP mode configurations described in this
document, MetalLB supports a few more advanced BGP configurations and supports
configuring multiple IP pools which can use different modes. For more
information, please refer to the [MetalLB configuration guide](https://metallb.universe.tf/configuration).
