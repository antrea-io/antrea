# PacketSampling User Guide

Starting with Antrea v1.16, Antrea supports using PacketSampling for network diagnosis. It can capture
specified number of packets from real traffic and upload them to a
supported storage location. Users can create a PacketSampling CRD to trigger
such an action on the target traffic flow.

<!-- toc -->
- [Prerequisites](#prerequisites)
- [Start a new PacketSampling](#start-a-new-packetsampling)
<!-- /toc -->

## Prerequisites

The PacketSampling feature is disabled by default. If you
want to enable this feature, you need to set PacketSampling feature gate to true in `antrea-config` ConfigMap for both antrea-controller and antrea-agent. In
order to use a Service as the destination in sampling, you also need to ensure
[AntreaProxy](feature-gates.md#antreaproxy) is enabled in the agent configuration:

```yaml
  antrea-controller.conf: |
    featureGates:
    # Enable packetsampling feature to help diagnose network issues by capture real traffic packets.
      PacketSampling: true
  antrea-agent.conf: |
    featureGates:
    # Enable packetsampling feature to capture real traffic packets.
      PacketSampling: true
```

## Start a new PacketSampling

When start a new packet sampling, you can provide the following information to identify
the target flow:

* Source Pod
* Destination Pod, Service or IP address
* Transport protocol (TCP/UDP/ICMP)
* Transport ports

You can start a new packet sampling by creating PacketSampling CRD via
`kubectl` and a yaml file which contains the essential configuration of
PacketSampling CRD. Following is an example yaml file of PacketSampling CRD:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketSampling
metadata:
  name: ps-test
spec:
  fileServer:
    url: sftp://127.0.0.1:22/upload # define your own ftp url here.
  authentication:
    authType: "BasicAuthentication"
    authSecret:
      name: test-secret
      namespace: default
  timeout: 600
  type: FirstNSampling
  firstNSamplingConfig:
    number: 5
  source:
    namespace: default
    pod: frontend
  destination:
    namespace: default
    pod: backend
    # Destination can also be an IP address ('ip' field) or a Service name ('service' field); the 3 choices are mutually exclusive.
  packet:
    ipHeader: # If ipHeader/ipv6Header is not set, the default value is IPv4+ICMP.
      protocol: 6 # Protocol here can be 6 (TCP), 17 (UDP) or 1 (ICMP), default value is 1 (ICMP)
    transportHeader:
      tcp:
        dstPort: 8080 # Destination port needs to be set when the protocol is TCP/UDP.
The CRD above starts a new packet sampling from a Pod named `frontend`
to the port 8080 of a Pod named `backend` using TCP protocol.
