# Packet Capture User Guide

Starting with Antrea v2.2, Antrea supports the packet capture feature for network diagnosis.
It can capture specified number of packets from real traffic and upload them to a
supported storage location. Users can create a PacketCapture CR to trigger
packet capture on the target traffic flow.

## Prerequisites

The PacketCapture feature is disabled by default. If you
want to enable this feature, you need to set PacketCapture feature gate to `true` in
the `antrea-config` ConfigMap for `antrea-agent`.

```yaml
  antrea-agent.conf: |
    # FeatureGates is a map of feature names to bools that enable or disable experimental features.
    featureGates:
    # Enable PacketCapture feature which provides packets capture feature to diagnose network issue.
      PacketCapture: true
```

## Start a new PacketCapture

When starting a new packet capture, you can provide the following information to identify
the target traffic flow:

* Source Pod
* Destination Pod, Service or IP address
* Transport protocol (TCP/UDP/ICMP)
* Transport ports

You can start a new packet capture by creating a PacketCapture CR. An optional `fileServer` field can be specified to
store the generated packets file. Before that, a Secret named `antrea-packetcapture-fileserver-auth`
located in the `kube-system` namespace must exist and carry the auth information for the target file server.
You can also create the Secret using following `kubectl` command:

```bash
kubectl create secret generic antrea-packetcapture-fileserver-auth -n kube-system --from-literal=username='<username>'  --from-literal=password='<password>'
```

(If no `fileServer` field present in the CR, the captured packets file will only exist in the antrea-agent pod)

And here is an example of `PacketCapture` CR:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketCapture
metadata:
  name: pc-test
spec:
  fileServer:
    url: sftp://127.0.0.1:22/upload # define your own ftp url here.
  timeout: 60
  captureConfig:
    firstN:
      number: 5
  source:
    pod:
      namespace: default
      name: frontend
  destination:
    pod:
      namespace: default
      name: backend
    # Destination can also be an IP address ('ip' field) or a Service name ('service' field); the 3 choices are mutually exclusive.
  packet:
    ipFamily: IPv4
 protocol: TCP # numerical format is also supported. eg. TCP (6), UDP (17), ICMP (1)
    transportHeader:
      tcp:
        dstPort: 8080 # Destination port needs to be set when the protocol is TCP/UDP.
status:
  numCapturedPackets: 5
  # path format: <pod-name>:<filepath>. If this file was uploaded to the target file server, filename format is <uid>.pcapng
  packetsFilePath: antrea-agent-z4zgw:/tmp/antrea/packetcapture/packets/70bedae9-ba65-4f9f-bfac-59c1332e8132.pcapng
```

The CR above starts a new packet capture of TCP flows from a Pod named `frontend`
to the port 8080 of a Pod named `backend` using TCP protocol. It will capture the first 5 packets
that meet this criterion and upload them to the specified sftp server. Users can download the
packet file from the sftp server(or from local antrea-agent pod) and analyze its contents with network diagnose tools
like Wireshark or tcpdump.
