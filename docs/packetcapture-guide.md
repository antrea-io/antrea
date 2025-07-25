# Packet Capture User Guide

Starting with Antrea v2.2, Antrea supports PacketCapture for network diagnosis.
It can capture specified number of packets from real traffic and upload them to a
supported storage location. Users can create a `PacketCapture` CR to trigger
packet capture on the target traffic flow.

## Prerequisites

PacketCapture is disabled by default. If you
want to enable this feature, you need to set feature gate `PacketCapture` to `true` in
the `antrea-config` ConfigMap for `antrea-agent`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      PacketCapture: true
```

## Start a new PacketCapture

When starting a new packet capture, you can provide the following information to identify
the target traffic flow:

* Source Pod, or IP address
* Destination Pod, or IP address
* Transport protocol (TCP/UDP/ICMP)
* Transport ports
* TCP Flags
* ICMP Messages
* Direction (SourceToDestination/DestinationToSource/Both)

You can start a new packet capture by creating a `PacketCapture` CR. An optional `fileServer`
field can be specified to store the generated packets file. Before that,
a Secret named `antrea-packetcapture-fileserver-auth` located in the same Namespace where
Antrea is deployed must exist and carry the authentication information for the target file server.
You can also create the Secret using the following `kubectl` command:

```bash
kubectl create secret generic antrea-packetcapture-fileserver-auth -n kube-system --from-literal=username='<username>' --from-literal=password='<password>'
```

If no `fileServer` field is present in the CR, the captured packets file will be saved in the
antrea-agent Pod (the one on the same Node with the source or destination Pod in the CR). The result
path information will be available in `.status.FilePath`.

And here is an example of `PacketCapture` CR:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketCapture
metadata:
  name: pc-test
spec:
  fileServer:
    url: sftp://127.0.0.1:22/upload # Define your own sftp url here.
    # Host public key (as a base64-encoded string) that will be accepted when connecting to the file server.
    # Get this key from your SSH server configuration, or from a known_hosts file.
    # If omitted, any host key will be accepted, which is insecure and not recommended.
    hostPublicKey: AAAAC3NzaC1lZDI1NTE5AAAAIBCUI6Yi9KbkiPXK2MzqYYtlluw7v_WQz071JZPdZEKr # Replace with your own.
  timeout: 60
  captureConfig:
    firstN:
      number: 5
  source:
    pod:
      namespace: default
      name: frontend
  destination:
  # Available options for source/destination could be `pod` (a Pod), `ip` (a specific IP address). These 2 options are mutually exclusive.
    pod:
      namespace: default
      name: backend
  # Available options for direction: `SourceToDestination` (default), `DestinationToSource` or `Both`.
  direction: SourceToDestination # optional to specify
  packet:
    ipFamily: IPv4
    protocol: TCP # support arbitrary number values and string values in [TCP,UDP,ICMP] (case insensitive)
    transportHeader:
      tcp:
        dstPort: 8080 # Destination port needs to be set when the protocol is TCP/UDP.
        # List of TCP Flag Matchers. Each specifies a value and optional mask to match against TCP flags in packets.
        # Equivalent to `tcp[13] & <mask> == <value>` tcpdump filter.
        flags:
          - value: 0x2 # SYN
            mask: 0x2 # defaults to value if not specified
```

The CR above starts a new packet capture of TCP flows from a Pod named `frontend`
to the port 8080 of a Pod named `backend` using TCP protocol and have the TCP SYN flag set. It
will capture the first 5 packets that meet this criterion and upload them to the specified sftp
server. Users can download the packet file from the sftp server (or from the local antrea-agent
Pod) and analyze its content with network diagnose tools like Wireshark or tcpdump.

Example of `PacketCapture` CR for capturing packets based on ICMP messages:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketCapture
metadata:
  name: pc-test
spec:
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
  direction: DestinationToSource
  packet:
    ipFamily: IPv4
    protocol: ICMP
    transportHeader:
      icmp:
        # List of ICMP Message Matchers. Each specifies a type and optional code to match against ICMP messages in packets.
        # type value can be provided either as a string or number. Available string options are 'icmp-echo', 'icmp-echoreply', 'icmp-unreach' and 'icmp-timxceed' 
        # code value can only be provided as a number.
        messages:
          - type: icmp-unreach # destination unreachable, or 3
            code: 1 # host unreachable
          - type: 0 # echo reply
```

The CR above starts a new packet capture of ICMP flows from a Pod named `frontend`
to a Pod named `backend` using ICMP protocol and targeting at either echo reply or destination (host) unreachable packets.
It will capture the first 5 packets in the reverse direction (destination to source).

Note: This feature is not supported on Windows for now.
