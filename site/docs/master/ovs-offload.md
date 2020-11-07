# OVS Hardware Offload

The OVS software based solution is CPU intensive, affecting system performance
and preventing fully utilizing available bandwidth. OVS 2.8 and above support
a feature called OVS Hardware Offload which improves performance significantly.
This feature allows offloading the OVS data-plane to the NIC while maintaining
OVS control-plane unmodified. It is using SR-IOV technology with VF representor
host net-device. The VF representor plays the same role as TAP devices
in Para-Virtual (PV) setup. A packet sent through the VF representor on the host
arrives to the VF, and a packet sent through the VF is received by its representor.

## Supported Ethernet controllers

The following manufacturers are known to work:

- Mellanox ConnectX-5 and above

## Prerequisites

- Antrea v0.9.0 or greater
- Linux Kernel 5.7 or greater
- iproute 4.12 or greater

## Instructions for Mellanox ConnectX-5 and Above

In order to enable Open vSwitch hardware offload, the following steps
are required. Please make sure you have root privileges to run the commands
below.

Check the Number of VF Supported on the NIC

```
cat /sys/class/net/enp3s0f0/device/sriov_totalvfs
8
```

Create the VFs

```
echo '4' > /sys/class/net/enp3s0f0/device/sriov_numvfs
```

Verify that the VFs are created

```
ip link show enp3s0f0
8: enp3s0f0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT qlen 1000
   link/ether a0:36:9f:8f:3f:b8 brd ff:ff:ff:ff:ff:ff
   vf 0 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
   vf 1 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
   vf 2 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
   vf 3 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
```

Set up the PF to be up

```
ip link set enp3s0f0 up
```

Unbind the VFs from the driver

```
echo 0000:03:00.2 > /sys/bus/pci/drivers/mlx5_core/unbind
echo 0000:03:00.3 > /sys/bus/pci/drivers/mlx5_core/unbind
echo 0000:03:00.4 > /sys/bus/pci/drivers/mlx5_core/unbind
echo 0000:03:00.5 > /sys/bus/pci/drivers/mlx5_core/unbind
```

Configure SR-IOV VFs to switchdev mode

```
devlink dev eswitch set pci/0000:03:00.0 mode switchdev
ethtool -K enp3s0f0 hw-tc-offload on
```

Bind the VFs to the driver

```
echo 0000:03:00.2 > /sys/bus/pci/drivers/mlx5_core/bind
echo 0000:03:00.3 > /sys/bus/pci/drivers/mlx5_core/bind
echo 0000:03:00.4 > /sys/bus/pci/drivers/mlx5_core/bind
echo 0000:03:00.5 > /sys/bus/pci/drivers/mlx5_core/bind
```

## SR-IOV network device plugin configuration

Create a ConfigMap that defines SR-IOV resource pool configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sriovdp-config
  namespace: kube-system
data:
  config.json: |
    {
      "resourceList": [{
          "resourcePrefix": "mellanox.com",
          "resourceName": "cx5_sriov_switchdev",
          "isRdma": true,
          "selectors": {
                  "vendors": ["15b3"],
                  "devices": ["1018"],
                  "drivers": ["mlx5_core"]
              }
      }
      ]
    }
```

Deploy SR-IOV network device plugin as DaemonSet. See https://github.com/intel/sriov-network-device-plugin.

Deploy multus CNI as DaemonSet. See https://github.com/intel/multus-cni.

Create NetworkAttachementDefinition CRD with Antrea CNI config.

```yaml
Kubernetes Network CRD Spec:
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: default
  annotations:
    k8s.v1.cni.cncf.io/resourceName: mellanox.com/cx5_sriov_switchdev
spec:
  config: '{
    "cniVersion": "0.3.1",
    "name": "antrea",
    "plugins": [ { "type": "antrea", "ipam": { "type": "host-local" } }, { "type": "portmap", "capabilities": {"portMappings": true}, { "type": "bandwidth", "capabilities": {"bandwidth": true} }]
}'
```
## Deploy Antrea Image with hw-offload enabled
Modify the build/yamls/antrea.yml with offload flag

```yaml
  - command:
    - start_ovs
    - --hw-offload
```

## Deploy POD with OVS hardware-offload

Create POD spec and request a VF

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ovs-offload-pod1
  annotations:
    v1.multus-cni.io/default-network: default
spec:
  containers:
  - name: networkstatic/iperf3
    image: centos/tools
    resources:
      requests:
        mellanox.com/cx5_sriov_switchdev: '1'
      limits:
        mellanox.com/cx5_sriov_switchdev: '1'
```

## Verify Hardware-Offloads is Working

Run iperf3 server on POD 1
```
kubectl exec -it ovs-offload-pod1 -- iperf3 -s
```
Run iperf3 client on POD 2

```
kubectl exec -it ovs-offload-pod2 -- iperf3 -c 192.168.1.17 -t 100
```

Check traffic on the VF representor port. Verify only TCP connection establishment appears
```
tcpdump -i mofed-te-b5583b tcp
listening on mofed-te-b5583b, link-type EN10MB (Ethernet), capture size 262144 bytes
22:24:44.969516 IP 192.168.1.16.43558 > 192.168.1.17.targus-getdata1: Flags [S], seq 89800743, win 64860, options [mss 1410,sackOK,TS val 491087056 ecr 0,nop,wscale 7], length 0
22:24:44.969773 IP 192.168.1.17.targus-getdata1 > 192.168.1.16.43558: Flags [S.], seq 1312764151, ack 89800744, win 64308, options [mss 1410,sackOK,TS val 4095895608 ecr 491087056,nop,wscale 7], length 0
22:24:45.085558 IP 192.168.1.16.43558 > 192.168.1.17.targus-getdata1: Flags [.], ack 1, win 507, options [nop,nop,TS val 491087222 ecr 4095895608], length 0
22:24:45.085592 IP 192.168.1.16.43558 > 192.168.1.17.targus-getdata1: Flags [P.], seq 1:38, ack 1, win 507, options [nop,nop,TS val 491087222 ecr 4095895608], length 37
22:24:45.086311 IP 192.168.1.16.43560 > 192.168.1.17.targus-getdata1: Flags [S], seq 3802331506, win 64860, options [mss 1410,sackOK,TS val 491087279 ecr 0,nop,wscale 7], length 0
22:24:45.086462 IP 192.168.1.17.targus-getdata1 > 192.168.1.16.43560: Flags [S.], seq 441940709, ack 3802331507, win 64308, options [mss 1410,sackOK,TS val 4095895725 ecr 491087279,nop,wscale 7], length 0
22:24:45.086624 IP 192.168.1.16.43560 > 192.168.1.17.targus-getdata1: Flags [.], ack 1, win 507, options [nop,nop,TS val 491087279 ecr 4095895725], length 0
22:24:45.086654 IP 192.168.1.16.43560 > 192.168.1.17.targus-getdata1: Flags [P.], seq 1:38, ack 1, win 507, options [nop,nop,TS val 491087279 ecr 4095895725], length 37
22:24:45.086715 IP 192.168.1.17.targus-getdata1 > 192.168.1.16.43560: Flags [.], ack 38, win 503, options [nop,nop,TS val 4095895725 ecr 491087279], length 0
```

Check datapath rules are offloaded
```
ovs-appctl dpctl/dump-flows --names type=offloaded
recirc_id(0),in_port(eth0),eth(src=16:fd:c6:0b:60:52),eth_type(0x0800),ipv4(src=192.168.1.17,frag=no), packets:2235857, bytes:147599302, used:0.550s, actions:ct(zone=65520),recirc(0x18)
ct_state(+est+trk),ct_mark(0),recirc_id(0x18),in_port(eth0),eth(dst=42:66:d7:45:0d:7e),eth_type(0x0800),ipv4(dst=192.168.1.0/255.255.255.0,frag=no), packets:2235857, bytes:147599302, used:0.550s, actions:eth1
recirc_id(0),in_port(eth1),eth(src=42:66:d7:45:0d:7e),eth_type(0x0800),ipv4(src=192.168.1.16,frag=no), packets:133410141, bytes:195255745684, used:0.550s, actions:ct(zone=65520),recirc(0x16)
ct_state(+est+trk),ct_mark(0),recirc_id(0x16),in_port(eth1),eth(dst=16:fd:c6:0b:60:52),eth_type(0x0800),ipv4(dst=192.168.1.0/255.255.255.0,frag=no), packets:133410138, bytes:195255745483, used:0.550s, actions:eth0
```
