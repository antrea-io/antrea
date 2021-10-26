# Traffic Encryption with Antrea

Antrea supports encrypting traffic across Linux Nodes with IPsec ESP or
WireGuard. Traffic encryption is not supported on Windows Nodes yet.

## IPsec

IPsec encyption works for all tunnel types supported by OVS including Geneve,
GRE, VXLAN, and STT tunnel.

### Prerequisites

IPsec requires a set of Linux kernel modules. Check the required kernel modules
listed in the [strongSwan documentation](https://wiki.strongswan.org/projects/strongswan/wiki/KernelModules).
Make sure the required kernel modules are loaded on the Kubernetes Nodes before
deploying Antrea with IPsec encyption enabled.

If you want to enable IPsec with Geneve, please make sure [this commit](https://github.com/torvalds/linux/commit/34beb21594519ce64a55a498c2fe7d567bc1ca20)
is included in the kernel. For Ubuntu 18.04, kernel version should be at least
`4.15.0-128`. For Ubuntu 20.04, kernel version should be at least `5.4.70`.

### Antrea installation

You can simply apply the [Antrea IPsec deployment yaml](/build/yamls/antrea-ipsec.yml)
to deploy Antrea with IPsec encyption enabled. To deploy a released version of
Antrea, pick a version from the [list of releases](https://github.com/antrea-io/antrea/releases).
Note that IPsec support was added in release 0.3.0, which means you can not
pick a release older than 0.3.0. For any given release `<TAG>` (e.g. `v0.3.0`),
get the Antrea IPsec deployment yaml at:

```text
https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-ipsec.yml
```

To deploy the latest version of Antrea (built from the main branch), get the
IPsec deployment yaml at:

```text
https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-ipsec.yml
```

Antrea leverages strongSwan as the IKE daemon, and supports using pre-shared key
(PSK) for IKE authentication. The deployment yaml creates a Kubernetes Secret
`antrea-ipsec` to store the PSK string. For security consideration, we recommend
to change the default PSK string in the yaml file. You can edit the yaml file,
and update the `psk` field in the `antrea-ipsec` Secret spec to any string you
want to use. Check the `antrea-ipsec` Secret spec below:

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: antrea-ipsec
  namespace: kube-system
stringData:
  psk: changeme
type: Opaque
```

After updating the PSK value, deploy Antrea with:

```bash
kubectl apply -f antrea-ipsec.yml
```

## WireGuard

Antrea can leverage [WireGuard](https://www.wireguard.com) to encrypt Pod traffic
between Nodes. WireGuard encryption works like another tunnel type, and when it
is enabled the `tunnelType` parameter in the `antrea-agent` configuration file
will be ignored.

### Prerequisites

WireGuard encryption requires `wireguard` kernel module be present on the
Kubernetes Nodes. `wireguard` module is part of mainline kernel since Linux 5.6.
Or, you can compile the module from source code with a kernel version >= 3.10.
[This WireGuard web page](https://www.wireguard.com/install) documents how to
install WireGuard together with the kernel module on various operating systems.

### Antrea installation

First, download the [Antrea deployment yaml](/build/yamls/antrea.yml). To deploy
a released version of Antrea, pick a version from the [list of releases](https://github.com/antrea-io/antrea/releases).
Note that WireGuard support was added in release 1.3.0, which means you can not
pick a release older than 1.3.0. For any given release `<TAG>` (e.g. `v1.3.0`),
get the Antrea deployment yaml at:

```text
https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml
```

To deploy the latest version of Antrea (built from the main branch), get the
deployment yaml at:

```text
https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea.yml
```

To enable WireGuard encryption, the `trafficEncryptionMode` config parameter of
`antrea-agent` to `wireGuard`. The `trafficEncryptionMode` config parameter is
defined in `antrea-agent.conf` of `antrea` ConfigMap in the Antrea deployment
yaml:

```yaml
  antrea-agent.conf: |
    ... ...
    trafficEncryptionMode: wireGuard
    ... ...
```

After saving the yaml file change, deploy Antrea with:

```bash
kubectl apply -f antrea.yml
```
