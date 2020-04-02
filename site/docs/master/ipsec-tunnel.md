# IPsec Encryption of Tunnel Traffic with Antrea

Antrea supports encrypting tunnel traffic across Nodes with IPsec ESP. At this
moment, IPsec encyption works only for GRE tunnel (but not VXLAN, Geneve, and
STT tunnel types).

## Prerequisites

IPsec requires a set of Linux kernel modules. Check the required kernel modules
listed in the [strongSwan documentation](https://wiki.strongswan.org/projects/strongswan/wiki/KernelModules).
Make sure the required kernel modules are loaded on the Kubernetes Nodes before
deploying Antrea with IPsec encyption enabled.

## Installation

You can simply apply the [Antrea IPsec deployment yaml](/build/yamls/antrea-ipsec.yml)
to deploy Antrea with IPsec encyption enabled. To deploy a released version of
Antrea, pick a version from the [list of releases](https://github.com/vmware-tanzu/antrea/releases).
Note that IPsec support was added in release 0.3.0, which means you can not
pick a release older than 0.3.0. For any given release `<TAG>` (e.g. `v0.3.0`),
get the Antrea IPsec deployment yaml at:
```
https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea-ipsec.yml
```

To deploy the latest version of Antrea (built from the master branch), get the
IPsec deployment yaml at:
```
https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea-ipsec.yml
```

Antrea leverages strongSwan as the IKE daemon, and supports using pre-shared key
(PSK) for IKE authentication. The deployment yaml creates a Kubernetes Secret
`antrea-ipsec` to store the PSK string. For security consideration, we recommend
to change the default PSK string in the yaml file. You can edit the yaml file,
and update the `psk` field in the `antrea-ipsec` Secret spec to any string you
want to use. Check the `antrea-ipsec` Secret spec below:
```
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
```
kubectl apply -f antrea-ipsec.yml
```
