# OS-specific known issues

The following issues were encountered when testing Antrea on different OSes, or
reported by Antrea users. When possible we try to provide a workaround.

## CoreOS

| Issues |
| ------ |
| [#626](https://github.com/vmware-tanzu/antrea/issues/626) |

**CoreOS Container Linux has reached its
  [end-of-life](https://www.openshift.com/learn/topics/coreos) on May 26, 2020
  and no longer receives updates. It is recommended to migrate to another
  Operating System as soon as possible.**

CoreOS uses networkd for network configuration. By default, all interfaces are
managed by networkd because of the [configuration
files](https://github.com/coreos/init/tree/master/systemd/network) that ship
with CoreOS. Unfortunately, that includes the gateway interface created by
Antrea (`antrea-gw0` by default). Most of the time, this is not an issue, but if
networkd is restarted for any reason, it will cause the interface to lose its IP
configuration, and all the routes associated with the interface will be
deleted. To avoid this issue, we recommend that you create the following
configuration files:

```text
# /etc/systemd/network/90-antrea-ovs.network
[Match]
# use the correct name for the gateway if you changed the Antrea configuration
Name=antrea-gw0 ovs-system
Driver=openvswitch

[Link]
Unmanaged=yes
```

```text
# /etc/systemd/network/90-antrea-veth.network
# may be redundant with 50-docker-veth.network (name may differ based on CoreOS version), which should not be an issue
[Match]
Driver=veth

[Link]
Unmanaged=yes
```

```text
# /etc/systemd/network/90-antrea-tun.network
[Match]
Name=genev_sys_* vxlan_sys_* gre_sys stt_sys_*

[Link]
Unmanaged=yes
```

Note that this fix requires a version of CoreOS `>= 1262.0.0` (Dec 2016), as the
networkd `Unmanaged` option was not supported before that.

## Photon OS 3.0

| Issues |
| ------ |
| [#591](https://github.com/vmware-tanzu/antrea/issues/591) |
| [#1516](https://github.com/vmware-tanzu/antrea/issues/1516) |

If your K8s Nodes are running Photon OS 3.0, you may see error messages in the
antrea-agent logs like this one: `"Received bundle error msg: [...]"`. These
messages indicate that some flow entries could not be added to the OVS
bridge. This usually indicates that the Kernel was not compiled with the
`CONFIG_NF_CONNTRACK_ZONES` option, as this option was only enabled recently in
Photon OS. This option is required by the Antrea OVS datapath. To confirm that
this is indeed the issue, you can run the following command on one of your
Nodes:

```bash
grep CONFIG_NF_CONNTRACK_ZONES= /boot/config-`uname -r`
```

If you do *not* see the following output, then it confirms that your Kernel is
indeed missing this option:

```text
CONFIG_NF_CONNTRACK_ZONES=y
```

To fix this issue and be able to run Antrea on your Photon OS Nodes, you will
need to upgrade to a more recent version: `>= 4.19.87-4` (Jan 2020). You can
achieve this by running `tdnf upgrade linux-esx` on all your Nodes.

After this fix, all the Antrea Agents should be running correctly. If you still
experience connectivity issues, it may be because of Photon's default firewall
rules, which are quite strict by
[default](https://vmware.github.io/photon/docs/administration-guide/security-policy/default-firewall-settings/). The
easiest workaround is to accept all traffic on the gateway interface created by
Antrea (`antrea-gw0` by default), which enables traffic to flow between the Node
and the Pod network:

```bash
iptables -A INPUT -i antrea-gw0 -j ACCEPT
```

### Pod Traffic Shaping

Antrea provides support for Pod [Traffic Shaping](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping)
by leveraging the open-source [bandwidth plugin](https://github.com/containernetworking/plugins/tree/master/plugins/meta/bandwidth)
maintained by the CNI project. This plugin requires the following Kernel
modules: `ifb`, `sch_tbf` and `sch_ingress`. It seems that at the moment Photon
OS 3.0 is built without the `ifb` Kernel module, which you can confirm by
running `modprobe --dry-run ifb`: an error would indicate that the module is
indeed missing. Without this module, Pods with the
`kubernetes.io/egress-bandwidth` annotation cannot be created successfully. Pods
with no traffic shaping annotation, or which only use the
`kubernetes.io/ingress-bandwidth` annotation, can still be created successfully
as they do not require the creation of an `ifb` device.

If Photon OS is patched to enable `ifb`, we will update this documentation to
reflect this change, and include information about which Photon OS version can
support egress traffic shaping.
