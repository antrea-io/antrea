# OS-specific known issues

The following issues were encountered when testing Antrea on different OSes, or
reported by Antrea users. When possible we try to provide a workaround.

## CoreOS

| Issues |
| ------ |
| [#626](https://github.com/vmware-tanzu/antrea/issues/626) |

**CoreOS Container Linux will reach its
  [end-of-life](https://coreos.com/os/eol/) on May 26, 2020 and will no longer
  receive updates. It is recommended to migrate to another Operating System as
  soon as possible.**

CoreOS uses
[networkd](https://coreos.com/os/docs/latest/network-config-with-networkd.html)
for network configuration. By default, all interfaces are managed by networkd
because of the [configuration
files](https://github.com/coreos/init/tree/master/systemd/network) that ship
with CoreOS. Unfortunately, that includes the gateway interface created by
Antrea (`gw0` by default). Most of the time, this is not an issue, but if
networkd is restarted for any reason, it will cause the interface to lose its IP
configuration, and all the routes associated with the interface will be
deleted. To avoid this issue, we recommend that you create the following
configuration files:
```
# /etc/systemd/network/90-antrea-ovs.network
[Match]
# use the correct name for the gateway if you changed the Antrea configuration
Name=gw0 ovs-system
Driver=openvswitch

[Network]
Unmanaged=yes
```
```
# /etc/systemd/network/90-antrea-veth.network
# may be redundant with 50-docker-veth.network, which should not be an issue
[Match]
Driver=veth

[Network]
Unmanaged=yes
```
```
# /etc/systemd/network/90-antrea-tun.network
[Match]
Name=vxlan_sys_* genev_sys_* gre_sys stt_sys_*

[Network]
Unmanaged=yes
```

Note that this fix requires a version of CoreOS `>= 1262.0.0` (Dec 2016), as the
networkd `Unmanaged` option was not supported before that. See CoreOS [release
notes](https://coreos.com/releases/).

## Photon OS 3.0

| Issues |
| ------ |
| [#591](https://github.com/vmware-tanzu/antrea/issues/591) |

If your K8s Nodes are running Photon OS 3.0, you may see error messages in the
antrea-agent logs like this one: `"Received bundle error msg: [...]"`. These
messages indicate that some flow entries could not be added to the OVS
bridge. This usually indicates that the Kernel was not compiled with the
`CONFIG_NF_CONNTRACK_ZONES` option, as this option was only enabled recently in
Photon OS. This option is required by the Antrea OVS datapath. To confirm that
this is indeed the issue, you can run the following command on one of your
Nodes:
```
grep CONFIG_NF_CONNTRACK_ZONES= /boot/config-`uname -r`
```
If you do *not* see the following output, then it confirms that your Kernel is
indeed missing this option:
```
CONFIG_NF_CONNTRACK_ZONES=y
```

To fix this issue and be able to run Antrea on your Photon OS Nodes, you will
need to upgrade to a more recent version: `>= 4.19.87-4` (Jan 2020). You can
achieve this by running `tdnf upgrade linux-esx` on all your Nodes.

After this fix, all the Antrea Agents should be running correctly. If you still
experience connectivity issues, it may be because of Photon's default firewall
rules, which are quite strict by
[default](https://vmware.github.io/photon/assets/files/html/3.0/photon_admin/default-firewall-settings.html). The
easiest workaround is to accept all traffic on the gateway interface created by
Antrea (`gw0` by default), which enables traffic to flow between the Node and
the Pod network:
```
iptables -A INPUT -i gw0 -j ACCEPT
```
