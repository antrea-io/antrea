# Manual Installation

## Overview

There are three components need to be deployed to run OKN:

* The OpenVSwitch daemons `ovs-vswitchd` and `ovsdb-server`

* The agent `okn-agent`

* The CNI plugin `okn-cni`

## Instructions

### OpenVSwitch

Open vSwitch >= 2.8.0 userspace daemon `ovs-vswitchd` and `ovsdb-server` should run on all worker nodes. See
[Installing Open vSwitch](https://docs.openvswitch.org/en/latest/intro/install/#installation-from-packages) for details.

### okn-agent

`okn-agent` must run all worker nodes.

1. Grant `okn-agent` user or ServiceAccount necessary permissions to Kubernetes APIs. You can follow the `ClusterRole`
and `ClusterRoleBinding` sections in the [Deployment yaml](/build/yamls/okn.yml) to configure
Kubernetes RBAC to do it.

2. Create the kubeconfig file that contains the tokens or certificates of ServiceAccount or user created in the above
step. See [Configure Access to Multiple Clusters](
https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/) for more information.

3. Create the okn-agent config file, see [Configuration](configuration.md) for details.
```
cat >okn-agent.conf <<EOF
clientConnection:
  kubeconfig: <PATH_TO_KUBE_CONF>
hostProcPathPrefix: ''
EOF
```

4. Install `okn-agent` to `/usr/local/bin/okn-agent`.
```
cp bin/okn-agent /usr/local/bin/okn-agent
```

5. Start `okn-agent`.
```
okn-agent --config okn-agent.conf
```

### okn-cni
`okn-cni` should be installed on all worker nodes.

1. Create the cni config file on all worker nodes.
```
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-okn.conf <<EOF
{
  "cniVersion":"0.3.0",
  "name": "okn",
  "type": "okn",
  "ipam": {
    "type": "host-local"
  }
}
EOF
```

2. Install `okn-cni` to `/opt/cni/bin/okn`.
```
cp bin/okn-cni /opt/cni/bin/okn
```
