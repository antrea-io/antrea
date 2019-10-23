# Manual Installation

## Overview

There are four components which need to be deployed in order to run Antrea:

* The OpenVSwitch daemons `ovs-vswitchd` and `ovsdb-server`

* The agent `antrea-agent`

* The CNI plugin `antrea-cni`

* **Optional** The controller `antrea-controller`

## Instructions

### OpenVSwitch

Open vSwitch >= 2.8.0 userspace daemon `ovs-vswitchd` and `ovsdb-server` should run on all worker nodes. See
[Installing Open vSwitch](https://docs.openvswitch.org/en/latest/intro/install/#installation-from-packages) for details.

### antrea-agent

`antrea-agent` must run all worker nodes.

1. Grant `antrea-agent` user or ServiceAccount necessary permissions to Kubernetes APIs. You can follow the `ClusterRole`
and `ClusterRoleBinding` sections in the [Deployment yaml](/build/yamls/antrea.yml) to configure
Kubernetes RBAC to do it.

2. Create the kubeconfig file that contains the tokens or certificates of ServiceAccount or user created in the above
step. See [Configure Access to Multiple Clusters](
https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/) for more information.

3. Create the antrea-agent config file, see [Configuration](configuration.md) for details.
```
cat >antrea-agent.conf <<EOF
clientConnection:
  kubeconfig: <PATH_TO_KUBE_CONF>
hostProcPathPrefix: "/"
EOF
```

4. Install `antrea-agent` to `/usr/local/bin/antrea-agent`.
```
cp bin/antrea-agent /usr/local/bin/antrea-agent
```

5. Start `antrea-agent`.
```
antrea-agent --config antrea-agent.conf
```

### antrea-cni
`antrea-cni` should be installed on all worker nodes.

1. Create the cni config file on all worker nodes.
```
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-antrea.conf <<EOF
{
  "cniVersion":"0.3.0",
  "name": "antrea",
  "type": "antrea",
  "ipam": {
    "type": "host-local"
  }
}
EOF
```

2. Install `antrea-cni` to `/opt/cni/bin/antrea`.
```
cp bin/antrea-cni /opt/cni/bin/antrea
```

### antrea-controller

`antrea-controller` is required to implement Kubernetes Network Policies. At any time, there should be only a single active replica of `antrea-controller`. Deploying `antrea-controller` may be skipped, if only basic Pod connectivity is desired.

1. Grant `antrea-controller` user or ServiceAccount necessary permissions to Kubernetes APIs. You can follow the `ClusterRole`
and `ClusterRoleBinding` sections in the [Deployment yaml](/build/yamls/antrea.yml) to configure
Kubernetes RBAC to do it.

2. Create the kubeconfig file that contains the tokens or certificates of ServiceAccount or user created in the above
step. See [Configure Access to Multiple Clusters](
https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/) for more information.

3. Create the `antrea-controller` config file, see [Configuration](configuration.md) for details.
```
cat >antrea-controller.conf <<EOF
clientConnection:
  kubeconfig: <PATH_TO_KUBE_CONF>
EOF
```

4. Start `antrea-controller`.
```
antrea-controller --config antrea-controller.conf
```
