# Manual Installation

## Overview

There are four components which need to be deployed in order to run Antrea:

* The OpenVSwitch daemons `ovs-vswitchd` and `ovsdb-server`

* The controller `antrea-controller`

* The agent `antrea-agent`

* The CNI plugin `antrea-cni`

## Instructions

Prior to bringing up the individual components, follow the common steps:

* Ensure Go v1.15 is [installed](https://golang.org/doc/install)

* Git clone your forked Antrea repository and `cd` into the `antrea` directory

    ```bash
    git clone https://github.com/$user/antrea
    cd antrea
    ```

* Build the binaries for all components under `bin` directory

    ```bash
    make bin
    ```

### OpenVSwitch

Open vSwitch >= 2.8.0 userspace daemon `ovs-vswitchd` and `ovsdb-server` should run on all worker nodes. See
[Installing Open vSwitch](https://docs.openvswitch.org/en/latest/intro/install/#installation-from-packages) for details.

### antrea-controller

`antrea-controller` is required to implement Kubernetes Network Policies. At any time, there should be only a single
active replica of `antrea-controller`.

1. Grant the `antrea-controller` ServiceAccount necessary permissions to Kubernetes APIs. You can apply
[controller-rbac.yaml](/build/yamls/base/controller-rbac.yml) to do it.

    ```bash
    kubectl apply -f build/yamls/base/controller-rbac.yml
    ```

2. Create the kubeconfig file that contains the K8s APIServer endpoint and the token of ServiceAccount created in the
above step. See [Configure Access to Multiple Clusters](
https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/) for more information.

    ```bash
    APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
    TOKEN=$(kubectl get secrets -n kube-system -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='antrea-controller')].data.token}"|base64 --decode)
    kubectl config --kubeconfig=antrea-controller.kubeconfig set-cluster kubernetes --server=$APISERVER --insecure-skip-tls-verify
    kubectl config --kubeconfig=antrea-controller.kubeconfig set-credentials antrea-controller --token=$TOKEN
    kubectl config --kubeconfig=antrea-controller.kubeconfig set-context antrea-controller@kubernetes --cluster=kubernetes --user=antrea-controller
    kubectl config --kubeconfig=antrea-controller.kubeconfig use-context antrea-controller@kubernetes
    ```

3. Create the `antrea-controller` config file, see [Configuration](../configuration.md) for details.

    ```bash
    cat >antrea-controller.conf <<EOF
    clientConnection:
      kubeconfig: antrea-controller.kubeconfig
    EOF
    ```

4. Start `antrea-controller`.

    ```bash
    bin/antrea-controller --config antrea-controller.conf
    ```

### antrea-agent

`antrea-agent` must run all worker nodes.

1. Grant the `antrea-agent` ServiceAccount necessary permissions to Kubernetes APIs. You can apply [agent-rbac.yaml](
/build/yamls/base/agent-rbac.yml) to do it.

    ```bash
    kubectl apply -f build/yamls/base/agent-rbac.yml
    ```

2. Create the kubeconfig file that contains the K8s APIServer endpoint and the token of ServiceAccount created in the
above step. See [Configure Access to Multiple Clusters](
https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/) for more information.

    ```bash
    APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
    TOKEN=$(kubectl get secrets -n kube-system -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='antrea-agent')].data.token}"|base64 --decode)
    kubectl config --kubeconfig=antrea-agent.kubeconfig set-cluster kubernetes --server=$APISERVER --insecure-skip-tls-verify
    kubectl config --kubeconfig=antrea-agent.kubeconfig set-credentials antrea-agent --token=$TOKEN
    kubectl config --kubeconfig=antrea-agent.kubeconfig set-context antrea-agent@kubernetes --cluster=kubernetes --user=antrea-agent
    kubectl config --kubeconfig=antrea-agent.kubeconfig use-context antrea-agent@kubernetes
    ```

3. Create the kubeconfig file that contains the `antrea-controller` APIServer endpoint and the token of ServiceAccount
created in the above step.

    ```bash
    # Change it to the correct endpoint if you are running antrea-controller somewhere else.
    ANTREA_APISERVER=https://localhost
    TOKEN=$(kubectl get secrets -n kube-system -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='antrea-agent')].data.token}"|base64 --decode)
    kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-cluster antrea --server=$ANTREA_APISERVER --insecure-skip-tls-verify
    kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-credentials antrea-agent --token=$TOKEN
    kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig set-context antrea-agent@antrea --cluster=antrea --user=antrea-agent
    kubectl config --kubeconfig=antrea-agent.antrea.kubeconfig use-context antrea-agent@antrea
    ```

4. Create the `antrea-agent` config file, see [Configuration](../configuration.md) for details.

    ```bash
    cat >antrea-agent.conf <<EOF
    clientConnection:
      kubeconfig: antrea-agent.kubeconfig
    antreaClientConnection:
      kubeconfig: antrea-agent.antrea.kubeconfig
    hostProcPathPrefix: "/"
    EOF
    ```

5. Start `antrea-agent`.

    ```bash
    bin/antrea-agent --config antrea-agent.conf
    ```

### antrea-cni

`antrea-cni` should be installed on all worker nodes.

1. Create the cni config file on all worker nodes.

    ```bash
    mkdir -p /etc/cni/net.d

    cat >/etc/cni/net.d/10-antrea.conflist <<EOF
    {
      "cniVersion":"0.3.0",
      "name": "antrea",
      "plugins": [
        {
          "type": "antrea",
          "ipam": {
            "type": "host-local"
          }
        },
        {
          "type": "portmap",
          "capabilities": {"portMappings": true}
        },
        {
          "type": "bandwidth",
          "capabilities": {"bandwidth": true}
        }
      ]
    }
    EOF
    ```

2. Install `antrea-cni` to `/opt/cni/bin/antrea`.

    ```bash
    cp bin/antrea-cni /opt/cni/bin/antrea
    ```
