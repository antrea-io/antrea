# Support Bundle User Guide

## What is Support Bundle

Antrea supports collecting support bundle tarballs, which include the information
from Antrea Controller and Antrea Agent. The collected information can help
debugging issues in the Kubernetes cluster.

**Be aware that the generated support bundle includes a lot of information,
including logs, so please review the contents before sharing it on Github
and ensure that you do not share any sensitive information.**

There are two ways of generating support bundles. Firstly, you can run `antctl supportbundle`
directly in the Antrea Agent Pod, Antrea Controller Pod, or on a host with a
`kubeconfig` file for the target cluster. Secondly, you can also apply
`SupportBundleCollection` CRs to create support bundles for K8s Nodes
or external Nodes. We name this feature as `SupportBundleCollection` in Antrea.
The details are provided in section [Usage examples](#usage-examples).

## Table of Contents

<!-- toc -->
- [Prerequisites](#prerequisites)
- [The SupportBundleCollection CRD](#the-supportbundlecollection-crd)
- [Usage examples](#usage-examples)
  - [Running antctl commands](#running-antctl-commands)
  - [Applying SupportBundleCollection CR](#applying-supportbundlecollection-cr)
- [List of collected items](#list-of-collected-items)
- [Limitations](#limitations)
<!-- /toc -->

## Prerequisites

The `antctl supportbundle` command is supported in Antrea since version 0.7.0.

The `SupportBundleCollection` CRD is introduced in Antrea v1.10.0 as an alpha
feature. The feature gate must be enabled in both antrea-controller and
antrea-agent configurations. If you plan to collect support bundle on an external
Node, you should enable it in the configuration on the external Node as well.

```yaml
  antrea-agent.conf: |
    featureGates:
    # Enable collecting support bundle files with SupportBundleCollection CRD.
    SupportBundleCollection: true
```

```yaml
  antrea-controller.conf: |
    featureGates:
    # Enable collecting support bundle files with SupportBundleCollection CRD.
    SupportBundleCollection: true
```

A single Namespace (e.g., default) is created for saving the Secrets that are
used to access the support bundle file server, and the permission to read Secrets
in this Namespace is given to antrea-controller by modifying and applying the
[RBAC file](../build/yamls/externalnode/support-bundle-collection-rbac.yml).

```yaml
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: antrea-read-secrets
  namespace: default  # Change the Namespace to where the Secret for file server's authentication credential is created.
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: antrea-secret-reader
subjects:
  - kind: ServiceAccount
    name: antrea-controller
    namespace: kube-system
```

## The SupportBundleCollection CRD

SupportBundleCollection CRD is introduced to supplement the `antctl` command
with three additional features:

1. Allow users to collect support bundle files on external Nodes.
2. Upload all the support bundle files into a user-provided SFTP Server.
3. Support tracking status of a SupportBundleCollection CR.

## Usage examples

### Running antctl commands

Please refer to the [antctl user guide section](antctl.md#collecting-support-information).
Note: `antctl supportbundle` only works on collecting the support bundles from
Antrea Controller and Antrea Agent that is running on a K8s Node, but it does
not work for the Agent on an external Node.

### Applying SupportBundleCollection CR

In this section, we will create two SupportBundleCollection CRs for K8s Nodes
and external Nodes. Note, it is supported to specify Nodes/ExternalNodes by their
names or by matching their labels in a SupportBundleCollection CR.

Assume we have a cluster with Nodes named "worker1" and "worker2". In addition,
we have set up two external Nodes named "vm1" and "vm2" in the "vm-ns" Namespace
by following the instruction of the [VM installation guide](external-node.md#install-antrea-agent-on-vm).
In addition, an SFTP server needs to be provided in advance to collect the bundle.
You can host the SFTP server by applying YAML `hack/externalnode/sftp-deployment.yml`
or deploy one by yourself.

A Secret needs to be created in advance with the username and password of the SFTP
Server. The Secret will be referred as `authSecret` in the following YAML examples.

```bash
# Set username and password with `--from-literal=username='foo' --from-literal=password='pass'`
# if the sftp server is deployed with sftp-deployment.yml
kubectl create secret generic support-bundle-secret  --from-literal=username='your-sftp-username'  --from-literal=password='your-sftp-password'
```

Then we can apply the following YAML files. The first one is to collect support
bundle on K8s Nodes "worker1" and "worker2": "worker1" is specified by the name,
and "worker2" is specified by matching label "role: workers". The second one is to
collect support bundle on external Nodes "vm1" and "vm2" in Namespace "vm-ns":
"vm1" is specified by the name, and "vm2" is specified by matching label "role: vms".

```bash
cat << EOF | kubectl apply -f -
apiVersion: crd.antrea.io/v1alpha1
kind: SupportBundleCollection
metadata:
  name: support-bundle-for-nodes
spec:
  nodes: # All Nodes will be selected if both nodeNames and matchLabels are empty
    nodeNames:
      - worker1
    matchLabels:
      role: workers
  expirationMinutes: 10 # expirationMinutes is the requested duration of validity of the SupportBundleCollection. A SupportBundleCollection will be marked as Failed if it does not finish before expiration.
  sinceTime: 2h # Collect the logs in the latest 2 hours. Collect all available logs if the time is not set.
  fileServer:
    url: sftp://yourtestdomain.com:22/root/test
  authentication:
    authType: "BasicAuthentication"
    authSecret:
      name: support-bundle-secret
      namespace: default # antrea-controller must be given the permission to read Secrets in "default" Namespace. 
EOF
```

```bash
cat << EOF | kubectl apply -f -
apiVersion: crd.antrea.io/v1alpha1
kind: SupportBundleCollection
metadata:
  name: support-bundle-for-vms
spec:
  externalNodes: # All ExternalNodes in the Namespace will be selected if both nodeNames and matchLabels are empty
    nodeNames:
      - vm1
    nodeSelector:
      matchLabels:
        role: vms
    namespace: vm-ns # namespace is mandatory when collecting support bundle from external Nodes.
  fileServer:
    url: yourtestdomain.com:22/root/test # Scheme sftp can be omitted. The url of "$controlplane_node_ip:30010/upload" is used if deployed with sftp-deployment.yml.
  authentication:
    authType: "BasicAuthentication"
    authSecret:
      name: support-bundle-secret
      namespace: default # antrea-controller must be given the permission to read Secrets in "default" Namespace.
EOF
```

For more information about the supported fields in a "SupportBundleCollection"
CR, please refer to the [CRD definition](../build/charts/antrea/crds/supportbundlecollection.yaml)

You can check the status of `SupportBundleCollection` by running command
`kubectl get supportbundlecollections [NAME] -ojson`.
The following example shows a successful realization of `SupportBundleCollection`.
`desiredNodes` shows the expected number of Nodes/ExternalNodes to collect with
this request, while `collectedNodes` shows the number of Nodes/ExternalNodes
which have already uploaded bundle files to the target file server. If the
collection completes successfully, `collectedNodes` and `desiredNodes`should
have an equal value which should match the number of Nodes/ExternalNodes you
want to collect support bundle.

If the following two conditions are presented, it means a bundle collection
succeeded,

1. "Completed" is true
2. "CollectionFailure" is false.

If any expected Node/ExternalNode failed to upload the bundle files in the
required time, the "CollectionFailure" condition will be set to true.

```bash
$ kubectl get supportbundlecollections support-bundle-for-nodes -ojson

...
 "status": {
        "collectedNodes": 1,
        "conditions": [
            {
                "lastTransitionTime": "2022-12-08T06:49:35Z",
                "status": "True",
                "type": "Started"
            },
            {
                "lastTransitionTime": "2022-12-08T06:49:41Z",
                "status": "True",
                "type": "BundleCollected"
            },
            {
                "lastTransitionTime": "2022-12-08T06:49:35Z",
                "status": "False",
                "type": "CollectionFailure"
            },
            {
                "lastTransitionTime": "2022-12-08T06:49:41Z",
                "status": "True",
                "type": "Completed"
            }
        ],
        "desiredNodes": 1
    }
```

The collected bundle should include three tarballs. To access these files, you
can download the files from the SFTP server `yourtestdomain.com`. There will be
two tarballs for `support-bundle-for-nodes`: "support-bundle-for-nodes_worker1.tar.gz"
and "support-bundle-for-nodes_worker2.tar.gz", and two for `support-bundle-for-vms`:
"support-bundle-for-vms_vm1.tar.gz" and "support-bundle-for-vms_vm2.tar.gz", in
the `/root/test` folder. Run the `tar xvf $TARBALL_NAME` command to extract the
files from the tarballs.

## List of collected items

Depending on the methods you use to collect the support bundle, the contents in
the bundle may differ. The following table shows the differences.

We use `agent`,`controller`, `outside` to represent running command
`antctl supportbundle` in Antrea Agent, Antrea Controller, out-of-cluster
respectively. Also, we use `Node` and `ExternalNode` to represent
"create SupportBundleCollection CR for Nodes" and "create SupportBundleCollection
CR for external Nodes".

| Collected Item              | Supported Collecting Method                              | Explanation                                                                                                                                                                                                                                                               |
|-----------------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Antrea Agent Log            | `agent`, `outside`, `Node`, `ExternalNode`               | Antrea Agent log files                                                                                                                                                                                                                                                    |
| Antrea Controller Log       | `controller`, `outside`                                  | Antrea Controller log files                                                                                                                                                                                                                                               |
| iptables (Linux Only)       | `agent`, `outside`, `Node`, `ExternalNode`               | Output of `ip6tables-save` and `iptable-save` with counters                                                                                                                                                                                                               |
| OVS Ports                   | `agent`, `outside`, `Node`, `ExternalNode`               | Output of `ovs-ofctl dump-ports-desc`                                                                                                                                                                                                                                     |
| NetworkPolicy Resources     | `agent`, `controller`, `outside`, `Node`, `ExternalNode` | YAML output of `antctl get appliedtogroups` and `antctl get addressgroups` commands                                                                                                                                                                                       |
| Heap Pprof                  | `agent`, `controller`, `outside`, `Node`, `ExternalNode` | Output of [`pprof.WriteHeapProfile`](https://pkg.go.dev/runtime/pprof#WriteHeapProfile)                                                                                                                                                                                   |
| HNSResources (Windows Only) | `agent`, `outside`, `Node`, `ExternalNode`               | Output of `Get-HNSNetwork` and `Get-HNSEndpoint` commands                                                                                                                                                                                                                 |
| Antrea Agent Info           | `agent`, `outside`, `Node`, `ExternalNode`               | YAML output of `antctl get agentinfo`                                                                                                                                                                                                                                     |
| Antrea Controller Info      | `controller`, `outside`                                  | YAML output of `antctl get controllerinfo`                                                                                                                                                                                                                                |
| IP Address Info             | `agent`, `outside`, `Node`, `ExternalNode`               | Output of `ip address` command on Linux or `ipconfig /all` command on Windows                                                                                                                                                                                             |
| IP Route Info               | `agent`, `outside`, `Node`, `ExternalNode`               | Output of `ip route` on Linux or `route print` on Windows                                                                                                                                                                                                                 |
| IP Link Info                | `agent`, `outside`, `Node`, `ExternalNode`               | Output of `ip link` on Linux or `Get-NetAdapter` on Windows                                                                                                                                                                                                               |
| Cluster Information         | `outside`                                                | Dump of resources in the cluster, including: 1. all Pods, Deployments, Replicasets and Daemonsets in all Namespaces with any resourceVersion. 2. all Nodes with any resourceVersion. 3. all ConfigMaps in all Namespaces with any resourceVersion and label `app=antrea`.                                                                                                                                                                                                                                  |
| Memberlist State            | `agent`, `outside`                                       | YAML output of `antctl get memberlist` |

## Limitations

Only SFTP basic authentication is supported for SupportBundleCollection.
Other authentication methods will be added in the future.
