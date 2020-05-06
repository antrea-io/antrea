# Troubleshooting

## Table of Contents

- [Looking at the Antrea logs](#looking-at-the-antrea-logs)
- [Accessing the antrea-controller API](#accessing-the-antrea-controller-api)
  - [Using antctl](#using-antctl)
  - [Using kubectl proxy](#using-kubectl-proxy)
  - [Directly accessing the antrea-controller API](#directly-accessing-the-antrea-controller-api)
- [Accessing the antrea-agent API](#accessing-the-antrea-agent-api)
  - [Using antctl](#using-antctl-1)
  - [Directly accessing the antrea-agent API](#directly-accessing-the-antrea-agent-api)
- [Troubleshooting OVS](#troubleshooting-ovs)
- [Troubleshooting with antctl](#troubleshooting-with-antctl)


## Looking at the Antrea logs

You can inspect the logs for the `antrea-agent` and `antrea-ovs` containers in any
`antrea-agent` Pod by running this `kubectl` command:
```
kubectl logs -n kube-system <antrea-agent Pod name> -c [antrea-agent|antrea-ovs]
```

The list of `antrea-agent` Pods, along with the node on which the Pod is scheduled,
can be obtained with:
```
kubectl get pods -n kube-system -l app=antrea -o wide
```

To check the Open vSwitch logs (e.g. if the `antrea-ovs` container logs indicate
that one of the Open vSwitch daemons generated an error), you can use `kubectl
exec`:
```
kubectl exec -n kube-system <antrea-agent Pod name> -c antrea-ovs tail /var/log/openvswitch/<DAEMON>.log
```
The Open vSwitch daemon logs for each `antrea-agent` Pod are also stored on the
persistent storage of the corresponding node (i.e. the node on which the Pod is
scheduled), under `/var/log/antrea/openvswitch`.

## Accessing the antrea-controller API

antrea-controller runs as a Deployment, exposes its API via a Service and
registers an APIService to aggregate into the Kubernetes API. To access the
antrea-controller API, you need to know its address and have the credentials
to access it. There are multiple ways in which you can access the API:

### Using antctl

Typically, `antctl` handles locating the Kubernetes API server and
authentication when it runs in an environment with kubeconfig set up. Same as
`kubectl`, `antctl` looks for a file named config in the $HOME/.kube directory.
You can specify other kubeconfig files by setting the `--kubeconfig` flag.

For example, you can view internal NetworkPolicy objects with this command:
```
antctl get networkpolicy
```

### Using kubectl proxy

As the antrea-controller API is aggregated into the Kubernetes API, you can
access it through the Kubernetes API using the appropriate URL paths. The
following command runs `kubectl` in a mode where it acts as a reverse proxy for
the Kubernetes API and handles authentication.
```
# Start the proxy in the background
kubectl proxy &
# Access the antrea-controller API path
curl 127.0.0.1:8001/apis/networking.antrea.tanzu.vmware.com
```

### Directly accessing the antrea-controller API

If you want to directly access the antrea-controller API, you need to get its
address and pass an authentication token when accessing it, like this:
```
# Get the antrea service address
ANTREA_SVC=$(kubectl get service antrea -n kube-system -o jsonpath='{.spec.clusterIP}')
# Get the token value of antctl account, you can use any service accounts that have permissions to antrea API.
TOKEN=$(kubectl get secrets -n kube-system -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='antctl')].data.token}"|base64 --decode)
# Access antrea API with TOKEN
curl --insecure --header "Authorization: Bearer $TOKEN" https://$ANTREA_SVC/apis
```

## Accessing the antrea-agent API

antrea-agent runs as a DaemonSet Pod on each Node and exposes its API via a
local endpoint. There are two ways you can access it:

### Using antctl

To use `antctl` to access the antrea-agent API, you need to exec into the
antrea-agent container first. `antctl` is embedded in the image so it can be
used directly.

For example, you can view the internal NetworkPolicy objects for a specific
agent with this command:
```
# Get into the antrea-agent container
kubectl exec -it <antrea-agent Pod name> -n kube-system -c antrea-agent bash
# View the agent's NetworkPolicy
antctl get networkpolicy
```

### Directly accessing the antrea-agent API

If you want to directly access the antrea-agent API, you need to log into the
Node that the antrea-agent runs on or exec into the antrea-agent container. Then
access the local endpoint directly using the Bearer Token stored in the file
system:
```
TOKEN=$(cat /var/run/antrea/apiserver/loopback-client-token)
curl --insecure --header "Authorization: Bearer $TOKEN" https://127.0.0.1:10350/
```

Note that you can also access the antrea-agent API from outside the Node by
using the authentication token of the `antctl` service account:
```
# Get the token value of antctl account.
TOKEN=$(kubectl get secrets -n kube-system -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='antctl')].data.token}"|base64 --decode)
# Access antrea API with TOKEN
curl --insecure --header "Authorization: Bearer $TOKEN" https://<Node IP address>:10350/podinterfaces
```
However, in this case you will be limited to the endpoints that `antctl` is
allowed to access, as defined
[here](https://github.com/vmware-tanzu/antrea/blob/master/build/yamls/base/antctl.yml).

## Troubleshooting OVS

OVS agents (`ovsdb-server` and `ovs-vswitchd`) run inside the `antrea-ovs`
container of the `antrea-agent` Pod. You can use `kubectl exec` to execute OVS
command line tools (e.g. `ovs-vsctl`, `ovs-ofctl`) in the container, for
example:
```
kubectl exec -n kube-system <antrea-agent Pod name> -c antrea-ovs ovs-vsctl show
```

By default the host directory `/var/run/antrea/openvswitch/` is mounted to
`/var/run/openvswitch/` of the `antrea-ovs` container and is used as the parent
directory of the OVS UNIX domain sockets and configuration database file.
Therefore, you may execute some OVS command line tools (inc. `ovs-vsctl` and
`ovs-ofctl`) from a Kubernetes Node - assuming they are installed on the Node -
by specifying the socket file path explicitly, for example:
```
ovs-vsctl --db unix:/var/run/antrea/openvswitch/db.sock show
ovs-ofctl show unix:/var/run/antrea/openvswitch/br-int.mgmt
```

## Troubleshooting with antctl

`antctl` provides some useful commands to troubleshoot Antrea Controller and
Agent, which can print the runtime information of `antrea-controller` and
`antrea-agent`, dump NetworkPolicy objects, dump Pod network interface
information on a Node, dump Antrea OVS flows, and perform OVS packet tracing.
Refer to the [`antctl` guide](/docs/antctl.md#usage) to learn how to use these
commands.
