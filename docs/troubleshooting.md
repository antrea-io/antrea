# Troubleshooting

## Table of Contents

<!-- toc -->
- [Looking at the Antrea logs](#looking-at-the-antrea-logs)
- [Accessing the antrea-controller API](#accessing-the-antrea-controller-api)
  - [Using antctl](#using-antctl)
  - [Using kubectl proxy](#using-kubectl-proxy)
  - [Using antctl proxy](#using-antctl-proxy)
  - [Directly accessing the antrea-controller API](#directly-accessing-the-antrea-controller-api)
- [Accessing the antrea-agent API](#accessing-the-antrea-agent-api)
  - [Using antctl](#using-antctl-1)
  - [Using antctl proxy](#using-antctl-proxy-1)
  - [Directly accessing the antrea-agent API](#directly-accessing-the-antrea-agent-api)
- [Accessing the flow-aggregator API](#accessing-the-flow-aggregator-api)
  - [Using antctl](#using-antctl-2)
  - [Directly accessing the flow-aggregator API](#directly-accessing-the-flow-aggregator-api)
- [Troubleshooting Open vSwitch](#troubleshooting-open-vswitch)
- [Troubleshooting with antctl](#troubleshooting-with-antctl)
- [Profiling Antrea components](#profiling-antrea-components)
- [Ask your questions to the Antrea community](#ask-your-questions-to-the-antrea-community)
<!-- /toc -->

## Looking at the Antrea logs

You can inspect the `antrea-controller` logs in the `antrea-controller` Pod by
running this `kubectl` command:

```bash
kubectl logs -n kube-system <antrea-controller Pod name>
```

To check the logs of the `antrea-agent`, `antrea-ovs`, and `antrea-ipsec`
containers in an `antrea-agent` Pod, run command:

```bash
kubectl logs -n kube-system <antrea-agent Pod name> -c [antrea-agent|antrea-ovs|antrea-ipsec]
```

To check the OVS daemon logs (e.g. if the `antrea-ovs` container logs indicate
that one of the OVS daemons generated an error), you can use `kubectl exec`:

```bash
kubectl exec -n kube-system <antrea-agent Pod name> -c antrea-ovs -- tail /var/log/openvswitch/<DAEMON>.log
```

The `antrea-controller` Pod and the list of `antrea-agent` Pods, along with the
Nodes on which the Pods are scheduled, can be returned by command:

```bash
kubectl get pods -n kube-system -l app=antrea -o wide
```

Logs of `antrea-controller`, `antrea-agent`, OVS and strongSwan daemons are also
stored in the filesystem of the Node (i.e. the Node on which the
`antrea-controller` or `antrea-agent` Pod is scheduled).

- `antrea-controller` logs are stored in directory: `/var/log/antrea` (on the
Node where the `antrea-controller` Pod is scheduled.
- `antrea-agent` logs are stored in directory: `/var/log/antrea` (on the Node
where the `antrea-agent` Pod is scheduled).
- Logs of the OVS daemons - `ovs-vswitchd`, `ovsdb-server`, `ovs-monitor-ipsec` -
are stored in directory: `/var/log/antrea/openvswitch` (on the Node where the
`antrea-agent` Pod is scheduled).
- strongSwan daemon logs are stored in directory: `/var/log/antrea/strongswan`
(on the Node where the `antrea-agent` Pod is scheduled).

To increase the log level for the `antrea-agent` and the `antrea-controller`, you
can edit the `--v=0` arg in the Antrea manifest to a desired level.
Alternatively, you can generate an Antrea manifest with increased log level of
4 (maximum debug level) using `generate_manifest.sh`:

```bash
hack/generate-manifest.sh --mode dev --verbose-log
```  

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

```bash
antctl get networkpolicy
```

### Using kubectl proxy

As the antrea-controller API is aggregated into the Kubernetes API, you can
access it through the Kubernetes API using the appropriate URL paths. The
following command runs `kubectl` in a mode where it acts as a reverse proxy for
the Kubernetes API and handles authentication.

```bash
# Start the proxy in the background
kubectl proxy &
# Access the antrea-controller API path
curl 127.0.0.1:8001/apis/controlplane.antrea.io
```

### Using antctl proxy

Antctl supports running a reverse proxy (similar to the kubectl one) which
enables access to the entire Antrea Controller API (not just aggregated API
Services), but does not secure the TLS connection between the proxy and the
Controller. Refer to the [antctl documentation](antctl.md#antctl-proxy) for more
information.

### Directly accessing the antrea-controller API

If you want to directly access the antrea-controller API, you need to get its
address and pass an authentication token when accessing it, like this:

```bash
# Get the antrea Service address
ANTREA_SVC=$(kubectl get service antrea -n kube-system -o jsonpath='{.spec.clusterIP}')
# Get the token value of antctl account, you can use any ServiceAccount that has permissions to antrea API.
TOKEN=$(kubectl get secret/antctl-service-account-token -n kube-system -o jsonpath="{.data.token}"|base64 --decode)
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

```bash
# Get into the antrea-agent container
kubectl exec -it <antrea-agent Pod name> -n kube-system -c antrea-agent -- bash
# View the agent's NetworkPolicy
antctl get networkpolicy
```

### Using antctl proxy

Antctl supports running a reverse proxy (similar to the kubectl one) which
enables access to the entire Antrea Agent API, but does not secure the TLS
connection between the proxy and the Controller. Refer to the [antctl
documentation](antctl.md#antctl-proxy) for more information.

### Directly accessing the antrea-agent API

If you want to directly access the antrea-agent API, you need to log into the
Node that the antrea-agent runs on or exec into the antrea-agent container. Then
access the local endpoint directly using the Bearer Token stored in the file
system:

```bash
TOKEN=$(cat /var/run/antrea/apiserver/loopback-client-token)
curl --insecure --header "Authorization: Bearer $TOKEN" https://127.0.0.1:10350/
```

Note that you can also access the antrea-agent API from outside the Node by
using the authentication token of the `antctl` ServiceAccount:

```bash
# Get the token value of antctl account.
TOKEN=$(kubectl get secret/antctl-service-account-token -n kube-system -o jsonpath="{.data.token}"|base64 --decode)
# Access antrea API with TOKEN
curl --insecure --header "Authorization: Bearer $TOKEN" https://<Node IP address>:10350/podinterfaces
```

However, in this case you will be limited to the endpoints that `antctl` is
allowed to access, as defined
[here](../build/charts/antrea/templates/antctl/clusterrole.yaml).

## Accessing the flow-aggregator API

flow-aggregator runs as a Deployment and exposes its API via a local endpoint.
There are two ways you can access it:

### Using antctl

To use `antctl` to access the flow-aggregator API, you need to exec into the
flow-aggregator container first. `antctl` is embedded in the image so it can be
used directly.

For example, you can dump the flow records with this command:

```bash
# Get into the flow-aggregator container
kubectl exec -it <flow-aggregator Pod name> -n flow-aggregator -- bash
# View the flow records
antctl get flowrecords
```

### Directly accessing the flow-aggregator API

If you want to directly access the flow-aggregator API, you need to exec into
the flow-aggregator container. Then access the local endpoint directly using the
Bearer Token stored in the file system:

```bash
TOKEN=$(cat /var/run/antrea/apiserver/loopback-client-token)
curl --insecure --header "Authorization: Bearer $TOKEN" https://127.0.0.1:10348/
```

## Troubleshooting Open vSwitch

OVS daemons (`ovsdb-server` and `ovs-vswitchd`) run inside the `antrea-ovs`
container of the `antrea-agent` Pod. You can use `kubectl exec` to execute OVS
command line tools (e.g. `ovs-vsctl`, `ovs-ofctl`, `ovs-appctl`) in the
container, for example:

```bash
kubectl exec -n kube-system <antrea-agent Pod name> -c antrea-ovs -- ovs-vsctl show
```

By default the host directory `/var/run/antrea/openvswitch/` is mounted to
`/var/run/openvswitch/` of the `antrea-ovs` container and is used as the parent
directory of the OVS UNIX domain sockets and configuration database file.
Therefore, you may execute some OVS command line tools (inc. `ovs-vsctl` and
`ovs-ofctl`) from a Kubernetes Node - assuming they are installed on the Node -
by specifying the socket file path explicitly, for example:

```bash
ovs-vsctl --db unix:/var/run/antrea/openvswitch/db.sock show
ovs-ofctl show unix:/var/run/antrea/openvswitch/br-int.mgmt
```

Commands to check basic OVS and OpenFlow information include:

- `ovs-vsctl show`: dump OVS bridge and port configuration. Outputs of the
command are like:

```bash
f06768ee-17ec-4abb-a971-b3b76abc8cda
    Bridge br-int
        datapath_type: system
        Port coredns--e526c8
            Interface coredns--e526c8
        Port antrea-tun0
            Interface antrea-tun0
                type: geneve
                options: {key=flow, remote_ip=flow}
        Port antrea-gw0
            Interface antrea-gw0
            type: internal
    ovs_version: "2.17.7"
```

- `ovs-ofctl show br-int`: show OpenFlow information of the OVS bridge.
- `ovs-ofctl dump-flows br-int`: dump OpenFlow entries of the OVS bridge.
- `ovs-ofctl dump-ports br-int`: dump traffic statistics of the OVS ports.

For more information on the usage of the OVS CLI tools, check the
[Open vSwitch Manpages](https://www.openvswitch.org/support/dist-docs).

## Troubleshooting with antctl

`antctl` provides some useful commands to troubleshoot Antrea Controller and
Agent, which can print the runtime information of `antrea-controller` and
`antrea-agent`, dump NetworkPolicy objects, dump Pod network interface
information on a Node, dump Antrea OVS flows, and perform OVS packet tracing.
Refer to the [`antctl` guide](antctl.md#usage) to learn how to use these
commands.

## Profiling Antrea components

The easiest way to profile the Antrea components is to use the Go
[pprof](https://golang.org/pkg/net/http/pprof/) tool. Both the Antrea Agent and
the Antrea Controller use the K8s apiserver library to serve their API, and this
library enables the pprof HTTP server by default. In order to access it without
having to worry about authentication, you can use the antctl proxy function.

For example, this is what you would do to look at a 30-second CPU profile for
the Antrea Controller:

```bash
# Start the proxy in the background
antctl proxy --controller&
# Look at a 30-second CPU profile
go tool pprof http://127.0.0.1:8001/debug/pprof/profile?seconds=30
```

## Ask your questions to the Antrea community

If you are running into issues when running Antrea and you need help, ask your
questions on [Github](https://github.com/antrea-io/antrea/issues/new/choose)
or [reach out to us on Slack or during the Antrea office
hours](../README.md#community).
