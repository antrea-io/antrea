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
- [Troubleshooting BGP](#troubleshooting-bgp)
  - [Checking the BGPPolicy applied to a Node](#checking-the-bgppolicy-applied-to-a-node)
  - [Checking the BGP peers of a Node](#checking-the-bgp-peers-of-a-node)
  - [Reading the BGP messages in the Antrea Agent log](#reading-the-bgp-messages-in-the-antrea-agent-log)
  - [Checking the Events of a BGPPolicy](#checking-the-events-of-a-bgppolicy)
  - [Monitoring BGP with Prometheus](#monitoring-bgp-with-prometheus)
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
    ovs_version: "3.7.1"
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

## Troubleshooting BGP

This section applies when the `BGPPolicy` feature gate is enabled. To configure
BGP, see the [BGPPolicy guide](bgp-policy.md).

Each Node applies at most one BGPPolicy: if several select the Node, the oldest
one is applied. The `antctl` commands below report the state of one Node. Run
them in the `antrea-agent` container on that Node, as described in [Accessing
the antrea-agent API](#accessing-the-antrea-agent-api).

### Checking the BGPPolicy applied to a Node

Run `antctl get bgppolicy`. The `STATUS` column is `Effective` when the last
attempt to apply the BGPPolicy succeeded, and `Failed` when it did not. To see
the error, use the JSON output:

```bash
$ antctl get bgppolicy -o json
{
  "name": "example-bgp-policy",
  "lastSyncError": "failed to start BGP server: listen tcp :179: bind: address already in use"
}
```

The Antrea Agent retries a failed BGPPolicy. The delay between attempts starts
at 5 seconds and doubles up to 5 minutes. When the BGP server could not be
started, `antctl get bgppeers` and `antctl get bgproutes` print the same error
instead of a list. If no BGPPolicy selects the Node, all three commands answer
that there is no effective BGP policy.

### Checking the BGP peers of a Node

Run `antctl get bgppeers` to see the state of the BGP session with each peer.
The JSON output (`-o json`) also shows how long each session has been
established, and how many routes were sent to each peer and received from it.
An `Established` session that sends no route means that the Node advertises
nothing: check which routes it advertises with `antctl get bgproutes`.

`antctl get bgproutes` prints the routes that the Node intends to advertise.
To see what a peer actually gets, run `antctl get bgproutes --peer <address>`.
It prints the routes that the BGP server sent to that peer, which is none while
the session is down. To see the routes that the peer sends to the Node, add
`--received`. The Node does not install them, but they show whether the peer
and the Node agree on the session.

### Reading the BGP messages in the Antrea Agent log

At the default log verbosity, the `antrea-agent` container logs:

- each BGP peer that is added, updated or removed.
- each BGP peer that has no entry in the `antrea-bgp-passwords` Secret, while
  that Secret exists. The message names the key that was looked up. The session
  with such a peer is not authenticated, so a peer that requires a password
  never reaches the `Established` state. See [BGP
  Authentication](bgp-policy.md#bgp-authentication) for the key format.
- each attempt to apply the BGPPolicy that fails, with the error.
- each BGP session that goes up or down, as `Peer Up` and `Peer Down`.

At verbosity 2, the log also records each attempt to apply the BGPPolicy and
how long it took, and each route that is advertised or withdrawn. To change the
verbosity, see [Looking at the Antrea logs](#looking-at-the-antrea-logs).

### Checking the Events of a BGPPolicy

Every Node that a BGPPolicy selects records Kubernetes Events on that
BGPPolicy, and each Event names its Node. The Events show which Nodes fail to
apply the BGPPolicy without running `antctl` on each Node. To see them, run
`kubectl describe bgppolicy <name>`. Because BGPPolicy is cluster-scoped, its
Events are in the `default` Namespace, and you can list the Events of all
BGPPolicies with:

```bash
kubectl get events -n default --field-selector involvedObject.kind=BGPPolicy
```

| Reason | Type | Recorded when |
| --- | --- | --- |
| `BGPServerStarted` | Normal | The BGP server of the Node starts. The Event gives the router ID, the local ASN and the listen port. |
| `BGPServerStartFailed` | Warning | The BGP server fails to start, for example because the listen port is already in use. |
| `BGPPeerConfigFailed` | Warning | A BGP peer cannot be added, updated or removed. The Event names the peer. |
| `BGPPolicySyncFailed` | Warning | The BGPPolicy cannot be applied for another reason, for example an invalid router ID. |
| `BGPPolicyNotEffective` | Normal | The BGPPolicy selects the Node, but the Node applies an older BGPPolicy, which the Event names. |
| `BGPPeerUp` | Normal | The BGP session with a peer reaches the `Established` state, or is already established when the Antrea Agent first checks it. |
| `BGPPeerDown` | Warning | The BGP session with a peer leaves the `Established` state. |

Repeated identical Events are combined into one Event with a count. The Antrea
Agent checks the BGP sessions every 15 seconds. A session is usually established
before the first check, for example right after the BGPPolicy is applied or the
Antrea Agent restarts, and it then records `BGPPeerUp` without a previous state.
A session that goes down and comes back up between two checks records no Event.
The `Peer Down` and `Peer Up` messages in the log still record it.

### Monitoring BGP with Prometheus

When the `BGPPolicy` feature gate and Prometheus metrics are both enabled, the
Antrea Agent exports the following metrics. Because the feature gate is
disabled by default, they are not in the list of the [Prometheus integration
guide](prometheus-integration.md#antrea-prometheus-metrics), which is generated
from a default deployment.

| Metric | Type | Labels | Value |
| --- | --- | --- | --- |
| `antrea_agent_bgp_peer_up` | Gauge | `peer`, `asn` | 1 when the BGP session with the peer is `Established`, otherwise 0. |
| `antrea_agent_bgp_peer_session_state` | Gauge | `peer`, `asn` | State of the BGP session with the peer: 0 for Unknown, 1 for Idle, 2 for Connect, 3 for Active, 4 for OpenSent, 5 for OpenConfirm and 6 for Established. |
| `antrea_agent_bgp_peer_advertised_route_count` | Gauge | `peer`, `asn` | Number of routes sent to the peer. It is 0 while the session with the peer is not `Established`. |
| `antrea_agent_bgp_route_advertisement_count` | Counter | `type` | Number of routes advertised to the BGP peers, by route type. |
| `antrea_agent_bgp_route_withdrawal_count` | Counter | `type` | Number of routes withdrawn from the BGP peers, by route type. |
| `antrea_agent_bgp_effective_policy` | Gauge | `policy` | Always 1, for the BGPPolicy that the Node applies, even when the last attempt to apply it failed. |

The route types are the ones that `antctl get bgproutes` prints. The Antrea
Agent reads the state of the BGP sessions every 15 seconds. The peer metrics
have one series per peer of the BGPPolicy, and have none when no BGPPolicy
selects the Node, like `antrea_agent_bgp_effective_policy`.

To add the name of the BGPPolicy to a peer metric, join it with
`antrea_agent_bgp_effective_policy`:

```text
antrea_agent_bgp_peer_up * on(instance) group_left(policy) antrea_agent_bgp_effective_policy
```

The Antrea Agent also exports the metrics of the queue that it uses to apply the
BGPPolicy, with the label `name="bgpPolicy"`. Each failed attempt increments
`workqueue_retries_total{name="bgpPolicy"}`.

These example Prometheus rules raise an alert when a BGP session stays down for
more than a minute, and when the Antrea Agent keeps failing to apply its
BGPPolicy:

```yaml
groups:
- name: antrea-bgp
  rules:
  - alert: AntreaBGPPeerDown
    expr: antrea_agent_bgp_peer_up == 0
    for: 1m
    annotations:
      summary: "BGP session with peer {{ $labels.peer }} (ASN {{ $labels.asn }}) is down on {{ $labels.instance }}"
  - alert: AntreaBGPPolicyFailing
    expr: increase(workqueue_retries_total{name="bgpPolicy"}[15m]) > 3
    annotations:
      summary: "Antrea Agent on {{ $labels.instance }} keeps failing to apply its BGPPolicy"
```

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
