# Traceflow User Guide

Antrea supports using Traceflow for network diagnosis: it generates tracing requests for traffic going through
Antrea-managed Pod network. Creating a new Traceflow CRD triggers the Traceflow module to inject packet into OVS,
provide various observation points along the packet's path and populate these observations into the status field of
the Traceflow CRD. Users can start a new trace simply from kubectl, antctl or Antrea-Octant-Plugin and view Traceflow
result via CRD, antctl or UI graph.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Start a New Trace](#start-a-new-trace)
  - [Using kubectl and YAML file](#using-kubectl-and-yaml-file)
  - [Using antctl and spec config](#using-antctl-and-spec-config)
  - [Using Octant with antrea-octant-plugin](#using-octant-with-antrea-octant-plugin)
- [View Traceflow Result and Graph](#view-traceflow-result-and-graph)
- [View Traceflow CRDs](#view-traceflow-crds)
- [RBAC](#rbac)

## Prerequisites

You need to enable Traceflow from the featureGates map defined in antrea.yml for
both Controller and Agent. In order to use a Service as the destination in
traces, you also need to ensure [AntreaProxy](feature-gates.md) is enabled in
the Agent configuration:

```yaml
  antrea-controller.conf: |
    featureGates:
    # Enable traceflow which provides packet tracing feature to diagnose network issue.
      Traceflow: true
  antrea-agent.conf: |
    featureGates:
    # Enable traceflow which provides packet tracing feature to diagnose network issue.
      Traceflow: true
    # Enable AntreaProxy which provides ServiceLB for in-cluster Services in antrea-agent.
    # It should be enabled on Windows, otherwise NetworkPolicy will not take effect on
    # Service traffic.
      AntreaProxy: true
```

For antrea-octant-plugin installation, please refer to [antrea-octant-installation](octant-plugin-installation.md).

## Start a New Trace

You can choose to use kubectl together with YAML file, antctl with spec information or Octant UI to start a new trace.

When starting a new trace, you can provide the following information which will be used to build the trace packet:

* source Pod
* destination Pod, Service or destination IP address
* transport protocol (TCP/UDP/ICMP)
* transport ports

### Using kubectl and YAML file

You can start a new trace by creating Traceflow CRD via kubectl and a YAML file which contains the essential
configuration of Traceflow CRD. An example YAML file of Traceflow CRD might look like this:

```yaml
apiVersion: ops.antrea.tanzu.vmware.com/v1alpha1
kind: Traceflow
metadata:
  name: tf-test
spec:
  source:
    namespace: default
    pod: tcp-sts-0
  destination:
    namespace: default
    pod: tcp-sts-2
    # destination can also be an IP address ('ip' field) or a Service name ('service' field); the 3 choices are mutually exclusive.
  packet:
    ipHeader:
      protocol: 6 # Protocol here can be 6 (TCP), 17 (UDP) or 1 (ICMP), default value is 1 (ICMP)
    transportHeader:
      tcp:
        srcPort: 10000 # Source port needs to be set when Protocol is TCP/UDP.
        dstPort: 80 # Destination port needs to be set when Protocol is TCP/UDP.
```

The CRD above starts a new trace from port 10000 of source Pod named `tcp-sts-0` to port 80
of destination Pod named `tcp-sts-2` using TCP protocol.

### Using antctl and spec config

Please refer to the corresponding [antctl page](antctl.md#traceflow).

### Using Octant with antrea-octant-plugin

![Start a New Trace](https://downloads.antrea.io/static/tf_create.1.png)

From Octant dashboard, you need to click on left navigation bar named "Antrea" and then
choose category named "Traceflow" to lead you to the Traceflow UI displayed on the right side.

Now, you can start a new trace by clicking on the button named "Start New Trace" and submitting the form with trace details.
It helps you create a Traceflow CRD and generates a corresponding Traceflow Graph.

## View Traceflow Result and Graph

You can always view Traceflow result directly via Traceflow CRD status and see if the packet is successfully delivered
or somehow dropped by certain packet-processing stage. Antrea also provides a more user-friendly way by showing the
Traceflow result via a trace graph on UI.

![Show Successful Trace](https://downloads.antrea.io/static/tf_graph_success.png)

From the graph above, we can see the inter-node traffic between two Pods has been successfully delivered.
Sometimes the traffic may not be successfully delivered and we can always easily identify where the traffic is dropped
via a trace graph like below.

![Show Failing Trace](https://downloads.antrea.io/static/tf_graph_failure.png)

You can also generate a historical trace graph by providing a specific Traceflow CRD name (assuming the CRD has not been deleted yet)
as shown below.

![Generate Historical Trace](https://downloads.antrea.io/static/tf_historical_graph.png)

## View Traceflow CRDs

![Antrea Overview](https://downloads.antrea.io/static/tf_overview.png)

As shown above, you can check the existing Traceflow CRDs in the "Traceflow Info" table of the Antrea Overview web page
in the Octant UI. You can generate a trace graph for any of these CRDs, as explained in the previous section.
Also, you can view all the Traceflow CRDs from the Traceflow page by clicking the right tab named "Traceflow Info" like below.

![Traceflow CRDs](https://downloads.antrea.io/static/tf_table.png)

## RBAC

Traceflow CRDs are meant for admins to troubleshoot and diagnose the network
by injecting a packet from a source workload to a destination workload. Thus,
access to manage these CRDs must be granted to subjects which
have the authority to perform these diagnostic actions. On cluster
initialization, Antrea grants the permissions to edit these CRDs with `admin`
and the `edit` ClusterRole. In addition to this, Antrea also grants the
permission to view these CRDs with the `view` ClusterRole. Cluster admins can
therefore grant these ClusterRoles to any subject who may be responsible to
troubleshoot the network. The admins may also decide to share the `view`
ClusterRole to a wider range of subjects to allow them to read the traceflows
that are active in the cluster.
