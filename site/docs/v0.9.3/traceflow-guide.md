# Traceflow User Guide

Antrea supports using Traceflow for network diagnosis: it generates tracing requests for traffic going through
Antrea-managed Pod network. Creating a new Traceflow CRD triggers the Traceflow module to inject packet into OVS,
provide various observation points along the packet's path and populate these observations into the status field of
the Traceflow CRD. Users can start a new trace simply from Kubectl, Antctl or Antrea-Octant-Plugin and view Traceflow
result via CRD, Antctl or UI graph.

## Table of Contents

- [Prerequisites](#Prerequisites)
- [Start a New Trace](#Start-a-New-Trace)
  - [Using kubectl and YAML file](#using-kubectl-and-YAML-file)
  - [Using antctl and spec config](#using-antctl-and-spec-config)
  - [Using Octant with antrea-octant-plugin](#Using-Octant-with-antrea-octant-plugin)
- [View Traceflow Result and Graph](#View-Traceflow-Result-and-Graph)
- [View Traceflow CRDs](#View-Traceflow-CRDs)

## Prerequisites
You need to switch on traceflow from featureGates defined in antrea.yml for both Controller and Agent.
```yaml
  antrea-controller.conf: |
    featureGates:
    # Enable traceflow which provides packet tracing feature to diagnose network issue.
      Traceflow: true
  antrea-agent.conf: |
    featureGates:
    # Enable traceflow which provides packet tracing feature to diagnose network issue.
      Traceflow: true
```
For antrea-octant-plugin installation, please refer to [antrea-octant-installation](/docs/octant-plugin-installation.md).

## Start a New Trace
You can choose to use Kubectl together with YAML file, Antctl with spec information or Octant UI to start a new trace.

If you use Kubectl or Antctl to start a new trace, you can provide the following information which will be used to build the trace packet:
* source Pod
* destination Pod, Service or destination IP address
* transport protocol (TCP/UDP/ICMP)
* transport ports

If you use the UI to start a new trace, we currently only support Pods as the destination, but will soon support
destination IPs and Service names.

### Using kubectl and YAML file
You can start a new trace by creating Traceflow CRD via Kubectl and a YAML file which contains the essential
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
#   ip: IP can also be marked as destination, but namespace/pod and ip are mutually exclusive.
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

### Using-antctl-and-spec-config

Please refer to the corresponding [Antctl page](https://github.com/vmware-tanzu/antrea/blob/master/docs/antctl.md#traceflow).

### Using Octant with antrea-octant-plugin

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/tf_create.png" width="600" alt="Start a New Trace">

From Octant dashboard, you need to click on left navigation bar named "Antrea" and then
choose category named "Traceflow" to lead you to the Traceflow UI displayed on the right side.

Now, you can start a new trace by clicking on the button named "Start New Trace" and submitting the form with trace details.
It helps you create a Traceflow CRD and generates a corresponding Traceflow Graph.

## View Traceflow Result and Graph

You can always view Traceflow result directly via Traceflow CRD status and see if the packet is successfully delivered
or somehow dropped by certain packet-processing stage. Antrea also provides a more user-friendly way by showing the
Traceflow result via a trace graph on UI.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/tf_graph_success.png" width="600" alt="Show Successful Trace">

From the graph above, we can see the inter-node traffic between two Pods has been successfully delivered.
Sometimes the traffic may not be successfully delivered and we can always easily identify where the traffic is dropped
via a trace graph like below.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/tf_graph_failure.png" width="600" alt="Show Failing Trace">

You can also generate a historical trace graph by providing a specific Traceflow CRD name (assuming the CRD has not been deleted yet)
as shown below.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/tf_historical_graph.png" width="600" alt="Generate Historical Trace">

## View Traceflow CRDs

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/tf_overview.png" width="600" alt="Antrea Overview">

As shown above, you can check the existing Traceflow CRDs in the "Traceflow Info" table of the Antrea Overview web page
in the Octant UI. You can generate a trace graph for any of these CRDs, as explained in the previous section.
Also, you can view all the traceflow CRDs from the Tracflow page by clicking the right tab named "Traceflow Info" like below.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/tf_table.png" width="600" alt="Traceflow CRDs">
