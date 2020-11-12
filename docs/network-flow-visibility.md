# Network Flow Visibility in Antrea

## Table of Contents

<!-- toc -->
- [Overview](#overview)
- [Flow Exporter feature](#flow-exporter-feature)
  - [Configuration](#configuration)
  - [IPFIX Information Elements (IEs) in a Flow Record](#ipfix-information-elements-ies-in-a-flow-record)
    - [IEs from IANA-assigned IE registry](#ies-from-iana-assigned-ie-registry)
    - [IEs from Reverse IANA-assigned IE Registry](#ies-from-reverse-iana-assigned-ie-registry)
    - [IEs from Antrea IE Registry](#ies-from-antrea-ie-registry)
  - [Supported capabilities](#supported-capabilities)
    - [Types of Flows and Associated Information](#types-of-flows-and-associated-information)
    - [Connection Metrics](#connection-metrics)
- [ELK Flow Collector](#elk-flow-collector)
  - [Purpose](#purpose)
  - [About Elastic Stack](#about-elastic-stack)
  - [Deployment Steps](#deployment-steps)
  - [Pre-built Dashboards](#pre-built-dashboards)
    - [Overview](#overview-1)
    - [Flows](#flows)
      - [Pod-to-Pod Traffic](#pod-to-pod-traffic)
      - [Pod-to-Service Traffic](#pod-to-service-traffic)
    - [Flow Records](#flow-records)
    - [Node Throughput](#node-throughput)
    - [Network Policy](#network-policy)
<!-- /toc -->

## Overview
[Antrea](design/architecture.md) is a Kubernetes network plugin that provides network
connectivity and security features for Pod workloads. Considering the scale and
dynamism of Kubernetes workloads in a cluster, Network Flow Visibility helps in
the management and configuration of Kubernetes resources such as Network Policy,
Services, Pods etc., and thereby provides opportunities to enhance the performance
and security aspects of Pod workloads.

For visualizing the network flows, Antrea monitors the flows in Linux conntrack
module. These flows are converted to flow records and are sent to the configured
flow controller. High-level design is given below:

![Flow Exporter Design](assets/flow_exporter.svg)

## Flow Exporter feature

In Antrea, the basic building block for the Network Flow Visibility is the **Flow
Exporter feature**. Flow Exporter operates within Antrea Agent; it builds and maintains
a connection store by polling and dumping flows from conntrack module periodically.
Connections from the connection store are exported to a flow collector using the
IPFIX protocol, and for this purpose we use the [go-ipfix](https://github.com/vmware/go-ipfix) library.
 
### Configuration

To enable the Flow Exporter feature at the Antrea Agent, the following config
parameters have to be set in the Antrea Agent ConfigMap as shown below. We provide
some examples for the parameter values in the following snippet.

```yaml
  antrea-agent.conf: |
    # FeatureGates is a map of feature names to bools that enable or disable experimental features.
    featureGates:
    # Enable flowexporter which exports polled conntrack connections as IPFIX flow records from each agent to a configured collector.
      FlowExporter: true
    # Enable antrea proxy which provides ServiceLB for in-cluster services in antrea agent.
    # It should be enabled on Windows, otherwise NetworkPolicy will not take effect on
    # Service traffic.
      AntreaProxy: true

    # Provide flow collector address as string with format <IP>:<port>[:<proto>], where proto is tcp or udp. This also enables
    # the flow exporter that sends IPFIX flow records of conntrack flows on OVS bridge. If no L4 transport proto is given,
    # we consider tcp as default.
    flowCollectorAddr: "192.168.86.86:4739:tcp"

    # Provide flow poll interval as a duration string. This determines how often the flow exporter dumps connections from the conntrack module.
    # Flow poll interval should be greater than or equal to 1s (one second).
    # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
    flowPollInterval: "1s"

    # Provide flow export frequency, which is the number of poll cycles elapsed before flow exporter exports flow records to
    # the flow collector.
    # Flow export frequency should be greater than or equal to 1.
    flowExportFrequency: 5
```
 
Please note that the default values for `flowPollInterval` and `flowExportFrequency`
parameters are set to 5s and 12, respectively. `flowCollectorAddr` is a required
parameter that is necessary for the Flow Exporter feature to work.

### IPFIX Information Elements (IEs) in a Flow Record

There are 23 IPFIX IEs in each exported flow record, which are defined in the
IANA-assigned IE registry, the Reverse IANA-assigned IE registry and the Antrea
IE registry. The reverse IEs are used to provide bi-directional information about
the flow. All the IEs used by the Antrea Flow Exporter are listed below:

#### IEs from IANA-assigned IE registry 

| IPFIX Information Element| Enterprise ID | Field ID | Type           |
|--------------------------|---------------|----------|----------------|
| flowStartSeconds         | 0             | 150      | dateTimeSeconds|
| flowEndSeconds           | 0             | 151      | dateTimeSeconds|
| sourceIPv4Address        | 0             | 8        | ipv4Address    |
| destinationIPv4Address   | 0             | 12       | ipv4Address    |
| sourceTransportPort      | 0             | 7        | unsigned16     |
| destinationTransportPort | 0             | 11       | unsigned16     |
| protocolIdentifier       | 0             | 4        | unsigned8      |
| packetTotalCount         | 0             | 86       | unsigned64     |
| octetTotalCount          | 0             | 85       | unsigned64     |
| packetDeltaCount         | 0             | 2        | unsigned64     |
| octetDeltaCount          | 0             | 1        | unsigned64     |

#### IEs from Reverse IANA-assigned IE Registry

| IPFIX Information Element| Enterprise ID | Field ID | Type           |
|--------------------------|---------------|----------|----------------|
| reversePacketTotalCount  | 29305         | 86       | unsigned64     |
| reverseOctetTotalCount   | 29305         | 85       | unsigned64     |
| reversePacketDeltaCount  | 29305         | 2        | unsigned64     |
| reverseOctetDeltaCount   | 29305         | 1        | unsigned64     |

#### IEs from Antrea IE Registry

| IPFIX Information Element    | Enterprise ID | Field ID | Type        |
|------------------------------|---------------|----------|-------------|
| sourcePodNamespace           | 56506         | 100      | string      |
| sourcePodName                | 56506         | 101      | string      |
| destinationPodNamespace      | 56506         | 102      | string      |
| destinationPodName           | 56506         | 103      | string      |
| sourceNodeName               | 56506         | 104      | string      |
| destinationNodeName          | 56506         | 105      | string      |
| destinationClusterIPv4       | 56506         | 106      | ipv4Address |
| destinationClusterIPv6       | 56506         | 107      | ipv6Address |
| destinationServicePort       | 56506         | 108      | unsigned16  |
| destinationServicePortName   | 56506         | 109      | string      |
| ingressNetworkPolicyName     | 56506         | 110      | string      |
| ingressNetworkPolicyNamespace| 56506         | 111      | string      |
| egressNetworkPolicyName      | 56506         | 112      | string      |
| egressNetworkPolicyNamespace | 56506         | 113      | string      |

### Supported capabilities

#### Types of Flows and Associated Information

Currently, the Flow Exporter feature provides visibility for Pod-to-Pod, Pod-to-Node,
Node-to-Pod, Node-to-Node and Pod-to-Service network flows along with the associated
statistics such as data throughput (bits per second), packet throughput (packets
per second), cumulative byte count, cumulative packet count etc. Pod-To-Service
flow visibility is supported only [when Antrea Proxy enabled](feature-gates.md). 

Kubernetes information such as Node name, Pod name, Pod Namespace, Service name, 
NetworkPolicy name and NetworkPolicy Namespace, is added to the flow records. For
flow records that are exported from any given Antrea Agent, we only provide the
information of Kubernetes entities that are local to the Antrea Agent. In the future,
we plan to extend this feature to provide information about remote Kubernetes entities
such as remote Node name, remote Pod name etc.

Please note that in the case of inter-Node flows, we are exporting only one copy
of the flow record from the source Node, where the flow originates from, and ignore
the flow record from the destination Node, where the destination Pod resides. Due
to this we miss key information such as destination Pod info, ingress NetworkPolicy
info, stats from the destination Node, etc. In the future, this behavior will be
changed when we add support for correlating the different flow records (from source
and destination Nodes) that belong to the same flow.

#### Connection Metrics

We support following connection metrics as Prometheus metrics that are exposed
through [Antrea Agent apiserver endpoint](prometheus-integration.md):
`antrea_agent_conntrack_total_connection_count`,
`antrea_agent_conntrack_antrea_connection_count` and
`antrea_agent_conntrack_max_connection_count`

## ELK Flow Collector

### Purpose
Antrea supports sending IPFIX flow records through the Flow Exporter feature
described above. The Elastic Stack (ELK Stack) works as the data collector, data 
storage and visualization tool for flow records and flow-related information. This 
document provides the guidelines for deploying Elastic Stack with support for 
Antrea-specific IPFIX fields in a Kubernetes cluster.

### About Elastic Stack
[Elastic Stack](https://www.elastic.co) is a group of open source products to
help collect, store, search, analyze and visualize data in real time. We will
use Logstash, Elasticsearch and Kibana in Antrea flow visualization.
[Logstash](https://www.elastic.co/logstash) works as data collector to
centralize flow records. [Logstash Netflow codec plugin](https://www.elastic.co/guide/en/logstash/current/plugins-codecs-netflow.html)
supports Netflow v5/v9/v10(IPFIX) protocols for flow data collection.
The flow exporter feature in Antrea Agent uses the IPFIX (Netflow v10) protocol 
to export flow records.

[Elasticsearch](https://www.elastic.co/elasticsearch/), as a RESTful search
engine, supports storing, searching and indexing records received. 
[Kibana](https://www.elastic.co/kibana/) is mainly for data visualization and
exploration.

### Deployment Steps
To create all the necessary resources in the `elk-flow-collector` Namespace
and get everything up-and-running, run:

```shell
kubectl create namespace elk-flow-collector
kubectl create configmap logstash-configmap -n elk-flow-collector --from-file=build/yamls/elk-flow-collector/logstash/
kubectl apply -f build/yamls/elk-flow-collector/elk-flow-collector.yml -n elk-flow-collector
```

Kibana dashboard is exposed as a Nodeport Service, which can be accessed via
`http://[NodeIP]: 30007`

`build/yamls/flow/kibana.ndjson` is an auto-generated reusable file containing 
pre-built objects for visualizing Pod-to-Pod, Pod-to-Service and Node-to-Node 
flow records. To import the dashboards into Kibana, go to 
**Management -> Saved Objects** and import `build/yamls/flow/kibana.ndjson`.


### Pre-built Dashboards
The following dashboards are pre-built and are recommended for Antrea flow
visualization.

#### Overview
An overview of Pod-based flow records information is provided.

<img src="https://downloads.antrea.io/static/flow-visualization-overview.png" width="900" alt="Flow
Visualization Overview Dashboard"> 

#### Flows
##### Pod-to-Pod Traffic
Pod-to-Pod Tx and Rx traffic is shown in sankey diagrams. Corresponding 
source or destination Pod throughput is visualized using stacked line graph. 

<img src="https://downloads.antrea.io/static/flow-visualization-flow-1.png" width="900" alt="Flow
Visualization Flows Dashboard"> 

<img src="https://downloads.antrea.io/static/flow-visualization-flow-2.png" width="900" alt="Flow
Visualization Flow Dashboard"> 

##### Pod-to-Service Traffic
Pod-to-Service traffic is presented similar to Pod-to-Pod traffic.
Corresponding source or destination IP addresses are shown in tooltips.

<img src="https://downloads.antrea.io/static/flow-visualization-flow-3.png" width="900" alt="Flow
Visualization Flows Dashboard"> 

<img src="https://downloads.antrea.io/static/flow-visualization-flow-4.png" width="900" alt="Flow
Visualization Flow Dashboard"> 

#### Flow Records 
Flow Records dashboard shows the raw flow records over time with support 
for filters.

<img src="https://downloads.antrea.io/static/flow-visualization-flow-record.png" width="900" alt="Flow
Visualization Flow Record Dashboard">

#### Node Throughput
Node Throughput dashboard shows the visualization of inter-Node and 
intra-Node traffic by aggregating all the Pod traffic per Node.

<img src="https://downloads.antrea.io/static/flow-visualization-node-1.png" width="900" alt="Flow
Visualization Node Throughput Dashboard">

<img src="https://downloads.antrea.io/static/flow-visualization-node-2.png" width="900" alt="Flow
Visualization Node Throughput Dashboard">

#### Network Policy 
Network Policy dashboard provides filters over ingress network policy name and namespace, egress 
network policy name and namespace to view corresponding flow throughput under network policy.
<img src="https://downloads.antrea.io/static/flow-visualization-np-1.png" width="900" alt="Flow
Visualization Network Policy Dashboard">

With filters applied:

<img src="https://downloads.antrea.io/static/flow-visualization-np-2.png" width="900" alt="Flow
Visualization Network Policy Dashboard">
