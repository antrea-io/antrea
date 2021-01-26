# Network Flow Visibility in Antrea

## Table of Contents

<!-- toc -->
- [Overview](#overview)
- [Flow Exporter](#flow-exporter)
  - [Configuration](#configuration)
  - [IPFIX Information Elements (IEs) in a Flow Record](#ipfix-information-elements-ies-in-a-flow-record)
    - [IEs from IANA-assigned IE registry](#ies-from-iana-assigned-ie-registry)
    - [IEs from Reverse IANA-assigned IE Registry](#ies-from-reverse-iana-assigned-ie-registry)
    - [IEs from Antrea IE Registry](#ies-from-antrea-ie-registry)
  - [Supported capabilities](#supported-capabilities)
    - [Types of Flows and Associated Information](#types-of-flows-and-associated-information)
    - [Connection Metrics](#connection-metrics)
- [Flow Aggregator](#flow-aggregator)
  - [Deployment](#deployment)
  - [Configuration](#configuration-1)
  - [IPFIX Information Elements (IEs) in an Aggregated Flow Record](#ipfix-information-elements-ies-in-an-aggregated-flow-record)
    - [IEs from IANA-assigned IE registry](#ies-from-iana-assigned-ie-registry-1)
    - [IEs from Antrea IE Registry](#ies-from-antrea-ie-registry-1)
  - [Supported capabilities](#supported-capabilities-1)
    - [Storage of Flow Records](#storage-of-flow-records)
    - [Correlation of Flow Records](#correlation-of-flow-records)
    - [Aggregation of Flow Records](#aggregation-of-flow-records)
- [Quick deployment](#quick-deployment)
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
module. These flows are converted to flow records, and then flow records are post-processed
before they are sent to the configured external flow collector. High-level design is given below:

![Antrea Flow Visibility Design](assets/flow_visibility.svg)

## Flow Exporter

In Antrea, the basic building block for the Network Flow Visibility is the **Flow
Exporter**. Flow Exporter operates within Antrea Agent; it builds and maintains
a connection store by polling and dumping flows from conntrack module periodically.
Connections from the connection store are exported to the [Flow Aggregator
Service](#flow-aggregator) using the IPFIX protocol, and for this purpose we use
the IPFIX exporter process from the [go-ipfix](https://github.com/vmware/go-ipfix)
library.

### Configuration

To enable the Flow Exporter feature at the Antrea Agent, the following config
parameters have to be set in the Antrea Agent ConfigMap:

```yaml
  antrea-agent.conf: |
    # FeatureGates is a map of feature names to bools that enable or disable experimental features.
    featureGates:
    # Enable flowexporter which exports polled conntrack connections as IPFIX flow records from each agent to a configured collector.
      FlowExporter: true

    # Provide the IPFIX collector address as a string with format <HOST>:[<PORT>][:<PROTO>].
    # HOST can either be the DNS name or the IP of the Flow Collector. For example,
    # "flow-aggregator.flow-aggregator.svc" can be provided as a DNS name to connect
    # to the Antrea Flow Aggregator Service. If IP, it can be either IPv4 or IPv6.
    # However, IPv6 address should be wrapped with [].
    # If PORT is empty, we default to 4739, the standard IPFIX port.
    # If no PROTO is given, we consider "tcp" as default. We support "tcp" and "udp"
    # L4 transport protocols.
    #flowCollectorAddr: "flow-aggregator.flow-aggregator.svc:4739:tcp"
    
    # Provide flow poll interval as a duration string. This determines how often the flow exporter dumps connections from the conntrack module.
    # Flow poll interval should be greater than or equal to 1s (one second).
    # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
    #flowPollInterval: "5s"
    
    # Provide flow export frequency, which is the number of poll cycles elapsed before flow exporter exports flow records to
    # the flow collector.
    # Flow export frequency should be greater than or equal to 1.
    #flowExportFrequency: 12
```

Please note that the default value for `flowCollectorAddr` is `"flow-aggregator.flow-aggregator.svc:4739:tcp"`,
which uses the DNS name of the Flow Aggregator Service, if the Service is deployed
with the Name and Namespace set to `flow-aggregator`. If you deploy the Flow Aggregator
Service with a different Name and Namespace, then either use the appropriate DNS
name or the Cluster IP of the Service. Please note that the default values for
`flowPollInterval` and `flowExportFrequency` parameters are set to 5s and 12, respectively.
Please modify them as per your requirements.

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
| sourceIPv6Address        | 0             | 27       | ipv6Address    |
| destinationIPv6Address   | 0             | 28       | ipv6Address    |
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

Currently, the Flow Exporter feature provides visibility for Pod-to-Pod, Pod-to-Service
and Pod-to-External network flows along with the associated statistics such as data
throughput (bits per second), packet throughput (packets per second), cumulative byte
count and cumulative packet count. Pod-To-Service flow visibility is supported
only [when Antrea Proxy enabled](feature-gates.md), which is the case by default
starting with Antrea v0.11. In the future, we will enable the support for External-To-Service
flows.

Kubernetes information such as Node name, Pod name, Pod Namespace, Service name,
NetworkPolicy name and NetworkPolicy Namespace, is added to the flow records. For
flow records that are exported from any given Antrea Agent, the Flow Exporter only
provides the information of Kubernetes entities that are local to the Antrea Agent.
In other words, flow records are only complete for intra-Node flows, but incomplete
for inter-Node flows. It is the responsibility of the [Flow Aggregator](#flow-aggregator)
to correlate flows from the source and destination Nodes and produce complete flow
records.

Flow Exporter is supported in IPv4 clusters, IPv6 clusters and dual-stack clusters.
Please note that Flow Aggregator is only supported in IPv4 clusters. We plan to
enable the Flow Aggregator support to IPv6 clusters and dual-stack clusters soon.

#### Connection Metrics

We support following connection metrics as Prometheus metrics that are exposed
through [Antrea Agent apiserver endpoint](prometheus-integration.md):
`antrea_agent_conntrack_total_connection_count`,
`antrea_agent_conntrack_antrea_connection_count` and
`antrea_agent_conntrack_max_connection_count`

## Flow Aggregator

Flow Aggregator is deployed as a Kubernetes Service. The main functionality of Flow
Aggregator is to store, correlate and aggregate the flow records received from the
Flow Exporter of Antrea Agents. More details on the functionality are provided in
the [Supported Capabilities](#supported-capabilities-1) section.

Flow Aggregator is implemented as IPFIX mediator, which
consists of IPFIX Collector Process, IPFIX Intermediate Process and IPFIX Exporter
Process. We use the [go-ipfix](https://github.com/vmware/go-ipfix) library to implement
the Flow Aggregator.

### Deployment

To deploy a released version of Flow Aggregator Service, pick a deployment manifest from the
[list of releases](https://github.com/vmware-tanzu/antrea/releases). For any
given release `<TAG>` (e.g. `v0.12.0`), you can deploy Flow Aggregator as follows:

```bash
kubectl apply -f https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/flow-aggregator.yml
```

To deploy the latest version of Flow Aggregator Service (built from the main branch), use the
checked-in [deployment yaml](/build/yamls/flow-aggregator.yml):

```bash
kubectl apply -f https://raw.githubusercontent.com/vmware-tanzu/antrea/main/build/yamls/flow-aggregator.yml
```

### Configuration

The following configuration parameters have to be provided through the Flow Aggregator
ConfigMap. `externalFlowCollectorAddr` is a mandatory parameter. We provide an example
value for this parameter in the following snippet.

```yaml
flow-aggregator.conf: |
  # Provide the flow collector address as a string with format <IP>:<port>[:<proto>], where proto is tcp or udp.
  # If no L4 transport proto is given, we consider tcp as default.
  externalFlowCollectorAddr: "192.168.86.86:4739:tcp"
  
  # Provide flow export interval as a duration string. This determines how often the flow aggregator exports flow
  # records to the flow collector.
  # Flow export interval should be greater than or equal to 1s (one second).
  # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  #flowExportInterval: 60s
  
  # Provide the transport protocol for the flow aggregator collecting process, which is tcp or udp.
  #aggregatorTransportProtocol: "tcp"
```

Please note that the default values for `flowExportInterval` and `aggregatorTransportProtocol`
parameters are set to `60s` and `tcp`, respectively. Please modify them as per your
requirements.

### IPFIX Information Elements (IEs) in an Aggregated Flow Record

In addition to IPFIX information elements provided in the [above section](#ipfix-information-elements-ies-in-a-flow-record),
the Flow Aggregator adds the following fields to the flow records.

#### IEs from IANA-assigned IE registry

| IPFIX Information Element  | Enterprise ID | Field ID | Type        |
|----------------------------|---------------|----------|-------------|
| originalExporterIPv4Address|      0        |   403    | ipv4Address |
| originalObservationDomainId|      0        |   151    | unsigned32  |

#### IEs from Antrea IE Registry

| IPFIX Information Element                 | Enterprise ID | Field ID | Type        |
|-------------------------------------------|---------------|----------|-------------|
| packetTotalCountFromSourceNode            | 56506         | 120      | unsigned64  |
| octetTotalCountFromSourceNode             | 56506         | 121      | unsigned64  |
| packetDeltaCountFromSourceNode            | 56506         | 122      | unsigned64  |
| octetDeltaCountFromSourceNode             | 56506         | 123      | unsigned64  |
| reversePacketTotalCountFromSourceNode     | 56506         | 124      | unsigned64  |
| reverseOctetTotalCountFromSourceNode      | 56506         | 125      | unsigned64  |
| reversePacketDeltaCountFromSourceNode     | 56506         | 126      | unsigned64  |
| reverseOctetDeltaCountFromSourceNode      | 56506         | 127      | unsigned64  |
| packetTotalCountFromDestinationNode       | 56506         | 128      | unsigned64  |
| octetTotalCountFromDestinationNode        | 56506         | 129      | unsigned64  |
| packetDeltaCountFromDestinationNode       | 56506         | 130      | unsigned64  |
| octetDeltaCountFromDestinationNode        | 56506         | 131      | unsigned64  |
| reversePacketTotalCountFromDestinationNode| 56506         | 132      | unsigned64  |
| reverseOctetTotalCountFromDestinationNode | 56506         | 133      | unsigned64  |
| reversePacketDeltaCountFromDestinationNode| 56506         | 134      | unsigned64  |
| reverseOctetDeltaCountFromDestinationNode | 56506         | 135      | unsigned64  |

### Supported capabilities

#### Storage of Flow Records

Flow Aggregator stores the received flow records from Antrea Agents in a hash map,
where the flow key is 5-tuple of a network connection. 5-tuple consists of Source IP,
Destination IP, Source Port, Destination Port and Transport protocol. Therefore,
Flow Aggregator maintains one flow record for any given connection, and this flow
record gets updated till the connection in the Kubernetes cluster becomes invalid.

#### Correlation of Flow Records

In the case of inter-Node flows, there are two flow records, one
from the source Node, where the flow originates from, and another one from the destination
Node, where the destination Pod resides. Both the flow records contain incomplete
information as mentioned [here](#types-of-flows-and-associated-information). Flow
Aggregator provides support for the correlation of the flow records from the
source Node and the destination Node, and it exports a single flow record with complete
information for both inter-Node and intra-Node flows.

#### Aggregation of Flow Records

Flow Aggregator aggregates the flow records that belong to a single connection.
As part of aggregation, fields such as flow timestamps, flow statistics etc. are
updated. For the purpose of updating flow statistics fields, Flow Aggregator introduces
the [new fields](#ies-from-antrea-ie-registry) in Antrea Enterprise IPFIX registry
corresponding to the Source Node and Destination Node, so that flow statistics from
different Nodes can be preserved.

## Quick deployment

If you would like to quickly try Network Flow Visibility feature, you can deploy
Antrea and the Flow Aggregator Service with the required configuration on a
[vagrant setup](../test/e2e/README.md). You can use the following command:

```shell
./infra/vagrant/push_antrea.sh -fc <externalFlowCollectorAddr>
```

For example, the address of ELK Flow Collector can be provided as `externalFlowCollectorAddr`
after successfully following the steps given in [here](#deployment-steps).

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

First step is to fetch the necessary resources from the Antrea repository. You can
either clone the entire repo or download the particular folder using the subversion (svn)
utility. If the deployed version of Antrea has a release `<TAG>` (e.g. `v0.10.0`),
then you can use the following command:

```shell
git clone --depth 1 --branch <TAG> https://github.com/vmware-tanzu/antrea.git && cd antrea/build/yamls/
or
svn export https://github.com/vmware-tanzu/antrea/tags/<TAG>/build/yamls/elk-flow-collector/
```

If the deployed version of Antrea is the latest version, i.e., built from the main
branch, then you can use the following command:

```shell
git clone --depth 1 --branch main https://github.com/vmware-tanzu/antrea.git && cd antrea/build/yamls/
or
svn export https://github.com/vmware-tanzu/antrea/trunk/build/yamls/elk-flow-collector/
```

To create the required K8s resources in the `elk-flow-collector` folder and get
everything up-and-running, run following commands:

```shell
kubectl create namespace elk-flow-collector
kubectl create configmap logstash-configmap -n elk-flow-collector --from-file=./elk-flow-collector/logstash/
kubectl apply -f ./elk-flow-collector/elk-flow-collector.yml -n elk-flow-collector
```

Kibana dashboard is exposed as a Nodeport Service, which can be accessed via
`http://[NodeIP]: 30007`

`elk-flow-collector/kibana.ndjson` is an auto-generated reusable file containing
pre-built objects for visualizing Pod-to-Pod, Pod-to-Service and Node-to-Node
flow records. To import the dashboards into Kibana, go to
**Management -> Saved Objects** and import `elk-flow-collector/kibana.ndjson`.

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
