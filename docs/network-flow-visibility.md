# ELK Flow Collector
## Purpose
Antrea supports sending IPFIX flow records through a flow exporter. The Elastic
Stack (ELK Stack) works as the data collector, data storage and visualization tool
for flow records and flow-related information. This doc provides guidelines for
deploying Elastic Stack with support for Antrea-specific fields in a Kubenetes
cluster.

## About Elastic Stack
[Elastic Stack](https://www.elastic.co) is a group of open source products to
help collect, store, search, analyze and visualize data in real time. We will
use Logstash, Elasticsearch and Kibana in Antrea flow visualization.
[Logstash](https://www.elastic.co/logstash) works as data collector to
centralize flow records. [Logstash Netflow codec plugin](https://www.elastic.co/guide/en/logstash/current/plugins-codecs-netflow.html)
supports Netflow v5/v9/v10(IPFIX) protocols for flow data collection.
The flow exporter feature in Antrea Agent uses the IPFIX (Netflow v10) protocol 
to export flow records.

Exported IPFIX flow records contain the following Antrea-specific fields along 
with standard IANA fields.

| IPFIX Information Element | Enterprise ID | Field ID | Type        |
|---------------------------|---------------|----------|-------------|
| sourcePodNamespace        | 55829         | 100      | string      |
| sourcePodName             | 55829         | 101      | string      |
| destinationPodNamespace   | 55829         | 102      | string      |
| destinationPodName        | 55829         | 103      | string      |
| sourceNodeName            | 55829         | 104      | string      |
| destinationNodeName       | 55829         | 105      | string      |
| destinationClusterIP      | 55829         | 106      | ipv4Address |
| destinationServicePortName| 55829         | 108      | string      |

[Elasticsearch](https://www.elastic.co/elasticsearch/), as a RESTful search
engine, supports storing, searching and indexing records received. 
[Kibana](https://www.elastic.co/kibana/) is mainly for data visualization and
exploration.

## Deployment Steps
To create all the necessary resources in the `elk-flow-collector` namespace
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


## Pre-built Dashboards
The following dashboards are pre-built and are recommended for Antrea flow
visualization.

### Overview
An overview of Pod-based flow records information is provided.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-overview.png" width="900" alt="Flow
Visualization Overview Dashboard"> 

### Flows
#### Pod-to-Pod Traffic
Pod-to-Pod Tx and Rx traffic is shown in sankey diagrams. Corresponding 
source or destination Pod throughput is visualized using stacked line graph. 

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-flow-1.png" width="900" alt="Flow
Visualization Flows Dashboard"> 

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-flow-2.png" width="900" alt="Flow
Visualization Flow Dashboard"> 

#### Pod-to-Service Traffic
Pod-to-Service traffic is presented similar to Pod-to-Pod traffic.
Corresponding source or destination IP addresses are shown in tooltips.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-flow-3.png" width="900" alt="Flow
Visualization Flows Dashboard"> 

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-flow-4.png" width="900" alt="Flow
Visualization Flow Dashboard"> 

### Flow Records 
Flow Records dashboard shows the raw flow records over time with support 
for filters.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-flow-record.png" width="900" alt="Flow
Visualization Flow Record Dashboard">

### Node Throughput
Node Throughput dashboard shows the visualization of inter-node and 
intra-node traffic by aggregating all the pod traffic per node.

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-node-1.png" width="900" alt="Flow
Visualization Node Throughput Dashboard">

<img src="https://s3-us-west-2.amazonaws.com/downloads.antrea.io/static/flow-visualization-node-2.png" width="900" alt="Flow
Visualization Node Throughput Dashboard">