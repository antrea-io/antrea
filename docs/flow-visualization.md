# Flow Visualization
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
Flow exporter feature in Antrea Agent uses IPFIX (Netflow v10) protocol to
export flow records.

IPFIX flow records contain following Antrea specific fields along with standard
IANA fields.

| IPFIX Information Element | Enterprise ID | Field ID | Type        |
|---------------------------|---------------|----------|-------------|
| sourcePodNamespace        | 55829         | 100      | string      |
| sourcePodName             | 55829         | 101      | string      |
| destinationPodNamespace   | 55829         | 102      | string      |
| destinationPodName        | 55829         | 103      | string      |
| sourceNodeName            | 55829         | 104      | string      |
| destinationNodeName       | 55829         | 105      | string      |
| destinationClusterIP      | 55829         | 106      | ipv4Address |
| destinationServicePort    | 55829         | 107      | unsigned16  |

[Elasticsearch](https://www.elastic.co/elasticsearch/), as a RESTful search
engine, supports storing, searching and indexing records received. 
[Kibana](https://www.elastic.co/kibana/) is mainly for data visualization and
exploration.

## Deployment Steps
To create all the necessary resources in the `antrea-flow-collector` namespace
and get
everything up-and-running, run:
```shell
kubectl create namespace antrea-flow-collector
kubectl create configmap logstash-configmap -n antrea-flow-collector --from-file=build/yamls/flow-collector/logstash/
kubectl apply -f build/yamls/flow-collector/flow-collector.yml -n antrea-flow-collector
```
Kibana dashboard is exposed as a Nodeport, which can be accessed via
`http://[NodeIP]: 30007`

To import the pre-built and recommended dashboard into Kibana, go to
**Management -> Saved Objects** and
import `build/yamls/flow/kibana.ndjson`


## Pre-built Dashboards
The following dashboards are pre-built and recommended for Antrea flow
visualization.

### Overview
<img src="/docs/assets/flow-visualization-overview.png" width="900" alt="Flow
Visualization Overview Dashboard"> 

### Flows
#### Pod-to-pod Traffic
<img src="/docs/assets/flow-visualization-flow-1.png" width="900" alt="Flow
Visualization Flows Dashboard"> 
<img src="/docs/assets/flow-visualization-flow-2.png" width="900" alt="Flow
Visualization Flow Dashboard"> 

#### Pod-to-service Traffic
<img src="/docs/assets/flow-visualization-flow-3.png" width="900" alt="Flow
Visualization Flows Dashboard"> 
<img src="/docs/assets/flow-visualization-flow-4.png" width="900" alt="Flow
Visualization Flow Dashboard"> 

### Flow Records 
<img src="/docs/assets/flow-visualization-flow-record.png" width="900" alt="Flow
Visualization Flow Record Dashboard">

### Node Throughput
<img src="/docs/assets/flow-visualization-node-1.png" width="900" alt="Flow
Visualization Node Throughput Dashboard">
<img src="/docs/assets/flow-visualization-node-2.png" width="900" alt="Flow
Visualization Node Throughput Dashboard">