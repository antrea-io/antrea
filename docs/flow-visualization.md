# Flow Visualization
## Purpose
Antrea supports sending IPFIX flow records as flow exporter. The Elastic Stack
(ELK Stack) works
as a data collector for flow records and flow-related information can be
visualized
in Kibana. This doc provides guidelines for deploying Elastic Stack with
support for
Antrea-specific fields in a Kubenetes cluster.

## About Elastic Stack
[Elastic Stack](https://www.elastic.co) is a group of open source products from
Elastic to help collect, store, search, analyze and visualize data in real
time. We will use Logstash, Elasticsearch and Kibana in Antrea flow
visualization.
[Logstash](https://www.elastic.co/logstash) works as data collector to
centralize flow records. [Logstash Netflow codec
plugin](https://www.elastic.co/guide/en/logstash/current/plugins-codecs-netflow.html)
supports Netflow v5/v9, sFlow and IPFIX protocols for flow data collection.
Flow exporter feature in Antrea Agent uses IPFIX protocol to export flow
records.

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
To create all the necessary resources in the `antreaflow` namespace and get
everything up-and-running, run:
```shell
kubectl create namespace antreaflow
kubectl create configmap logstash-configmap -n antreaflow
--from-file=build/yamls/flow/logstash/
kubectl apply -f build/yamls/flow/flow-visualization.yml -n antreaflow
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
<img src="/docs/assets/flow-visualization-overview.png" width="600" alt="Flow
Visualization Overview Dashboard"> 

### Flows
<img src="/docs/assets/flow-visualization-flows.png" width="600" alt="Flow
Visualization Flows Dashboard"> 

### Flow Records 
<img src="/docs/assets/flow-visualization-records.png" width="600" alt="Flow
Visualization Flow Records Dashboard">