# Elastiflow Integration
## Purpose
Antrea supports sending IPFIX flow records as flow exporter. Elastiflow works
as a data collector for flow records and flow-related information can be visualized
in Kibana. This doc provides guidelines for deploying Elastiflow with support for
Antrea-specific fields in a Kubenetes cluster.

## About Elastiflow
[Elastiflow](https://github.com/robcowart/elastiflow) is a network flow data
collection and visualization tool based on [Elastic
Stack](https://www.elastic.co/elastic-stack) (Elasticsearch, Logstash and
Kibana). It supports Netflow v5/v9, sFlow and IPFIX flow types. We will use the
IPFIX flow records with following fields:

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

For the requirements to deploy Elastiflow, please refer to
[this](https://github.com/robcowart/elastiflow/blob/master/INSTALL.md#requirements).

## Instruction
To create all the necessary resources in the `elastiflow` namespace and get everything up-and-running, run:
```shell
kubectl create namespace elastiflow
kubectl create configmap logstash-configmap -n elastiflow --from-file=build/yamls/elastiflow/logstash/
kubectl apply -n elastiflow -f build/yamls/elastiflow/elastiflow.yml
```
Kibana dashboard is exposed as a Nodeport, which can be accessed via `http://[NodeIP]: 30007`
```
To import the dashboard into Kibana, go to **Management -> Saved Objects** and
import `build/yamls/elastiflow/kibana.ndjson`
