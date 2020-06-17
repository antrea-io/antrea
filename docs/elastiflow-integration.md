# Elastiflow Integration
## Purpose
Antrea supports sending IPFIX flow records as flow exporter. Elastiflow works as data collector for flow records and visualizes the flow-related information in Kibana. This doc provides guidelines for deploying Elastiflow with Antrea-specific fields in Kubenetes cluster.  

## About Elastiflow
[Elastiflow](https://github.com/robcowart/elastiflow) is a network flow data collection and visualization tool based on [Elastic Stack](https://www.elastic.co/elastic-stack) (Elasticsearch, Logstash and Kibana). It supports Netflow v5/v9, sFlow and IPFIX flow types. We will use the IPFIX flow records with following fields:

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
For the requirements to deploy Elastiflow, please refer to [this](https://github.com/robcowart/elastiflow/blob/master/INSTALL.md#requirements).

## Instruction
To put everyting in elastiflow namespace and get the configuration up and running, run:
```shell script
kubectl create namespace elastiflow
kubectl create configmap logstash-definitions -n elastiflow --from-file=build/yamls/elastiflow/src/definitions/
kubectl apply -n elastiflow -f build/yamls/elastiflow/elastiflow.yml
```
To view the Kibana dashboard from `localhost:5601`, we need to set port forwarding:
```shell script
kubectl -n elastiflow port-forward $(kubectl -n elastiflow get pod -l app=elasticsearch -l type=kibana -o jsonpath="{.items[0].metadata.name}") 5601
```
To import the dashboard into Kibana, go to `Management -> Saved Objects` and import `build/yamls/elastiflow/kibana.ndjson`