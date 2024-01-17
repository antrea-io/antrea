# Network Flow Visibility in Antrea

## Table of Contents

<!-- toc -->
- [Overview](#overview)
- [Flow Exporter](#flow-exporter)
  - [Configuration](#configuration)
    - [Configuration pre Antrea v1.13](#configuration-pre-antrea-v113)
  - [IPFIX Information Elements (IEs) in a Flow Record](#ipfix-information-elements-ies-in-a-flow-record)
    - [IEs from IANA-assigned IE Registry](#ies-from-iana-assigned-ie-registry)
    - [IEs from Reverse IANA-assigned IE Registry](#ies-from-reverse-iana-assigned-ie-registry)
    - [IEs from Antrea IE Registry](#ies-from-antrea-ie-registry)
  - [Supported Capabilities](#supported-capabilities)
    - [Types of Flows and Associated Information](#types-of-flows-and-associated-information)
    - [Connection Metrics](#connection-metrics)
- [Flow Aggregator](#flow-aggregator)
  - [Deployment](#deployment)
  - [Configuration](#configuration-1)
    - [Configuring secure connections to the ClickHouse database](#configuring-secure-connections-to-the-clickhouse-database)
    - [Example of flow-aggregator.conf](#example-of-flow-aggregatorconf)
  - [IPFIX Information Elements (IEs) in an Aggregated Flow Record](#ipfix-information-elements-ies-in-an-aggregated-flow-record)
    - [IEs from Antrea IE Registry](#ies-from-antrea-ie-registry-1)
  - [Supported Capabilities](#supported-capabilities-1)
    - [Storage of Flow Records](#storage-of-flow-records)
    - [Correlation of Flow Records](#correlation-of-flow-records)
    - [Aggregation of Flow Records](#aggregation-of-flow-records)
  - [Antctl Support](#antctl-support)
- [Quick Deployment](#quick-deployment)
  - [Image-building Steps](#image-building-steps)
  - [Deployment Steps](#deployment-steps)
- [Flow Collectors](#flow-collectors)
  - [Go-ipfix Collector](#go-ipfix-collector)
    - [Deployment Steps](#deployment-steps-1)
    - [Output Flow Records](#output-flow-records)
  - [Grafana Flow Collector (migrated)](#grafana-flow-collector-migrated)
  - [ELK Flow Collector (removed)](#elk-flow-collector-removed)
- [Layer 7 Network Flow Exporter](#layer-7-network-flow-exporter)
  - [Prerequisites](#prerequisites)
  - [Usage](#usage)
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

In addition to enabling the Flow Exporter feature gate (if needed), you need to
ensure that the `flowExporter.enable` flag is set to true in the Antrea Agent
configuration.

your `antrea-agent` ConfigMap should look like this:

```yaml
  antrea-agent.conf: |
    # FeatureGates is a map of feature names to bools that enable or disable experimental features.
    featureGates:
    # Enable flowexporter which exports polled conntrack connections as IPFIX flow records from each agent to a configured collector.
      FlowExporter: true

    flowExporter:
      # Enable FlowExporter, a feature used to export polled conntrack connections as
      # IPFIX flow records from each agent to a configured collector. To enable this
      # feature, you need to set "enable" to true, and ensure that the FlowExporter
      # feature gate is also enabled.
      enable: true
      # Provide the IPFIX collector address as a string with format <HOST>:[<PORT>][:<PROTO>].
      # HOST can either be the DNS name, IP, or Service name of the Flow Collector. If
      # using an IP, it can be either IPv4 or IPv6. However, IPv6 address should be
      # wrapped with []. When the collector is running in-cluster as a Service, set
      # <HOST> to <Service namespace>/<Service name>. For example,
      # "flow-aggregator/flow-aggregator" can be provided to connect to the Antrea
      # Flow Aggregator Service.
      # If PORT is empty, we default to 4739, the standard IPFIX port.
      # If no PROTO is given, we consider "tls" as default. We support "tls", "tcp" and
      # "udp" protocols. "tls" is used for securing communication between flow exporter and
      # flow aggregator.
      flowCollectorAddr: "flow-aggregator/flow-aggregator:4739:tls"

      # Provide flow poll interval as a duration string. This determines how often the
      # flow exporter dumps connections from the conntrack module. Flow poll interval
      # should be greater than or equal to 1s (one second).
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      flowPollInterval: "5s"

      # Provide the active flow export timeout, which is the timeout after which a flow
      # record is sent to the collector for active flows. Thus, for flows with a continuous
      # stream of packets, a flow record will be exported to the collector once the elapsed
      # time since the last export event is equal to the value of this timeout.
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      activeFlowExportTimeout: "5s"

      # Provide the idle flow export timeout, which is the timeout after which a flow
      # record is sent to the collector for idle flows. A flow is considered idle if no
      # packet matching this flow has been observed since the last export event.
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      idleFlowExportTimeout: "15s"
```

Please note that the default value for `flowExporter.flowCollectorAddr` is
`"flow-aggregator/flow-aggregator:4739:tls"`, which enables the Flow Exporter to connect
the Flow Aggregator Service, assuming it is running in the same K8 cluster with the Name
and Namespace set to `flow-aggregator`. If you deploy the Flow Aggregator Service with
a different Name and Namespace, then set `flowExporter.flowCollectorAddr` appropriately.

Please note that the default values for
`flowExporter.flowPollInterval`, `flowExporter.activeFlowExportTimeout`, and
`flowExporter.idleFlowExportTimeout` parameters are set to 5s, 5s, and 15s, respectively.
TLS communication between the Flow Exporter and the Flow Aggregator is enabled by default.
Please modify them as per your requirements.

#### Configuration pre Antrea v1.13

Prior to the Antrea v1.13 release, the `flowExporter` option group in the
Antrea Agent configuration did not exist. To enable the Flow Exporter feature,
one simply needed to enable the feature gate, and the Flow Exporter related
configuration could be configured using the (now deprecated) `flowCollectorAddr`,
`flowPollInterval`, `activeFlowExportTimeout`, `idleFlowExportTimeout`
parameters.

### IPFIX Information Elements (IEs) in a Flow Record

There are 34 IPFIX IEs in each exported flow record, which are defined in the
IANA-assigned IE registry, the Reverse IANA-assigned IE registry and the Antrea
IE registry. The reverse IEs are used to provide bi-directional information about
the flow. The Enterprise ID is 0 for IANA-assigned IE registry, 29305 for reverse
IANA IE registry, 56505 for Antrea IE registry. All the IEs used by the Antrea
Flow Exporter are listed below:

#### IEs from IANA-assigned IE Registry

| IPFIX Information Element| Field ID | Type           |
|--------------------------|----------|----------------|
| flowStartSeconds         | 150      | dateTimeSeconds|
| flowEndSeconds           | 151      | dateTimeSeconds|
| flowEndReason            | 136      | unsigned8      |
| sourceIPv4Address        | 8        | ipv4Address    |
| destinationIPv4Address   | 12       | ipv4Address    |
| sourceIPv6Address        | 27       | ipv6Address    |
| destinationIPv6Address   | 28       | ipv6Address    |
| sourceTransportPort      | 7        | unsigned16     |
| destinationTransportPort | 11       | unsigned16     |
| protocolIdentifier       | 4        | unsigned8      |
| packetTotalCount         | 86       | unsigned64     |
| octetTotalCount          | 85       | unsigned64     |
| packetDeltaCount         | 2        | unsigned64     |
| octetDeltaCount          | 1        | unsigned64     |

#### IEs from Reverse IANA-assigned IE Registry

| IPFIX Information Element| Field ID | Type           |
|--------------------------|----------|----------------|
| reversePacketTotalCount  | 86       | unsigned64     |
| reverseOctetTotalCount   | 85       | unsigned64     |
| reversePacketDeltaCount  | 2        | unsigned64     |
| reverseOctetDeltaCount   | 1        | unsigned64     |

#### IEs from Antrea IE Registry

| IPFIX Information Element        | Field ID | Type        | Description |
|----------------------------------|----------|-------------|-------------|
| sourcePodNamespace               | 100      | string      |             |
| sourcePodName                    | 101      | string      |             |
| destinationPodNamespace          | 102      | string      |             |
| destinationPodName               | 103      | string      |             |
| sourceNodeName                   | 104      | string      |             |
| destinationNodeName              | 105      | string      |             |
| destinationClusterIPv4           | 106      | ipv4Address |             |
| destinationClusterIPv6           | 107      | ipv6Address |             |
| destinationServicePort           | 108      | unsigned16  |             |
| destinationServicePortName       | 109      | string      |             |
| ingressNetworkPolicyName         | 110      | string      | Name of the ingress network policy applied to the destination Pod for this flow. |
| ingressNetworkPolicyNamespace    | 111      | string      | Namespace of the ingress network policy applied to the destination Pod for this flow. |
| ingressNetworkPolicyType         | 115      | unsigned8   | 1 stands for Kubernetes Network Policy. 2 stands for Antrea Network Policy. 3 stands for Antrea Cluster Network Policy. |
| ingressNetworkPolicyRuleName     | 141      | string      | Name of the ingress network policy Rule applied to the destination Pod for this flow. |
| egressNetworkPolicyName          | 112      | string      | Name of the egress network policy applied to the source Pod for this flow. |
| egressNetworkPolicyNamespace     | 113      | string      | Namespace of the egress network policy applied to the source Pod for this flow. |
| egressNetworkPolicyType          | 118      | unsigned8   |             |
| egressNetworkPolicyRuleName      | 142      | string      | Name of the egress network policy rule applied to the source Pod for this flow. |
| ingressNetworkPolicyRuleAction   | 139      | unsigned8   | 1 stands for Allow. 2 stands for Drop. 3 stands for Reject. |
| egressNetworkPolicyRuleAction    | 140      | unsigned8   |             |
| tcpState                         | 136      | string      | The state of the TCP connection. The states are: LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT, and CLOSED. |
| flowType                         | 137      | unsigned8   | 1 stands for Intra-Node. 2 stands for Inter-Node. 3 stands for To External. 4 stands for From External. |

### Supported Capabilities

#### Types of Flows and Associated Information

Currently, the Flow Exporter feature provides visibility for Pod-to-Pod, Pod-to-Service
and Pod-to-External network flows along with the associated statistics such as data
throughput (bits per second), packet throughput (packets per second), cumulative byte
count and cumulative packet count. Pod-To-Service flow visibility is supported
only [when Antrea Proxy enabled](feature-gates.md), which is the case by default
starting with Antrea v0.11. In the future, we will enable the support for External-To-Service
flows.

Kubernetes information such as Node name, Pod name, Pod Namespace, Service name,
NetworkPolicy name and NetworkPolicy Namespace, is added to the flow records.
Network Policy Rule Action (Allow, Reject, Drop) is also supported for both
Antrea-native NetworkPolicies and K8s NetworkPolicies. For K8s NetworkPolicies,
connections dropped due to [isolated Pod behavior](https://kubernetes.io/docs/concepts/services-networking/network-policies/#isolated-and-non-isolated-pods)
will be assigned the Drop action.
For flow records that are exported from any given Antrea Agent, the Flow Exporter
only provides the information of Kubernetes entities that are local to the Antrea
Agent. In other words, flow records are only complete for intra-Node flows, but
incomplete for inter-Node flows. It is the responsibility of the [Flow Aggregator](#flow-aggregator)
to correlate flows from the source and destination Nodes and produce complete flow
records.

Both Flow Exporter and Flow Aggregator are supported in IPv4 clusters, IPv6 clusters and dual-stack clusters.

#### Connection Metrics

We support following connection metrics as Prometheus metrics that are exposed
through [Antrea Agent apiserver endpoint](prometheus-integration.md):
`antrea_agent_conntrack_total_connection_count`,
`antrea_agent_conntrack_antrea_connection_count`,
`antrea_agent_denied_connection_count`,
`antrea_agent_conntrack_max_connection_count`, and
`antrea_agent_flow_collector_reconnection_count`

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
[list of releases](https://github.com/antrea-io/antrea/releases). For any
given release `<TAG>` (e.g. `v0.12.0`), you can deploy Flow Aggregator as follows:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/flow-aggregator.yml
```

To deploy the latest version of Flow Aggregator Service (built from the main branch), use the
checked-in [deployment yaml](../build/yamls/flow-aggregator.yml):

```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/flow-aggregator.yml
```

### Configuration

The following configuration parameters have to be provided through the Flow
Aggregator ConfigMap. Flow aggregator needs to be configured with at least one
of the supported [Flow Collectors](#flow-collectors).
`flowCollector` is mandatory for [go-ipfix collector](#deployment-steps), and
`clickHouse` is mandatory for [Grafana Flow Collector](#grafana-flow-collector-migrated).
We provide an example value for this parameter in the following snippet.  

* If you have deployed the [go-ipfix collector](#deployment-steps),
then please set `flowCollector.enable` to `true` and use the address for
`flowCollector.address`: `<Ipfix-Collector Cluster IP>:<port>:<tcp|udp>`
* If you have deployed the [Grafana Flow Collector](#grafana-flow-collector-migrated),
then please enable the collector by setting `clickHouse.enable` to `true`. If
it is deployed following the [deployment steps](#deployment-steps-1), the
ClickHouse server is already exposed via a K8s Service, and no further
configuration is required. If a different FQDN or IP is desired, please use
the URL for `clickHouse.databaseURL` in the following format:
`<protocol>://<ClickHouse server FQDN or IP>:<ClickHouse port>`.

#### Configuring secure connections to the ClickHouse database

Starting with Antrea v1.13, you can enable TLS when connecting to the ClickHouse
Server by setting `clickHouse.databaseURL` with protocol `tls` or `https`.
You can also change the value of `clickHouse.tls.insecureSkipVerify` to
determine whether to skip the verification of the server's certificate.
If you want to provide a custom CA certificate, you can set
`clickHouse.tls.caCert` to `true` and the flow Aggregator will read the
certificate key pair from the`clickhouse-ca` Secret.

Make sure to follow the following form when creating the `clickhouse-ca` Secret
with the custom CA certificate:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: clickhouse-ca
  namespace: flow-aggregator
data:
  ca.crt: <BASE64 ENCODED CA CERTIFICATE>
```

You can use `kubectl apply -f <PATH TO SECRET YAML>` to create the above secret
, or use `kubectl create secret`:

```bash
kubectl create secret generic clickhouse-ca -n flow-aggregator --from-file=ca.crt=<PATH TO CA CERTIFICATE>
```

Prior to Antrea v1.13, secure connections to ClickHouse are not supported,
and TCP is the only supported protocol when connecting to the ClickHouse
server from the Flow Aggregator.

#### Example of flow-aggregator.conf

```yaml
flow-aggregator.conf: |  
  # Provide the active flow record timeout as a duration string. This determines
  # how often the flow aggregator exports the active flow records to the flow
  # collector. Thus, for flows with a continuous stream of packets, a flow record
  # will be exported to the collector once the elapsed time since the last export
  # event in the flow aggregator is equal to the value of this timeout.
  # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  activeFlowRecordTimeout: 60s

  # Provide the inactive flow record timeout as a duration string. This determines
  # how often the flow aggregator exports the inactive flow records to the flow
  # collector. A flow record is considered to be inactive if no matching record
  # has been received by the flow aggregator in the specified interval.
  # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  inactiveFlowRecordTimeout: 90s

  # Provide the transport protocol for the flow aggregator collecting process, which is tls, tcp or udp.
  aggregatorTransportProtocol: "tls"

  # Provide an extra DNS name or IP address of flow aggregator for generating TLS certificate.
  flowAggregatorAddress: ""

  # recordContents enables configuring some fields in the flow records. Fields can
  # be excluded to reduce record size, but some features or external tooling may
  # depend on these fields.
  recordContents:
    # Determine whether source and destination Pod labels will be included in the flow records.
    podLabels: false

  # apiServer contains APIServer related configuration options.
  apiServer:
    # The port for the flow-aggregator APIServer to serve on.
    apiPort: 10348

    # Comma-separated list of Cipher Suites. If omitted, the default Go Cipher Suites will be used.
    # https://golang.org/pkg/crypto/tls/#pkg-constants
    # Note that TLS1.3 Cipher Suites cannot be added to the list. But the apiserver will always
    # prefer TLS1.3 Cipher Suites whenever possible.
    tlsCipherSuites: ""

    # TLS min version from: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13.
    tlsMinVersion: ""

  # flowCollector contains external IPFIX or JSON collector related configuration options.
  flowCollector:
    # Enable is the switch to enable exporting flow records to external flow collector.
    enable: false

    # Provide the flow collector address as string with format <IP>:<port>[:<proto>], where proto is tcp or udp.
    # If no L4 transport proto is given, we consider tcp as default.
    address: ""

    # Provide the 32-bit Observation Domain ID which will uniquely identify this instance of the flow
    # aggregator to an external flow collector. If omitted, an Observation Domain ID will be generated
    # from the persistent cluster UUID generated by Antrea. Failing that (e.g. because the cluster UUID
    # is not available), a value will be randomly generated, which may vary across restarts of the flow
    # aggregator.
    #observationDomainID:

    # Provide format for records sent to the configured flow collector.
    # Supported formats are IPFIX and JSON.
    recordFormat: "IPFIX"

  # clickHouse contains ClickHouse related configuration options.
  clickHouse:
    # Enable is the switch to enable exporting flow records to ClickHouse.
    enable: false

    # Database is the name of database where Antrea "flows" table is created.
    database: "default"

    # DatabaseURL is the url to the database. Provide the database URL as a string with format
    # <Protocol>://<ClickHouse server FQDN or IP>:<ClickHouse port>. The protocol has to be
    # one of the following: "tcp", "tls", "http", "https". When "tls" or "https" is used, tls
    # will be enabled.
    databaseURL: "tcp://clickhouse-clickhouse.flow-visibility.svc:9000"

    # TLS configuration options, when using TLS to connect to the ClickHouse service.
    tls:
      # InsecureSkipVerify determines whether to skip the verification of the server's certificate chain and host name.
      # Default is false.
      insecureSkipVerify: false

      # CACert indicates whether to use custom CA certificate. Default root CAs will be used if this field is false.
      # If true, a Secret named "clickhouse-ca" must be provided with the following keys:
      # ca.crt: <CA certificate>
      caCert: false

    # Debug enables debug logs from ClickHouse sql driver.
    debug: false

    # Compress enables lz4 compression when committing flow records.
    compress: true

    # CommitInterval is the periodical interval between batch commit of flow records to DB.
    # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
    # The minimum interval is 1s based on ClickHouse documentation for best performance.
    commitInterval: "8s"
```

Please note that the default values for `activeFlowRecordTimeout`,
`inactiveFlowRecordTimeout`, `aggregatorTransportProtocol` parameters are set to
`60s`, `90s` and `tls` respectively. Please make sure that
`aggregatorTransportProtocol` and protocol of `flowCollectorAddr` in
`agent-agent.conf` are set to `tls` to guarantee secure communication works
properly. Protocol of `flowCollectorAddr` and `aggregatorTransportProtocol` must
always match, so TLS must either be enabled for both sides or disabled for both
sides. Please modify the parameters as per your requirements.

Please note that the default value for `recordContents.podLabels` is `false`,
which indicates source and destination Pod labels will not be included in the
flow records exported to `flowCollector` and `clickHouse`. If you would like
to include them, you can modify the value to `true`.

Please note that the default value for `apiServer.apiPort` is `10348`, which
is the port used to expose the Flow Aggregator's APIServer. Please modify the
parameters as per your requirements.

Please note that the default value for `clickHouse.commitInterval` is `8s`,
which is based on experiment results to achieve best ClickHouse write
performance and data retention. Based on ClickHouse recommendation for best
performance, this interval is required be no shorter than `1s`. Also note
that flow aggregator has a cache limit of ~500k records for ClickHouse-Grafana
collector. If `clickHouse.commitInterval` is set to a value too large, there's
a risk of losing records.

### IPFIX Information Elements (IEs) in an Aggregated Flow Record

In addition to IPFIX information elements provided in the [above section](#ipfix-information-elements-ies-in-a-flow-record),
the Flow Aggregator adds the following fields to the flow records.

#### IEs from Antrea IE Registry

| IPFIX Information Element                 | Field ID | Type        | Description |
|-------------------------------------------|----------|-------------|-------------|
| packetTotalCountFromSourceNode            | 120      | unsigned64  | The cumulative number of packets for this flow as reported by the source Node, since the flow started. |
| octetTotalCountFromSourceNode             | 121      | unsigned64  | The cumulative number of octets for this flow as reported by the source Node, since the flow started. |
| packetDeltaCountFromSourceNode            | 122      | unsigned64  | The number of packets for this flow as reported by the source Node, since the previous report for this flow at the observation point. |
| octetDeltaCountFromSourceNode             | 123      | unsigned64  | The number of octets for this flow as reported by the source Node, since the previous report for this flow at the observation point. |
| reversePacketTotalCountFromSourceNode     | 124      | unsigned64  | The cumulative number of reverse packets for this flow as reported by the source Node, since the flow started. |
| reverseOctetTotalCountFromSourceNode      | 125      | unsigned64  | The cumulative number of reverse octets for this flow as reported by the source Node, since the flow started. |
| reversePacketDeltaCountFromSourceNode     | 126      | unsigned64  | The number of reverse packets for this flow as reported by the source Node, since the previous report for this flow at the observation point. |
| reverseOctetDeltaCountFromSourceNode      | 127      | unsigned64  | The number of reverse octets for this flow as reported by the source Node, since the previous report for this flow at the observation point. |
| packetTotalCountFromDestinationNode       | 128      | unsigned64  | The cumulative number of packets for this flow as reported by the destination Node, since the flow started. |
| octetTotalCountFromDestinationNode        | 129      | unsigned64  | The cumulative number of octets for this flow as reported by the destination Node, since the flow started. |
| packetDeltaCountFromDestinationNode       | 130      | unsigned64  | The number of packets for this flow as reported by the destination Node, since the previous report for this flow at the observation point. |
| octetDeltaCountFromDestinationNode        | 131      | unsigned64  | The number of octets for this flow as reported by the destination Node, since the previous report for this flow at the observation point. |
| reversePacketTotalCountFromDestinationNode| 132      | unsigned64  | The cumulative number of reverse packets for this flow as reported by the destination Node, since the flow started. |
| reverseOctetTotalCountFromDestinationNode | 133      | unsigned64  | The cumulative number of reverse octets for this flow as reported by the destination Node, since the flow started. |
| reversePacketDeltaCountFromDestinationNode| 134      | unsigned64  | The number of reverse packets for this flow as reported by the destination Node, since the previous report for this flow at the observation point. |
| reverseOctetDeltaCountFromDestinationNode | 135      | unsigned64  | The number of reverse octets for this flow as reported by the destination Node, since the previous report for this flow at the observation point. |
| sourcePodLabels                           | 143      | string      |             |
| destinationPodLabels                      | 144      | string      |             |
| throughput                                | 145      | unsigned64  | The average amount of traffic flowing from source to destination, since the previous report for this flow at the observation point. The unit is bits per second. |
| reverseThroughput                         | 146      | unsigned64  | The average amount of reverse traffic flowing from destination to source, since the previous report for this flow at the observation point. The unit is bits per second. |
| throughputFromSourceNode                  | 147      | unsigned64  | The average amount of traffic flowing from source to destination, since the previous report for this flow at the observation point, based on the records sent from the source Node. The unit is bits per second. |
| throughputFromDestinationNode             | 148      | unsigned64  | The average amount of traffic flowing from source to destination, since the previous report for this flow at the observation point, based on the records sent from the destination Node. The unit is bits per second. |
| reverseThroughputFromSourceNode           | 149      | unsigned64  | The average amount of reverse traffic flowing from destination to source, since the previous report for this flow at the observation point, based on the records sent from the source Node. The unit is bits per second. |
| reverseThroughputFromDestinationNode      | 150      | unsigned64  | The average amount of reverse traffic flowing from destination to source, since the previous report for this flow at the observation point, based on the records sent from the destination Node. The unit is bits per second. |
| flowEndSecondsFromSourceNode              | 151      | unsigned32  | The absolute timestamp of the last packet of this flow, based on the records sent from the source Node. The unit is seconds. |
| flowEndSecondsFromDestinationNode         | 152      | unsigned32  | The absolute timestamp of the last packet of this flow, based on the records sent from the destination Node. The unit is seconds. |

### Supported Capabilities

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

### Antctl Support

antctl can access the Flow Aggregator API to dump flow records and print metrics
about flow record processing. Refer to the
[antctl documentation](antctl.md#flow-aggregator-commands) for more information.

## Quick Deployment

If you would like to quickly try Network Flow Visibility feature, you can deploy
Antrea, the Flow Aggregator Service, the Grafana Flow Collector on the
[Vagrant setup](../test/e2e/README.md).

### Image-building Steps

Build required image under antrea by using make command:

```shell
make
make flow-aggregator-image
```

### Deployment Steps

Given any external IPFIX flow collector, you can deploy Antrea and the Flow
Aggregator Service on a default Vagrant setup by running the following commands:

```shell
./infra/vagrant/provision.sh
./infra/vagrant/push_antrea.sh --flow-collector <externalFlowCollectorAddress>
```

If you would like to deploy the Grafana Flow Collector, you can run the following command:

```shell
./infra/vagrant/provision.sh
./infra/vagrant/push_antrea.sh --flow-collector Grafana
```

## Flow Collectors

Here we list two choices the external configured flow collector: go-ipfix collector
and Grafana flow collector. For each collector, we introduce how to deploy it and
how to output or visualize the collected flow records information.

### Go-ipfix Collector

#### Deployment Steps

The go-ipfix collector can be built from [go-ipfix library](https://github.com/vmware/go-ipfix).
It is used to collect, decode and log the IPFIX records.

* To deploy a released version of the go-ipfix collector, please choose one
deployment manifest from the list of releases (supported after v0.5.2).
For any given release <TAG> (e.g. v0.5.2), you can deploy the collector as follows:

```shell
kubectl apply -f https://github.com/vmware/go-ipfix/releases/download/<TAG>/ipfix-collector.yaml
```

* To deploy the latest version of the go-ipfix collector (built from the main branch),
use the checked-in [deployment manifest](https://github.com/vmware/go-ipfix/blob/main/build/yamls/ipfix-collector.yaml):

```shell
kubectl apply -f https://raw.githubusercontent.com/vmware/go-ipfix/main/build/yamls/ipfix-collector.yaml
```

Go-ipfix collector also supports customization on its parameters: port and protocol.
Please follow the [go-ipfix documentation](https://github.com/vmware/go-ipfix#readme)
to configure those parameters if needed.

#### Output Flow Records

To output the flow records collected by the go-ipfix collector, use the command below:

```shell
kubectl logs <ipfix-collector-pod-name> -n ipfix
```

### Grafana Flow Collector (migrated)

**Starting with Antrea v1.8, support for the Grafana Flow Collector has been migrated to Theia.**

The Grafana Flow Collector was added in Antrea v1.6.0. In Antrea v1.7.0, we
start to move the network observability and analytics functionalities of Antrea
to [Project Theia](https://github.com/antrea-io/theia), including the Grafana
Flow Collector. Going forward, further development of the Grafana Flow Collector
will be in the Theia repo. For the up-to-date version of Grafana Flow Collector
and other Theia features, please refer to the
[Theia document](https://github.com/antrea-io/theia/blob/main/docs/network-flow-visibility.md).

### ELK Flow Collector (removed)

**Starting with Antrea v1.7, support for the ELK Flow Collector has been removed.**
Please consider using the [Grafana Flow Collector](#grafana-flow-collector-migrated)
instead, which is actively maintained.

## Layer 7 Network Flow Exporter

In addition to layer 4 network visibility, Antrea adds layer 7 network flow
export.

### Prerequisites

To achieve L7 (Layer 7) network flow export, the `L7FlowExporter` feature gate
must be enabled.

### Usage

To export layer 7 flows of a Pod or a Namespace, user can annotate Pods or
Namespaces with the annotation key `visibility.antrea.io/l7-export` and set the
value to indicate the traffic flow direction, which can be `ingress`, `egress`
or `both`.

For example, to enable L7 flow export in the ingress direction on
Pod test-pod in the default Namespace, you can use:

```bash
kubectl annotate pod test-pod visibility.antrea.io/l7-export=ingress
```

Based on the annotation, Flow Exporter will export the L7 flow data to the
Flow Aggregator or configured IPFix collector using the fields `appProtocolName`
and `httpVals`.

* `appProtocolName` field is used to indicate the application layer protocol
name (e.g. http) and it will be empty if application layer data is not exported.
* `httpVals` stores a serialized JSON dictionary with every HTTP request for
a connection mapped to a unique transaction ID. This format lets us group all
the HTTP transactions pertaining to the same connection, into the same exported
record.

An example of `httpVals` is :

`"{\"0\":{\"hostname\":\"10.10.0.1\",\"url\":\"/public/\",\"http_user_agent\":\"curl/7.74.0\",\"http_content_type\":\"text/html\",\"http_method\":\"GET\",\"protocol\":\"HTTP/1.1\",\"status\":200,\"length\":153}}"`

HTTP fields in the `httpVals` are:

| Http field        | Description                                            |
|-------------------|--------------------------------------------------------|
| hostname          | IP address of the sender                               |
| URL               | url requested on the server                            |
| http_user_agent   | application used for HTTP                              |
| http_content_type | type of content being returned by the server           |
| http_method       | HTTP method used for the request                       |
| protocol          | HTTP protocol version used for the request or response |
| status            | HTTP status code                                       |
| length            | size of the response body                              |

As of now, the only supported layer 7 protocol is `HTTP1.1`. Support for more
protocols may be added in the future. Antrea supports L7FlowExporter feature only
on Linux Nodes.
