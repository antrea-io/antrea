#!/usr/bin/env bash

# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
clickhouse client -n -h 127.0.0.1 <<-EOSQL

    CREATE TABLE IF NOT EXISTS flows (
        timeInserted DateTime DEFAULT now(),
        flowStartSeconds DateTime,
        flowEndSeconds DateTime,
        flowEndSecondsFromSourceNode DateTime,
        flowEndSecondsFromDestinationNode DateTime,
        flowEndReason UInt8,
        sourceIP String,
        destinationIP String,
        sourceTransportPort UInt16,
        destinationTransportPort UInt16,
        protocolIdentifier UInt8,
        packetTotalCount UInt64,
        octetTotalCount UInt64,
        packetDeltaCount UInt64,
        octetDeltaCount UInt64,
        reversePacketTotalCount UInt64,
        reverseOctetTotalCount UInt64,
        reversePacketDeltaCount UInt64,
        reverseOctetDeltaCount UInt64,
        sourcePodName String,
        sourcePodNamespace String,
        sourceNodeName String,
        destinationPodName String,
        destinationPodNamespace String,
        destinationNodeName String,
        destinationClusterIP String,
        destinationServicePort UInt16,
        destinationServicePortName String,
        ingressNetworkPolicyName String,
        ingressNetworkPolicyNamespace String,
        ingressNetworkPolicyRuleName String,
        ingressNetworkPolicyRuleAction UInt8,
        ingressNetworkPolicyType UInt8,
        egressNetworkPolicyName String,
        egressNetworkPolicyNamespace String,
        egressNetworkPolicyRuleName String,
        egressNetworkPolicyRuleAction UInt8,
        egressNetworkPolicyType UInt8,
        tcpState String,
        flowType UInt8,
        sourcePodLabels String,
        destinationPodLabels String,
        throughput UInt64,
        reverseThroughput UInt64,
        throughputFromSourceNode UInt64,
        throughputFromDestinationNode UInt64,
        reverseThroughputFromSourceNode UInt64,
        reverseThroughputFromDestinationNode UInt64,
        trusted UInt8 DEFAULT 0
    ) engine=MergeTree
    ORDER BY (timeInserted, flowEndSeconds)
    TTL timeInserted + INTERVAL 1 HOUR
    SETTINGS merge_with_ttl_timeout = 3600;

    CREATE MATERIALIZED VIEW IF NOT EXISTS flows_pod_view
    ENGINE = SummingMergeTree
    ORDER BY (
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        sourcePodName,
        destinationPodName,
        destinationIP,
        destinationServicePortName,
        flowType,
        sourcePodNamespace,
        destinationPodNamespace)
    TTL timeInserted + INTERVAL 1 HOUR
    SETTINGS merge_with_ttl_timeout = 3600
    POPULATE
    AS SELECT
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        sourcePodName,
        destinationPodName,
        destinationIP,
        destinationServicePortName,
        flowType,
        sourcePodNamespace,
        destinationPodNamespace,
        sum(octetDeltaCount) AS octetDeltaCount,
        sum(reverseOctetDeltaCount) AS reverseOctetDeltaCount,
        sum(throughput) AS throughput,
        sum(reverseThroughput) AS reverseThroughput,
        sum(throughputFromSourceNode) AS throughputFromSourceNode,
        sum(throughputFromDestinationNode) AS throughputFromDestinationNode
    FROM flows
    GROUP BY
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        sourcePodName,
        destinationPodName,
        destinationIP,
        destinationServicePortName,
        flowType,
        sourcePodNamespace,
        destinationPodNamespace;

    CREATE MATERIALIZED VIEW IF NOT EXISTS flows_node_view
    ENGINE = SummingMergeTree
    ORDER BY (
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        sourceNodeName,
        destinationNodeName,
        sourcePodNamespace,
        destinationPodNamespace)
    TTL timeInserted + INTERVAL 1 HOUR
    SETTINGS merge_with_ttl_timeout = 3600
    POPULATE
    AS SELECT
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        sourceNodeName,
        destinationNodeName,
        sourcePodNamespace,
        destinationPodNamespace,
        sum(octetDeltaCount) AS octetDeltaCount,
        sum(reverseOctetDeltaCount) AS reverseOctetDeltaCount,
        sum(throughput) AS throughput,
        sum(reverseThroughput) AS reverseThroughput,
        sum(throughputFromSourceNode) AS throughputFromSourceNode,
        sum(reverseThroughputFromSourceNode) AS reverseThroughputFromSourceNode,
        sum(throughputFromDestinationNode) AS throughputFromDestinationNode,
        sum(reverseThroughputFromDestinationNode) AS reverseThroughputFromDestinationNode
    FROM flows
    GROUP BY
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        sourceNodeName,
        destinationNodeName,
        sourcePodNamespace,
        destinationPodNamespace;

    CREATE MATERIALIZED VIEW IF NOT EXISTS flows_policy_view
    ENGINE = SummingMergeTree
    ORDER BY (
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        egressNetworkPolicyName,
        egressNetworkPolicyRuleAction,
        ingressNetworkPolicyName,
        ingressNetworkPolicyRuleAction,
        sourcePodNamespace,
        destinationPodNamespace)
    TTL timeInserted + INTERVAL 1 HOUR
    SETTINGS merge_with_ttl_timeout = 3600
    POPULATE
    AS SELECT
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        egressNetworkPolicyName,
        egressNetworkPolicyRuleAction,
        ingressNetworkPolicyName,
        ingressNetworkPolicyRuleAction,
        sourcePodNamespace,
        destinationPodNamespace,
        sum(octetDeltaCount) AS octetDeltaCount,
        sum(reverseOctetDeltaCount) AS reverseOctetDeltaCount,
        sum(throughput) AS throughput,
        sum(reverseThroughput) AS reverseThroughput,
        sum(throughputFromSourceNode) AS throughputFromSourceNode,
        sum(reverseThroughputFromSourceNode) AS reverseThroughputFromSourceNode,
        sum(throughputFromDestinationNode) AS throughputFromDestinationNode,
        sum(reverseThroughputFromDestinationNode) AS reverseThroughputFromDestinationNode
    FROM flows
    GROUP BY
        timeInserted,
        flowEndSeconds,
        flowEndSecondsFromSourceNode,
        flowEndSecondsFromDestinationNode,
        egressNetworkPolicyName,
        egressNetworkPolicyRuleAction,
        ingressNetworkPolicyName,
        ingressNetworkPolicyRuleAction,
        sourcePodNamespace,
        destinationPodNamespace;

    CREATE TABLE IF NOT EXISTS recommendations (
        id String,
        type String,
        timeCreated DateTime,
        yamls String
    ) engine=MergeTree
    ORDER BY (timeCreated);
    
EOSQL
