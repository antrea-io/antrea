// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"
)

const (
	metricNamespaceAntrea = "antrea"
	metricSubsystemAgent  = "agent"

	LabelPacketInMeterNetworkPolicy   = "PacketInMeterNetworkPolicy"
	LabelPacketInMeterTraceflow       = "PacketInMeterTraceflow"
	LabelPacketInMeterDNSInterception = "PacketInMeterDNSInterception"
)

var (
	EgressNetworkPolicyRuleCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "egress_networkpolicy_rule_count",
			Help:           "Number of egress NetworkPolicy rules on local Node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	IngressNetworkPolicyRuleCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "ingress_networkpolicy_rule_count",
			Help:           "Number of ingress NetworkPolicy rules on local Node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	PodCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "local_pod_count",
			Help:           "Number of Pods on local Node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	NetworkPolicyCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "networkpolicy_count",
			Help:           "Number of NetworkPolicies on local Node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	OVSTotalFlowCount = metrics.NewGauge(&metrics.GaugeOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemAgent,
		Name:           "ovs_total_flow_count",
		Help:           "Total flow count of all OVS flow tables.",
		StabilityLevel: metrics.STABLE,
	},
	)

	OVSFlowCount = metrics.NewGaugeVec(&metrics.GaugeOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemAgent,
		Name:           "ovs_flow_count",
		Help:           "Flow count for each OVS flow table. The TableID and TableName are used as labels.",
		StabilityLevel: metrics.STABLE,
	}, []string{"table_id", "table_name"})

	OVSFlowOpsCount = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "ovs_flow_ops_count",
			Help:           "Number of OVS flow operations, partitioned by operation type (add, modify and delete).",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation"},
	)

	OVSFlowOpsErrorCount = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "ovs_flow_ops_error_count",
			Help:           "Number of OVS flow operation errors, partitioned by operation type (add, modify and delete).",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation"},
	)

	OVSFlowOpsLatency = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "ovs_flow_ops_latency_milliseconds",
			Help:           "The latency of OVS flow operations, partitioned by operation type (add, modify and delete).",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation"},
	)

	// OVSMeterPacketDroppedCount is defined as a Gauge and not a Counter, even though this metric is monotonically
	// increasing (only being reset to 0 on restart).  This is because we want to set its value directly using the
	// Set method (using the value provided by OVS), and using Inc / Add is not convenient.
	OVSMeterPacketDroppedCount = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "ovs_meter_packet_dropped_count",
			Help:           "Number of packets dropped by OVS meter. The value is greater than 0 when the packets exceed the rate-limit.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"meter_id"},
	)

	TotalConnectionsInConnTrackTable = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "conntrack_total_connection_count",
			Help:           "Number of connections in the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.",
			StabilityLevel: metrics.ALPHA,
		},
	)

	TotalAntreaConnectionsInConnTrackTable = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "conntrack_antrea_connection_count",
			Help:           "Number of connections in the Antrea ZoneID of the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.",
			StabilityLevel: metrics.ALPHA,
		},
	)

	TotalDenyConnections = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "denied_connection_count",
			Help:           "Number of denied connections detected by Flow Exporter deny connections tracking. This metric gets updated when a flow is rejected/dropped by network policy.",
			StabilityLevel: metrics.ALPHA,
		},
	)

	ReconnectionsToFlowCollector = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "flow_collector_reconnection_count",
			Help:           "Number of re-connections between Flow Exporter and flow collector. This metric gets updated whenever the connection is re-established between the Flow Exporter and the flow collector (e.g. the Flow Aggregator).",
			StabilityLevel: metrics.ALPHA,
		},
	)

	MaxConnectionsInConnTrackTable = metrics.NewGauge(
		&metrics.GaugeOpts{
			Namespace:      metricNamespaceAntrea,
			Subsystem:      metricSubsystemAgent,
			Name:           "conntrack_max_connection_count",
			Help:           "Size of the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.",
			StabilityLevel: metrics.ALPHA,
		},
	)
)

func InitializePrometheusMetrics() {
	klog.Info("Initializing prometheus metrics")

	InitializePodMetrics()
	InitializeNetworkPolicyMetrics()
	InitializeOVSMetrics()
	InitializeConnectionMetrics()
}

func InitializePodMetrics() {
	if err := legacyregistry.Register(PodCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_local_pod_count")
	}
}

func InitializeNetworkPolicyMetrics() {
	if err := legacyregistry.Register(EgressNetworkPolicyRuleCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_egress_networkpolicy_rule_count")
	}

	if err := legacyregistry.Register(IngressNetworkPolicyRuleCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ingress_networkpolicy_rule_count")
	}

	if err := legacyregistry.Register(NetworkPolicyCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_networkpolicy_count")
	}
}

func InitializeOVSMetrics() {
	if err := legacyregistry.Register(OVSTotalFlowCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ovs_total_flow_count")
	}
	if err := legacyregistry.Register(OVSFlowCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ovs_flow_count")
	}

	if err := legacyregistry.Register(OVSFlowOpsCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ovs_flow_ops_count")
	}
	if err := legacyregistry.Register(OVSFlowOpsErrorCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ovs_flow_ops_error_count")
	}
	if err := legacyregistry.Register(OVSFlowOpsLatency); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ovs_flow_ops_latency_milliseconds")
	}
	if err := legacyregistry.Register(OVSMeterPacketDroppedCount); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ovs_meter_packet_dropped_count")
	}
	// Initialize OpenFlow operations metrics with label add, modify and delete
	// since those metrics won't come out until observation.
	for _, ops := range []string{"add", "modify", "delete"} {
		OVSFlowOpsCount.WithLabelValues(ops)
		OVSFlowOpsErrorCount.WithLabelValues(ops)
		OVSFlowOpsLatency.WithLabelValues(ops)
	}
	for _, label := range []string{LabelPacketInMeterNetworkPolicy, LabelPacketInMeterTraceflow, LabelPacketInMeterDNSInterception} {
		OVSMeterPacketDroppedCount.WithLabelValues(label)
	}
}

func InitializeConnectionMetrics() {
	if err := legacyregistry.Register(TotalConnectionsInConnTrackTable); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_conntrack_total_connection_count")
	}
	if err := legacyregistry.Register(TotalAntreaConnectionsInConnTrackTable); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_conntrack_antrea_connection_count")
	}
	if err := legacyregistry.Register(TotalDenyConnections); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_denied_connection_count")
	}
	if err := legacyregistry.Register(ReconnectionsToFlowCollector); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_flow_collector_reconnection_count")
	}
	if err := legacyregistry.Register(MaxConnectionsInConnTrackTable); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_conntrack_max_connection_count")
	}
}
