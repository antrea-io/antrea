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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

var (
	EgressNetworkPolicyRuleCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_egress_networkpolicy_rule_count",
			Help:           "Number of egress networkpolicy rules on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	IngressNetworkPolicyRuleCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_ingress_networkpolicy_rule_count",
			Help:           "Number of ingress networkpolicy rules on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	PodCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_local_pod_count",
			Help:           "Number of pods on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	NetworkPolicyCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_networkpolicy_count",
			Help:           "Number of networkpolicies on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	OVSTotalFlowCount = metrics.NewGauge(&metrics.GaugeOpts{
		Name:           "antrea_agent_ovs_total_flow_count",
		Help:           "Total flow count of all OVS flow tables.",
		StabilityLevel: metrics.STABLE,
	},
	)

	OVSFlowCount = metrics.NewGaugeVec(&metrics.GaugeOpts{
		Name:           "antrea_agent_ovs_flow_count",
		Help:           "Flow count for each OVS flow table. The TableID is used as a label.",
		StabilityLevel: metrics.STABLE,
	}, []string{"table_id"})

	OVSFlowOpsCount = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "antrea_agent_ovs_flow_ops_count",
			Help:           "Number of OVS flow operations, partitioned by operation type (add, modify and delete).",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation"},
	)

	OVSFlowOpsErrorCount = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "antrea_agent_ovs_flow_ops_error_count",
			Help:           "Number of OVS flow operation errors, partitioned by operation type (add, modify and delete).",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation"},
	)

	OVSFlowOpsLatency = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Name:           "antrea_agent_ovs_flow_ops_latency_milliseconds",
			Help:           "The latency of OVS flow operations, partitioned by operation type (add, modify and delete).",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation"},
	)
)

func InitializePrometheusMetrics() {
	klog.Info("Initializing prometheus metrics")

	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Errorf("Failed to retrieve agent K8S node name: %v", err)
	}
	deprecatedGaugeHost := metrics.NewGauge(&metrics.GaugeOpts{
		Name:              "antrea_agent_runtime_info",
		Help:              "Antrea agent runtime info (Deprecated since Antrea 0.10.0), defined as labels. The value of the gauge is always set to 1.",
		ConstLabels:       metrics.Labels{"k8s_nodename": nodeName, "k8s_podname": env.GetPodName()},
		StabilityLevel:    metrics.STABLE,
		DeprecatedVersion: "0.10.0",
	})
	if err := legacyregistry.Register(deprecatedGaugeHost); err != nil {
		klog.Error("Failed to register antrea_agent_runtime_info with Prometheus")
	}
	// This must be after registering the metrics.Gauge as it is lazily instantiated
	// and will not measure anything unless the collector is first registered.
	deprecatedGaugeHost.Set(1)

	InitializePodMetrics()
	InitializeNetworkPolicyMetrics()
	InitializeOVSMetrics()
}

func InitializePodMetrics() {
	if err := legacyregistry.Register(PodCount); err != nil {
		klog.Error("Failed to register antrea_agent_local_pod_count with Prometheus")
	}
}

func InitializeNetworkPolicyMetrics() {
	if err := legacyregistry.Register(EgressNetworkPolicyRuleCount); err != nil {
		klog.Error("Failed to register antrea_agent_egress_networkpolicy_rule_count with Prometheus")
	}

	if err := legacyregistry.Register(IngressNetworkPolicyRuleCount); err != nil {
		klog.Error("Failed to register antrea_agent_ingress_networkpolicy_rule_count with Prometheus")
	}

	if err := legacyregistry.Register(NetworkPolicyCount); err != nil {
		klog.Error("Failed to register antrea_agent_networkpolicy_count with Prometheus")
	}
}

func InitializeOVSMetrics() {
	if err := legacyregistry.Register(OVSTotalFlowCount); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_total_flow_count with Prometheus")
	}
	if err := legacyregistry.Register(OVSFlowCount); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_flow_count with Prometheus")
	}

	if err := legacyregistry.Register(OVSFlowOpsCount); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_flow_ops_count with Prometheus")
	}
	if err := legacyregistry.Register(OVSFlowOpsErrorCount); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_flow_ops_error_count with Prometheus")
	}
	if err := legacyregistry.Register(OVSFlowOpsLatency); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_flow_ops_latency_milliseconds with Prometheus")
	}
	// Initialize OpenFlow operations metrics with label add, modify and delete
	// since those metrics won't come out until observation.
	opsArray := [3]string{"add", "modify", "delete"}
	for _, ops := range opsArray {
		OVSFlowOpsCount.WithLabelValues(ops)
		OVSFlowOpsErrorCount.WithLabelValues(ops)
		OVSFlowOpsLatency.WithLabelValues(ops)
	}
}
