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
)

var (
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

func InitializeOVSMetrics() {
	if err := legacyregistry.Register(OVSTotalFlowCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_ovs_total_flow_count with error: %v", err)
	}

	if err := legacyregistry.Register(OVSFlowCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_ovs_flow_count with error: %v", err)
	}

	if err := legacyregistry.Register(OVSFlowOpsCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_ovs_flow_ops_count with error: %v", err)
	}

	if err := legacyregistry.Register(OVSFlowOpsErrorCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_ovs_flow_ops_error_count with error: %v", err)
	}

	if err := legacyregistry.Register(OVSFlowOpsLatency); err != nil {
		klog.Errorf("Failed to register antrea_agent_ovs_flow_ops_latency_milliseconds with error: %v", err)
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
