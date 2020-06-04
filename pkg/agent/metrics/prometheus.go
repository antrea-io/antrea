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
	PodCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_local_pod_count",
			Help:           "Number of pods on local node which are managed by the Antrea Agent.",
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
)

func InitializePrometheusMetrics() {
	klog.Info("Initializing prometheus metrics")

	if err := legacyregistry.Register(PodCount); err != nil {
		klog.Error("Failed to register antrea_agent_local_pod_count with Prometheus")
	}

	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Errorf("Failed to retrieve agent K8S node name: %v", err)
	}

	gaugeHost := metrics.NewGauge(&metrics.GaugeOpts{
		Name:           "antrea_agent_runtime_info",
		Help:           "Antrea agent runtime info , defined as labels. The value of the gauge is always set to 1.",
		ConstLabels:    metrics.Labels{"k8s_nodename": nodeName, "k8s_podname": env.GetPodName()},
		StabilityLevel: metrics.STABLE,
	})
	if err := legacyregistry.Register(gaugeHost); err != nil {
		klog.Error("Failed to register antrea_agent_runtime_info with Prometheus")
	}
	// This must be after registering the metrics.Gauge as it is lazily instantiated
	// and will not measure anything unless the collector is first registered.
	gaugeHost.Set(1)

	if err := legacyregistry.Register(OVSTotalFlowCount); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_total_flow_count with Prometheus")
	}
	if err := legacyregistry.Register(OVSFlowCount); err != nil {
		klog.Error("Failed to register antrea_agent_ovs_flow_count with Prometheus")
	}
}
