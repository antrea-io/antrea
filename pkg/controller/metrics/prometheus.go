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

	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

var (
	OpsAppliedToGroupProcessed = metrics.NewCounter(&metrics.CounterOpts{
		Name:           "antrea_controller_applied_to_group_processed",
		Help:           "The total number of applied-to-group processed",
		StabilityLevel: metrics.STABLE,
	})
	OpsAddressGroupProcessed = metrics.NewCounter(&metrics.CounterOpts{
		Name:           "antrea_controller_address_group_processed",
		Help:           "The total number of address-group processed ",
		StabilityLevel: metrics.STABLE,
	})
	OpsInternalNetworkPolicyProcessed = metrics.NewCounter(&metrics.CounterOpts{
		Name:           "antrea_controller_network_policy_processed",
		Help:           "The total number of internal-networkpolicy processed",
		StabilityLevel: metrics.STABLE,
	})
	DurationAppliedToGroupSyncing = metrics.NewSummary(&metrics.SummaryOpts{
		Name:           "antrea_controller_applied_to_group_sync_duration_milliseconds",
		Help:           "The duration of syncing applied-to-group",
		StabilityLevel: metrics.STABLE,
	})
	DurationAddressGroupSyncing = metrics.NewSummary(&metrics.SummaryOpts{
		Name:           "antrea_controller_address_group_sync_duration_milliseconds",
		Help:           "The duration of syncing address-group",
		StabilityLevel: metrics.STABLE,
	})
	DurationInternalNetworkPolicySyncing = metrics.NewSummary(&metrics.SummaryOpts{
		Name:           "antrea_controller_network_policy_sync_duration_milliseconds",
		Help:           "The duration of syncing internal-networkpolicy",
		StabilityLevel: metrics.STABLE,
	})
	LengthAppliedToGroupQueue = metrics.NewGauge(&metrics.GaugeOpts{
		Name:           "antrea_controller_length_applied_to_group_queue",
		Help:           "The length of AppliedToGroupQueue",
		StabilityLevel: metrics.STABLE,
	})
	LengthAddressGroupQueue = metrics.NewGauge(&metrics.GaugeOpts{
		Name:           "antrea_controller_length_address_group_queue",
		Help:           "The length of AddressGroupQueue",
		StabilityLevel: metrics.STABLE,
	})
	LengthInternalNetworkPolicyQueue = metrics.NewGauge(&metrics.GaugeOpts{
		Name:           "antrea_controller_length_network_policy_queue",
		Help:           "The length of InternalNetworkPolicyQueue",
		StabilityLevel: metrics.STABLE,
	})
)

// Initialize Prometheus metrics collection.
func InitializePrometheusMetrics() {
	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Errorf("Failed to retrieve controller K8S node name: %v", err)
	}

	klog.Info("Initializing prometheus metrics")
	gaugeHost := metrics.NewGauge(&metrics.GaugeOpts{
		Name:           "antrea_controller_runtime_info",
		Help:           "Antrea controller runtime info, defined as labels. The value of the gauge is always set to 1.",
		ConstLabels:    metrics.Labels{"k8s_nodename": nodeName, "k8s_podname": env.GetPodName()},
		StabilityLevel: metrics.STABLE,
	})
	if err = legacyregistry.Register(gaugeHost); err != nil {
		klog.Errorf("Failed to register antrea_controller_runtime_info with Prometheus: %s", err.Error())
	}
	// This must be after registering the metrics.Gauge as it is lazily instantiated
	// and will not measure anything unless the collector is first registered.
	gaugeHost.Set(1)
	if err := legacyregistry.Register(OpsAppliedToGroupProcessed); err != nil {
		klog.Errorf("Failed to register antrea_controller_applied_to_group_processed with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(OpsAddressGroupProcessed); err != nil {
		klog.Errorf("Failed to register antrea_controller_address_group_processed with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(OpsInternalNetworkPolicyProcessed); err != nil {
		klog.Errorf("Failed to register antrea_controller_network_policy_processed with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(DurationAppliedToGroupSyncing); err != nil {
		klog.Errorf("Failed to register antrea_controller_applied_to_group_sync_duration_milliseconds with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(DurationAddressGroupSyncing); err != nil {
		klog.Errorf("Failed to register antrea_controller_address_group_sync_duration_milliseconds with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(DurationInternalNetworkPolicySyncing); err != nil {
		klog.Errorf("Failed to register antrea_controller_network_policy_sync_duration_milliseconds with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(LengthAppliedToGroupQueue); err != nil {
		klog.Errorf("Failed to register antrea_controller_length_applied_to_group_queue with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(LengthAddressGroupQueue); err != nil {
		klog.Errorf("Failed to register antrea_controller_length_address_group_queue with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(LengthInternalNetworkPolicyQueue); err != nil {
		klog.Errorf("Failed to register antrea_controller_length_network_policy_queue with Prometheus: %s", err.Error())
	}
}
