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
	metricNamespaceAntrea     = "antrea"
	metricSubsystemController = "controller"
)

var (
	OpsAppliedToGroupProcessed = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "applied_to_group_processed",
		Help:           "The total number of applied-to-group processed",
		StabilityLevel: metrics.STABLE,
	})
	OpsAddressGroupProcessed = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "address_group_processed",
		Help:           "The total number of address-group processed ",
		StabilityLevel: metrics.STABLE,
	})
	OpsInternalNetworkPolicyProcessed = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "network_policy_processed",
		Help:           "The total number of internal-networkpolicy processed",
		StabilityLevel: metrics.STABLE,
	})
	DurationAppliedToGroupSyncing = metrics.NewHistogram(&metrics.HistogramOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "applied_to_group_sync_duration_milliseconds",
		Help:           "The duration of syncing applied-to-group",
		StabilityLevel: metrics.ALPHA,
	})
	DurationAddressGroupSyncing = metrics.NewHistogram(&metrics.HistogramOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "address_group_sync_duration_milliseconds",
		Help:           "The duration of syncing address-group",
		StabilityLevel: metrics.ALPHA,
	})
	DurationInternalNetworkPolicySyncing = metrics.NewHistogram(&metrics.HistogramOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "network_policy_sync_duration_milliseconds",
		Help:           "The duration of syncing internal-networkpolicy",
		StabilityLevel: metrics.ALPHA,
	})
	LengthAppliedToGroupQueue = metrics.NewGauge(&metrics.GaugeOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "length_applied_to_group_queue",
		Help:           "The length of AppliedToGroupQueue",
		StabilityLevel: metrics.STABLE,
	})
	LengthAddressGroupQueue = metrics.NewGauge(&metrics.GaugeOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "length_address_group_queue",
		Help:           "The length of AddressGroupQueue",
		StabilityLevel: metrics.STABLE,
	})
	LengthInternalNetworkPolicyQueue = metrics.NewGauge(&metrics.GaugeOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "length_network_policy_queue",
		Help:           "The length of InternalNetworkPolicyQueue",
		StabilityLevel: metrics.STABLE,
	})
	AntreaNetworkPolicyStatusUpdates = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "annp_status_updates",
		Help:           "The total number of actual status updates performed for Antrea NetworkPolicy Custom Resources",
		StabilityLevel: metrics.ALPHA,
	})
	AntreaEgressStatusUpdates = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "eg_status_updates",
		Help:           "The total number of actual status updates performed for Antrea Egress Custom Resources",
		StabilityLevel: metrics.ALPHA,
	})
	AntreaExternalIPPoolStatusUpdates = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "eip_status_updates",
		Help:           "The total number of actual status updates performed for Antrea ExternalIPPool Custom Resources",
		StabilityLevel: metrics.ALPHA,
	})
	AntreaClusterNetworkPolicyStatusUpdates = metrics.NewCounter(&metrics.CounterOpts{
		Namespace:      metricNamespaceAntrea,
		Subsystem:      metricSubsystemController,
		Name:           "acnp_status_updates",
		Help:           "The total number of actual status updates performed for Antrea ClusterNetworkPolicy Custom Resources",
		StabilityLevel: metrics.ALPHA,
	})
)

// Initialize Prometheus metrics collection.
func InitializePrometheusMetrics() {
	klog.Info("Initializing prometheus metrics")

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
	if err := legacyregistry.Register(AntreaNetworkPolicyStatusUpdates); err != nil {
		klog.Errorf("Failed to register antrea_controller_annp_status_updates with Prometheus: %s", err.Error())
	}
	if err := legacyregistry.Register(AntreaClusterNetworkPolicyStatusUpdates); err != nil {
		klog.Errorf("Failed to register antrea_controller_acnp_status_updates with Prometheus: %s", err.Error())
	}
}
