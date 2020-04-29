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
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

var (
	OpsAppliedToGroupProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antrea_controller_applied_to_group_processed",
		Help: "The total number of applied-to-group processed",
	})
	OpsAddressGroupProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antrea_controller_address_group_processed",
		Help: "The total number of address-group processed ",
	})
	OpsInternalNetworkPolicyProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antrea_controller_network_policy_processed",
		Help: "The total number of internal-networkpolicy processed",
	})
	DurationAppliedToGroupSyncing = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "antrea_controller_applied_to_group_sync_duration_milliseconds",
		Help: "The duration of syncing applied-to-group",
	})
	DurationAddressGroupSyncing = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "antrea_controller_address_group_sync_duration_milliseconds",
		Help: "The duration of syncing address-group",
	})
	DurationInternalNetworkPolicySyncing = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "antrea_controller_network_policy_sync_duration_milliseconds",
		Help: "The duration of syncing internal-networkpolicy",
	})
	LengthAppliedToGroupQueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antrea_controller_length_applied_to_group_queue",
		Help: "The length of AppliedToGroupQueue",
	})
	LengthAddressGroupQueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antrea_controller_length_address_group_queue",
		Help: "The length of AddressGroupQueue",
	})
	LengthInternalNetworkPolicyQueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antrea_controller_length_network_policy_queue",
		Help: "The length of InternalNetworkPolicyQueue",
	})
)

// Initialize Prometheus metrics collection.
func InitializePrometheusMetrics() {
	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Errorf("Failed to retrieve controller K8S node name: %v", err)
	}

	klog.Info("Initializing prometheus metrics")
	gaugeHost := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "antrea_controller_runtime_info",
		Help:        "Antrea controller runtime info, defined as labels. The value of the gauge is always set to 1.",
		ConstLabels: prometheus.Labels{"k8s_nodename": nodeName, "k8s_podname": env.GetPodName()},
	})
	gaugeHost.Set(1)
	if err = prometheus.Register(gaugeHost); err != nil {
		klog.Errorf("Failed to register antrea_controller_runtime_info with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(OpsAppliedToGroupProcessed); err != nil {
		klog.Errorf("Failed to register antrea_controller_applied_to_group_processed with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(OpsAddressGroupProcessed); err != nil {
		klog.Errorf("Failed to register antrea_controller_address_group_processed with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(OpsInternalNetworkPolicyProcessed); err != nil {
		klog.Errorf("Failed to register antrea_controller_network_policy_processed with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(DurationAppliedToGroupSyncing); err != nil {
		klog.Errorf("Failed to register antrea_controller_applied_to_group_sync_duration_milliseconds with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(DurationAddressGroupSyncing); err != nil {
		klog.Errorf("Failed to register antrea_controller_address_group_sync_duration_milliseconds with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(DurationInternalNetworkPolicySyncing); err != nil {
		klog.Errorf("Failed to register antrea_controller_network_policy_sync_duration_milliseconds with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(LengthAppliedToGroupQueue); err != nil {
		klog.Errorf("Failed to register antrea_controller_length_applied_to_group_queue with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(LengthAddressGroupQueue); err != nil {
		klog.Errorf("Failed to register antrea_controller_length_address_group_queue with Prometheus: %s", err.Error())
	}
	if err := prometheus.Register(LengthInternalNetworkPolicyQueue); err != nil {
		klog.Errorf("Failed to register antrea_controller_length_network_policy_queue with Prometheus: %s", err.Error())
	}
}
