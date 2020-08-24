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
	"k8s.io/klog"
)

const (
	AllMetrics           string = "AllMetrics"
	PodMetrics           string = "PodMetrics"
	NetworkPolicyMetrics string = "NetworkPolicyMetrics"
	OVSMetrics           string = "OVSMetrics"
	ConnectionMetrics    string = "ConnectionMetrics"
)

var (
	MetricCategoriesMap = map[string]bool{
		AllMetrics:           false,
		PodMetrics:           false,
		NetworkPolicyMetrics: false,
		OVSMetrics:           false,
		ConnectionMetrics:    false,
	}
)

func InitializePrometheusMetrics() {
	klog.Info("Initializing prometheus metrics")

	if MetricCategoriesMap[PodMetrics] {
		InitializePodMetrics()
	}
	if MetricCategoriesMap[NetworkPolicyMetrics] {
		InitializeNetworkPolicyMetrics()
	}
	if MetricCategoriesMap[OVSMetrics] {
		InitializeOVSMetrics()
	}
	if MetricCategoriesMap[ConnectionMetrics] {
		InitializeConnectionMetrics()
	}
}

func SetMetricCategoriesMap(metricsMap map[string]bool) bool {
	enableMetrics := false
	if metricsMap[AllMetrics] {
		for key := range MetricCategoriesMap {
			MetricCategoriesMap[key] = true
		}
		enableMetrics = true
		return enableMetrics
	}

	for key, value := range metricsMap {
		if value {
			MetricCategoriesMap[key] = value
			if !enableMetrics {
				enableMetrics = true
			}
		}
	}
	return enableMetrics
}
