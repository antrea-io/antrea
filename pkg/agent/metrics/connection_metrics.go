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
	TotalConnectionCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_conntrack_total_connection_count",
			Help:           "Number of connections in the conntrack table.",
			StabilityLevel: metrics.ALPHA,
		},
	)

	AntreaConnectionCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_conntrack_antrea_connection_count",
			Help:           "Number of connections in the Antrea ZoneID of the conntrack table.",
			StabilityLevel: metrics.ALPHA,
		},
	)
)

func InitializeConnectionMetrics() {
	if err := legacyregistry.Register(TotalConnectionCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_conntrack_total_connection_count with error: %v", err)
	}
	if err := legacyregistry.Register(AntreaConnectionCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_conntrack_antrea_connection_count with error: %v", err)
	}
}
