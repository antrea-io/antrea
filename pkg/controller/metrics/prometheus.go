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
		klog.Error("Failed to register antrea_controller_runtime_info with Prometheus")
	}
}
