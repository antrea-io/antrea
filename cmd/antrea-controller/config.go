// Copyright 2019 Antrea Authors
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

package main

import (
	componentbaseconfig "k8s.io/component-base/config"
)

type ControllerConfig struct {
	// clientConnection specifies the kubeconfig file and client connection settings for the agent
	// to communicate with the apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
	// Enable metrics exposure via Prometheus. Initializes Prometheus metrics listener
	// Defaults to false.
	EnablePrometheusMetrics bool `yaml:"enablePrometheusMetrics,omitempty"`
	// Enable golang metrics exposure via Prometheus
	// Defaults to false.
	EnablePrometheusGoMetrics bool `yaml:"enablePrometheusGoMetrics,omitempty"`
	// Enable process metrics exposure via Prometheus
	// Defaults to false.
	EnablePrometheusProcessMetrics bool `yaml:"enablePrometheusProcessMetrics,omitempty"`
	// Prometheus metrics hostname.
	// Defaults to empty string
	PrometheusHost string `yaml:"prometheusHost,omitempty"`
	// Prometheus listener port.
	// Default is 9093
	PrometheusPort int `yaml:"prometheusPort,omitempty"`
}
