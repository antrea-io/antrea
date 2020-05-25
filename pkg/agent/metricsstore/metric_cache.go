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

package metricsstore

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	IngressNetworkPolicyCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antrea_agent_local_ingress_networkpolicy_count",
		Help: "Number of ingress network policieson local node which are managed by the Antrea Agent.",			
	})

	EgressNetworkPolicyCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antrea_agent_local_egress_networkpolicy_count",
		Help: "Number of egress network policieson local node which are managed by the Antrea Agent.",			
	})
)