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
	EgressNetworkPolicyRuleCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_egress_networkpolicy_rule_count",
			Help:           "Number of egress networkpolicy rules on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	IngressNetworkPolicyRuleCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_ingress_networkpolicy_rule_count",
			Help:           "Number of ingress networkpolicy rules on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)

	NetworkPolicyCount = metrics.NewGauge(
		&metrics.GaugeOpts{
			Name:           "antrea_agent_networkpolicy_count",
			Help:           "Number of networkpolicies on local node which are managed by the Antrea Agent.",
			StabilityLevel: metrics.STABLE,
		},
	)
)

func InitializeNetworkPolicyMetrics() {
	if err := legacyregistry.Register(EgressNetworkPolicyRuleCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_egress_networkpolicy_rule_count with error: %v", err)
	}

	if err := legacyregistry.Register(IngressNetworkPolicyRuleCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_ingress_networkpolicy_rule_count with error: %v", err)
	}

	if err := legacyregistry.Register(NetworkPolicyCount); err != nil {
		klog.Errorf("Failed to register antrea_agent_networkpolicy_count with error: %v", err)
	}
}
