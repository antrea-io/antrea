// Copyright 2026 Antrea Authors
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

package antreanodeconfig

import (
	corev1 "k8s.io/api/core/v1"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
)

// EffectiveSnapshot aggregates AntreaNodeConfig-derived settings for this Node
// that the agent exposes to SubscribableChannel subscribers.
//
// When new spec fields are added to AntreaNodeConfig and consumed by the agent,
// extend this struct and ComputeEffectiveSnapshot so the sync controller can
// detect changes to any derived sub-state, not only secondary networking.
type EffectiveSnapshot struct {
	SecondaryOVSBridge *agenttypes.OVSBridgeConfig
}

// DeepCopy returns a deep copy of the snapshot suitable for passing to
// channel subscribers.
func (s *EffectiveSnapshot) DeepCopy() *EffectiveSnapshot {
	if s == nil {
		return nil
	}
	out := &EffectiveSnapshot{}
	if s.SecondaryOVSBridge != nil {
		out.SecondaryOVSBridge = s.SecondaryOVSBridge.DeepCopy()
	}
	return out
}

// ComputeEffectiveSnapshot builds the full derived state from the informer
// cache and static secondary-network YAML. Keep this the single place that
// maps ANC objects into agent-facing values as new ANC areas are added.
func ComputeEffectiveSnapshot(
	node *corev1.Node,
	ancConfigs []*crdv1alpha1.AntreaNodeConfig,
	listErr error,
	staticSecondaryNetworkCfg *agentconfig.SecondaryNetworkConfig,
) *EffectiveSnapshot {
	return &EffectiveSnapshot{
		SecondaryOVSBridge: EffectiveSecondaryOVSBridge(node, ancConfigs, listErr, true, staticSecondaryNetworkCfg),
	}
}
