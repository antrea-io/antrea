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

package secondarynetwork

import (
	"errors"

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
)

// EffectiveSecondaryOVSBridgeFromStatic returns the secondary OVS bridge from agent static
// ConfigMap settings only. Used when AntreaNodeConfig does not drive the secondary bridge.
func EffectiveSecondaryOVSBridgeFromStatic(staticCfg *agentconfig.SecondaryNetworkConfig) *agenttypes.OVSBridgeConfig {
	return ovsBridgeFromStatic(staticCfg)
}

// EffectiveSecondaryOVSBridgeFromSnapshot resolves the desired secondary OVS bridge from an
// immutable *antreanodeconfig.Snapshot (for example the payload on the AntreaNodeConfig notify
// channel) merged with static agent ConfigMap settings.
//
// When snap is nil or snap.Node is nil, nil is returned (no bridge from this snapshot).
//
// When the snapshot records a non-empty AntreaNodeConfigListError, staticCfg is used
// after logging. Otherwise, when the oldest matching AntreaNodeConfig specifies secondary
// network settings, those override staticCfg; when it does not, staticCfg is used.
func EffectiveSecondaryOVSBridgeFromSnapshot(snap *antreanodeconfig.Snapshot, staticCfg *agentconfig.SecondaryNetworkConfig) *agenttypes.OVSBridgeConfig {
	if snap == nil {
		return nil
	}
	if snap.Node == nil {
		return nil
	}
	if snap.AntreaNodeConfigListError != "" {
		klog.ErrorS(errors.New(snap.AntreaNodeConfigListError), "Failed to list AntreaNodeConfigs, falling back to static config")
		return ovsBridgeFromStatic(staticCfg)
	}
	effective := ApplySecondaryNetworkConfig(snap.AntreaNodeConfig)
	if effective != nil {
		if effective.OVSBridge != nil {
			klog.V(2).InfoS("Using AntreaNodeConfig secondary network config", "bridge", effective.OVSBridge.BridgeName)
		}
		return effective.OVSBridge
	}
	return ovsBridgeFromStatic(staticCfg)
}

func ovsBridgeFromStatic(staticCfg *agentconfig.SecondaryNetworkConfig) *agenttypes.OVSBridgeConfig {
	if staticCfg == nil || len(staticCfg.OVSBridges) == 0 {
		return nil
	}
	b := staticCfg.OVSBridges[0]
	bridge := &agenttypes.OVSBridgeConfig{
		BridgeName:              b.BridgeName,
		EnableMulticastSnooping: b.EnableMulticastSnooping,
	}
	for _, iface := range b.PhysicalInterfaces {
		bridge.PhysicalInterfaces = append(bridge.PhysicalInterfaces, agenttypes.PhysicalInterfaceConfig{Name: iface})
	}
	return bridge
}

// ApplySecondaryNetworkConfig derives the effective SecondaryNetworkConfig from the
// AntreaNodeConfig carried in the snapshot (the oldest matching object for the Node).
// It returns nil when cfg is nil or does not specify SecondaryNetwork, so static
// agent config stays in effect.
func ApplySecondaryNetworkConfig(cfg *crdv1alpha1.AntreaNodeConfig) *agenttypes.SecondaryNetworkConfig {
	if cfg == nil || cfg.Spec.SecondaryNetwork == nil {
		return nil
	}
	converted := convertCRDSecondaryNetwork(cfg.Spec.SecondaryNetwork, cfg.ObjectMeta.Name)
	return &converted
}

// convertCRDSecondaryNetwork converts from the CRD type to SecondaryNetworkConfig.
// The CRD schema enforces at most one OVS bridge; OVSBridge is nil when the
// list is empty or the sole bridge has an empty name (treated as unspecified).
func convertCRDSecondaryNetwork(in *crdv1alpha1.SecondaryNetworkConfig, antreaNodeConfigName string) agenttypes.SecondaryNetworkConfig {
	if len(in.OVSBridges) == 0 {
		return agenttypes.SecondaryNetworkConfig{}
	}
	b := in.OVSBridges[0]
	if b.BridgeName == "" {
		klog.ErrorS(errors.New("empty OVS bridge name"), "Ignoring AntreaNodeConfig secondary network config with empty bridge name", "antreaNodeConfig", antreaNodeConfigName)
		return agenttypes.SecondaryNetworkConfig{}
	}
	bridge := &agenttypes.OVSBridgeConfig{
		BridgeName:              b.BridgeName,
		EnableMulticastSnooping: b.EnableMulticastSnooping,
	}
	for _, iface := range b.PhysicalInterfaces {
		pi := agenttypes.PhysicalInterfaceConfig{Name: iface.Name}
		if len(iface.AllowedVLANs) > 0 {
			pi.AllowedVLANs = append(pi.AllowedVLANs, iface.AllowedVLANs...)
		}
		bridge.PhysicalInterfaces = append(bridge.PhysicalInterfaces, pi)
	}
	return agenttypes.SecondaryNetworkConfig{OVSBridge: bridge}
}
