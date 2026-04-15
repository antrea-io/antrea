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

// EffectiveSecondaryOVSBridge resolves the desired OVS bridge for secondary networking
// from optional *antreanodeconfig.Controller (ancController) and static agent ConfigMap settings.
//
// When ancController is nil, AntreaNodeConfig is ignored and only staticCfg is used.
//
// When ancController is non-nil and InformersSynced is false, nil is returned so the bridge is
// not created from static config before AntreaNodeConfig objects are visible in the cache.
//
// When ancController is non-nil, InformersSynced is true, and the snapshot's Node is nil, nil is
// returned (local Node not loaded yet).
//
// When the snapshot records a non-empty AntreaNodeConfigListError, staticCfg is used
// after logging. Otherwise, when the oldest matching AntreaNodeConfig specifies secondary
// network settings, those override staticCfg; when it does not, staticCfg is used.
func EffectiveSecondaryOVSBridge(ancController *antreanodeconfig.Controller, staticCfg *agentconfig.SecondaryNetworkConfig) *agenttypes.OVSBridgeConfig {
	if ancController == nil {
		return ovsBridgeFromStatic(staticCfg)
	}
	if !ancController.InformersSynced() {
		return nil
	}
	return effectiveOVSBridgeFromSnapshot(ancController.CurrentSnapshot(), staticCfg)
}

func effectiveOVSBridgeFromSnapshot(snap *antreanodeconfig.Snapshot, staticCfg *agentconfig.SecondaryNetworkConfig) *agenttypes.OVSBridgeConfig {
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
	converted := convertCRDSecondaryNetwork(cfg.Spec.SecondaryNetwork)
	return &converted
}

// convertCRDSecondaryNetwork converts from the CRD type to SecondaryNetworkConfig.
// The CRD schema enforces at most one OVS bridge; OVSBridge is nil when the
// list is empty.
func convertCRDSecondaryNetwork(in *crdv1alpha1.SecondaryNetworkConfig) agenttypes.SecondaryNetworkConfig {
	if len(in.OVSBridges) == 0 {
		return agenttypes.SecondaryNetworkConfig{}
	}
	b := in.OVSBridges[0]
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
