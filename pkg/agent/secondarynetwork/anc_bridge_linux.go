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
	"fmt"

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
)

// effectiveSecondaryOVSBridgeFromSnapshot resolves the desired secondary OVS bridge from an
// immutable *antreanodeconfig.Snapshot (for example the payload on the AntreaNodeConfig notify
// channel) merged with static agent ConfigMap settings.
//
// Static agent config always takes precedence. If staticCfg specifies a secondary network bridge,
// it is returned. Otherwise, the oldest matching AntreaNodeConfig specifying secondary network
// settings is used.
//
// When snap is nil, nil is returned (no bridge from this snapshot).
//
// Callers must check snap.AntreaNodeConfigListError before calling this function. When the list
// failed, this function receives a nil AntreaNodeConfig (since the controller clears the ANC on
// errors to avoid acting on a partial view) and returns nil unless the static config provides a
// bridge — which the caller may interpret as "delete the bridge." To prevent that, callers should
// skip reconciliation when AntreaNodeConfigListError is non-empty and there is no static bridge.
func effectiveSecondaryOVSBridgeFromSnapshot(snap *antreanodeconfig.Snapshot, staticCfg *agentconfig.SecondaryNetworkConfig, primaryOVSBridgeName string) *agenttypes.OVSBridgeConfig {
	if staticCfg != nil && len(staticCfg.OVSBridges) > 0 {
		return ovsBridgeFromStatic(staticCfg)
	}
	if snap == nil || snap.AntreaNodeConfig == nil {
		return nil
	}
	cfg := snap.AntreaNodeConfig
	if cfg.Spec.SecondaryNetwork == nil {
		return nil
	}
	effective := convertCRDSecondaryNetwork(cfg.Spec.SecondaryNetwork, cfg.ObjectMeta.Name)
	if effective == nil {
		return nil
	}
	if primaryOVSBridgeName != "" && effective.BridgeName == primaryOVSBridgeName {
		klog.ErrorS(fmt.Errorf("secondary OVS bridge %q conflicts with primary OVS bridge", effective.BridgeName),
			"Ignoring AntreaNodeConfig secondary network config with invalid bridge name", "antreaNodeConfig", cfg.ObjectMeta.Name)
		return nil
	}
	klog.V(2).InfoS("Using AntreaNodeConfig secondary network config", "bridge", effective.BridgeName)
	return effective
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
		// Static agent config only stores interface names, not AllowedVLANs. When
		// static config takes effect after an AntreaNodeConfig with VLAN trunks,
		// the empty AllowedVLANs below intentionally causes stale trunks to be
		// cleared during bridge reconciliation.
		bridge.PhysicalInterfaces = append(bridge.PhysicalInterfaces, agenttypes.PhysicalInterfaceConfig{Name: iface})
	}
	return bridge
}

// convertCRDSecondaryNetwork converts from the CRD type to the effective bridge
// config. It returns nil when the CRD config does not specify a valid OVS bridge
// (the list is empty or the sole bridge has an empty name, both treated as
// unspecified).
func convertCRDSecondaryNetwork(in *crdv1alpha1.SecondaryNetworkConfig, antreaNodeConfigName string) *agenttypes.OVSBridgeConfig {
	if len(in.OVSBridges) == 0 {
		return nil
	}
	b := in.OVSBridges[0]
	if b.BridgeName == "" {
		klog.ErrorS(errors.New("empty OVS bridge name"), "Ignoring AntreaNodeConfig secondary network config with empty bridge name", "antreaNodeConfig", antreaNodeConfigName)
		return nil
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
	return bridge
}
