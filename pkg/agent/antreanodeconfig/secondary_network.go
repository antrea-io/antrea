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
	"k8s.io/klog/v2"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
)

// EffectiveSecondaryOVSBridge returns the effective OVS bridge configuration for
// secondary networking on this Node.
//
// When useAntreaNodeConfig is false, AntreaNodeConfig objects are ignored and
// only staticCfg from the agent ConfigMap is used (rule 1).
//
// When useAntreaNodeConfig is true, staticCfg is only used after the Node and
// AntreaNodeConfig informer caches have synced (enforced in
// antreanodeconfig.Controller.EffectiveSecondaryOVSBridge) and the local Node
// object is known. That avoids treating a transient empty ANC list as “no CR”
// and applying static config before CRs are visible.
//
// When useAntreaNodeConfig is true and node is nil (Node not loaded yet), this
// function returns nil so static secondary-network config is not applied in
// place of AntreaNodeConfig.
//
// When useAntreaNodeConfig is true and node is non-nil, ancConfigs is the
// current list of AntreaNodeConfig objects from the informer cache. If listErr
// is non-nil, the static config is used after logging. Otherwise, when a
// matching AntreaNodeConfig specifies secondary network settings, those
// override staticCfg entirely (rule 2). When no matching config applies, or the
// winner has no bridge, the return value follows the same semantics as the
// previous resolveEffectiveBridgeConfig helper in the secondary network
// package.
func EffectiveSecondaryOVSBridge(
	node *corev1.Node,
	ancConfigs []*crdv1alpha1.AntreaNodeConfig,
	listErr error,
	useAntreaNodeConfig bool,
	staticSecondaryNetworkCfg *agentconfig.SecondaryNetworkConfig,
) *agenttypes.OVSBridgeConfig {
	if useAntreaNodeConfig && node == nil {
		return nil
	}
	if useAntreaNodeConfig && node != nil {
		if listErr != nil {
			klog.ErrorS(listErr, "Failed to list AntreaNodeConfigs, falling back to static config")
		} else {
			effective := SelectAndApplySecondaryNetworkConfigs(node, ancConfigs)
			if effective != nil {
				if effective.OVSBridge != nil {
					klog.V(2).InfoS("Using AntreaNodeConfig secondary network config", "bridge", effective.OVSBridge.BridgeName)
				}
				return effective.OVSBridge
			}
		}
	}

	if staticSecondaryNetworkCfg == nil || len(staticSecondaryNetworkCfg.OVSBridges) == 0 {
		return nil
	}
	b := staticSecondaryNetworkCfg.OVSBridges[0]
	bridge := &agenttypes.OVSBridgeConfig{
		BridgeName:              b.BridgeName,
		EnableMulticastSnooping: b.EnableMulticastSnooping,
	}
	for _, iface := range b.PhysicalInterfaces {
		bridge.PhysicalInterfaces = append(bridge.PhysicalInterfaces, agenttypes.PhysicalInterfaceConfig{Name: iface})
	}
	return bridge
}
