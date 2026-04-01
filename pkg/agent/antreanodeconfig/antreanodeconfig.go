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

// Package antreanodeconfig provides a utility framework for evaluating which
// AntreaNodeConfig resources apply to a given Node and computing the effective
// merged secondary-network configuration.
//
// Controller watches AntreaNodeConfig and the local Node,
// computes an EffectiveSnapshot of all derived agent settings, and broadcasts
// updates on a util/channel SubscribableChannel so feature controllers do not
// each register their own ANC informer handlers. Extend EffectiveSnapshot and
// ComputeEffectiveSnapshot when new ANC spec fields gain agent consumers.
//
// SelectAndApplySecondaryNetworkConfig (and EffectiveSecondaryOVSBridge) can also be called directly
// with an informer-cached list of AntreaNodeConfig objects and the current Node
// to obtain merged configuration. See EffectiveSecondaryOVSBridge and
// Controller.EffectiveSecondaryOVSBridge for when the result is nil versus static fallback.
//
// # Selection and override semantics
//
// All AntreaNodeConfigs whose nodeSelector matches the Node's labels are
// gathered and sorted by creationTimestamp ascending (oldest first; name is
// used as a stable tiebreaker when timestamps are equal).  The first (oldest)
// config that specifies a non-nil SecondaryNetwork takes effect entirely —
// there is no field-level merging within SecondaryNetwork and later configs
// are ignored once a winner is found.
package antreanodeconfig

import (
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

// SelectMatchingSecondaryNetworkConfigs returns the subset of configs whose nodeSelector
// matches node's labels, sorted by creationTimestamp ascending (oldest first).
// Configs with an invalid nodeSelector are skipped with a warning.
func SelectMatchingSecondaryNetworkConfigs(node *corev1.Node, configs []*crdv1alpha1.AntreaNodeConfig) []*crdv1alpha1.AntreaNodeConfig {
	nodeLabels := labels.Set(node.Labels)
	var matching []*crdv1alpha1.AntreaNodeConfig
	for _, cfg := range configs {
		sel, err := metav1.LabelSelectorAsSelector(&cfg.Spec.NodeSelector)
		if err != nil {
			klog.ErrorS(err, "Skipping AntreaNodeConfig with invalid nodeSelector", "config", cfg.Name)
			continue
		}
		if sel.Matches(nodeLabels) {
			matching = append(matching, cfg)
		}
	}
	sort.Slice(matching, func(i, j int) bool {
		ti := matching[i].CreationTimestamp
		tj := matching[j].CreationTimestamp
		if ti.Equal(&tj) {
			return matching[i].Name < matching[j].Name
		}
		return ti.Before(&tj)
	})
	return matching
}

// ApplySecondaryNetworkConfigs computes the effective SecondaryNetworkConfig from an
// ordered (oldest-first) slice of AntreaNodeConfigs.  It returns the
// SecondaryNetworkConfig from the first (oldest) config that specifies a
// non-nil SecondaryNetwork, and ignores all subsequent configs.  It returns
// nil when none of the configs specifies a SecondaryNetwork, meaning the
// static agent config should remain in effect unchanged.
func ApplySecondaryNetworkConfigs(configs []*crdv1alpha1.AntreaNodeConfig) *agenttypes.SecondaryNetworkConfig {
	for _, cfg := range configs {
		if cfg.Spec.SecondaryNetwork == nil {
			continue
		}
		converted := convertSecondaryNetwork(cfg.Spec.SecondaryNetwork)
		return &converted
	}
	return nil
}

// SelectAndApplySecondaryNetworkConfigs is a convenience wrapper that calls SelectMatchingSecondaryNetworkConfigsConfigs
// followed by ApplySecondaryNetworkConfigs.  It returns the effective SecondaryNetworkConfig
// for node, or nil when no matching AntreaNodeConfig specifies a
// SecondaryNetwork (in which case the static agent config stays in effect).
func SelectAndApplySecondaryNetworkConfigs(node *corev1.Node, configs []*crdv1alpha1.AntreaNodeConfig) *agenttypes.SecondaryNetworkConfig {
	return ApplySecondaryNetworkConfigs(SelectMatchingSecondaryNetworkConfigs(node, configs))
}

// convertSecondaryNetwork converts from the CRD type to SecondaryNetworkConfig.
// The CRD schema enforces at most one OVS bridge; OVSBridge is nil when the
// list is empty.
func convertSecondaryNetwork(in *crdv1alpha1.SecondaryNetworkConfig) agenttypes.SecondaryNetworkConfig {
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
