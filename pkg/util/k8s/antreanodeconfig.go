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

package k8s

import (
	"cmp"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

// MatchingAntreaNodeConfigs returns non-terminating configurations selecting node,
// ordered by creation time and then name, with the effective configuration first.
func MatchingAntreaNodeConfigs(node *corev1.Node, configs []*crdv1alpha1.AntreaNodeConfig) []*crdv1alpha1.AntreaNodeConfig {
	if node == nil {
		return nil
	}
	nodeLabels := labels.Set(node.Labels)
	var matching []*crdv1alpha1.AntreaNodeConfig
	for _, parsed := range parseAntreaNodeConfigs(configs) {
		if parsed.selector.Matches(nodeLabels) {
			matching = append(matching, parsed.config)
		}
	}
	return matching
}

// SelectAntreaNodeConfigs returns the effective configuration for each Node UID.
// Selectors are parsed and configurations sorted once for the whole batch. Nodes
// without a matching configuration have a nil entry in the returned map.
func SelectAntreaNodeConfigs(nodes []*corev1.Node, configs []*crdv1alpha1.AntreaNodeConfig) map[types.UID]*crdv1alpha1.AntreaNodeConfig {
	parsed := parseAntreaNodeConfigs(configs)
	selected := make(map[types.UID]*crdv1alpha1.AntreaNodeConfig, len(nodes))
	for _, node := range nodes {
		nodeLabels := labels.Set(node.Labels)
		selected[node.UID] = nil
		for _, cfg := range parsed {
			if cfg.selector.Matches(nodeLabels) {
				selected[node.UID] = cfg.config
				break
			}
		}
	}
	return selected
}

type parsedAntreaNodeConfig struct {
	config   *crdv1alpha1.AntreaNodeConfig
	selector labels.Selector
}

func parseAntreaNodeConfigs(configs []*crdv1alpha1.AntreaNodeConfig) []parsedAntreaNodeConfig {
	var parsed []parsedAntreaNodeConfig
	for _, cfg := range configs {
		if cfg == nil || cfg.DeletionTimestamp != nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&cfg.Spec.NodeSelector)
		if err != nil {
			klog.V(2).InfoS("Skipping AntreaNodeConfig with invalid nodeSelector", "config", cfg.Name, "err", err)
			continue
		}
		parsed = append(parsed, parsedAntreaNodeConfig{config: cfg, selector: sel})
	}
	slices.SortFunc(parsed, func(first, second parsedAntreaNodeConfig) int {
		a, b := first.config, second.config
		if a.CreationTimestamp.Before(&b.CreationTimestamp) {
			return -1
		}
		if b.CreationTimestamp.Before(&a.CreationTimestamp) {
			return 1
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return parsed
}
