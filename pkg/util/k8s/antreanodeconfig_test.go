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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

func TestSelectAntreaNodeConfigs(t *testing.T) {
	now := time.Now()
	old := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "z-old", CreationTimestamp: metav1.NewTime(now)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "one"}},
		},
	}
	newer := old.DeepCopy()
	newer.Name, newer.CreationTimestamp = "newer", metav1.NewTime(now.Add(time.Minute))
	tied := old.DeepCopy()
	tied.Name = "a-old"
	terminating := old.DeepCopy()
	terminating.CreationTimestamp = metav1.NewTime(now.Add(-time.Hour))
	terminating.DeletionTimestamp = &terminating.CreationTimestamp
	invalid := old.DeepCopy()
	invalid.Spec.NodeSelector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "pool", Operator: "Invalid"},
	}}
	expression := old.DeepCopy()
	expression.Name = "expression"
	expression.Spec.NodeSelector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "pool", Operator: metav1.LabelSelectorOpIn, Values: []string{"two"}},
	}}
	all := old.DeepCopy()
	all.Name, all.Spec.NodeSelector = "all", metav1.LabelSelector{}
	nodes := []*corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{UID: "one", Labels: map[string]string{"pool": "one"}}},
		{ObjectMeta: metav1.ObjectMeta{UID: "two", Labels: map[string]string{"pool": "two"}}},
		{ObjectMeta: metav1.ObjectMeta{UID: "unlabeled"}},
	}
	for _, tt := range []struct {
		name    string
		configs []*crdv1alpha1.AntreaNodeConfig
		want    []string
	}{
		{name: "no configurations", want: []string{"", "", ""}},
		{name: "oldest wins", configs: []*crdv1alpha1.AntreaNodeConfig{newer, old}, want: []string{"z-old", "", ""}},
		{name: "name breaks timestamp ties", configs: []*crdv1alpha1.AntreaNodeConfig{old, newer, tied}, want: []string{"a-old", "", ""}},
		{
			name:    "skip invalid terminating and nil",
			configs: []*crdv1alpha1.AntreaNodeConfig{nil, terminating, invalid, newer},
			want:    []string{"newer", "", ""},
		},
		{name: "match expressions", configs: []*crdv1alpha1.AntreaNodeConfig{expression, old}, want: []string{"z-old", "expression", ""}},
		{name: "empty selector", configs: []*crdv1alpha1.AntreaNodeConfig{all}, want: []string{"all", "all", "all"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var original []*crdv1alpha1.AntreaNodeConfig
			for _, cfg := range tt.configs {
				original = append(original, cfg.DeepCopy())
			}
			selected := SelectAntreaNodeConfigs(nodes, tt.configs)
			require.Len(t, selected, len(nodes))
			for i, node := range nodes {
				cfg := selected[node.UID]
				if tt.want[i] == "" {
					assert.Nil(t, cfg, "Node %s must have no selected configuration", node.UID)
				} else {
					require.NotNil(t, cfg)
					assert.Equal(t, tt.want[i], cfg.Name)
				}
				matching := MatchingAntreaNodeConfigs(node, tt.configs)
				if len(matching) > 0 {
					assert.Same(t, matching[0], cfg, "Batch selection must agree with the Agent")
				} else {
					assert.Nil(t, cfg)
				}
			}
			assert.Equal(t, original, tt.configs, "Selection must not mutate informer objects or input order")
			assert.Empty(t, SelectAntreaNodeConfigs(nil, tt.configs))
		})
	}
}

func BenchmarkSelectAntreaNodeConfigs(b *testing.B) {
	var configs []*crdv1alpha1.AntreaNodeConfig
	for i := 9; i >= 0; i-- {
		configs = append(configs, &crdv1alpha1.AntreaNodeConfig{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("config-%d", i), CreationTimestamp: metav1.NewTime(time.Unix(int64(i), 0))},
			Spec: crdv1alpha1.AntreaNodeConfigSpec{NodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"pool": "one"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "kubernetes.io/os", Operator: metav1.LabelSelectorOpIn, Values: []string{"linux", "windows"}},
				},
			}},
		})
	}
	var nodes []*corev1.Node
	for i := range 5000 {
		nodes = append(nodes, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			UID: types.UID(fmt.Sprintf("node-%d", i)), Labels: map[string]string{"pool": "one", "kubernetes.io/os": "linux"},
		}})
	}
	b.Run("per-node", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			selected := make(map[types.UID]*crdv1alpha1.AntreaNodeConfig, len(nodes))
			for _, node := range nodes {
				matching := MatchingAntreaNodeConfigs(node, configs)
				selected[node.UID] = matching[0]
			}
		}
	})
	b.Run("batch", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			SelectAntreaNodeConfigs(nodes, configs)
		}
	})
}
