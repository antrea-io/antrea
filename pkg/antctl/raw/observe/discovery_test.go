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

package observe

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func flowAggregatorPod(namespace, name, ip string, running bool) *corev1.Pod {
	phase := corev1.PodRunning
	if !running {
		phase = corev1.PodPending
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{"app": "flow-aggregator"},
		},
		Status: corev1.PodStatus{Phase: phase, PodIP: ip},
	}
}

func TestDiscoverFlowAggregator(t *testing.T) {
	t.Run("no Pods at all, cluster-wide search", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no running Flow Aggregator Pod found in the cluster")
	})

	t.Run("no Pods at all, Namespace-scoped search names the Namespace", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := discoverFlowAggregator(context.Background(), client, "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `no running Flow Aggregator Pod found in Namespace "flow-aggregator"`)
	})

	t.Run("Pods exist but none are Running with a PodIP", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorPod("flow-aggregator", "flow-aggregator-1", "10.0.0.5", false),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-2", "", true),
		)
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no running Flow Aggregator Pod found")
	})

	t.Run("single instance found", func(t *testing.T) {
		client := fake.NewSimpleClientset(flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true))
		target, err := discoverFlowAggregator(context.Background(), client, "")
		require.NoError(t, err)
		assert.Equal(t, &flowAggregatorTarget{namespace: "flow-aggregator", podName: "flow-aggregator-abc", podIP: "10.0.0.5"}, target)
	})

	t.Run("multiple replicas of the same instance (same Namespace) is not ambiguous", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorPod("flow-aggregator", "flow-aggregator-1", "10.0.0.5", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-2", "10.0.0.6", true),
		)
		target, err := discoverFlowAggregator(context.Background(), client, "")
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator", target.namespace)
	})

	t.Run("instances in multiple Namespaces are ambiguous", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorPod("flow-aggregator-1", "flow-aggregator", "10.0.0.5", true),
			flowAggregatorPod("flow-aggregator-2", "flow-aggregator", "10.0.0.6", true),
		)
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "found Flow Aggregator instances in multiple Namespaces")
		assert.Contains(t, err.Error(), "--flow-aggregator")
	})

	t.Run("Namespace-scoped search only considers Pods in that Namespace", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorPod("flow-aggregator-1", "flow-aggregator", "10.0.0.5", true),
			flowAggregatorPod("flow-aggregator-2", "flow-aggregator", "10.0.0.6", true),
		)
		target, err := discoverFlowAggregator(context.Background(), client, "flow-aggregator-2")
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-2", target.namespace)
		assert.Equal(t, "10.0.0.6", target.podIP)
	})
}

func TestFindFlowAggregatorByName(t *testing.T) {
	t.Run("Deployment not found", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := findFlowAggregatorByName(context.Background(), client, "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error when getting Deployment")
	})

	t.Run("Deployment exists but has no matching running Pod", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "flow-aggregator", Name: "flow-aggregator"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "flow-aggregator"}},
			},
		}
		client := fake.NewSimpleClientset(deployment)
		_, err := findFlowAggregatorByName(context.Background(), client, "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no running Pod found for Deployment")
	})

	t.Run("Deployment exists with an invalid selector", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "flow-aggregator", Name: "flow-aggregator"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: "InvalidOperator", Values: []string{"flow-aggregator"}},
				}},
			},
		}
		client := fake.NewSimpleClientset(deployment)
		_, err := findFlowAggregatorByName(context.Background(), client, "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid selector")
	})

	t.Run("successful match", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "flow-aggregator-1", Name: "flow-aggregator-1"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "flow-aggregator"}},
			},
		}
		pod := flowAggregatorPod("flow-aggregator-1", "flow-aggregator-1-xyz", "10.0.0.9", true)
		client := fake.NewSimpleClientset(deployment, pod)
		target, err := findFlowAggregatorByName(context.Background(), client, "flow-aggregator-1", "flow-aggregator-1")
		require.NoError(t, err)
		assert.Equal(t, &flowAggregatorTarget{namespace: "flow-aggregator-1", podName: "flow-aggregator-1-xyz", podIP: "10.0.0.9"}, target)
	})

	t.Run("Deployment's own Namespace is not considered when listing Pods for another", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "flow-aggregator-1", Name: "flow-aggregator-1"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "flow-aggregator"}},
			},
		}
		// Same label, wrong Namespace: must not be picked up.
		pod := flowAggregatorPod("flow-aggregator-2", "flow-aggregator-2-xyz", "10.0.0.9", true)
		client := fake.NewSimpleClientset(deployment, pod)
		_, err := findFlowAggregatorByName(context.Background(), client, "flow-aggregator-1", "flow-aggregator-1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no running Pod found for Deployment")
	})
}

func TestResolveListNamespace(t *testing.T) {
	assert.Equal(t, metav1.NamespaceAll, resolveListNamespace(""))
	assert.Equal(t, "flow-aggregator", resolveListNamespace("flow-aggregator"))
}
