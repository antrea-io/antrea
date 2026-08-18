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
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

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

// flowAggregatorService builds a Flow Aggregator Service selecting Pods labeled app=flow-aggregator,
// carrying the discovery label unless labeled is false.
func flowAggregatorService(namespace, name string, labeled bool) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: map[string]string{"app": "flow-aggregator"}},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "flow-aggregator"}},
	}
	if labeled {
		svc.Labels["observability.antrea.io/flow-stream-service"] = "true"
	}
	return svc
}

func TestDiscoverFlowAggregator(t *testing.T) {
	t.Run("no labeled Service, cluster-wide search", func(t *testing.T) {
		_, err := discoverFlowAggregator(context.Background(), fake.NewSimpleClientset(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no Flow Aggregator Service labeled")
		assert.Contains(t, err.Error(), "in the cluster")
	})

	t.Run("no labeled Service, Namespace-scoped search names the Namespace", func(t *testing.T) {
		_, err := discoverFlowAggregator(context.Background(), fake.NewSimpleClientset(), "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `in Namespace "flow-aggregator"`)
	})

	t.Run("a Flow Aggregator whose Service is not labeled does not serve FlowStreamService", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("proxy-mode", "flow-aggregator", false),
			flowAggregatorPod("proxy-mode", "flow-aggregator-abc", "10.0.0.9", true),
		)
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no Flow Aggregator Service labeled")
	})

	t.Run("Service exists but no Pod behind it is Running with a PodIP", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "", false),
		)
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no running Pod found for Service flow-aggregator/flow-aggregator")
	})

	t.Run("single instance found", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true),
		)
		target, err := discoverFlowAggregator(context.Background(), client, "")
		require.NoError(t, err)
		assert.Equal(t, &flowAggregatorTarget{namespace: "flow-aggregator", serviceName: "flow-aggregator", podName: "flow-aggregator-abc", podIP: "10.0.0.5"}, target)
	})

	t.Run("the labeled instance is found next to one that does not serve FlowStreamService", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true),
			flowAggregatorService("proxy-mode", "flow-aggregator", false),
			flowAggregatorPod("proxy-mode", "flow-aggregator-xyz", "10.0.0.9", true),
		)
		target, err := discoverFlowAggregator(context.Background(), client, "")
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-abc", target.podName)
	})

	t.Run("only Pods running and behind the Service are considered", func(t *testing.T) {
		stray := flowAggregatorPod("flow-aggregator", "stray", "10.0.0.7", true)
		stray.Labels = map[string]string{"app": "something-else"}
		client := fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			stray,
			flowAggregatorPod("flow-aggregator", "flow-aggregator-pending", "", false),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true),
		)
		target, err := discoverFlowAggregator(context.Background(), client, "")
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-abc", target.podName)
	})

	t.Run("instances in multiple Namespaces are ambiguous", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("ns-a", "flow-aggregator", true),
			flowAggregatorService("ns-b", "flow-aggregator", true),
			flowAggregatorPod("ns-a", "flow-aggregator-abc", "10.0.0.5", true),
			flowAggregatorPod("ns-b", "flow-aggregator-def", "10.0.0.6", true),
		)
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "multiple Flow Aggregator instances")
		assert.Contains(t, err.Error(), "ns-a/flow-aggregator, ns-b/flow-aggregator")
		assert.Contains(t, err.Error(), "--flow-aggregator <namespace>/<service-name>")
	})

	t.Run("two instances in the same Namespace are ambiguous too", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("ns-a", "fa-1", true),
			flowAggregatorService("ns-a", "fa-2", true),
		)
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ns-a/fa-1, ns-a/fa-2")
	})

	t.Run("Namespace-scoped search only considers Services in that Namespace", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("ns-a", "flow-aggregator", true),
			flowAggregatorService("ns-b", "flow-aggregator", true),
			flowAggregatorPod("ns-a", "flow-aggregator-abc", "10.0.0.5", true),
			flowAggregatorPod("ns-b", "flow-aggregator-def", "10.0.0.6", true),
		)
		target, err := discoverFlowAggregator(context.Background(), client, "ns-b")
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-def", target.podName)
	})
}

func TestFindFlowAggregatorByName(t *testing.T) {
	t.Run("Service not found", func(t *testing.T) {
		_, err := findFlowAggregatorByName(context.Background(), fake.NewSimpleClientset(), "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error when getting Service flow-aggregator/flow-aggregator")
	})

	t.Run("Service has no selector", func(t *testing.T) {
		svc := flowAggregatorService("flow-aggregator", "flow-aggregator", true)
		svc.Spec.Selector = nil
		_, err := findFlowAggregatorByName(context.Background(), fake.NewSimpleClientset(svc), "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no selector")
	})

	t.Run("Service exists but has no matching running Pod", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "", false),
		)
		_, err := findFlowAggregatorByName(context.Background(), client, "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no running Pod found for Service")
	})

	t.Run("an unlabeled Service can be named explicitly", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("proxy-mode", "flow-aggregator", false),
			flowAggregatorPod("proxy-mode", "flow-aggregator-xyz", "10.0.0.9", true),
		)
		target, err := findFlowAggregatorByName(context.Background(), client, "proxy-mode", "flow-aggregator")
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-xyz", target.podName)
		assert.Equal(t, "flow-aggregator", target.serviceName)
	})

	t.Run("Pods of another Namespace are not considered", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("ns-a", "flow-aggregator", true),
			flowAggregatorPod("ns-b", "flow-aggregator-def", "10.0.0.6", true),
		)
		_, err := findFlowAggregatorByName(context.Background(), client, "ns-a", "flow-aggregator")
		require.Error(t, err)
	})
}

// failingClient returns a client whose requests to list the given resource fail.
func failingClient(resource string, objects ...apiruntime.Object) *fake.Clientset {
	client := fake.NewSimpleClientset(objects...)
	client.PrependReactor("list", resource, func(k8stesting.Action) (bool, apiruntime.Object, error) {
		return true, nil, errors.New("the API server is unavailable")
	})
	return client
}

func TestDiscovery_APIServerFailures(t *testing.T) {
	t.Run("listing the Services fails", func(t *testing.T) {
		_, err := discoverFlowAggregator(context.Background(), failingClient("services"), "")
		require.Error(t, err)
		assert.ErrorContains(t, err, "error when listing Flow Aggregator Services")
		assert.ErrorContains(t, err, "the API server is unavailable")
	})

	t.Run("listing the Pods of a Service fails", func(t *testing.T) {
		client := failingClient("pods", flowAggregatorService("flow-aggregator", "flow-aggregator", true))
		_, err := discoverFlowAggregator(context.Background(), client, "")
		require.Error(t, err)
		assert.ErrorContains(t, err, "error when listing Pods for Service flow-aggregator/flow-aggregator")

		_, err = findFlowAggregatorByName(context.Background(), client, "flow-aggregator", "flow-aggregator")
		require.Error(t, err)
		assert.ErrorContains(t, err, "error when listing Pods for Service flow-aggregator/flow-aggregator")
	})
}

func TestResolveListNamespace(t *testing.T) {
	assert.Equal(t, metav1.NamespaceAll, resolveListNamespace(""))
	assert.Equal(t, "flow-aggregator", resolveListNamespace("flow-aggregator"))
}
