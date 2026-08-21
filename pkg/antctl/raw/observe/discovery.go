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
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
)

// flowAggregatorLabelSelector matches every Flow Aggregator Deployment, regardless of Namespace
// or instance name. It is the same selector the flow-aggregator Helm chart applies to its own
// Deployment (`app: flow-aggregator`).
const flowAggregatorLabelSelector = "app=flow-aggregator"

// defaultFlowAggregatorNamespace is used only as a fallback when --flow-aggregator-address
// bypasses discovery and the user did not also set --flow-aggregator-namespace: there is no
// discovered Pod to read a Namespace from, but a Namespace is still needed to fetch the
// flow-aggregator-ca ConfigMap for TLS verification. It is NOT the default for discovery itself
// (see discoverFlowAggregator): that default must remain cluster-wide, otherwise silently
// narrowing the search to this one Namespace could hide a second instance in another Namespace
// entirely, which is exactly the "silently pick one when several exist" behavior multi-instance
// discovery is meant to avoid.
const defaultFlowAggregatorNamespace = "flow-aggregator"

// flowAggregatorTarget identifies a specific Flow Aggregator Pod to connect to.
type flowAggregatorTarget struct {
	namespace string
	podName   string
	podIP     string
}

// discoverFlowAggregator finds a single Flow Aggregator instance to connect to.
//
// namespace, when non-empty, restricts the search to that Namespace; otherwise the search is
// cluster-wide. There is deliberately no "preferred instance" heuristic: each Flow Aggregator
// instance runs its own independent FlowStreamService with no cross-instance relationship (e.g.
// one instance may serve NetOps integration in Proxy mode, another in-cluster visibility in
// Aggregate mode), so silently picking one when several exist would be actively misleading. If
// more than one instance is found (i.e. Pods matching the label selector span more than one
// Namespace), discovery fails and the caller must disambiguate explicitly with --server or
// --flow-aggregator.
func discoverFlowAggregator(ctx context.Context, k8sClient kubernetes.Interface, namespace string) (*flowAggregatorTarget, error) {
	pods, err := k8sClient.CoreV1().Pods(resolveListNamespace(namespace)).List(ctx, metav1.ListOptions{
		LabelSelector: flowAggregatorLabelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("error when listing Flow Aggregator Pods: %w", err)
	}

	running := make([]corev1.Pod, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			running = append(running, pod)
		}
	}
	if len(running) == 0 {
		if namespace != "" {
			return nil, fmt.Errorf("no running Flow Aggregator Pod found in Namespace %q", namespace)
		}
		return nil, fmt.Errorf("no running Flow Aggregator Pod found in the cluster")
	}

	namespaces := sets.New[string]()
	for _, pod := range running {
		namespaces.Insert(pod.Namespace)
	}
	if namespaces.Len() > 1 {
		return nil, fmt.Errorf(
			"found Flow Aggregator instances in multiple Namespaces (%s); use --server <host:port> or --flow-aggregator <namespace>/<deployment-name> to select one",
			strings.Join(sets.List(namespaces), ", "),
		)
	}

	// All remaining Pods are in the same Namespace, i.e. the same instance (possibly with
	// several replicas in Proxy mode). Any one of them serves an equivalent ring buffer view
	// for that instance's own traffic, so picking the first running Pod is not a disambiguation
	// shortcut, just a stable, arbitrary choice among interchangeable replicas.
	pod := running[0]
	return &flowAggregatorTarget{namespace: pod.Namespace, podName: pod.Name, podIP: pod.Status.PodIP}, nil
}

// findFlowAggregatorByName resolves a specific Flow Aggregator instance named by the user via
// --flow-aggregator <namespace>/<deployment-name>, bypassing the discovery search above.
func findFlowAggregatorByName(ctx context.Context, k8sClient kubernetes.Interface, namespace, deploymentName string) (*flowAggregatorTarget, error) {
	deployment, err := k8sClient.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when getting Deployment %s/%s: %w", namespace, deploymentName, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("invalid selector on Deployment %s/%s: %w", namespace, deploymentName, err)
	}
	// We must resolve target to a pod IP because we're using SPDY port-forward
	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("error when listing Pods for Deployment %s/%s: %w", namespace, deploymentName, err)
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			return &flowAggregatorTarget{namespace: pod.Namespace, podName: pod.Name, podIP: pod.Status.PodIP}, nil
		}
	}
	return nil, fmt.Errorf("no running Pod found for Deployment %s/%s", namespace, deploymentName)
}

func resolveListNamespace(namespace string) string {
	if namespace == "" {
		return metav1.NamespaceAll
	}
	return namespace
}
