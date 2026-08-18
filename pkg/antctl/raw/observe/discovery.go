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
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// flowStreamServiceLabelSelector matches the Service of every Flow Aggregator that serves
// FlowStreamService. The flow-aggregator Helm chart sets this label on the Service only when
// flowStreamService is enabled, because a cluster can run several Flow Aggregators and only some of
// them serve it (e.g. one in Proxy mode for IPFIX export does not).
const flowStreamServiceLabelSelector = "observability.antrea.io/flow-stream-service=true"

// flowAggregatorTarget identifies a specific Flow Aggregator Pod to connect to, and the Service
// that selected it.
type flowAggregatorTarget struct {
	namespace   string
	serviceName string
	podName     string
	podIP       string
}

// discoverFlowAggregator finds the single Flow Aggregator instance that serves FlowStreamService,
// by looking for Services carrying flowStreamServiceLabelSelector.
//
// namespace, when non-empty, restricts the search to that Namespace; otherwise the search is
// cluster-wide. There is deliberately no "preferred instance" heuristic, silently picking one when
// several exist would be actively misleading. If more than one Service is found, discovery fails
// and the caller must pick one explicitly with --flow-aggregator.
func discoverFlowAggregator(ctx context.Context, k8sClient kubernetes.Interface, namespace string) (*flowAggregatorTarget, error) {
	services, err := k8sClient.CoreV1().Services(resolveListNamespace(namespace)).List(ctx, metav1.ListOptions{
		LabelSelector: flowStreamServiceLabelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("error when listing Flow Aggregator Services: %w", err)
	}

	switch len(services.Items) {
	case 0:
		where := "in the cluster"
		if namespace != "" {
			where = fmt.Sprintf("in Namespace %q", namespace)
		}
		return nil, fmt.Errorf("no Flow Aggregator Service labeled %s found %s: is the Flow Aggregator's "+
			"flowStreamService enabled? Use --flow-aggregator <namespace>/<service-name> or "+
			"--flow-aggregator-address to select one that is not labeled", flowStreamServiceLabelSelector, where)
	case 1:
		return targetForService(ctx, k8sClient, &services.Items[0])
	default:
		names := make([]string, 0, len(services.Items))
		for _, svc := range services.Items {
			names = append(names, svc.Namespace+"/"+svc.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("found multiple Flow Aggregator instances serving FlowStreamService (%s); "+
			"use --flow-aggregator <namespace>/<service-name> to select one", strings.Join(names, ", "))
	}
}

// findFlowAggregatorByName resolves a specific Flow Aggregator instance named by the user via
// --flow-aggregator <namespace>/<service-name>, bypassing the discovery search above. The Service
// is not required to carry the discovery label: naming it is the user's own assertion that it
// serves FlowStreamService.
func findFlowAggregatorByName(ctx context.Context, k8sClient kubernetes.Interface, namespace, serviceName string) (*flowAggregatorTarget, error) {
	svc, err := k8sClient.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when getting Service %s/%s: %w", namespace, serviceName, err)
	}
	return targetForService(ctx, k8sClient, svc)
}

// targetForService resolves a Flow Aggregator Service to one of the Pods backing it. The Pod, not
// the Service, is the target, because the tunnel fallback is a port-forward to a Pod.
func targetForService(ctx context.Context, k8sClient kubernetes.Interface, svc *corev1.Service) (*flowAggregatorTarget, error) {
	if len(svc.Spec.Selector) == 0 {
		return nil, fmt.Errorf("Service %s/%s has no selector, so there is no Pod to connect to", svc.Namespace, svc.Name)
	}
	pods, err := k8sClient.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(svc.Spec.Selector).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("error when listing Pods for Service %s/%s: %w", svc.Namespace, svc.Name, err)
	}
	// There should always be a single pod for a flow aggregator. However, any running Pod behind the Service
	// serves an equivalent ring buffer view, so picking the first is a valid choice even if we end up finding
	// multiple pods (if this happens during a rolling update, then though luck, the connection might fail)
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			return &flowAggregatorTarget{namespace: pod.Namespace, serviceName: svc.Name, podName: pod.Name, podIP: pod.Status.PodIP}, nil
		}
	}
	return nil, fmt.Errorf("no running Pod found for Service %s/%s", svc.Namespace, svc.Name)
}

func resolveListNamespace(namespace string) string {
	if namespace == "" {
		return metav1.NamespaceAll
	}
	return namespace
}
