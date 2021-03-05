// +build !race

// Copyright 2020 Antrea Authors
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

package networkpolicy

import (
	"context"
	"fmt"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
)

/*
TestInitXLargeScaleWithSmallNamespaces tests the execution time and the memory usage of computing a scale
of 25k Namespaces, 75k NetworkPolicies, 100k Pods. The reference value is:

NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
25000        100000  75000               6.10       1626         519853        208503 166707 208503
25000        100000  75000               5.84       1522         585696        225480 182641 225480
25000        100000  75000               6.42       1708         507003        206149 163293 206149

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithSmallNamespaces(t *testing.T) {
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		networkPolicies := []*networkingv1.NetworkPolicy{
			newNetworkPolicy(namespace, "default-deny-all", nil, nil, nil),
			newNetworkPolicy(namespace, "np-1", map[string]string{"app-1": "scale-1"}, map[string]string{"app-1": "scale-1"}, nil),
			newNetworkPolicy(namespace, "np-2", map[string]string{"app-2": "scale-2"}, map[string]string{"app-2": "scale-2"}, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "pod1", map[string]string{"app-1": "scale-1"}),
			newPod(namespace, "pod2", map[string]string{"app-1": "scale-1"}),
			newPod(namespace, "pod3", map[string]string{"app-2": "scale-2"}),
			newPod(namespace, "pod4", map[string]string{"app-2": "scale-2"}),
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(25000, getObjects)
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, networkPolicies, pods)
}

/*
TestInitXLargeScaleWithOneNamespaces tests the execution time and the memory usage of computing a scale
of 1 Namespaces, 10k NetworkPolicies, 10k Pods where each network policy selects each pod (applied + ingress).

NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   10000               10.66       1157         30380         20368 5 20368

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithOneNamespace(t *testing.T) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		networkPolicies := []*networkingv1.NetworkPolicy{newNetworkPolicy(namespace, "", map[string]string{"app-1": "scale-1"}, map[string]string{"app-1": "scale-1"}, nil)}
		pods := []*corev1.Pod{newPod(namespace, "", map[string]string{"app-1": "scale-1"})}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(10000, getObjects)
	testComputeNetworkPolicy(t, 15*time.Second, namespaces[0:1], networkPolicies, pods)
}

func testComputeNetworkPolicy(t *testing.T, maxExecutionTime time.Duration, namespaces []*corev1.Namespace, networkPolicies []*networkingv1.NetworkPolicy, pods []*corev1.Pod) {
	objs := toRunTimeObjects(namespaces, networkPolicies, pods)
	_, c := newController(objs...)
	c.heartbeatCh = make(chan heartbeat, 1000)

	stopCh := make(chan struct{})

	// executionMetric is used to count the executions of each routine and to record the last execution time.
	type executionMetric struct {
		executions    int
		lastExecution time.Time
	}
	executionMetrics := map[string]*executionMetric{}

	// If we don't receive any heartbeat from NetworkPolicyController for 3 seconds, it means all computation
	// finished 3 seconds ago.
	idleTimeout := 3 * time.Second
	timer := time.NewTimer(idleTimeout)
	go func() {
		for {
			timer.Reset(idleTimeout)
			select {
			case heartbeat := <-c.heartbeatCh:
				m, ok := executionMetrics[heartbeat.name]
				if !ok {
					m = &executionMetric{}
					executionMetrics[heartbeat.name] = m
				}
				m.executions++
				m.lastExecution = heartbeat.timestamp
			case <-timer.C:
				// Send the stop signal if we don't receive any heartbeat for 3 seconds.
				close(stopCh)
				return
			}
		}
	}()

	var wg sync.WaitGroup

	// Stat how many events we will get during the computation.
	var addressGroupEvents, appliedToGroupEvents, networkPolicyEvents int32
	wg.Add(1)
	go func() {
		statEvents(c, &addressGroupEvents, &appliedToGroupEvents, &networkPolicyEvents, stopCh)
		wg.Done()
	}()

	// Stat the maximum heap allocation.
	var maxAlloc uint64
	wg.Add(1)
	go func() {
		statMaxMemAlloc(&maxAlloc, 500*time.Millisecond, stopCh)
		wg.Done()
	}()

	// Everything is ready, now start timing.
	start := time.Now()
	c.informerFactory.Start(stopCh)
	go c.Run(stopCh)

	// Block until all computation is done.
	<-stopCh
	// Minus the idle time to get the actual execution time.
	executionTime := time.Since(start) - idleTimeout
	if executionTime > maxExecutionTime {
		t.Errorf("The actual execution time %v is greater than the maximum value %v", executionTime, maxExecutionTime)
	}
	totalExecution := 0
	for name, m := range executionMetrics {
		t.Logf("Execution metrics of %s, executions: %d, duration: %v", name, m.executions, m.lastExecution.Sub(start))
		totalExecution += m.executions
	}

	// Block until all statistics are done.
	wg.Wait()

	t.Logf(`Summary metrics:
NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
%-12d %-7d %-19d %-10.2f %-12d %-13d %d %d %d
`, len(namespaces), len(pods), len(networkPolicies), float64(executionTime)/float64(time.Second), maxAlloc/1024/1024, totalExecution, networkPolicyEvents, appliedToGroupEvents, networkPolicyEvents)
}

func statEvents(c *networkPolicyController, addressGroupEvents, appliedToGroupEvents, networkPolicyEvents *int32, stopCh chan struct{}) {
	addressGroupWatcher, _ := c.addressGroupStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	appliedToGroupWatcher, _ := c.appliedToGroupStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	networkPolicyWatcher, _ := c.internalNetworkPolicyStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	for {
		select {
		case <-addressGroupWatcher.ResultChan():
			*addressGroupEvents++
		case <-appliedToGroupWatcher.ResultChan():
			*appliedToGroupEvents++
		case <-networkPolicyWatcher.ResultChan():
			*networkPolicyEvents++
		case <-stopCh:
			return
		}
	}
}

func statMaxMemAlloc(maxAlloc *uint64, interval time.Duration, stopCh chan struct{}) {
	var memStats goruntime.MemStats
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			goruntime.ReadMemStats(&memStats)
			if memStats.Alloc > *maxAlloc {
				*maxAlloc = memStats.Alloc
			}
		case <-stopCh:
			return
		}
	}
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func getRandomNodeName() string {
	return fmt.Sprintf("Node-%d", rand.Intn(1000))
}

// getXObjects calls the provided getObjectsFunc x times and aggregate the objects.
func getXObjects(x int, getObjectsFunc func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod)) ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	var namespaces []*corev1.Namespace
	var networkPolicies []*networkingv1.NetworkPolicy
	var pods []*corev1.Pod
	for i := 0; i < x; i++ {
		newNamespaces, newNetworkPolicies, newPods := getObjectsFunc()
		namespaces = append(namespaces, newNamespaces...)
		networkPolicies = append(networkPolicies, newNetworkPolicies...)
		pods = append(pods, newPods...)
	}
	return namespaces, networkPolicies, pods
}

func toRunTimeObjects(namespaces []*corev1.Namespace, networkPolicies []*networkingv1.NetworkPolicy, pods []*corev1.Pod) []runtime.Object {
	objs := make([]runtime.Object, 0, len(namespaces)+len(networkPolicies)+len(pods))
	for i := range namespaces {
		objs = append(objs, namespaces[i])
	}
	for i := range networkPolicies {
		objs = append(objs, networkPolicies[i])
	}
	for i := range pods {
		objs = append(objs, pods[i])
	}
	return objs
}

func newNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
}

func newPod(namespace, name string, labels map[string]string) *corev1.Pod {
	if name == "" {
		name = "pod-" + rand.String(8)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String()), Labels: labels},
		Spec:       corev1.PodSpec{NodeName: getRandomNodeName()},
		Status:     corev1.PodStatus{PodIP: getRandomIP()},
	}
	return pod
}

func newNetworkPolicy(namespace, name string, podSelector, ingressPodSelector, egressPodSelector map[string]string) *networkingv1.NetworkPolicy {
	if name == "" {
		name = "np-" + rand.String(8)
	}
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String())},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podSelector},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	if ingressPodSelector != nil {
		policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: ingressPodSelector,
						},
					},
				},
			},
		}
	}
	if egressPodSelector != nil {
		policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
			{
				To: []networkingv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: egressPodSelector,
						},
					},
				},
			},
		}
	}
	return policy
}

func BenchmarkSyncAddressGroup(b *testing.B) {
	namespace := "default"
	labels := map[string]string{"app-1": "scale-1"}
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespaces := []*corev1.Namespace{newNamespace(namespace, nil)}
		networkPolicies := []*networkingv1.NetworkPolicy{newNetworkPolicy(namespace, "", labels, labels, nil)}
		pods := []*corev1.Pod{newPod(namespace, "", labels)}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(1000, getObjects)
	objs := toRunTimeObjects(namespaces[0:1], networkPolicies, pods)
	stopCh := make(chan struct{})
	defer close(stopCh)
	_, c := newController(objs...)
	c.informerFactory.Start(stopCh)

	for c.appliedToGroupQueue.Len() > 0 {
		key, _ := c.appliedToGroupQueue.Get()
		c.syncAppliedToGroup(key.(string))
		c.appliedToGroupQueue.Done(key)
	}
	for c.internalNetworkPolicyQueue.Len() > 0 {
		key, _ := c.internalNetworkPolicyQueue.Get()
		c.syncInternalNetworkPolicy(key.(string))
		c.internalNetworkPolicyQueue.Done(key)
	}
	key, _ := c.addressGroupQueue.Get()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.syncAddressGroup(key.(string))
	}
}
