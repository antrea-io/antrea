//go:build !race
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
	"flag"
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
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
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
	namespaces, networkPolicies, pods := getXLargeScaleWithSmallNamespaces()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, networkPolicies, pods)
}

func getXLargeScaleWithSmallNamespaces() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
	getObjects := func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
		namespace := rand.String(8)
		namespaces = []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		networkPolicies = []runtime.Object{
			newNetworkPolicy(namespace, "default-deny-all", nil, nil, nil, nil, nil),
			newNetworkPolicy(namespace, "np-1", map[string]string{"app-1": "scale-1"}, map[string]string{"app-1": "scale-1"}, nil, nil, nil),
			newNetworkPolicy(namespace, "np-2", map[string]string{"app-2": "scale-2"}, map[string]string{"app-2": "scale-2"}, nil, nil, nil),
		}
		pods = []runtime.Object{
			newPod(namespace, "pod1", map[string]string{"app-1": "scale-1"}),
			newPod(namespace, "pod2", map[string]string{"app-1": "scale-1"}),
			newPod(namespace, "pod3", map[string]string{"app-2": "scale-2"}),
			newPod(namespace, "pod4", map[string]string{"app-2": "scale-2"}),
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods = getXObjects(25000, getObjects)
	return namespaces, networkPolicies, pods
}

func TestInitXLargeScaleWithLargeNamespaces(t *testing.T) {
	namespaces, networkPolicies, pods := getXLargeScaleWithLargeNamespaces()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, networkPolicies, pods)
}

func getXLargeScaleWithLargeNamespaces() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
	getObjects := func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
		namespace := rand.String(8)
		namespaces = []*corev1.Namespace{
			newNamespace(namespace, map[string]string{"app": namespace}),
		}
		networkPolicies = []runtime.Object{
			newNetworkPolicy(namespace, "default-deny-all", nil, nil, nil, nil, nil),
		}
		for i := 0; i < 100; i++ {
			labels := map[string]string{fmt.Sprintf("app-%d", i): fmt.Sprintf("scale-%d", i)}
			networkPolicies = append(networkPolicies, newNetworkPolicy(namespace, fmt.Sprintf("np-%d", i), labels, labels, nil, nil, nil))
			for j := 0; j < 10; j++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", i, j), labels))
			}
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods = getXObjects(100, getObjects)
	return namespaces, networkPolicies, pods
}

/*
TestInitXLargeScaleWithOneNamespaces tests the execution time and the memory usage of computing a scale
of 1 Namespaces, 10k NetworkPolicies, 10k Pods where each network policy selects each pod (applied + ingress).

NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   10000               10.66       1157         30380         20368 5 20368

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithOneNamespace(t *testing.T) {
	namespace, networkPolicies, pods := getXLargeScaleWithOneNamespace()
	testComputeNetworkPolicy(t, 15*time.Second, namespace, networkPolicies, pods)
}

func getXLargeScaleWithOneNamespace() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
	namespace := rand.String(8)
	getObjects := func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
		namespaces = []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		networkPolicies = []runtime.Object{newNetworkPolicy(namespace, "", map[string]string{"app-1": "scale-1"}, map[string]string{"app-1": "scale-1"}, nil, nil, nil)}
		pods = []runtime.Object{newPod(namespace, "", map[string]string{"app-1": "scale-1"})}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods = getXObjects(10000, getObjects)
	return namespaces[0:1], networkPolicies, pods
}

func TestInitXLargeScaleWithNetpolPerPod(t *testing.T) {
	namespace, networkPolicies, pods := getXLargeScaleWithNetpolPerPod()
	testComputeNetworkPolicy(t, 300*time.Second, namespace, networkPolicies, pods)
}

// getXLargeScaleWithNetpolPerPod returns 1 Namespace, 10k Pods, 10k NetworkPolicies.
// 1 NP per Pod, with one ingress rule: each Pod can receive traffic from a single other Pod.
func getXLargeScaleWithNetpolPerPod() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
	namespace := rand.String(8)
	getObjects := func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
		namespaces = []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		app1 := rand.String(8)
		labels1 := map[string]string{"app": fmt.Sprintf("scale-%v", app1)}
		app2 := rand.String(8)
		labels2 := map[string]string{"app": fmt.Sprintf("scale-%v", app2)}
		networkPolicies = []runtime.Object{
			newNetworkPolicy(namespace, "", labels1, labels2, nil, nil, nil),
			newNetworkPolicy(namespace, "", labels2, labels1, nil, nil, nil),
		}
		pods = []runtime.Object{
			newPod(namespace, "", labels1),
			newPod(namespace, "", labels2),
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods = getXObjects(5000, getObjects)
	return namespaces[0:1], networkPolicies, pods
}

func TestInitXLargeScaleWithANNPPerExternalEntity(t *testing.T) {
	namespace, annps, externalEntities := getXLargeScaleWithANNPPerExternalEntity()
	testComputeNetworkPolicy(t, 10*time.Second, namespace, annps, externalEntities)
}

func getXLargeScaleWithANNPPerExternalEntity() (namespaces []*corev1.Namespace, annps []runtime.Object, externalEntities []runtime.Object) {
	namespace := rand.String(8)
	getObjects := func() (namespaces []*corev1.Namespace, annps []runtime.Object, externalEntities []runtime.Object) {
		namespaces = []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		ee1 := rand.String(8)
		labels1 := map[string]string{"ee": fmt.Sprintf("scale-%v", ee1)}
		ee2 := rand.String(8)
		labels2 := map[string]string{"ee": fmt.Sprintf("scale-%v", ee2)}
		annps = []runtime.Object{
			newANNPAppliedToExternalEntity(namespace, "", labels1, labels2, nil, nil, nil),
			newANNPAppliedToExternalEntity(namespace, "", labels2, labels1, nil, nil, nil),
		}
		externalEntities = []runtime.Object{
			newExternalEntity(namespace, "", labels1),
			newExternalEntity(namespace, "", labels2),
		}
		return namespaces, annps, externalEntities
	}
	namespaces, annps, externalEntities = getXObjects(5000, getObjects)
	return namespaces[0:1], annps, externalEntities
}

func TestInitXLargeScaleWithClusterScopedNetpol(t *testing.T) {
	namespaces, networkPolicies, pods := getXLargeScaleWithNetpolPerPod()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces[0:1], networkPolicies, pods)
}

// getXLargeScaleWithClusterScopedNetpol returns 1k Namespace, 100k Pods, 10k NetworkPolicies.
// - 100 Pods, 10 NetworkPolicies per Namespace
// - Each NetworkPolicy selects 100 Pods from 10 Namespaces as peers.
func getXLargeScaleWithClusterScopedNetpol() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
	i := 0
	getObjects := func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
		// There are 100 different namespace labels in total.
		company := fmt.Sprintf("company-%d", i%100)
		i += 1
		namespace := fmt.Sprintf("%v-%v", company, rand.String(8))
		namespaceLabels := map[string]string{"company": company}
		namespaces = []*corev1.Namespace{newNamespace(namespace, namespaceLabels)}
		for j := 0; j < 10; j++ {
			labels := map[string]string{"app": fmt.Sprintf("scale-%d", j)}
			networkPolicies = append(networkPolicies, newNetworkPolicy(namespace, fmt.Sprintf("np-%d", j), labels, labels, namespaceLabels, nil, nil))
			for k := 0; k < 10; k++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", j, k), labels))
			}
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods = getXObjects(1000, getObjects)
	return namespaces, networkPolicies, pods
}

func testComputeNetworkPolicy(t *testing.T, maxExecutionTime time.Duration, namespaces []*corev1.Namespace, networkPolicies []runtime.Object, entities []runtime.Object) {
	disableLogToStderr()

	var k8sObjs, crdObjs []runtime.Object
	for _, obj := range networkPolicies {
		switch policy := obj.(type) {
		case *networkingv1.NetworkPolicy:
			k8sObjs = append(k8sObjs, policy)
		case *v1beta1.NetworkPolicy:
			crdObjs = append(crdObjs, policy)
		}
	}
	for _, obj := range entities {
		switch entity := obj.(type) {
		case *corev1.Pod:
			k8sObjs = append(k8sObjs, entity)
		case *v1alpha2.ExternalEntity:
			crdObjs = append(crdObjs, entity)
		}
	}

	k8sObjs = append(k8sObjs, toRunTimeObjects(namespaces)...)
	_, c := newController(k8sObjs, crdObjs)
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
	c.crdInformerFactory.Start(stopCh)
	go c.groupingInterface.Run(stopCh)
	go c.groupingController.Run(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	cache.WaitForCacheSync(stopCh, c.groupingInterfaceSynced)
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
NAMESPACES   ENTITIES    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
%-12d %-11d %-19d %-10.2f %-12d %-13d %d %d %d
`, len(namespaces), len(entities), len(networkPolicies), float64(executionTime)/float64(time.Second), maxAlloc/1024/1024, totalExecution, networkPolicyEvents, appliedToGroupEvents, networkPolicyEvents)
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
func getXObjects(x int, getObjectsFunc func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, entities []runtime.Object)) (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, entities []runtime.Object) {
	for i := 0; i < x; i++ {
		newNamespaces, newNetworkPolicies, newEntities := getObjectsFunc()
		namespaces = append(namespaces, newNamespaces...)
		networkPolicies = append(networkPolicies, newNetworkPolicies...)
		entities = append(entities, newEntities...)
	}
	return namespaces, networkPolicies, entities
}

func toRunTimeObjects(namespaces []*corev1.Namespace) []runtime.Object {
	objs := make([]runtime.Object, 0, len(namespaces))
	for i := range namespaces {
		objs = append(objs, namespaces[i])
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
	podIP := getRandomIP()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String()), Labels: labels},
		Spec: corev1.PodSpec{
			NodeName:    getRandomNodeName(),
			HostNetwork: false,
		},
		Status: corev1.PodStatus{PodIP: podIP, PodIPs: []corev1.PodIP{{IP: podIP}}},
	}
	return pod
}

func newExternalEntity(namespace, name string, labels map[string]string) *v1alpha2.ExternalEntity {
	if name == "" {
		name = "ee-" + rand.String(8)
	}
	externalEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String()), Labels: labels},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{
					IP: getRandomIP(),
				},
			},
			Ports: []v1alpha2.NamedPort{
				{
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
		},
	}
	return externalEntity
}

func newNetworkPolicy(namespace, name string, podSelector, ingressPodSelector, ingressNamespaceSelector, egressPodSelector, egressNamespaceSelector map[string]string) *networkingv1.NetworkPolicy {
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
	if ingressPodSelector != nil || ingressNamespaceSelector != nil {
		peer := networkingv1.NetworkPolicyPeer{}
		if ingressPodSelector != nil {
			peer.PodSelector = &metav1.LabelSelector{MatchLabels: ingressPodSelector}
		}
		if ingressNamespaceSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: ingressNamespaceSelector}
		}
		policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{peer}}}
	}
	if egressPodSelector != nil || egressNamespaceSelector != nil {
		peer := networkingv1.NetworkPolicyPeer{}
		if egressPodSelector != nil {
			peer.PodSelector = &metav1.LabelSelector{MatchLabels: egressPodSelector}
		}
		if egressNamespaceSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: egressNamespaceSelector}
		}
		policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{peer}}}
	}
	return policy
}

func newANNPAppliedToExternalEntity(namespace, name string, externalEntitySelector, ingressExternalEntitySelector, ingressNamespaceSelector, egressExternalEntitySelector, egressNamespaceSelector map[string]string) *v1beta1.NetworkPolicy {
	if name == "" {
		name = "annp-" + rand.String(8)
	}
	annp := &v1beta1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String())},
		Spec: v1beta1.NetworkPolicySpec{
			AppliedTo: []v1beta1.AppliedTo{
				{
					ExternalEntitySelector: &metav1.LabelSelector{MatchLabels: externalEntitySelector},
				},
			},
		},
	}
	allowAction := v1beta1.RuleActionAllow
	if ingressExternalEntitySelector != nil || ingressNamespaceSelector != nil {
		peer := v1beta1.NetworkPolicyPeer{}
		if ingressExternalEntitySelector != nil {
			peer.ExternalEntitySelector = &metav1.LabelSelector{MatchLabels: ingressExternalEntitySelector}
		}
		if ingressNamespaceSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: ingressNamespaceSelector}
		}
		annp.Spec.Ingress = []v1beta1.Rule{
			{
				Action: &allowAction,
				From:   []v1beta1.NetworkPolicyPeer{peer},
			},
		}
	}
	if egressExternalEntitySelector != nil || egressNamespaceSelector != nil {
		peer := v1beta1.NetworkPolicyPeer{}
		if egressExternalEntitySelector != nil {
			peer.ExternalEntitySelector = &metav1.LabelSelector{MatchLabels: egressExternalEntitySelector}
		}
		if egressNamespaceSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: egressNamespaceSelector}
		}
		annp.Spec.Egress = []v1beta1.Rule{
			{
				Action: &allowAction,
				To:     []v1beta1.NetworkPolicyPeer{peer},
			},
		}
	}
	return annp
}

func BenchmarkSyncAddressGroup(b *testing.B) {
	disableLogToStderr()
	namespace := "default"
	labels := map[string]string{"app-1": "scale-1"}
	getObjects := func() (namespaces []*corev1.Namespace, networkPolicies []runtime.Object, pods []runtime.Object) {
		namespaces = []*corev1.Namespace{newNamespace(namespace, nil)}
		networkPolicies = []runtime.Object{newNetworkPolicy(namespace, "", labels, labels, nil, nil, nil)}
		pods = []runtime.Object{newPod(namespace, "", labels)}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(1000, getObjects)
	objs := toRunTimeObjects(namespaces[0:1])
	objs = append(objs, networkPolicies...)
	objs = append(objs, pods...)
	stopCh := make(chan struct{})
	defer close(stopCh)
	_, c := newController(objs, nil)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.Start(stopCh)
	go c.groupingController.Run(stopCh)
	go c.groupingInterface.Run(stopCh)
	// wait for cache syncs
	// after that, event handlers should have been called to enqueue AppliedToGroups and
	// InternalNetworkPolicies.
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	cache.WaitForCacheSync(stopCh, c.groupingInterfaceSynced)

	for c.appliedToGroupQueue.Len() > 0 {
		key, _ := c.appliedToGroupQueue.Get()
		c.syncAppliedToGroup(key.(string))
		c.appliedToGroupQueue.Done(key)
	}
	for c.internalNetworkPolicyQueue.Len() > 0 {
		key, _ := c.internalNetworkPolicyQueue.Get()
		networkPolicyRef := key.(controlplane.NetworkPolicyReference)
		c.syncInternalNetworkPolicy(&networkPolicyRef)
		c.internalNetworkPolicyQueue.Done(key)
	}
	key, _ := c.addressGroupQueue.Get()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.syncAddressGroup(key.(string))
	}
}

func BenchmarkInitXLargeScaleWithSmallNamespaces(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithSmallNamespaces()
	benchmarkInit(b, namespaces, networkPolicies, pods)
}

func BenchmarkInitXLargeScaleWithLargeNamespaces(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithLargeNamespaces()
	benchmarkInit(b, namespaces, networkPolicies, pods)
}

func BenchmarkInitXLargeScaleWithOneNamespace(b *testing.B) {
	namespace, networkPolicies, pods := getXLargeScaleWithOneNamespace()
	benchmarkInit(b, namespace, networkPolicies, pods)
}

func BenchmarkInitXLargeScaleWithNetpolPerPod(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithNetpolPerPod()
	benchmarkInit(b, namespaces, networkPolicies, pods)
}

func BenchmarkInitXLargeScaleWithANNPPerExternalEntity(b *testing.B) {
	namespace, annps, externalEntities := getXLargeScaleWithANNPPerExternalEntity()
	benchmarkInit(b, namespace, annps, externalEntities)
}

func BenchmarkInitXLargeScaleWithClusterScopedNetpol(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithClusterScopedNetpol()
	benchmarkInit(b, namespaces, networkPolicies, pods)
}

func benchmarkInit(b *testing.B, namespaces []*corev1.Namespace, networkPolicies []runtime.Object, entities []runtime.Object) {
	disableLogToStderr()

	var k8sObjs, crdObjs []runtime.Object
	for _, obj := range networkPolicies {
		switch policy := obj.(type) {
		case *networkingv1.NetworkPolicy:
			k8sObjs = append(k8sObjs, policy)
		case *v1beta1.NetworkPolicy:
			crdObjs = append(crdObjs, policy)
		}
	}
	for _, obj := range entities {
		switch entity := obj.(type) {
		case *corev1.Pod:
			k8sObjs = append(k8sObjs, entity)
		case *v1alpha2.ExternalEntity:
			crdObjs = append(crdObjs, entity)
		}
	}
	k8sObjs = append(k8sObjs, toRunTimeObjects(namespaces)...)

	b.ReportAllocs()
	b.ResetTimer()

	bench := func() {
		b.StopTimer()
		stopCh := make(chan struct{})
		defer close(stopCh)
		_, c := newControllerWithoutEventHandler(k8sObjs, crdObjs)
		c.informerFactory.Start(stopCh)
		c.crdInformerFactory.Start(stopCh)
		go c.groupingInterface.Run(stopCh)
		defer func() {
			c.addressGroupStore.Stop()
			c.appliedToGroupStore.Stop()
			c.internalGroupStore.Stop()
			c.internalNetworkPolicyStore.Stop()
		}()
		c.informerFactory.WaitForCacheSync(stopCh)
		c.crdInformerFactory.WaitForCacheSync(stopCh)
		b.StartTimer()

		for _, namespace := range namespaces {
			c.groupingInterface.AddNamespace(namespace)
		}
		for _, obj := range entities {
			switch entity := obj.(type) {
			case *corev1.Pod:
				c.groupingInterface.AddPod(entity)
			case *v1alpha2.ExternalEntity:
				c.groupingInterface.AddExternalEntity(entity)
			}
		}
		for _, obj := range networkPolicies {
			switch policy := obj.(type) {
			case *networkingv1.NetworkPolicy:
				c.addNetworkPolicy(policy)
			case *v1beta1.NetworkPolicy:
				c.addANNP(policy)
			}
		}
		for c.appliedToGroupQueue.Len() > 0 {
			key, _ := c.appliedToGroupQueue.Get()
			c.syncAppliedToGroup(key.(string))
			c.appliedToGroupQueue.Done(key)
		}
		for c.internalNetworkPolicyQueue.Len() > 0 {
			key, _ := c.internalNetworkPolicyQueue.Get()
			networkPolicyRef := key.(controlplane.NetworkPolicyReference)
			c.syncInternalNetworkPolicy(&networkPolicyRef)
			c.internalNetworkPolicyQueue.Done(key)
		}
		for c.addressGroupQueue.Len() > 0 {
			key, _ := c.addressGroupQueue.Get()
			c.syncAddressGroup(key.(string))
			c.addressGroupQueue.Done(key)
		}
		// We stop the time for deferred functions, even if they should
		// all execute quickly. Note that StopTimer() can be called
		// several times in a row without issue, even if the timer is
		// not restarted in-between.
		b.StopTimer()
	}

	for i := 0; i < b.N; i++ {
		bench()
	}
}

func disableLogToStderr() {
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	klogFlagSet.Parse([]string{"-logtostderr=false"})
}
