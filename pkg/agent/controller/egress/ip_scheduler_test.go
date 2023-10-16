// Copyright 2023 Antrea Authors
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

package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/consistenthash"
	"antrea.io/antrea/pkg/agent/memberlist"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

type fakeMemberlistCluster struct {
	nodes         []string
	hashMap       *consistenthash.Map
	eventHandlers []memberlist.ClusterNodeEventHandler
}

func newFakeMemberlistCluster(nodes []string) *fakeMemberlistCluster {
	hashMap := memberlist.NewNodeConsistentHashMap()
	hashMap.Add(nodes...)
	return &fakeMemberlistCluster{
		nodes:   nodes,
		hashMap: hashMap,
	}
}

func (f *fakeMemberlistCluster) updateNodes(nodes []string) {
	hashMap := memberlist.NewNodeConsistentHashMap()
	hashMap.Add(nodes...)
	f.hashMap = hashMap
	for _, h := range f.eventHandlers {
		h("dummy")
	}
}

func (f *fakeMemberlistCluster) AddClusterEventHandler(h memberlist.ClusterNodeEventHandler) {
	f.eventHandlers = append(f.eventHandlers, h)
}

func (f *fakeMemberlistCluster) AliveNodes() sets.Set[string] {
	return sets.New[string](f.nodes...)
}

func (f *fakeMemberlistCluster) SelectNodeForIP(ip, externalIPPool string, filters ...func(string) bool) (string, error) {
	node := f.hashMap.GetWithFilters(ip, filters...)
	if node == "" {
		return "", memberlist.ErrNoNodeAvailable
	}
	return node, nil
}

func (f *fakeMemberlistCluster) ShouldSelectIP(ip string, pool string, filters ...func(node string) bool) (bool, error) {
	return false, nil
}

func TestSchedule(t *testing.T) {
	egresses := []runtime.Object{
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.1", ExternalIPPool: "pool1"},
		},
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB", CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.11", ExternalIPPool: "pool1"},
		},
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC", CreationTimestamp: metav1.NewTime(time.Unix(3, 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.21", ExternalIPPool: "pool1"},
		},
	}
	tests := []struct {
		name                string
		nodes               []string
		maxEgressIPsPerNode int
		nodeToMaxEgressIPs  map[string]int
		expectedResults     map[string]*scheduleResult
	}{
		{
			name:                "sufficient capacity",
			nodes:               []string{"node1", "node2", "node3"},
			maxEgressIPsPerNode: 3,
			expectedResults: map[string]*scheduleResult{
				"egressA": {
					node: "node1",
					ip:   "1.1.1.1",
				},
				"egressB": {
					node: "node3",
					ip:   "1.1.1.11",
				},
				"egressC": {
					node: "node1",
					ip:   "1.1.1.21",
				},
			},
		},
		{
			name:                "node specific limit",
			nodes:               []string{"node1", "node2", "node3"},
			maxEgressIPsPerNode: 3,
			nodeToMaxEgressIPs: map[string]int{
				"node1": 0,
				"node2": 2,
				"node3": 0,
			},
			expectedResults: map[string]*scheduleResult{
				"egressA": {
					node: "node2",
					ip:   "1.1.1.1",
				},
				"egressB": {
					node: "node2",
					ip:   "1.1.1.11",
				},
				"egressC": {
					err: memberlist.ErrNoNodeAvailable,
				},
			},
		},
		{
			name:                "insufficient node capacity",
			nodes:               []string{"node1", "node2", "node3"},
			maxEgressIPsPerNode: 1,
			// egressC was moved to node2 due to insufficient node capacity.
			expectedResults: map[string]*scheduleResult{
				"egressA": {
					node: "node1",
					ip:   "1.1.1.1",
				},
				"egressB": {
					node: "node3",
					ip:   "1.1.1.11",
				},
				"egressC": {
					node: "node2",
					ip:   "1.1.1.21",
				},
			},
		},
		{
			name:                "insufficient cluster capacity",
			nodes:               []string{"node1", "node3"},
			maxEgressIPsPerNode: 1,
			// egressC was not scheduled to any Node due to insufficient node capacity.
			expectedResults: map[string]*scheduleResult{
				"egressA": {
					node: "node1",
					ip:   "1.1.1.1",
				},
				"egressB": {
					node: "node3",
					ip:   "1.1.1.11",
				},
				"egressC": {
					err: memberlist.ErrNoNodeAvailable,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeCluster := newFakeMemberlistCluster(tt.nodes)
			crdClient := fakeversioned.NewSimpleClientset(egresses...)
			crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
			egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
			clientset := fake.NewSimpleClientset()
			informerFactory := informers.NewSharedInformerFactory(clientset, 0)
			nodeInformer := informerFactory.Core().V1().Nodes()

			s := NewEgressIPScheduler(fakeCluster, egressInformer, nodeInformer, tt.maxEgressIPsPerNode)
			s.nodeToMaxEgressIPs = tt.nodeToMaxEgressIPs
			stopCh := make(chan struct{})
			defer close(stopCh)
			crdInformerFactory.Start(stopCh)
			informerFactory.Start(stopCh)
			crdInformerFactory.WaitForCacheSync(stopCh)
			informerFactory.WaitForCacheSync(stopCh)

			s.schedule()
			assert.Equal(t, tt.expectedResults, s.scheduleResults)
		})
	}
}

func BenchmarkSchedule(b *testing.B) {
	var egresses []runtime.Object
	for i := 0; i < 1000; i++ {
		egresses = append(egresses, &crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("egress-%d", i), UID: types.UID(fmt.Sprintf("uid-%d", i)), CreationTimestamp: metav1.NewTime(time.Unix(int64(i), 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: fmt.Sprintf("1.1.%d.%d", rand.Intn(256), rand.Intn(256)), ExternalIPPool: "pool1"},
		})
	}
	var nodes []string
	for i := 0; i < 1000; i++ {
		nodes = append(nodes, fmt.Sprintf("node-%d", i))
	}
	fakeCluster := newFakeMemberlistCluster(nodes)
	crdClient := fakeversioned.NewSimpleClientset(egresses...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()

	s := NewEgressIPScheduler(fakeCluster, egressInformer, nodeInformer, 10)
	stopCh := make(chan struct{})
	defer close(stopCh)
	crdInformerFactory.Start(stopCh)
	informerFactory.Start(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.schedule()
	}
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	egresses := []runtime.Object{
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA", CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.1", ExternalIPPool: "pool1"},
		},
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB", CreationTimestamp: metav1.NewTime(time.Unix(2, 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.11", ExternalIPPool: "pool1"},
		},
		&crdv1b1.Egress{
			ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC", CreationTimestamp: metav1.NewTime(time.Unix(3, 0))},
			Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.21", ExternalIPPool: "pool1"},
		},
	}
	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "node1",
			Annotations: map[string]string{},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "node2",
			Annotations: map[string]string{},
		},
	}
	fakeCluster := newFakeMemberlistCluster([]string{"node1", "node2"})
	crdClient := fakeversioned.NewSimpleClientset(egresses...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
	clientset := fake.NewSimpleClientset(node1, node2)
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()

	s := NewEgressIPScheduler(fakeCluster, egressInformer, nodeInformer, 2)
	egressUpdates := make(chan string, 10)
	s.AddEventHandler(func(egress string) {
		egressUpdates <- egress
	})
	stopCh := make(chan struct{})
	defer close(stopCh)
	crdInformerFactory.Start(stopCh)
	informerFactory.Start(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	go s.Run(stopCh)

	// The original distribution when the total capacity is sufficient.
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressA", "egressB", "egressC"))
	assertScheduleResult(t, s, "egressA", "1.1.1.1", "node1", true)
	assertScheduleResult(t, s, "egressB", "1.1.1.11", "node2", true)
	assertScheduleResult(t, s, "egressC", "1.1.1.21", "node1", true)

	// After egressA is updated, it should be moved to node2 determined by its consistent hash result.
	patch := map[string]interface{}{
		"spec": map[string]string{
			"egressIP": "1.1.1.5",
		},
	}
	patchBytes, _ := json.Marshal(patch)
	crdClient.CrdV1beta1().Egresses().Patch(context.TODO(), "egressA", types.MergePatchType, patchBytes, metav1.PatchOptions{})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressA"))
	assertScheduleResult(t, s, "egressA", "1.1.1.5", "node2", true)
	assertScheduleResult(t, s, "egressB", "1.1.1.11", "node2", true)
	assertScheduleResult(t, s, "egressC", "1.1.1.21", "node1", true)

	// After node2 leaves, egress A and egressB should be moved to node1 as they were created earlier than egressC.
	// egressC should be left unassigned.
	fakeCluster.updateNodes([]string{"node1"})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressA", "egressB", "egressC"))
	assertScheduleResult(t, s, "egressA", "1.1.1.5", "node1", true)
	assertScheduleResult(t, s, "egressB", "1.1.1.11", "node1", true)
	assertScheduleResult(t, s, "egressC", "", "", false)

	// After egressA is deleted, egressC should be assigned to node1.
	crdClient.CrdV1beta1().Egresses().Delete(ctx, "egressA", metav1.DeleteOptions{})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressA", "egressC"))
	assertScheduleResult(t, s, "egressA", "", "", false)
	assertScheduleResult(t, s, "egressB", "1.1.1.11", "node1", true)
	assertScheduleResult(t, s, "egressC", "1.1.1.21", "node1", true)

	// After egressD is created, it should be left unassigned as the total capacity is insufficient.
	crdClient.CrdV1beta1().Egresses().Create(ctx, &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressD", UID: "uidD", CreationTimestamp: metav1.NewTime(time.Unix(4, 0))},
		Spec:       crdv1b1.EgressSpec{EgressIP: "1.1.1.1", ExternalIPPool: "pool1"},
	}, metav1.CreateOptions{})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressD"))
	assertScheduleResult(t, s, "egressD", "", "", false)

	// After node2 joins, egressB should be moved to node2 determined by its consistent hash result, and egressD should be assigned to node1.
	fakeCluster.updateNodes([]string{"node1", "node2"})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressB", "egressD"))
	assertScheduleResult(t, s, "egressB", "1.1.1.11", "node2", true)
	assertScheduleResult(t, s, "egressC", "1.1.1.21", "node1", true)
	assertScheduleResult(t, s, "egressD", "1.1.1.1", "node1", true)

	// Set node1's max-egress-ips annotation to invalid value, nothing should happen.
	updatedNode1 := node1.DeepCopy()
	updatedNode1.Annotations[agenttypes.NodeMaxEgressIPsAnnotationKey] = "invalid-value"
	clientset.CoreV1().Nodes().Update(ctx, updatedNode1, metav1.UpdateOptions{})
	assertReceivedItems(t, egressUpdates, sets.New[string]())
	// Set node1's max-egress-ips annotation to 1, egressD should be moved to node2.
	updatedNode1 = node1.DeepCopy()
	updatedNode1.Annotations[agenttypes.NodeMaxEgressIPsAnnotationKey] = "1"
	clientset.CoreV1().Nodes().Update(ctx, updatedNode1, metav1.UpdateOptions{})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressD"))
	assertScheduleResult(t, s, "egressD", "1.1.1.1", "node2", true)
	// Unset node1's max-egress-ips annotation, egressD should be moved to node1.
	clientset.CoreV1().Nodes().Update(ctx, node1, metav1.UpdateOptions{})
	assertReceivedItems(t, egressUpdates, sets.New[string]("egressD"))
	assertScheduleResult(t, s, "egressD", "1.1.1.1", "node1", true)
}

func assertReceivedItems(t *testing.T, ch <-chan string, expectedItems sets.Set[string]) {
	t.Helper()
	receivedItems := sets.New[string]()
	for i := 0; i < expectedItems.Len(); i++ {
		select {
		case <-time.After(2 * time.Second):
			t.Fatalf("Timeout getting item #%d from the channel", i)
		case item := <-ch:
			receivedItems.Insert(item)
		}
	}
	assert.Equal(t, expectedItems, receivedItems)

	select {
	case <-time.After(100 * time.Millisecond):
	case item := <-ch:
		t.Fatalf("Got unexpected item %s from the channel", item)
	}
}

func assertScheduleResult(t *testing.T, s *egressIPScheduler, egress, egressIP, egressNode string, scheduled bool) {
	t.Helper()
	gotEgressIP, gotEgressNode, _, gotScheduled := s.GetEgressIPAndNode(egress)
	assert.Equal(t, egressIP, gotEgressIP)
	assert.Equal(t, egressNode, gotEgressNode)
	assert.Equal(t, scheduled, gotScheduled)
}
