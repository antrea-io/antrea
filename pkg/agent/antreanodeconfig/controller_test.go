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

package antreanodeconfig

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	crdv1a1inf "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1alpha1"
)

const (
	testLocalNodeName = "node-under-test"
	testRoleWorker    = "worker"
)

var testANCBaseTime = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

// notifyRecorder implements channel.Notifier for tests.
type notifyRecorder struct {
	mu   sync.Mutex
	seen []interface{}
	fail bool
}

func (n *notifyRecorder) Notify(e interface{}) bool {
	n.mu.Lock()
	n.seen = append(n.seen, e)
	n.mu.Unlock()
	return !n.fail
}

func (n *notifyRecorder) Len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.seen)
}

func (n *notifyRecorder) Last() interface{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.seen) == 0 {
		return nil
	}
	return n.seen[len(n.seen)-1]
}

func testWorkerNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   testLocalNodeName,
			Labels: map[string]string{"role": testRoleWorker},
		},
	}
}

func testANC(name, bridge string) *crdv1alpha1.AntreaNodeConfig {
	return &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: testANCBaseTime},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": testRoleWorker}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{BridgeName: bridge, PhysicalInterfaces: []crdv1alpha1.OVSPhysicalInterfaceConfig{{Name: "eth1"}}},
				},
			},
		},
	}
}

func ancAsRuntime(anc ...*crdv1alpha1.AntreaNodeConfig) []runtime.Object {
	out := make([]runtime.Object, len(anc))
	for i := range anc {
		out[i] = anc[i]
	}
	return out
}

// startTestInformers runs Node and AntreaNodeConfig informers until stopCh is closed.
// kube is the fake Kubernetes clientset backing nodeInformer; use it to mutate Node
// objects so the informer cache stays consistent with what the controller observes.
func startTestInformers(t *testing.T, node *corev1.Node, ancObjs ...runtime.Object) (
	stopCh chan struct{},
	ancInformer crdv1a1inf.AntreaNodeConfigInformer,
	nodeInformer corev1informers.NodeInformer,
	kube kubernetes.Interface,
) {
	t.Helper()
	stopCh = make(chan struct{})
	crdClient := fakeversioned.NewSimpleClientset(ancObjs...)
	var kubeObjs []runtime.Object
	if node != nil {
		kubeObjs = append(kubeObjs, node)
	}
	kubeClient := fake.NewClientset(kubeObjs...)
	kubeFactory := informers.NewSharedInformerFactory(kubeClient, 0)
	crdFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	nodeInformer = kubeFactory.Core().V1().Nodes()
	ancInformer = crdFactory.Crd().V1alpha1().AntreaNodeConfigs()
	// Eagerly construct SharedIndexInformers so factory Start runs their reflectors.
	_ = nodeInformer.Informer()
	_ = ancInformer.Informer()
	kubeFactory.Start(stopCh)
	crdFactory.Start(stopCh)
	require.Eventually(t, func() bool {
		return nodeInformer.Informer().HasSynced() && ancInformer.Informer().HasSynced()
	}, 5*time.Second, 5*time.Millisecond, "informer caches should sync")
	return stopCh, ancInformer, nodeInformer, kubeClient
}

// controllerTestEnv is a controller wired to synced fake informers. StopCh is closed via t.Cleanup.
type controllerTestEnv struct {
	t    *testing.T
	C    *Controller
	Rec  *notifyRecorder
	Kube kubernetes.Interface
}

// newControllerTestEnv starts informers and constructs a Controller. If rec is nil, a new notifyRecorder is used.
func newControllerTestEnv(t *testing.T, rec *notifyRecorder, node *corev1.Node, ancObjs ...runtime.Object) *controllerTestEnv {
	t.Helper()
	if rec == nil {
		rec = &notifyRecorder{}
	}
	stopCh, ancInf, nodeInf, kube := startTestInformers(t, node, ancObjs...)
	t.Cleanup(func() { close(stopCh) })
	c := NewController(ancInf, nodeInf, testLocalNodeName, rec)
	return &controllerTestEnv{t: t, C: c, Rec: rec, Kube: kube}
}

// drainQueue processes all work items currently queued by informer handlers (for example
// the initial sync after registering handlers on already-synced caches).
func (e *controllerTestEnv) drainQueue() {
	e.t.Helper()
	require.Eventually(e.t, func() bool {
		if e.C.queue.Len() == 0 {
			return true
		}
		if !e.C.processNextWorkItem() {
			return e.C.queue.Len() == 0
		}
		return false
	}, 3*time.Second, 5*time.Millisecond, "workqueue should drain")
}

// loadLocalNode drains queued snapshot work so tests start from a quiet baseline.
func (e *controllerTestEnv) loadLocalNode() {
	e.t.Helper()
	e.drainQueue()
}

func (e *controllerTestEnv) recompute() {
	e.t.Helper()
	e.C.enqueueSnapshot()
	require.True(e.t, e.C.processNextWorkItem())
}

func TestLocalNodeFromLister(t *testing.T) {
	tests := []struct {
		name    string
		node    *corev1.Node
		wantNil bool
	}{
		{name: "local node present", node: testWorkerNode()},
		{name: "local node missing", node: nil, wantNil: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newControllerTestEnv(t, nil, tc.node)
			env.drainQueue()
			got, err := env.C.nodeLister.Get(testLocalNodeName)
			if tc.wantNil {
				require.Error(t, err)
				assert.True(t, apierrors.IsNotFound(err))
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, testLocalNodeName, got.Name)
			}
		})
	}
}

func TestCurrentSnapshotNilBeforeInformerSync(t *testing.T) {
	rec := &notifyRecorder{}
	kube := fake.NewClientset(testWorkerNode())
	nodeInf := informers.NewSharedInformerFactory(kube, 0).Core().V1().Nodes()
	crdClient := fakeversioned.NewSimpleClientset(testANC("a1", "br-anc"))
	crdInf := crdinformers.NewSharedInformerFactory(crdClient, 0).Crd().V1alpha1().AntreaNodeConfigs()

	c := NewController(crdInf, nodeInf, testLocalNodeName, rec)
	// Informers are not started: caches are unsynced.
	assert.Nil(t, c.CurrentSnapshot())
}

func TestCurrentSnapshotUsesInformerCaches(t *testing.T) {
	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(testANC("a1", "br-anc"))...)
	env.drainQueue()

	snap := env.C.CurrentSnapshot()
	require.NotNil(t, snap)
	require.NotNil(t, snap.AntreaNodeConfig)
	require.NotNil(t, snap.AntreaNodeConfig.Spec.SecondaryNetwork)
	require.Len(t, snap.AntreaNodeConfig.Spec.SecondaryNetwork.OVSBridges, 1)
	assert.Equal(t, "br-anc", snap.AntreaNodeConfig.Spec.SecondaryNetwork.OVSBridges[0].BridgeName)
}

func TestRecomputeAndNotifyDedup(t *testing.T) {
	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(testANC("a1", "br-anc"))...)
	env.loadLocalNode()
	env.recompute()
	env.recompute()
	assert.Equal(t, 1, env.Rec.Len(), "identical snapshot should not notify twice")
}

func TestRecomputeAndNotifyOnLabelChange(t *testing.T) {
	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(testANC("a1", "br-anc"))...)
	env.loadLocalNode()
	env.recompute()
	require.Equal(t, 1, env.Rec.Len())

	newNode := testWorkerNode().DeepCopy()
	newNode.Labels = map[string]string{"role": "other"}
	newNode.ResourceVersion = "2"
	_, err := env.Kube.CoreV1().Nodes().Update(context.Background(), newNode, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		n, e := env.C.nodeLister.Get(testLocalNodeName)
		if e != nil || n.Labels["role"] != "other" {
			return false
		}
		for env.C.queue.Len() > 0 {
			if !env.C.processNextWorkItem() {
				break
			}
		}
		return env.Rec.Len() >= 2
	}, 2*time.Second, 10*time.Millisecond,
		"label change should trigger another notify")
	last, ok := env.Rec.Last().(*Snapshot)
	require.True(t, ok)
	require.NotNil(t, last.Node)
	assert.Equal(t, "other", last.Node.Labels["role"], "snapshot should reflect updated Node labels")
	assert.Nil(t, last.AntreaNodeConfig, "ANC matched worker role only; labels no longer match")
}

func TestNodeEventHandlersNoExtraNotify(t *testing.T) {
	otherNode := func() *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node", Labels: map[string]string{"a": "b"}}}
	}
	// Handlers either no-op or enqueue a snapshot reconcile. Drain after each act
	// so queue-driven notifies are applied before asserting counts.
	tests := []struct {
		name string
		act  func(t *testing.T, c *Controller)
	}{
		{
			name: "OnNodeUpdate same labels",
			act: func(t *testing.T, c *Controller) {
				old := testWorkerNode()
				newN := old.DeepCopy()
				newN.ResourceVersion = "2"
				newN.UID = "updated-uid"
				c.onNodeUpdate(old, newN)
			},
		},
		{
			name: "OnNodeAdd ignores other node",
			act: func(t *testing.T, c *Controller) {
				c.onNodeAdd(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}})
			},
		},
		{
			name: "OnNodeUpdate wrong type ignored",
			act: func(t *testing.T, c *Controller) {
				c.onNodeUpdate("not-a-node", testWorkerNode())
			},
		},
		{
			name: "OnNodeUpdate different node ignored",
			act: func(t *testing.T, c *Controller) {
				o := otherNode()
				o2 := o.DeepCopy()
				o2.Labels["c"] = "d"
				c.onNodeUpdate(o, o2)
			},
		},
		{
			name: "OnNodeAdd wrong type ignored",
			act: func(t *testing.T, c *Controller) {
				c.onNodeAdd("not-a-node")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newControllerTestEnv(t, nil, testWorkerNode())
			env.loadLocalNode()
			env.recompute()
			require.Equal(t, 1, env.Rec.Len())
			tc.act(t, env.C)
			env.drainQueue()
			assert.Equal(t, 1, env.Rec.Len())
		})
	}
}

func TestRunReturnsWhenStopClosedWhileCachesNeverSynced(t *testing.T) {
	rec := &notifyRecorder{}
	crdClient := fakeversioned.NewSimpleClientset()
	kubeClient := fake.NewClientset(testWorkerNode())
	kf := informers.NewSharedInformerFactory(kubeClient, 0)
	cf := crdinformers.NewSharedInformerFactory(crdClient, 0)
	nodeInf := kf.Core().V1().Nodes()
	ancInf := cf.Crd().V1alpha1().AntreaNodeConfigs()
	_ = nodeInf.Informer()
	_ = ancInf.Informer()
	// Intentionally do not Start factories: HasSynced stays false.
	c := NewController(ancInf, nodeInf, testLocalNodeName, rec)
	runStop := make(chan struct{})
	close(runStop)
	c.Run(runStop)
	assert.Equal(t, 0, rec.Len(), "Run should exit when stopCh is closed before caches sync")
}

func TestRecomputeNotifyFailureSkipsLastNotifiedUpdate(t *testing.T) {
	rec := &notifyRecorder{fail: true}
	env := newControllerTestEnv(t, rec, testWorkerNode())

	assert.Nil(t, env.C.lastNotified, "lastNotified should reflect last successful notify only")
	require.Error(t, env.C.syncSnapshot(snapshotQueueKey))

	rec.fail = false
	require.NoError(t, env.C.syncSnapshot(snapshotQueueKey))
	require.NotNil(t, env.C.lastNotified)
	require.NotNil(t, env.C.lastNotified.Node)
	assert.Empty(t, env.C.lastNotified.AntreaNodeConfigListError)
}

func TestControllerRunPublishesInitialSnapshot(t *testing.T) {
	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(testANC("a1", "br-run"))...)
	runStop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		env.C.Run(runStop)
	}()

	require.Eventually(t, func() bool { return env.Rec.Len() >= 1 }, 3*time.Second, 10*time.Millisecond)
	snap, ok := env.Rec.Last().(*Snapshot)
	require.True(t, ok)
	require.NotNil(t, snap.AntreaNodeConfig)
	require.NotNil(t, snap.AntreaNodeConfig.Spec.SecondaryNetwork)
	assert.Equal(t, "br-run", snap.AntreaNodeConfig.Spec.SecondaryNetwork.OVSBridges[0].BridgeName)

	close(runStop)
	wg.Wait()
}

func TestCurrentSnapshotOldestMatchWhenMultipleANC(t *testing.T) {
	olderTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newerTS := metav1.NewTime(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	older := testANC("a-older", "br-old")
	older.CreationTimestamp = olderTS
	newer := testANC("a-newer", "br-new")
	newer.CreationTimestamp = newerTS

	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(newer, older)...)
	env.drainQueue()
	snap := env.C.CurrentSnapshot()
	require.NotNil(t, snap)
	require.NotNil(t, snap.AntreaNodeConfig)
	assert.Equal(t, "a-older", snap.AntreaNodeConfig.Name)
	assert.Equal(t, "br-old", snap.AntreaNodeConfig.Spec.SecondaryNetwork.OVSBridges[0].BridgeName)
}

func matchTestNode(labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node1",
			Labels: labels,
		},
	}
}

func matchTestANC(name string, ts time.Time, nodeSelector map[string]string) *crdv1alpha1.AntreaNodeConfig {
	return &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(ts),
		},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{
				MatchLabels: nodeSelector,
			},
		},
	}
}

func TestSelectAntreaNodeConfigsForNode(t *testing.T) {
	node := matchTestNode(map[string]string{"role": "worker", "zone": "us-east"})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(2 * time.Minute)

	anc1 := matchTestANC("anc1", t0, map[string]string{"role": "worker"})
	anc2 := matchTestANC("anc2", t1, map[string]string{"role": "control-plane"})
	anc3 := matchTestANC("anc3", t2, map[string]string{"zone": "us-east"})
	ancInvalidSel := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid"},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "x", Operator: "BadOp", Values: []string{"v"}},
				},
			},
		},
	}

	tests := []struct {
		name      string
		node      *corev1.Node
		configs   []*crdv1alpha1.AntreaNodeConfig
		wantLen   int
		wantOrder []string
	}{
		{
			name:    "nil node",
			node:    nil,
			configs: []*crdv1alpha1.AntreaNodeConfig{anc1},
			wantLen: 0,
		},
		{
			name:    "no configs",
			node:    node,
			configs: nil,
			wantLen: 0,
		},
		{
			name:    "one matching",
			node:    node,
			configs: []*crdv1alpha1.AntreaNodeConfig{anc1},
			wantLen: 1,
		},
		{
			name:    "one non-matching",
			node:    node,
			configs: []*crdv1alpha1.AntreaNodeConfig{anc2},
			wantLen: 0,
		},
		{
			name:      "two matching sorted oldest-first",
			node:      node,
			configs:   []*crdv1alpha1.AntreaNodeConfig{anc3, anc1},
			wantLen:   2,
			wantOrder: []string{"anc1", "anc3"},
		},
		{
			name:    "invalid selector is skipped",
			node:    node,
			configs: []*crdv1alpha1.AntreaNodeConfig{ancInvalidSel, anc1},
			wantLen: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectAntreaNodeConfigsForNode(tc.node, tc.configs)
			require.Len(t, got, tc.wantLen)
			if tc.wantOrder != nil {
				for i, name := range tc.wantOrder {
					assert.Equal(t, name, got[i].Name)
				}
			}
		})
	}
}

func TestSelectAntreaNodeConfigsForNode_TimestampTiebreaker(t *testing.T) {
	node := matchTestNode(map[string]string{"role": "worker"})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ancA := matchTestANC("zzz", t0, map[string]string{"role": "worker"})
	ancB := matchTestANC("aaa", t0, map[string]string{"role": "worker"})

	got := SelectAntreaNodeConfigsForNode(node, []*crdv1alpha1.AntreaNodeConfig{ancA, ancB})
	require.Len(t, got, 2)
	assert.Equal(t, "aaa", got[0].Name, "alphabetically earlier name should sort first")
	assert.Equal(t, "zzz", got[1].Name)
}

func TestOldestMatchingAntreaNodeConfigForNode(t *testing.T) {
	node := matchTestNode(map[string]string{"role": "worker"})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	ancOld := matchTestANC("old", t0, map[string]string{"role": "worker"})
	ancYoung := matchTestANC("young", t1, map[string]string{"role": "worker"})

	assert.Nil(t, OldestMatchingAntreaNodeConfigForNode(nil, []*crdv1alpha1.AntreaNodeConfig{ancOld}))
	assert.Nil(t, OldestMatchingAntreaNodeConfigForNode(node, nil))

	got := OldestMatchingAntreaNodeConfigForNode(node, []*crdv1alpha1.AntreaNodeConfig{ancYoung, ancOld})
	require.NotNil(t, got)
	assert.Equal(t, "old", got.Name)
}
