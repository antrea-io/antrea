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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	crdv1a1inf "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
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

func testStaticSecondaryNet() *agentconfig.AgentConfig {
	return &agentconfig.AgentConfig{
		SecondaryNetwork: agentconfig.SecondaryNetworkConfig{
			OVSBridges: []agentconfig.OVSBridgeConfig{
				{BridgeName: "br-static", PhysicalInterfaces: []string{"eth0"}},
			},
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
	c := NewController(ancInf, nodeInf, testLocalNodeName, testStaticSecondaryNet(), rec)
	return &controllerTestEnv{t: t, C: c, Rec: rec, Kube: kube}
}

func (e *controllerTestEnv) loadLocalNode() {
	e.t.Helper()
	e.C.loadLocalNodeFromLister()
}

func (e *controllerTestEnv) recompute() {
	e.t.Helper()
	e.C.recomputeAndNotify()
}

func TestLoadLocalNodeFromLister(t *testing.T) {
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
			env.loadLocalNode()
			env.C.mu.RLock()
			got := env.C.node
			env.C.mu.RUnlock()
			if tc.wantNil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, testLocalNodeName, got.Name)
			}
		})
	}
}

func TestEffectiveSecondaryOVSBridgeReturnsNilBeforeInformerSync(t *testing.T) {
	rec := &notifyRecorder{}
	kube := fake.NewClientset(testWorkerNode())
	nodeInf := informers.NewSharedInformerFactory(kube, 0).Core().V1().Nodes()
	crdClient := fakeversioned.NewSimpleClientset(testANC("a1", "br-anc"))
	crdInf := crdinformers.NewSharedInformerFactory(crdClient, 0).Crd().V1alpha1().AntreaNodeConfigs()

	c := NewController(crdInf, nodeInf, testLocalNodeName, testStaticSecondaryNet(), rec)
	// Informers are not started: caches are unsynced. Static secondary config
	// must not be used while AntreaNodeConfig objects are not yet visible.
	assert.Nil(t, c.EffectiveSecondaryOVSBridge())
}

func TestEffectiveSecondaryOVSBridgeUsesInformerCaches(t *testing.T) {
	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(testANC("a1", "br-anc"))...)
	env.loadLocalNode()

	br := env.C.EffectiveSecondaryOVSBridge()
	require.NotNil(t, br)
	assert.Equal(t, "br-anc", br.BridgeName)
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

	require.Eventually(t, func() bool { return env.Rec.Len() >= 2 }, 2*time.Second, 10*time.Millisecond,
		"label change should trigger another notify")
	last, ok := env.Rec.Last().(*EffectiveSnapshot)
	require.True(t, ok)
	require.NotNil(t, last.SecondaryOVSBridge)
	assert.Equal(t, "br-static", last.SecondaryOVSBridge.BridgeName, "non-matching ANC should fall back to static")
}

func TestNodeEventHandlersNoExtraNotify(t *testing.T) {
	otherNode := func() *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node", Labels: map[string]string{"a": "b"}}}
	}
	// These handlers either no-op before touching the local Node or update c.node
	// without calling recomputeAndNotifyAsync (same labels). All paths are
	// synchronous — no synctest / sleep needed.
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
			name: "OnNodeDelete wrong type ignored",
			act: func(t *testing.T, c *Controller) {
				c.onNodeDelete("not-a-node")
			},
		},
		{
			name: "OnNodeDelete different node ignored",
			act: func(t *testing.T, c *Controller) {
				c.onNodeDelete(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}})
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
	c := NewController(ancInf, nodeInf, testLocalNodeName, testStaticSecondaryNet(), rec)
	runStop := make(chan struct{})
	close(runStop)
	c.Run(runStop)
	assert.Equal(t, 0, rec.Len(), "Run should exit when stopCh is closed before caches sync")
}

func TestOnNodeDeleteTombstone(t *testing.T) {
	env := newControllerTestEnv(t, nil, testWorkerNode(), ancAsRuntime(testANC("a1", "br-anc"))...)
	env.loadLocalNode()
	env.recompute()
	require.Equal(t, 1, env.Rec.Len())

	env.C.onNodeDelete(cache.DeletedFinalStateUnknown{
		Key: testLocalNodeName,
		Obj: testWorkerNode(),
	})

	require.Eventually(t, func() bool { return env.Rec.Len() >= 2 }, 2*time.Second, 10*time.Millisecond)
	env.C.mu.RLock()
	n := env.C.node
	env.C.mu.RUnlock()
	assert.Nil(t, n)
}

func TestRecomputeNotifyFailureStillStoresLastNotified(t *testing.T) {
	rec := &notifyRecorder{fail: true}
	env := newControllerTestEnv(t, rec, testWorkerNode())
	env.loadLocalNode()
	env.recompute()

	env.C.mu.RLock()
	ln := env.C.lastNotified
	env.C.mu.RUnlock()
	require.NotNil(t, ln)
	require.NotNil(t, ln.SecondaryOVSBridge)
	assert.Equal(t, "br-static", ln.SecondaryOVSBridge.BridgeName)
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
	snap, ok := env.Rec.Last().(*EffectiveSnapshot)
	require.True(t, ok)
	require.NotNil(t, snap.SecondaryOVSBridge)
	assert.Equal(t, "br-run", snap.SecondaryOVSBridge.BridgeName)

	close(runStop)
	wg.Wait()
}
