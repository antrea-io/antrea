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

package secondarynetwork

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/workqueue"

	agenttypes "antrea.io/antrea/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha1listers "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

// fakeANCListerBase is used by both init_test.go (cross-platform) and
// init_linux_test.go. It is defined here under the build tag "!linux" to
// avoid a duplicate-definition compile error when both files are compiled
// together on Linux (where init_linux_test.go also defines fakeANCLister).
// On non-Linux platforms init_linux_test.go is excluded, so we define it here.

// ancListerStub is shared between init_test.go and init_linux_test.go.
// To avoid the duplicate symbol issue on Linux (where both test files are
// compiled together), we embed the lister as an unexported type and expose
// only what we need through the helper functions below.
type sharedANCLister struct {
	items []*crdv1alpha1.AntreaNodeConfig
	err   error
}

func (f *sharedANCLister) List(_ labels.Selector) ([]*crdv1alpha1.AntreaNodeConfig, error) {
	return f.items, f.err
}

func (f *sharedANCLister) Get(name string) (*crdv1alpha1.AntreaNodeConfig, error) {
	for _, item := range f.items {
		if item.Name == name {
			return item, nil
		}
	}
	return nil, nil
}

var _ crdv1alpha1listers.AntreaNodeConfigLister = (*sharedANCLister)(nil)

// ---- helpers ----

func makeTestNode(lbls map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: lbls}}
}

func makeTestANC(name string, ts time.Time, matchLabels map[string]string, secNet *crdv1alpha1.SecondaryNetworkConfig) *crdv1alpha1.AntreaNodeConfig {
	return &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(ts)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector:     metav1.LabelSelector{MatchLabels: matchLabels},
			SecondaryNetwork: secNet,
		},
	}
}

var ancTime0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestResolveEffectiveBridgeConfig(t *testing.T) {
	staticCfg := &agentconfig.SecondaryNetworkConfig{
		OVSBridges: []agentconfig.OVSBridgeConfig{
			{BridgeName: "br-static", PhysicalInterfaces: []string{"eth0"}},
		},
	}
	emptyCfg := &agentconfig.SecondaryNetworkConfig{}

	workerNode := makeTestNode(map[string]string{"role": "worker"})

	ancMatchingWithBridge := makeTestANC("anc1", ancTime0, map[string]string{"role": "worker"}, &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{
			{
				BridgeName: "br-anc",
				PhysicalInterfaces: []crdv1alpha1.PhysicalInterfaceConfig{
					{Name: "eth1", AllowedVLANs: []string{"100"}},
				},
			},
		},
	})
	ancMatchingNoBridge := makeTestANC("anc2", ancTime0, map[string]string{"role": "worker"}, &crdv1alpha1.SecondaryNetworkConfig{})
	ancNonMatching := makeTestANC("anc3", ancTime0, map[string]string{"role": "control-plane"}, &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: "br-other"}},
	})

	tests := []struct {
		name       string
		node       *corev1.Node
		ancLister  crdv1alpha1listers.AntreaNodeConfigLister
		staticCfg  *agentconfig.SecondaryNetworkConfig
		wantBridge *agenttypes.OVSBridgeConfig
	}{
		{
			name:      "rule 1: no ANCLister, use static config",
			node:      workerNode,
			ancLister: nil,
			staticCfg: staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{
				BridgeName:         "br-static",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}},
			},
		},
		{
			name:      "rule 1: no matching ANC, use static config",
			node:      workerNode,
			ancLister: &sharedANCLister{items: []*crdv1alpha1.AntreaNodeConfig{ancNonMatching}},
			staticCfg: staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{
				BridgeName:         "br-static",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}},
			},
		},
		{
			name:       "rule 1: empty static config and no matching ANC",
			node:       workerNode,
			ancLister:  &sharedANCLister{items: []*crdv1alpha1.AntreaNodeConfig{ancNonMatching}},
			staticCfg:  emptyCfg,
			wantBridge: nil,
		},
		{
			name:      "rule 2: matching ANC overrides static config",
			node:      workerNode,
			ancLister: &sharedANCLister{items: []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge}},
			staticCfg: staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{
				BridgeName: "br-anc",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: "eth1", AllowedVLANs: []string{"100"}},
				},
			},
		},
		{
			name:       "rule 2: matching ANC with no bridge yields nil",
			node:       workerNode,
			ancLister:  &sharedANCLister{items: []*crdv1alpha1.AntreaNodeConfig{ancMatchingNoBridge}},
			staticCfg:  staticCfg,
			wantBridge: nil,
		},
		{
			name:      "nil node falls back to static config",
			node:      nil,
			ancLister: &sharedANCLister{items: []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge}},
			staticCfg: staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{
				BridgeName:         "br-static",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveEffectiveBridgeConfig(tc.node, tc.ancLister, tc.staticCfg)
			if tc.wantBridge == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tc.wantBridge.BridgeName, got.BridgeName)
				assert.Equal(t, tc.wantBridge.EnableMulticastSnooping, got.EnableMulticastSnooping)
				assert.Equal(t, tc.wantBridge.PhysicalInterfaces, got.PhysicalInterfaces)
			}
		})
	}
}

func TestOnNodeUpdate(t *testing.T) {
	workerLabels := map[string]string{"role": "worker"}
	otherLabels := map[string]string{"role": "other"}

	tests := []struct {
		name           string
		oldLabels      map[string]string
		newLabels      map[string]string
		nodeName       string
		wantEnqueued   bool
		wantNodeUpdate bool
	}{
		{
			name:           "same labels on local node — no enqueue",
			oldLabels:      workerLabels,
			newLabels:      workerLabels,
			nodeName:       "node1",
			wantEnqueued:   false,
			wantNodeUpdate: false,
		},
		{
			name:           "labels changed on local node — enqueue",
			oldLabels:      workerLabels,
			newLabels:      otherLabels,
			nodeName:       "node1",
			wantEnqueued:   true,
			wantNodeUpdate: true,
		},
		{
			name:           "labels changed on different node — no enqueue",
			oldLabels:      workerLabels,
			newLabels:      otherLabels,
			nodeName:       "other-node",
			wantEnqueued:   false,
			wantNodeUpdate: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: tc.oldLabels}}
			newNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: tc.newLabels}}

			c := &Controller{
				nodeName:     tc.nodeName,
				node:         oldNode,
				secNetConfig: &agentconfig.SecondaryNetworkConfig{},
				queue:        newTestQueue(),
			}
			c.onNodeUpdate(oldNode, newNode)

			if tc.wantEnqueued {
				assert.Equal(t, 1, c.queue.Len(), "expected item in queue")
			} else {
				assert.Equal(t, 0, c.queue.Len(), "expected empty queue")
			}
			if tc.wantNodeUpdate {
				c.mu.RLock()
				assert.Equal(t, newNode, c.node)
				c.mu.RUnlock()
			}
		})
	}
}

// newTestQueue returns a simple rate-limiting queue for testing.
func newTestQueue() workqueue.TypedRateLimitingInterface[string] {
	return workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
}

// fakePodController implements podControllerInterface for unit tests.
// It records calls to UpdateOVSBridge so tests can assert on them.
type fakePodController struct {
	updateBridgeCalls []ovsconfig.OVSBridgeClient
	updateBridgeErr   error
}

func (f *fakePodController) Run(_ <-chan struct{}) {}

func (f *fakePodController) AllowCNIDelete(_, _ string) bool { return true }

func (f *fakePodController) UpdateOVSBridge(c ovsconfig.OVSBridgeClient) error {
	f.updateBridgeCalls = append(f.updateBridgeCalls, c)
	return f.updateBridgeErr
}
