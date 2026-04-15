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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/util/channel"
)

const ancBridgeTestLocalNodeName = "node1"

// fakeANCController mirrors egress.fakeController: fake clients and informer factories
// around a real *antreanodeconfig.Controller. Call start from within t.Run after construction
// so informers and Run lifetimes match the subtest (see egress_controller_test.go).
type fakeANCController struct {
	*antreanodeconfig.Controller

	crdInformerFactory  crdinformers.SharedInformerFactory
	kubeInformerFactory informers.SharedInformerFactory

	stopCh      chan struct{}
	fixtureNode *corev1.Node
}

// newANCBridgeTestNotifier mirrors cniserver.newAsyncWaiter: a SubscribableChannel implements
// channel.Notifier and must have Run started so Notify does not block when the buffer fills.
func newANCBridgeTestNotifier(stopCh chan struct{}) *channel.SubscribableChannel {
	n := channel.NewSubscribableChannel("ANCBridgeTest", 100)
	n.Subscribe(func(interface{}) {})
	go n.Run(stopCh)
	return n
}

// newFakeANCController wires fake Node + AntreaNodeConfig API objects and informers like
// egress.newFakeController; it does not start informers or Run until start is called.
func newFakeANCController(t *testing.T, node *corev1.Node, ancObjs []*crdv1alpha1.AntreaNodeConfig) *fakeANCController {
	t.Helper()
	rt := make([]runtime.Object, len(ancObjs))
	for i := range ancObjs {
		rt[i] = ancObjs[i]
	}
	stopCh := make(chan struct{})
	notifier := newANCBridgeTestNotifier(stopCh)
	crdClient := fakeversioned.NewSimpleClientset(rt...)
	var kubeObjs []runtime.Object
	if node != nil {
		kubeObjs = append(kubeObjs, node)
	}
	kubeClient := fake.NewClientset(kubeObjs...)
	kubeFactory := informers.NewSharedInformerFactory(kubeClient, 0)
	crdFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	nodeInformer := kubeFactory.Core().V1().Nodes()
	ancInformer := crdFactory.Crd().V1alpha1().AntreaNodeConfigs()
	_ = nodeInformer.Informer()
	_ = ancInformer.Informer()
	c := antreanodeconfig.NewController(ancInformer, nodeInformer, ancBridgeTestLocalNodeName, notifier)
	return &fakeANCController{
		Controller:          c,
		crdInformerFactory:  crdFactory,
		kubeInformerFactory: kubeFactory,
		stopCh:              stopCh,
		fixtureNode:         node,
	}
}

// start starts informer factories, runs the AntreaNodeConfig controller, and waits until
// CurrentSnapshot reflects fixtureNode (non-nil Node object in API → non-nil snap.Node;
// nil fixture node → snap.Node nil after Run).
func (f *fakeANCController) start(t *testing.T) {
	t.Helper()
	f.kubeInformerFactory.Start(f.stopCh)
	f.crdInformerFactory.Start(f.stopCh)
	nodeInformer := f.kubeInformerFactory.Core().V1().Nodes()
	ancInformer := f.crdInformerFactory.Crd().V1alpha1().AntreaNodeConfigs()
	require.Eventually(t, func() bool {
		return nodeInformer.Informer().HasSynced() && ancInformer.Informer().HasSynced()
	}, 5*time.Second, 5*time.Millisecond, "informer caches should sync")

	runDone := make(chan struct{})
	go func() {
		f.Run(f.stopCh)
		close(runDone)
	}()
	t.Cleanup(func() {
		close(f.stopCh)
		<-runDone
	})

	require.Eventually(t, func() bool {
		snap := f.CurrentSnapshot()
		if snap == nil {
			return false
		}
		if f.fixtureNode != nil {
			return snap.Node != nil
		}
		return snap.Node == nil
	}, 5*time.Second, 10*time.Millisecond, "controller should expose snapshot after Run")
}

func TestEffectiveSecondaryOVSBridge(t *testing.T) {
	staticCfg := &agentconfig.SecondaryNetworkConfig{
		OVSBridges: []agentconfig.OVSBridgeConfig{
			{BridgeName: "br-static", PhysicalInterfaces: []string{"eth0"}},
		},
	}
	emptyCfg := &agentconfig.SecondaryNetworkConfig{}

	workerNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: ancBridgeTestLocalNodeName, Labels: map[string]string{"role": "worker"}}}

	ancTime0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ancMatchingWithBridge := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc1", CreationTimestamp: metav1.NewTime(ancTime0)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{
						BridgeName: "br-anc",
						PhysicalInterfaces: []crdv1alpha1.OVSPhysicalInterfaceConfig{
							{Name: "eth1", AllowedVLANs: []string{"100"}},
						},
					},
				},
			},
		},
	}
	ancMatchingNoBridge := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc2", CreationTimestamp: metav1.NewTime(ancTime0)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector:     metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{},
		},
	}
	wantStaticBridge := &agenttypes.OVSBridgeConfig{
		BridgeName:         "br-static",
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}},
	}

	tests := []struct {
		name            string
		noANCController bool
		node            *corev1.Node
		ancObjs         []*crdv1alpha1.AntreaNodeConfig
		staticCfg       *agentconfig.SecondaryNetworkConfig
		wantBridge      *agenttypes.OVSBridgeConfig
	}{
		{
			name:            "rule 1: AntreaNodeConfig disabled, use static config",
			noANCController: true,
			staticCfg:       staticCfg,
			wantBridge:      wantStaticBridge,
		},
		{
			name:       "rule 1: no ANC in snapshot, use static config",
			node:       workerNode,
			staticCfg:  staticCfg,
			wantBridge: wantStaticBridge,
		},
		{
			name:       "rule 1: empty static config and no ANC in snapshot",
			node:       workerNode,
			staticCfg:  emptyCfg,
			wantBridge: nil,
		},
		{
			name:      "rule 2: matching ANC overrides static config",
			node:      workerNode,
			ancObjs:   []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge},
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
			ancObjs:    []*crdv1alpha1.AntreaNodeConfig{ancMatchingNoBridge},
			staticCfg:  staticCfg,
			wantBridge: nil,
		},
		{
			name:       "nil node returns nil when ANC enabled — do not prefer static over CR",
			node:       nil,
			ancObjs:    []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge},
			staticCfg:  staticCfg,
			wantBridge: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got *agenttypes.OVSBridgeConfig
			if tc.noANCController {
				got = EffectiveSecondaryOVSBridgeFromStatic(tc.staticCfg)
			} else {
				fc := newFakeANCController(t, tc.node, tc.ancObjs)
				fc.start(t)
				got = EffectiveSecondaryOVSBridgeFromSnapshot(fc.CurrentSnapshot(), tc.staticCfg)
			}
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

func TestEffectiveOVSBridgeFromSnapshot_ListErrorFallsBackToStatic(t *testing.T) {
	staticCfg := &agentconfig.SecondaryNetworkConfig{
		OVSBridges: []agentconfig.OVSBridgeConfig{
			{BridgeName: "br-static", PhysicalInterfaces: []string{"eth0"}},
		},
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: ancBridgeTestLocalNodeName}}
	snap := antreanodeconfig.NewSnapshot(node, nil, errors.New("informer list failed"))
	got := EffectiveSecondaryOVSBridgeFromSnapshot(snap, staticCfg)
	require.NotNil(t, got)
	assert.Equal(t, "br-static", got.BridgeName)
}

func makeANC(name string, ts time.Time, nodeSelector map[string]string, secNet *crdv1alpha1.SecondaryNetworkConfig) *crdv1alpha1.AntreaNodeConfig {
	return &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(ts),
		},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{
				MatchLabels: nodeSelector,
			},
			SecondaryNetwork: secNet,
		},
	}
}

func makeBridge(name string, mcast bool, ifaces ...crdv1alpha1.OVSPhysicalInterfaceConfig) crdv1alpha1.OVSBridgeConfig {
	return crdv1alpha1.OVSBridgeConfig{
		BridgeName:              name,
		EnableMulticastSnooping: mcast,
		PhysicalInterfaces:      ifaces,
	}
}

func makeIface(name string, vlans ...string) crdv1alpha1.OVSPhysicalInterfaceConfig {
	return crdv1alpha1.OVSPhysicalInterfaceConfig{Name: name, AllowedVLANs: vlans}
}

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 = t0.Add(2 * time.Minute)
)

func TestApplySecondaryNetworkConfig(t *testing.T) {
	secNet1 := &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{
			makeBridge("br0", false, makeIface("eth0")),
		},
	}
	anc1 := makeANC("anc1", t0, nil, secNet1)
	ancNoSec := makeANC("ancNoSec", t2, nil, nil)

	tests := []struct {
		name string
		cfg  *crdv1alpha1.AntreaNodeConfig
		want *agenttypes.SecondaryNetworkConfig
	}{
		{
			name: "nil cfg",
			cfg:  nil,
			want: nil,
		},
		{
			name: "nil SecondaryNetwork",
			cfg:  ancNoSec,
			want: nil,
		},
		{
			name: "with SecondaryNetwork",
			cfg:  anc1,
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0", EnableMulticastSnooping: false,
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplySecondaryNetworkConfig(tc.cfg)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConvertCRDSecondaryNetwork(t *testing.T) {
	const testANCName = "test-antrea-node-config"

	tests := []struct {
		name                 string
		in                   *crdv1alpha1.SecondaryNetworkConfig
		antreaNodeConfigName string
		want                 agenttypes.SecondaryNetworkConfig
	}{
		{
			name:                 "empty bridges yields nil OVSBridge",
			in:                   &crdv1alpha1.SecondaryNetworkConfig{},
			antreaNodeConfigName: testANCName,
			want:                 agenttypes.SecondaryNetworkConfig{},
		},
		{
			name: "empty bridge name yields nil OVSBridge",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{BridgeName: "", PhysicalInterfaces: []crdv1alpha1.OVSPhysicalInterfaceConfig{{Name: "eth0"}}},
				},
			},
			antreaNodeConfigName: "anc-empty-bridge-name",
			want:                 agenttypes.SecondaryNetworkConfig{},
		},
		{
			name: "interface without AllowedVLANs has nil AllowedVLANs in output",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", false, makeIface("eth0")),
				},
			},
			antreaNodeConfigName: testANCName,
			want: agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0",
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0", AllowedVLANs: nil},
					},
				},
			},
		},
		{
			name: "AllowedVLANs are preserved",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", false, makeIface("eth0", "100", "200-300")),
				},
			},
			antreaNodeConfigName: testANCName,
			want: agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0",
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0", AllowedVLANs: []string{"100", "200-300"}},
					},
				},
			},
		},
		{
			name: "multicast snooping flag is preserved",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", true),
				},
			},
			antreaNodeConfigName: testANCName,
			want: agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName:              "br0",
					EnableMulticastSnooping: true,
				},
			},
		},
		{
			name: "bridge with multiple interfaces",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", false, makeIface("eth0"), makeIface("eth1", "10")),
				},
			},
			antreaNodeConfigName: testANCName,
			want: agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0",
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0", AllowedVLANs: nil},
						{Name: "eth1", AllowedVLANs: []string{"10"}},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := convertCRDSecondaryNetwork(tc.in, tc.antreaNodeConfigName)
			assert.Equal(t, tc.want, got)
		})
	}
}
