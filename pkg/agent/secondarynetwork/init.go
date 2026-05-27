// Copyright 2024 Antrea Authors
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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/secondarynetwork/podwatch"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	"antrea.io/antrea/v2/pkg/util/channel"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

const (
	// reconcileKey is the single key used in the work queue. Any change that
	// may affect the effective bridge configuration enqueues this key.
	reconcileKey = "reconcile"

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
)

// podControllerInterface is the subset of podwatch.PodController used by Controller.
// Defined as an interface to allow test injection.
type podControllerInterface interface {
	Run(stopCh <-chan struct{})
	AllowCNIDelete(podName, podNamespace string) bool
	UpdateOVSBridgeClient(newClient ovsconfig.OVSBridgeClient) error
}

// Controller manages secondary network resources for a Node.
type Controller struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	secNetConfig    *agentconfig.SecondaryNetworkConfig
	podController   podControllerInterface
	nodeName        string
	ovsdbConn       *ovsdb.OVSDB

	// latestANCSnapshot is the last *antreanodeconfig.Snapshot received on the ANC
	// notify channel.
	latestANCSnapshot atomic.Pointer[antreanodeconfig.Snapshot]
	// effectiveBridgeOverride is set only by unit tests to stub desired bridge resolution.
	effectiveBridgeOverride func() *agenttypes.OVSBridgeConfig

	// ancFirstSnapshotCh is closed when the first *Snapshot is delivered after ANC
	// informers have synced (including the no-ANC case: non-nil *Snapshot with nil
	// AntreaNodeConfig). Only used when dynamicBridgeReconcile is true.
	ancFirstSnapshotCh chan struct{}
	signalFirstANC     sync.Once

	// mu protects effectiveBridgeCfg for atomic point-in-time reads and writes.
	// It must never be held across blocking OVS calls.
	// Only init_linux.go references mu; Windows uses stub reconcile/Initialize methods.
	mu                 sync.RWMutex //nolint:unused // platform: Linux-only bridge reconciliation in init_linux.go
	effectiveBridgeCfg *agenttypes.OVSBridgeConfig

	// dynamicBridgeReconcile is true when AntreaNodeConfig is enabled: bridge
	// updates are driven by the AntreaNodeConfig channel after the AntreaNodeConfig
	// controller has synced informers and published the first snapshot.
	dynamicBridgeReconcile bool

	queue workqueue.TypedRateLimitingInterface[string]
}

func NewController(
	clientConnectionConfig componentbaseconfig.ClientConnectionConfiguration,
	kubeAPIServerOverride string,
	k8sClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	podUpdateSubscriber channel.Subscriber,
	primaryInterfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
	secNetConfig *agentconfig.SecondaryNetworkConfig,
	ovsdbConn *ovsdb.OVSDB,
	ipPoolLister crdlisters.IPPoolLister,
	ancUpdateSubscriber channel.Subscriber,
) (*Controller, error) {
	c := &Controller{
		secNetConfig: secNetConfig,
		nodeName:     nodeConfig.Name,
		ovsdbConn:    ovsdbConn,
	}

	if ancUpdateSubscriber != nil {
		c.dynamicBridgeReconcile = true
		c.ancFirstSnapshotCh = make(chan struct{})
		c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "secondaryNetworkBridge"},
		)
	}

	var effectiveBridgeCfg *agenttypes.OVSBridgeConfig
	var ovsBridgeClient ovsconfig.OVSBridgeClient
	var err error

	if !c.dynamicBridgeReconcile {
		effectiveBridgeCfg, ovsBridgeClient, err = resolveAndCreateOVSBridge(c.effectiveOVSBridge, c.ovsdbConn)
		if err != nil {
			return nil, err
		}
	}

	netAttachDefClient, err := createNetworkAttachDefClient(clientConnectionConfig, kubeAPIServerOverride)
	if err != nil {
		return nil, fmt.Errorf("NetworkAttachmentDefinition client creation failed: %v", err)
	}

	podWatchController, err := podwatch.NewPodController(
		k8sClient, netAttachDefClient, podInformer,
		podUpdateSubscriber, primaryInterfaceStore, nodeConfig, ovsBridgeClient, ipPoolLister)
	if err != nil {
		return nil, err
	}

	c.ovsBridgeClient = ovsBridgeClient
	c.effectiveBridgeCfg = effectiveBridgeCfg
	c.podController = podWatchController

	if c.dynamicBridgeReconcile {
		ancUpdateSubscriber.Subscribe(func(p interface{}) {
			snap, ok := p.(*antreanodeconfig.Snapshot)
			if !ok {
				klog.ErrorS(errors.New("unexpected notify payload"), "AntreaNodeConfig notify payload", "type", fmt.Sprintf("%T", p))
				return
			}
			if snap == nil {
				klog.ErrorS(errors.New("nil snapshot from notifier"), "AntreaNodeConfig notify payload")
				return
			}
			c.latestANCSnapshot.Store(snap)
			c.signalFirstANC.Do(func() { close(c.ancFirstSnapshotCh) })
			c.enqueue()
		})
	}

	return c, nil
}

// effectiveOVSBridge returns the desired OVS bridge for this node. When AntreaNodeConfig
// drives the bridge, only snapshots delivered on the notify channel are used.
// When ANC is disabled, only static agent config is consulted.
func (c *Controller) effectiveOVSBridge() *agenttypes.OVSBridgeConfig {
	if c.effectiveBridgeOverride != nil {
		return c.effectiveBridgeOverride()
	}
	if c.dynamicBridgeReconcile {
		return EffectiveSecondaryOVSBridgeFromSnapshot(c.latestANCSnapshot.Load(), c.secNetConfig)
	}
	return EffectiveSecondaryOVSBridgeFromAgentConfig(c.secNetConfig)
}

// enqueue adds the single reconciliation key to the work queue.
func (c *Controller) enqueue() {
	c.queue.Add(reconcileKey)
}

func (c *Controller) AllowCNIDelete(podName, podNamespace string) bool {
	return c.podController.AllowCNIDelete(podName, podNamespace)
}

// CreateNetworkAttachDefClient creates net-attach-def client handle from the given config.
func createNetworkAttachDefClient(cfg componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (netdefclient.K8sCniCncfIoV1Interface, error) {
	kubeConfig, err := k8s.CreateRestConfig(cfg, kubeAPIServerOverride)
	if err != nil {
		return nil, err
	}

	netAttachDefClient, err := netdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return netAttachDefClient, nil
}
