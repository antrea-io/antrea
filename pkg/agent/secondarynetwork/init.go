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
	"sync"
	"sync/atomic"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
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
