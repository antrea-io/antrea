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

	"github.com/ovn-kubernetes/libovsdb/client"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

// podControllerInterface is the subset of podwatch.PodController used by Controller.
// Defined as an interface to allow test injection.
type podControllerInterface interface {
	Run(stopCh <-chan struct{})
	AllowCNIDelete(podName, podNamespace string) bool
	DrainOVSBridge(client ovsconfig.OVSBridgeClient) (bool, error)
	CompleteOVSBridgeDrain()
	CancelOVSBridgeDrain()
	UpdateOVSBridgeClient(newClient ovsconfig.OVSBridgeClient) error
}

// Controller manages secondary network resources for a Node.
type Controller struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient           //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	secNetConfig    *agentconfig.SecondaryNetworkConfig //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	podController   podControllerInterface
	nodeName        string //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	// primaryOVSBridgeName is the integration bridge used by the Antrea Agent. A
	// secondary bridge must never use this name, as the secondary bridge controller
	// owns the lifecycle of its bridge and may delete it during reconciliation.
	primaryOVSBridgeName string        //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	ovsdbClient          client.Client //nolint:unused // Used by Linux-only secondary bridge reconciliation.

	// latestANCSnapshot is the last *antreanodeconfig.Snapshot received on the ANC
	// notify channel.
	latestANCSnapshot atomic.Pointer[antreanodeconfig.Snapshot] //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	// effectiveBridgeOverride is set only by unit tests to stub desired bridge resolution.
	effectiveBridgeOverride func() *agenttypes.OVSBridgeConfig //nolint:unused // Used by Linux-only secondary bridge tests.

	// ancFirstSnapshotCh is closed when the first *Snapshot is delivered after ANC
	// informers have synced (including the no-ANC case: non-nil *Snapshot with nil
	// AntreaNodeConfig). Only used when dynamicBridgeReconcile is true.
	ancFirstSnapshotCh chan struct{} //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	signalFirstANC     sync.Once     //nolint:unused // Used by Linux-only secondary bridge reconciliation.

	// mu protects effectiveBridgeCfg for atomic point-in-time reads and writes.
	// It must never be held across blocking OVS calls.
	mu                 sync.RWMutex                                 //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	effectiveBridgeCfg *agenttypes.OVSBridgeConfig                  //nolint:unused // Used by Linux-only secondary bridge reconciliation.
	queue              workqueue.TypedRateLimitingInterface[string] //nolint:unused // Used by Linux-only secondary bridge reconciliation.

	// dynamicBridgeReconcile is true when AntreaNodeConfig is enabled: bridge
	// updates are driven by the AntreaNodeConfig channel after the AntreaNodeConfig
	// controller has synced informers and published the first snapshot.
	dynamicBridgeReconcile bool //nolint:unused // Used by Linux-only secondary bridge reconciliation.
}

func (c *Controller) AllowCNIDelete(podName, podNamespace string) bool {
	return c.podController.AllowCNIDelete(podName, podNamespace)
}
