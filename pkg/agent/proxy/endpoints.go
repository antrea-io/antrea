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

package proxy

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"

	"antrea.io/antrea/v2/pkg/agent/proxy/types"
	k8sproxy "antrea.io/antrea/v2/third_party/proxy"
)

// endpointsChangesTracker tracks Endpoints changes.
type endpointsChangesTracker struct {
	sync.RWMutex
	// initialized tells whether Endpoints have been synced.
	initialized bool

	tracker *k8sproxy.EndpointsChangeTracker
}

func newEndpointsChangesTracker(hostname string, ipFamily v1.IPFamily) *endpointsChangesTracker {
	tracker := k8sproxy.NewEndpointsChangeTracker(ipFamily, hostname, types.NewEndpointInfo, nil)
	return &endpointsChangesTracker{tracker: tracker}
}

func (t *endpointsChangesTracker) OnEndpointsSynced() {
	t.Lock()
	defer t.Unlock()

	t.initialized = true
}

func (t *endpointsChangesTracker) OnEndpointSliceUpdate(endpointSlice *discovery.EndpointSlice, removeSlice bool) bool {
	return t.tracker.EndpointSliceUpdate(endpointSlice, removeSlice)
}

func (t *endpointsChangesTracker) Synced() bool {
	t.RLock()
	defer t.RUnlock()

	return t.initialized
}

// Update updates an EndpointsMap and numLocalEndpoints based on current changes.
func (t *endpointsChangesTracker) Update(em k8sproxy.EndpointsMap) k8sproxy.UpdateEndpointsMapResult {
	return em.Update(t.tracker)
}
