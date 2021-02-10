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
	"fmt"
	"net"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
)

// endpointsChange describes an Endpoints change, previous is the state from before
// all of them, current is state after applying all of those.
type endpointsChange struct {
	previous types.EndpointsMap
	current  types.EndpointsMap
}

// endpointsChangesTracker tracks Endpoints changes.
type endpointsChangesTracker struct {
	// hostname is used to tell whether the Endpoint is located on current Node.
	hostname string

	sync.RWMutex
	// initialized tells whether Endpoints have been synced.
	initialized bool
	// changes contains endpoints changes since the last checkoutChanges call.
	changes map[apimachinerytypes.NamespacedName]*endpointsChange
}

func newEndpointsChangesTracker(hostname string) *endpointsChangesTracker {
	return &endpointsChangesTracker{
		hostname: hostname,
		changes:  map[apimachinerytypes.NamespacedName]*endpointsChange{},
	}
}

// OnEndpointUpdate updates given Service's Endpoints change map based on the
// <previous, current> Endpoints pair. It returns true if items changed,
// otherwise it returns false.
// Update can be used to add/update/delete items of EndpointsChangeMap.
// For example,
// Add item
//   - pass <nil, Endpoints> as the <previous, current> pair.
// Update item
//   - pass <oldEndpoints, Endpoints> as the <previous, current> pair.
// Delete item
//   - pass <Endpoints, nil> as the <previous, current> pair.
func (t *endpointsChangesTracker) OnEndpointUpdate(previous, current *corev1.Endpoints) bool {
	endpoints := current
	if endpoints == nil {
		endpoints = previous
	}
	// previous == nil && current == nil is unexpected, we should return false directly.
	if endpoints == nil {
		return false
	}
	namespacedName := apimachinerytypes.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name}

	t.Lock()
	defer t.Unlock()

	change, exists := t.changes[namespacedName]
	if !exists {
		change = &endpointsChange{}
		change.previous = t.endpointsToEndpointsMap(previous)
		t.changes[namespacedName] = change
	}

	change.current = t.endpointsToEndpointsMap(current)
	// If change.previous equals to change.current, it means no change.
	if reflect.DeepEqual(change.previous, change.current) {
		delete(t.changes, namespacedName)
	}

	return len(t.changes) > 0
}

func (t *endpointsChangesTracker) checkoutChanges() []*endpointsChange {
	t.Lock()
	defer t.Unlock()

	var changes []*endpointsChange
	for _, change := range t.changes {
		changes = append(changes, change)
	}
	t.changes = make(map[apimachinerytypes.NamespacedName]*endpointsChange)
	return changes
}

func (t *endpointsChangesTracker) OnEndpointsSynced() {
	t.Lock()
	defer t.Unlock()

	t.initialized = true
}

func (t *endpointsChangesTracker) Synced() bool {
	t.RLock()
	defer t.RUnlock()

	return t.initialized
}

// endpointsToEndpointsMap translates single Endpoints object to EndpointsMap.
// This function is used for incremental update of EndpointsMap.
func (t *endpointsChangesTracker) endpointsToEndpointsMap(endpoints *corev1.Endpoints) types.EndpointsMap {
	if endpoints == nil {
		return nil
	}
	endpointsMap := make(types.EndpointsMap)
	// We need to build a map of portname -> all ip:ports for that
	// portname.  Explode Endpoints.Subsets[*] into this structure.
	for i := range endpoints.Subsets {
		ss := &endpoints.Subsets[i]
		for i := range ss.Ports {
			port := &ss.Ports[i]
			if port.Port == 0 {
				klog.Warningf("Ignoring invalid endpoint port %s", port.Name)
				continue
			}
			svcPortName := k8sproxy.ServicePortName{
				NamespacedName: apimachinerytypes.NamespacedName{Namespace: endpoints.Namespace, Name: endpoints.Name},
				Protocol:       port.Protocol,
				Port:           port.Name,
			}
			if _, ok := endpointsMap[svcPortName]; !ok {
				endpointsMap[svcPortName] = map[string]k8sproxy.Endpoint{}
			}
			for i := range ss.Addresses {
				addr := &ss.Addresses[i]
				if addr.IP == "" {
					klog.Warningf("Ignoring invalid endpoint port %s with empty host", port.Name)
					continue
				}
				isLocal := addr.NodeName != nil && *addr.NodeName == t.hostname
				ei := types.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
					Endpoint: net.JoinHostPort(addr.IP, fmt.Sprint(port.Port)),
					IsLocal:  isLocal,
				})
				endpointsMap[svcPortName][ei.String()] = ei
			}
		}
	}
	return endpointsMap
}

// Update updates an EndpointsMap based on current changes.
func (t *endpointsChangesTracker) Update(em types.EndpointsMap) {
	for _, change := range t.checkoutChanges() {
		for spn := range change.previous {
			delete(em, spn)
		}
		for spn, endpoints := range change.current {
			em[spn] = endpoints
		}
	}
}
