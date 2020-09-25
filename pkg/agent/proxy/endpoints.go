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
	discovery "k8s.io/api/discovery/v1beta1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
)

var supportedEndpointSliceAddressTypes = map[string]struct{}{
	string(discovery.AddressTypeIP):   {}, // IP is a deprecated address type
	string(discovery.AddressTypeIPv4): {},
	string(discovery.AddressTypeIPv6): {},
}

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
	changes    map[apimachinerytypes.NamespacedName]*endpointsChange
	sliceCache *EndpointSliceCache
}

// TODO: enable IPV6
func newEndpointsChangesTracker(hostname string, enableEndpointSlice bool) *endpointsChangesTracker {
	tracker := &endpointsChangesTracker{
		hostname: hostname,
		changes:  map[apimachinerytypes.NamespacedName]*endpointsChange{},
	}
	ipv6 := false
	if enableEndpointSlice {
		tracker.sliceCache = NewEndpointSliceCache(hostname, &ipv6)
	}
	return tracker
}

// OnEndpointUpdate updates given the Service's Endpoints change map based on the
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

// EndpointSliceUpdate updates given the service's endpoints change map based on the <previous, current> endpoints pair.
// It returns true if items changed, otherwise it returns false. Will add/update/delete items of endpointsChange Map.
// If removeSlice is true, slice will be removed, otherwise it will be added or updated.
func (t *endpointsChangesTracker) OnEndpointSliceUpdate(endpointSlice *discovery.EndpointSlice, removeSlice bool) bool {
	// This should never happen.
	if endpointSlice == nil {
		klog.Error("Nil endpointSlice passed to EndpointSliceUpdate")
		return false
	}

	if _, has := supportedEndpointSliceAddressTypes[string(endpointSlice.AddressType)]; !has {
		klog.V(4).Infof("EndpointSlice address type not supported: %s", endpointSlice.AddressType)
		return false
	}

	if _, _, err := endpointSliceCacheKeys(endpointSlice); err != nil {
		klog.Warningf("Error getting endpoint slice cache keys: %v", err)
		return false
	}

	t.Lock()
	defer t.Unlock()

	changeNeeded := t.sliceCache.updatePending(endpointSlice, removeSlice)

	return changeNeeded
}

func (t *endpointsChangesTracker) checkoutChanges() []*endpointsChange {
	t.Lock()
	defer t.Unlock()

	if t.sliceCache != nil {
		return t.sliceCache.checkoutChanges()
	}

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
					klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
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

// Update updates an EndpointsMap based on current changes and returns stale
// Endpoints of each Service.
func (t *endpointsChangesTracker) Update(em types.EndpointsMap) map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint {
	staleEndpoints := map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint{}
	for _, change := range t.checkoutChanges() {
		for spn := range change.previous {
			delete(em, spn)
		}
		for spn, endpoints := range change.current {
			em[spn] = endpoints
		}
		detectStaleConnections(change.previous, change.current, staleEndpoints)
	}
	return staleEndpoints
}

// detectStaleConnections updates staleEndpoints with detected stale connections.
func detectStaleConnections(oldEndpointsMap, newEndpointsMap types.EndpointsMap, staleEndpoints map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint) {
	for svcPortName, epList := range oldEndpointsMap {
		for _, ep := range epList {
			stale := true
			for i := range newEndpointsMap[svcPortName] {
				if newEndpointsMap[svcPortName][i].Equal(ep) {
					stale = false
					break
				}
			}
			if stale {
				if _, ok := staleEndpoints[svcPortName]; !ok {
					staleEndpoints[svcPortName] = map[string]k8sproxy.Endpoint{}
				}
				staleEndpoints[svcPortName][ep.String()] = ep
			}
		}
	}
}
