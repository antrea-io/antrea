/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
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

Modifies:
- Cleanup unused imports due to code removal and relocation
- Remove NodeHandler member from metaProxier struct
- Remove Sync() func as Provider interface removes it
- Remove EndPointSlice handling
*/

package proxy

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

type metaProxier struct {
	ipv4Proxier Provider
	ipv6Proxier Provider
}

// NewMetaProxier returns a dual-stack "meta-proxier". Proxier API
// calls will be dispatched to the ProxyProvider instances depending
// on address family.
func NewMetaProxier(ipv4Proxier, ipv6Proxier Provider) Provider {
	return Provider(&metaProxier{
		ipv4Proxier: ipv4Proxier,
		ipv6Proxier: ipv6Proxier,
	})
}

// SyncLoop runs periodic work.  This is expected to run as a
// goroutine or as the main loop of the app.  It does not return.
func (proxier *metaProxier) SyncLoop() {
	go proxier.ipv6Proxier.SyncLoop() // Use go-routine here!
	proxier.ipv4Proxier.SyncLoop()    // never returns
}

// SyncedOnce returns true if the proxier has synced rules at least once.
func (proxier *metaProxier) SyncedOnce() bool {
	return proxier.ipv4Proxier.SyncedOnce() && proxier.ipv6Proxier.SyncedOnce()
}

// OnServiceAdd is called whenever creation of new service object is observed.
func (proxier *metaProxier) OnServiceAdd(service *v1.Service) {
	proxier.ipv4Proxier.OnServiceAdd(service)
	proxier.ipv6Proxier.OnServiceAdd(service)
}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (proxier *metaProxier) OnServiceUpdate(oldService, service *v1.Service) {
	proxier.ipv4Proxier.OnServiceUpdate(oldService, service)
	proxier.ipv6Proxier.OnServiceUpdate(oldService, service)
}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (proxier *metaProxier) OnServiceDelete(service *v1.Service) {
	proxier.ipv4Proxier.OnServiceDelete(service)
	proxier.ipv6Proxier.OnServiceDelete(service)
}

// OnServiceSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *metaProxier) OnServiceSynced() {
	proxier.ipv4Proxier.OnServiceSynced()
	proxier.ipv6Proxier.OnServiceSynced()
}

// OnEndpointsAdd is called whenever creation of new endpoints object
// is observed.
func (proxier *metaProxier) OnEndpointsAdd(endpoints *v1.Endpoints) {
	ipFamily, err := endpointsIPFamily(endpoints)
	if err != nil {
		klog.Warningf("failed to add endpoints %s/%s with error %v", endpoints.ObjectMeta.Namespace, endpoints.ObjectMeta.Name, err)
		return
	}
	if *ipFamily == v1.IPv4Protocol {
		proxier.ipv4Proxier.OnEndpointsAdd(endpoints)
		return
	}
	proxier.ipv6Proxier.OnEndpointsAdd(endpoints)
}

// OnEndpointsUpdate is called whenever modification of an existing
// endpoints object is observed.
func (proxier *metaProxier) OnEndpointsUpdate(oldEndpoints, endpoints *v1.Endpoints) {
	ipFamily, err := endpointsIPFamily(endpoints)
	if err != nil {
		klog.Warningf("failed to update endpoints %s/%s with error %v", endpoints.ObjectMeta.Namespace, endpoints.ObjectMeta.Name, err)
		return
	}

	if *ipFamily == v1.IPv4Protocol {
		proxier.ipv4Proxier.OnEndpointsUpdate(oldEndpoints, endpoints)
		return
	}
	proxier.ipv6Proxier.OnEndpointsUpdate(oldEndpoints, endpoints)
}

// OnEndpointsDelete is called whenever deletion of an existing
// endpoints object is observed.
func (proxier *metaProxier) OnEndpointsDelete(endpoints *v1.Endpoints) {
	ipFamily, err := endpointsIPFamily(endpoints)
	if err != nil {
		klog.Warningf("failed to delete endpoints %s/%s with error %v", endpoints.ObjectMeta.Namespace, endpoints.ObjectMeta.Name, err)
		return
	}

	if *ipFamily == v1.IPv4Protocol {
		proxier.ipv4Proxier.OnEndpointsDelete(endpoints)
		return
	}
	proxier.ipv6Proxier.OnEndpointsDelete(endpoints)
}

// OnEndpointsSynced is called once all the initial event handlers
// were called and the state is fully propagated to local cache.
func (proxier *metaProxier) OnEndpointsSynced() {
	proxier.ipv4Proxier.OnEndpointsSynced()
	proxier.ipv6Proxier.OnEndpointsSynced()
}

func (proxier *metaProxier) Run(stopCh <-chan struct{}) {
	go proxier.ipv4Proxier.Run(stopCh)
	proxier.ipv6Proxier.Run(stopCh)
}

// endpointsIPFamily that returns IPFamily of endpoints or error if
// failed to identify the IP family.
func endpointsIPFamily(endpoints *v1.Endpoints) (*v1.IPFamily, error) {
	if len(endpoints.Subsets) == 0 {
		return nil, fmt.Errorf("failed to identify ipfamily for endpoints (no subsets)")
	}

	// we only need to work with subset [0],endpoint controller
	// ensures that endpoints selected are of the same family.
	subset := endpoints.Subsets[0]
	if len(subset.Addresses) == 0 {
		return nil, fmt.Errorf("failed to identify ipfamily for endpoints (no addresses)")
	}
	// same apply on addresses
	address := subset.Addresses[0]
	if len(address.IP) == 0 {
		return nil, fmt.Errorf("failed to identify ipfamily for endpoints (address has no ip)")
	}

	ipv4 := v1.IPv4Protocol
	ipv6 := v1.IPv6Protocol
	if utilnet.IsIPv6String(address.IP) {
		return &ipv6, nil
	}

	return &ipv4, nil
}
