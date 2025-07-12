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

package responder

import (
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

<<<<<<< HEAD
	"antrea.io/antrea/v2/pkg/agent/ipassigner/linkmonitor"
=======
	"antrea.io/antrea/pkg/agent/ipassigner/linkmonitor"
>>>>>>> origin/main
)

var (
	// map of transportInterfaceName to ARP responder
	arpResponders = make(map[string]*arpResponder)
	// map of transportInterfaceName to NDP responder
	ndpResponders = make(map[string]*ndpResponder)
)

// NewARPResponder creates a new ARP responder if it does not exist for the given transportInterfaceName.
// This function is not thread-safe.
func NewARPResponder(transportInterfaceName string, linkMonitor linkmonitor.Interface) *arpResponder {
	if responder, ok := arpResponders[transportInterfaceName]; ok {
		klog.InfoS("ARP responder already exists", "interface", transportInterfaceName)
		return responder
	}
	a := &arpResponder{
		linkName:    transportInterfaceName,
		assignedIPs: sets.New[string](),
		linkEventCh: make(chan struct{}, 1),
	}
	if linkMonitor != nil {
		linkMonitor.AddEventHandler(a.onLinkUpdate, transportInterfaceName)
	}
	klog.InfoS("Created new ARP responder", "interface", transportInterfaceName)
	arpResponders[transportInterfaceName] = a
	return a
}

// NewNDPResponder creates a new NDP responder if it does not exist for the given transportInterfaceName.
// This function is not thread-safe.
func NewNDPResponder(transportInterfaceName string, linkMonitor linkmonitor.Interface) *ndpResponder {
	if responder, ok := ndpResponders[transportInterfaceName]; ok {
		klog.InfoS("NDP responder already exists", "interface", transportInterfaceName)
		return responder
	}
	n := &ndpResponder{
		linkName:        transportInterfaceName,
		multicastGroups: make(map[netip.Addr]int),
		assignedIPs:     sets.New[netip.Addr](),
		linkEventCh:     make(chan struct{}, 1),
	}
	if linkMonitor != nil {
		linkMonitor.AddEventHandler(n.onLinkUpdate, transportInterfaceName)
	}
	klog.InfoS("Created new NDP responder", "interface", transportInterfaceName)
	ndpResponders[transportInterfaceName] = n
	return n
}
