// Copyright 2021 Antrea Authors
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

package ipassigner

import (
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

// The devices that should be excluded from Egress.
var excludeEgressDevices = []string{"kube-ipvs0"}

type localIPDetector struct {
	mutex         sync.RWMutex
	localIPs      sets.Set[string]
	cacheSynced   bool
	eventHandlers []LocalIPEventHandler
}

func NewLocalIPDetector() *localIPDetector {
	return &localIPDetector{localIPs: sets.New[string]()}
}

// IsLocalIP checks if the provided IP is configured on the Node.
func (d *localIPDetector) IsLocalIP(ip string) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.localIPs.Has(ip)
}

func (d *localIPDetector) HasSynced() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.cacheSynced
}

func (d *localIPDetector) AddEventHandler(handler LocalIPEventHandler) {
	d.eventHandlers = append(d.eventHandlers, handler)
}

func (d *localIPDetector) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting localIPDetector")

	go wait.NonSlidingUntil(func() {
		d.listAndWatchIPAddresses(stopCh)
	}, 5*time.Second, stopCh)

	<-stopCh
}

func (d *localIPDetector) notify(ip string, added bool) {
	for _, handler := range d.eventHandlers {
		handler(ip, added)
	}
}

func (d *localIPDetector) listAndWatchIPAddresses(stopCh <-chan struct{}) {
	// Subscribe IP address update before listing existing IP addresses to prevent event loss.
	ch := make(chan netlink.AddrUpdate)
	if err := netlink.AddrSubscribeWithOptions(ch, stopCh, netlink.AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			klog.Errorf("Received error from IP address update subscription: %v", err)
		},
	}); err != nil {
		klog.Errorf("Failed to subscribe IP address update: %v", err)
		return
	}

	// List existing IP addresses first.
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		klog.Errorf("Failed to list IP addresses on the Node")
		return
	}

	// List existing excluding devices first.
	excludeLinkIndexes := sets.New[int]()
	for _, deviceName := range excludeEgressDevices {
		link, err := netlink.LinkByName(deviceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				klog.ErrorS(err, "Failed to find dev", "deviceName", deviceName)
			}
			continue
		}
		excludeLinkIndexes.Insert(link.Attrs().Index)
	}

	ips := sets.New[string]()
	for _, addr := range addresses {
		// Ignore IP Addresses events of excluded devices.
		if !excludeLinkIndexes.Has(addr.LinkIndex) {
			ips.Insert(addr.IP.String())
		}
	}

	klog.V(4).Infof("Listed existing IP address: %v", ips)
	// Find IP addresses removed or added during the period it was not watching and call eventHandlers to process them.
	addedAddresses, deletedAddresses := func() (sets.Set[string], sets.Set[string]) {
		d.mutex.Lock()
		defer d.mutex.Unlock()

		added := ips.Difference(d.localIPs)
		deleted := d.localIPs.Difference(added)
		d.localIPs = ips
		d.cacheSynced = true
		return added, deleted
	}()
	for addr := range addedAddresses {
		d.notify(addr, true)
	}
	for addr := range deletedAddresses {
		d.notify(addr, false)
	}

	for {
		select {
		case <-stopCh:
			return
		case addrUpdate, ok := <-ch:
			if !ok {
				klog.Warning("IP address update channel was closed")
				return
			}
			klog.V(4).Infof("Received IP address update: %v", addrUpdate)

			// Ignore IP Addresses events of excluded devices.
			if excludeLinkIndexes.Has(addrUpdate.LinkIndex) {
				continue
			}

			ip := addrUpdate.LinkAddress.IP.String()
			d.mutex.Lock()
			if addrUpdate.NewAddr {
				if !d.localIPs.Has(ip) {
					d.localIPs.Insert(ip)
					d.notify(ip, true)
				}
			} else {
				if d.localIPs.Has(ip) {
					d.localIPs.Delete(ip)
					d.notify(ip, false)
				}
			}
			d.mutex.Unlock()
		}
	}
}
