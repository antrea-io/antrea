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

package linkmonitor

import (
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/set"

<<<<<<< HEAD
	utilnetlink "antrea.io/antrea/v2/pkg/agent/util/netlink"
=======
	utilnetlink "antrea.io/antrea/pkg/agent/util/netlink"
>>>>>>> origin/main
)

const (
	linkAny = ""
)

type linkMonitor struct {
	mutex             sync.RWMutex
	cacheSynced       bool
	linkSubscribeFunc func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, options netlink.LinkSubscribeOptions) error
	eventHandlers     map[string][]LinkEventHandler
	linkNames         set.Set[string]  // known link names
	linkIndexMap      map[int32]string // map from link index to link name
	netlink           utilnetlink.Interface
}

func NewLinkMonitor() *linkMonitor {
	return &linkMonitor{
		linkSubscribeFunc: netlink.LinkSubscribeWithOptions,
		eventHandlers:     make(map[string][]LinkEventHandler),
		linkNames:         set.New[string](),
		linkIndexMap:      make(map[int32]string),
		netlink:           &netlink.Handle{},
	}
}

func (d *linkMonitor) HasSynced() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.cacheSynced
}

func (d *linkMonitor) AddEventHandler(handler LinkEventHandler, linkNames ...string) {
	if len(linkNames) == 0 {
		d.eventHandlers[linkAny] = append(d.eventHandlers[linkAny], handler)
		return
	}
	for _, name := range linkNames {
		d.eventHandlers[name] = append(d.eventHandlers[name], handler)
	}
}

func (d *linkMonitor) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting LinkMonitor")

	wait.NonSlidingUntil(func() { d.listAndWatchLinks(stopCh) }, 5*time.Second, stopCh)

	<-stopCh
}

func (d *linkMonitor) listAndWatchLinks(stopCh <-chan struct{}) {
	ch := make(chan netlink.LinkUpdate, 100)
	if err := d.linkSubscribeFunc(ch, stopCh, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			klog.ErrorS(err, "Received error from link update subscription")
		},
	}); err != nil {
		klog.ErrorS(err, "Failed to subscribe link update")
		return
	}

	links, err := d.netlink.LinkList()
	if err != nil {
		klog.ErrorS(err, "failed to list links on the Node")
		return
	}

	d.mutex.Lock()
	for _, l := range links {
		d.linkIndexMap[int32(l.Attrs().Index)] = l.Attrs().Name
		d.linkNames.Insert(l.Attrs().Name)
	}
	d.cacheSynced = true
	d.mutex.Unlock()

	for _, l := range links {
		d.notifyHandlers(l.Attrs().Name)
	}

	for {
		select {
		case <-stopCh:
			return
		case event := <-ch:
			eventLinkName := event.Attrs().Name
			index := event.Index
			previousName, exists := d.linkIndexMap[index]

			isDelete := event.Header.Type == unix.RTM_DELLINK
			if isDelete {
				delete(d.linkIndexMap, index)
				d.deleteLinkName(eventLinkName)
			} else {
				d.linkIndexMap[index] = eventLinkName
				d.addLinkName(eventLinkName)
			}

			// For link rename events, notify handlers watching the original name
			if exists && previousName != eventLinkName {
				d.deleteLinkName(previousName)
				d.notifyHandlers(previousName)
			}
			d.notifyHandlers(eventLinkName)
		}
	}
}

func (d *linkMonitor) notifyHandlers(linkName string) {
	for _, h := range d.eventHandlers[linkName] {
		h(linkName)
	}
	for _, h := range d.eventHandlers[linkAny] {
		h(linkName)
	}
}

// LinkExists checks if the provided interface is configured on the Node.
func (d *linkMonitor) LinkExists(name string) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.linkNames.Has(name)
}

func (d *linkMonitor) addLinkName(name string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.linkNames.Insert(name)
}

func (d *linkMonitor) deleteLinkName(name string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.linkNames.Delete(name)
}
