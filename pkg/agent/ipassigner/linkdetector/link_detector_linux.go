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

package linkdetector

import (
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/set"

	utilnetlink "antrea.io/antrea/pkg/agent/util/netlink"
)

var linkSubscribeFunc = netlink.LinkSubscribeWithOptions

type linkDetector struct {
	mutex         sync.RWMutex
	cacheSynced   bool
	eventHandlers map[string][]LinkEventHandler
	linkNames     set.Set[string]  // known link names
	linkIndexMap  map[int32]string // map from link index to link name
	netlink       utilnetlink.Interface
}

func NewLinkDetector() *linkDetector {
	return &linkDetector{
		eventHandlers: make(map[string][]LinkEventHandler),
		linkNames:     make(set.Set[string]),
		linkIndexMap:  make(map[int32]string),
		netlink:       &netlink.Handle{},
	}
}

func (d *linkDetector) HasSynced() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.cacheSynced
}

func (d *linkDetector) AddEventHandler(handler LinkEventHandler, linkName ...string) {
	if len(linkName) == 0 {
		d.eventHandlers[""] = append(d.eventHandlers[""], handler)
		return
	}
	for _, name := range linkName {
		d.eventHandlers[name] = append(d.eventHandlers[name], handler)
	}
}

func (d *linkDetector) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting localLinkDetector")

	go wait.NonSlidingUntil(func() {
		d.listAndWatchLinks(stopCh)
	}, 5*time.Second, stopCh)

	<-stopCh
}

func (d *linkDetector) listAndWatchLinks(stopCh <-chan struct{}) {
	ch := make(chan netlink.LinkUpdate)
	if err := linkSubscribeFunc(ch, stopCh, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			klog.Errorf("Received error from link update subscription: %v", err)
		},
	}); err != nil {
		klog.Errorf("Failed to subscribe link update: %v", err)
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
			} else {
				d.linkIndexMap[index] = eventLinkName
			}

			d.mutex.Lock()
			if isDelete {
				d.linkNames.Delete(eventLinkName)
			} else {
				d.linkNames.Insert(eventLinkName)
			}
			d.mutex.Unlock()

			// For link rename events, notify handlers watching the original name
			if exists && previousName != eventLinkName {
				d.notifyHandlers(previousName)
			}
			d.notifyHandlers(eventLinkName)
		}
	}
}

func (d *linkDetector) notifyHandlers(linkName string) {
	handlers := d.eventHandlers[linkName]
	handlers = append(handlers, d.eventHandlers[""]...)
	for _, h := range handlers {
		h(linkName)
	}
}

// LinkExists checks if the provided interface is configured on the Node.
func (d *linkDetector) LinkExists(name string) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.linkNames.Has(name)
}
