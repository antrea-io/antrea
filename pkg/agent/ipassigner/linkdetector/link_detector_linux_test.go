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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"
	"k8s.io/utils/set"

	netlinktesting "antrea.io/antrea/pkg/agent/util/netlink/testing"
)

type linkEventHandler struct {
	watchLinkNames     []string
	receivedEvents     []string
	lock               sync.Mutex
	expectedLinkEvents []string
}

func (l *linkEventHandler) onLinkEvent(linkName string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.receivedEvents = append(l.receivedEvents, linkName)
}

func newLinkEventHandler(expectedLinkEvents []string, watchLinkNames ...string) *linkEventHandler {
	return &linkEventHandler{
		expectedLinkEvents: expectedLinkEvents,
		watchLinkNames:     watchLinkNames,
	}
}

func newLinkEvent(remove bool, linkName string, index int) netlink.LinkUpdate {
	et := unix.RTM_NEWLINK
	if remove {
		et = unix.RTM_DELLINK
	}
	e := netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{
			IfInfomsg: unix.IfInfomsg{
				Index: int32(index),
			},
		},
		Link: &netlink.Device{
			LinkAttrs: netlink.LinkAttrs{
				Name: linkName,
			},
		},
		Header: unix.NlMsghdr{
			Type: uint16(et),
		},
	}
	return e
}

func newLink(name string, index int) netlink.Link {
	return &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Index: index,
			Name:  name,
		},
	}
}

func Test_linkDetector_listAndWatchLinks(t *testing.T) {
	tests := []struct {
		name               string
		eventHandlers      []*linkEventHandler
		linkEvents         []netlink.LinkUpdate
		expectNetlinkCalls func(netlink *netlinktesting.MockInterfaceMockRecorder)
	}{
		{
			name: "initial notification",
			eventHandlers: []*linkEventHandler{
				newLinkEventHandler([]string{
					"lo",
					"eth0",
				}),
			},
			expectNetlinkCalls: func(nl *netlinktesting.MockInterfaceMockRecorder) {
				nl.LinkList().Return([]netlink.Link{
					newLink("lo", 1),
					newLink("eth0", 2),
				}, nil)
			},
		},
		{
			name: "watch all links",
			eventHandlers: []*linkEventHandler{
				newLinkEventHandler([]string{
					"lo",
					"eth0",
					"eth1",
				}),
			},
			linkEvents: []netlink.LinkUpdate{
				newLinkEvent(false, "eth1", 3),
			},
			expectNetlinkCalls: func(nl *netlinktesting.MockInterfaceMockRecorder) {
				nl.LinkList().Return([]netlink.Link{
					newLink("lo", 1),
					newLink("eth0", 2),
				}, nil)
			},
		},
		{
			name: "watch eth1",
			eventHandlers: []*linkEventHandler{
				newLinkEventHandler([]string{
					"eth1",
				}, "eth1"),
			},
			linkEvents: []netlink.LinkUpdate{
				newLinkEvent(false, "eth1", 3),
			},
			expectNetlinkCalls: func(nl *netlinktesting.MockInterfaceMockRecorder) {
				nl.LinkList().Return([]netlink.Link{
					newLink("lo", 1),
					newLink("eth0", 2),
				}, nil)
			},
		},
		{
			name: "watch eth1 and eth1 renamed",
			eventHandlers: []*linkEventHandler{
				newLinkEventHandler([]string{
					"eth1", // initial notification
					"eth1", // rename notification
				}, "eth1"),
			},
			linkEvents: []netlink.LinkUpdate{
				newLinkEvent(false, "eth1~", 3),
			},
			expectNetlinkCalls: func(nl *netlinktesting.MockInterfaceMockRecorder) {
				nl.LinkList().Return([]netlink.Link{
					newLink("lo", 1),
					newLink("eth0", 2),
					newLink("eth1", 3),
				}, nil)
			},
		},
		{
			name: "watch eth1, eth1 renamed and created with new index",
			eventHandlers: []*linkEventHandler{
				newLinkEventHandler([]string{
					"eth1", // initial notification
					"eth1", // rename notification
					"eth1", // new link notification
				}, "eth1"),
			},
			linkEvents: []netlink.LinkUpdate{
				newLinkEvent(false, "eth1~", 3),
				newLinkEvent(false, "eth1", 4),
			},
			expectNetlinkCalls: func(nl *netlinktesting.MockInterfaceMockRecorder) {
				nl.LinkList().Return([]netlink.Link{
					newLink("lo", 1),
					newLink("eth0", 2),
					newLink("eth1", 3),
				}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			prevLinkSubscribeFunc := linkSubscribeFunc
			defer func() { linkSubscribeFunc = prevLinkSubscribeFunc }()
			linkSubscribeFunc = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, options netlink.LinkSubscribeOptions) error {
				go func() {
					for _, e := range tt.linkEvents {
						ch <- e
					}
				}()
				return nil
			}

			netlink := netlinktesting.NewMockInterface(ctrl)
			tt.expectNetlinkCalls(netlink.EXPECT())

			d := &linkDetector{
				eventHandlers: map[string][]LinkEventHandler{},
				linkNames:     set.New[string](),
				linkIndexMap:  map[int32]string{},
				netlink:       netlink,
			}
			for _, h := range tt.eventHandlers {
				d.AddEventHandler(h.onLinkEvent, h.watchLinkNames...)
			}

			stopCh := make(chan struct{})
			defer close(stopCh)
			go d.listAndWatchLinks(stopCh)
			assert.Eventuallyf(t,
				func() bool {
					for _, l := range tt.eventHandlers {
						l.lock.Lock()
						defer l.lock.Unlock()
						if !reflect.DeepEqual(l.expectedLinkEvents, l.receivedEvents) {
							t.Logf("expected %v, actual %v", l.expectedLinkEvents, l.receivedEvents)
							return false
						}
					}
					return true
				}, 1*time.Second, 100*time.Millisecond, "timeout waiting for link events")
		})
	}
}
