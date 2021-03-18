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

package openflow

import (
	"errors"
	"fmt"

	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type ofpPacketInReason uint8

type PacketInHandler interface {
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// Max packetInQueue size.
	packetInQueueSize int = 256
	// PacketIn reasons
	PacketInReasonTF ofpPacketInReason = 1
	PacketInReasonNP ofpPacketInReason = 0
)

// RegisterPacketInHandler stores controller handler in a map of map with reason and name as keys.
func (c *client) RegisterPacketInHandler(packetHandlerReason uint8, packetHandlerName string, packetInHandler interface{}) {
	handler, ok := packetInHandler.(PacketInHandler)
	if !ok {
		klog.Errorf("Invalid controller to handle packetin.")
		return
	}
	if c.packetInHandlers[packetHandlerReason] == nil {
		c.packetInHandlers[packetHandlerReason] = map[string]PacketInHandler{}
	}
	c.packetInHandlers[packetHandlerReason][packetHandlerName] = handler
}

// featureStartPacketIn contains packetin resources specifically for each feature that uses packetin.
type featureStartPacketIn struct {
	reason        uint8
	subscribeCh   chan *ofctrl.PacketIn
	stopCh        <-chan struct{}
	packetInQueue *workqueue.Type
}

func newfeatureStartPacketIn(reason uint8, stopCh <-chan struct{}) *featureStartPacketIn {
	featurePacketIn := featureStartPacketIn{reason: reason, stopCh: stopCh}
	featurePacketIn.subscribeCh = make(chan *ofctrl.PacketIn)
	featurePacketIn.packetInQueue = workqueue.NewNamed(string(reason))
	return &featurePacketIn
}

func (f *featureStartPacketIn) ListenPacketIn() {
	for {
		select {
		case pktIn := <-f.subscribeCh:
			// Ensure that the queue doesn't grow too big. This is NOT to provide an exact guarantee.
			if f.packetInQueue.Len() < packetInQueueSize {
				f.packetInQueue.Add(pktIn)
			} else {
				klog.Warningf("Max packetInQueue size exceeded.")
			}
		case <-f.stopCh:
			f.packetInQueue.ShutDown()
			return
		}
	}
}

// StartPacketInHandler is the starting point for processing feature packetin requests.
func (c *client) StartPacketInHandler(packetInStartedReason []uint8, stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 || len(packetInStartedReason) == 0 {
		return
	}

	// Iterate through each feature that starts packetin. Subscribe with their specified reason.
	for _, reason := range packetInStartedReason {
		featurePacketIn := newfeatureStartPacketIn(reason, stopCh)
		err := c.subscribeFeaturePacketIn(featurePacketIn)
		if err != nil {
			klog.Errorf("received error %+v while subscribing packetin for each feature", err)
		}
	}
}

func (c *client) subscribeFeaturePacketIn(featurePacketIn *featureStartPacketIn) error {
	err := c.SubscribePacketIn(featurePacketIn.reason, featurePacketIn.subscribeCh)
	if err != nil {
		return errors.New(fmt.Sprintf("Subscribe %d PacketIn failed %+v", featurePacketIn.reason, err))
	}
	go c.parsePacketIn(featurePacketIn.packetInQueue, featurePacketIn.reason)
	go featurePacketIn.ListenPacketIn()
	return nil
}

func (c *client) parsePacketIn(packetInQueue workqueue.Interface, packetHandlerReason uint8) {
	for {
		obj, quit := packetInQueue.Get()
		if quit {
			break
		}
		packetInQueue.Done(obj)
		pktIn, ok := obj.(*ofctrl.PacketIn)
		if !ok {
			klog.Errorf("Invalid packetin data in queue, skipping.")
			continue
		}
		// Use corresponding handlers subscribed to the reason to handle PacketIn
		for name, handler := range c.packetInHandlers[packetHandlerReason] {
			err := handler.HandlePacketIn(pktIn)
			if err != nil {
				klog.Errorf("PacketIn handler %s failed to process packet: %+v", name, err)
			}
		}
	}
}
