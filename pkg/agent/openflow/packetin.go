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
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

type ofpPacketInReason uint

type PacketInHandler interface {
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// Max packetInQueue size.
	packetInQueueSize int = 256
)

func NewOFReason(value uint8) ofpPacketInReason{
	return ofpPacketInReason(value)
}

func (c *client) RegisterPacketInHandler(packetHandlerReason ofpPacketInReason, packetHandlerName string, packetInHandler interface{}) {
	handler, ok := packetInHandler.(PacketInHandler)
	if !ok {
		klog.Errorf("Invalid controller.")
		return
	}
	if c.packetInHandlers[packetHandlerReason] == nil {
		c.packetInHandlers[packetHandlerReason] = map[string]PacketInHandler{}
	}
	c.packetInHandlers[packetHandlerReason][packetHandlerName] = handler
}

func (c *client) StartPacketInHandler(packetInStartedReason []uint8, stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 || len(packetInStartedReason) == 0 {
		return
	}
	// Subscribe packetin for TraceFlow with reason[0], using reason 1 in ovs
	tfCh := make(chan *ofctrl.PacketIn)
	err := c.SubscribePacketIn(packetInStartedReason[0], tfCh)
	if err != nil {
		klog.Errorf("Subscribe Traceflow PacketIn failed %+v", err)
		return
	}
	tfPacketInQueue := workqueue.NewNamed("traceflow")
	go c.parsePacketIn(tfPacketInQueue, NewOFReason(packetInStartedReason[0]))

	// Subscribe packetin for NetworkPolicy with reason[1], using reason 0 in ovs
	npCh := make(chan *ofctrl.PacketIn)
	err = c.SubscribePacketIn(packetInStartedReason[1], npCh)
	if err != nil {
		klog.Errorf("Subscribe NetworkPolicy PacketIn failed %+v", err)
		return
	}
	npPacketInQueue := workqueue.NewNamed("networkpolicy")
	go c.parsePacketIn(npPacketInQueue, NewOFReason(packetInStartedReason[1]))

	for {
		// Prioritize traceflow over networkpolicy
		select {
		case tfPktIn := <-tfCh:
			// Ensure that the queue doesn't grow too big. This is NOT to provide an exact guarantee.
			if tfPacketInQueue.Len() < packetInQueueSize {
				tfPacketInQueue.Add(tfPktIn)
			} else {
				klog.Warningf("Max packetInQueue size exceeded.")
			}
		default:
		}
		select {
		case tfPktIn := <-tfCh:
			// Ensure that the queue doesn't grow too big. This is NOT to provide an exact guarantee.
			if tfPacketInQueue.Len() < packetInQueueSize {
				tfPacketInQueue.Add(tfPktIn)
			} else {
				klog.Warningf("Max packetInQueue size exceeded.")
			}
		case npPktIn := <-npCh:
			npPacketInQueue.Add(npPktIn)
		case <-stopCh:
			tfPacketInQueue.ShutDown()
			npPacketInQueue.ShutDown()
			break
		}
	}
}

func (c *client) parsePacketIn(packetInQueue workqueue.Interface, packetHandlerReason ofpPacketInReason) {
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
