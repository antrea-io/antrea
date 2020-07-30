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
	"k8s.io/klog/v2"
)

type ofpPacketInReason uint

type PacketInHandler interface {
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// Action explicitly output to controller.
	ofprAction ofpPacketInReason = 1
	// Max packetInQueue size.
	packetInQueueSize int = 256
)

func (c *client) RegisterPacketInHandler(packetHandlerName string, packetInHandler interface{}) {
	handler, ok := packetInHandler.(PacketInHandler)
	if !ok {
		klog.Errorf("Invalid Traceflow controller.")
		return
	}
	c.packetInHandlers[packetHandlerName] = handler
}

func (c *client) StartPacketInHandler(stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 {
		return
	}
	ch := make(chan *ofctrl.PacketIn)
	err := c.SubscribePacketIn(uint8(ofprAction), ch)
	if err != nil {
		klog.Errorf("Subscribe PacketIn failed %+v", err)
		return
	}
	packetInQueue := workqueue.NewNamed("packetIn")
	go c.parsePacketIn(packetInQueue, stopCh)

	for {
		select {
		case pktIn := <-ch:
			// Ensure that the queue doesn't grow too big. This is NOT to provide an exact guarantee.
			if packetInQueue.Len() < packetInQueueSize {
				packetInQueue.Add(pktIn)
			} else {
				klog.Warningf("Max packetInQueue size exceeded.")
			}
		case <-stopCh:
			packetInQueue.ShutDown()
			break
		}
	}
}

func (c *client) parsePacketIn(packetInQueue workqueue.Interface, stopCh <-chan struct{}) {
	for {
		obj, quit := packetInQueue.Get()
		if quit {
			break
		}
		packetInQueue.Done(obj)
		pktIn, ok := obj.(*ofctrl.PacketIn)
		if !ok {
			klog.Errorf("Invalid packet in data in queue, skipping.")
			continue
		}
		for name, handler := range c.packetInHandlers {
			err := handler.HandlePacketIn(pktIn)
			if err != nil {
				klog.Errorf("PacketIn handler %s failed to process packet: %+v", name, err)
			}
		}
	}
}
