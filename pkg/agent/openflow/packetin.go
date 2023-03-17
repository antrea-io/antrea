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
	"encoding/binary"
	"fmt"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/ovs/openflow"
)

type ofpPacketInReason uint8

type PacketInHandler interface {
	// HandlePacketIn should not modify the input pktIn and should not
	// assume that the pktIn contents(e.g. NWSrc/NWDst) will not be
	// modified at a later time.
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// We use OpenFlow Meter for packet-in rate limiting on OVS side.
	// Meter Entry ID.
	PacketInMeterIDNP = 1
	PacketInMeterIDTF = 2
	// Meter Entry Rate. It is represented as number of events per second.
	// Packets which exceed the rate will be dropped.
	PacketInMeterRateNP = 100
	PacketInMeterRateTF = 100

	// PacketIn reasons
	PacketInReasonTF ofpPacketInReason = 1
	// PacketInReasonNP is used for the custom packetIn reasons for Network Policy, including: Logging, Reject, Deny.
	// It is also used to mark the DNS Response packet.
	PacketInReasonNP ofpPacketInReason = 0
	// PacketInReasonMC shares PacketInReasonNP for IGMP packet_in message. This is because OVS "controller" action
	// only correctly supports reason 0 or 1. Change to another value after the OVS action is corrected.
	PacketInReasonMC = PacketInReasonNP
	// PacketInQueueSize defines the size of PacketInQueue.
	// When PacketInQueue reaches PacketInQueueSize, new packet-in will be dropped.
	PacketInQueueSize = 200
	// PacketInQueueRate defines the maximum frequency of getting items from PacketInQueue.
	// PacketInQueueRate is represented as number of events per second.
	PacketInQueueRate = 100
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
	stopCh        <-chan struct{}
	packetInQueue *openflow.PacketInQueue
}

func newfeatureStartPacketIn(reason uint8, stopCh <-chan struct{}) *featureStartPacketIn {
	featurePacketIn := featureStartPacketIn{reason: reason, stopCh: stopCh}
	featurePacketIn.packetInQueue = openflow.NewPacketInQueue(PacketInQueueSize, rate.Limit(PacketInQueueRate))

	return &featurePacketIn
}

// StartPacketInHandler is the starting point for processing feature packetin requests.
func (c *client) StartPacketInHandler(stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 {
		return
	}

	// Iterate through each feature that starts packetin. Subscribe with their specified reason.
	for reason := range c.packetInHandlers {
		featurePacketIn := newfeatureStartPacketIn(reason, stopCh)
		err := c.subscribeFeaturePacketIn(featurePacketIn)
		if err != nil {
			klog.Errorf("received error %+v while subscribing packetin for each feature", err)
		}
	}
}

func (c *client) subscribeFeaturePacketIn(featurePacketIn *featureStartPacketIn) error {
	err := c.SubscribePacketIn(featurePacketIn.reason, featurePacketIn.packetInQueue)
	if err != nil {
		return fmt.Errorf("subscribe %d PacketIn failed %+v", featurePacketIn.reason, err)
	}
	go c.parsePacketIn(featurePacketIn)
	return nil
}

func (c *client) parsePacketIn(featurePacketIn *featureStartPacketIn) {
	for {
		pktIn := featurePacketIn.packetInQueue.GetRateLimited(featurePacketIn.stopCh)
		if pktIn == nil {
			return
		}
		// Use corresponding handlers subscribed to the reason to handle PacketIn
		for name, handler := range c.packetInHandlers[featurePacketIn.reason] {
			klog.V(2).InfoS("Received packetIn", "reason", featurePacketIn.reason, "handler", name)
			if err := handler.HandlePacketIn(pktIn); err != nil {
				klog.ErrorS(err, "PacketIn handler failed to process packet", "handler", name)
			}
		}
	}
}

func GetMatchFieldByRegID(matchers *ofctrl.Matchers, regID int) *ofctrl.MatchField {
	xregID := uint8(regID / 2)
	startBit := 4 * (regID % 2)
	f := matchers.GetMatch(openflow15.OXM_CLASS_PACKET_REGS, xregID)
	if f == nil {
		return nil
	}
	dataBytes := f.Value.(*openflow15.ByteArrayField).Data
	data := binary.BigEndian.Uint32(dataBytes[startBit : startBit+4])
	var mask uint32
	if f.HasMask {
		maskBytes, _ := f.Mask.MarshalBinary()
		mask = binary.BigEndian.Uint32(maskBytes[startBit : startBit+4])
	}
	if data == 0 && mask == 0 {
		return nil
	}
	return &ofctrl.MatchField{MatchField: openflow15.NewRegMatchFieldWithMask(regID, data, mask)}
}
