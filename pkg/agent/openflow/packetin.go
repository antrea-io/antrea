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
	"errors"
	"fmt"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/ovs/openflow"
)

type ofpPacketInCategory uint8

type PacketInHandler interface {
	// HandlePacketIn should not modify the input pktIn and should not
	// assume that the pktIn contents(e.g. NWSrc/NWDst) will not be
	// modified at a later time.
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// PacketIn categories below are used to distribute packetIn to specific handlers.
	// PacketIn category should be loaded in the first byte of packetIn2 userData.
	// PacketInCategoryTF is used for traceflow.
	PacketInCategoryTF ofpPacketInCategory = iota
	// PacketInCategoryNP is used for packetIn messages related to Network Policy,
	// including: Logging, Reject, Deny.
	PacketInCategoryNP
	// PacketInCategoryDNS is used for DNS response packetIn messages.
	PacketInCategoryDNS
	// PacketInCategoryIGMP is used for IGMP packetIn messages.
	PacketInCategoryIGMP
	// PacketInCategorySvcReject is used to process the Service packets not matching any
	// Endpoints within packetIn message.
	PacketInCategorySvcReject

	// PacketIn operations below are used to decide which operation(s) should be
	// executed by a handler. It(they) should be loaded in the second byte of the
	// packetIn2 userData. Operations for different handlers could share the value.
	// If there is only one operation for a handler, then there is no need to provide an
	// operation.
	// For example, if a packetIn2 needs Reject and Logging, the userData of the
	// packetIn2 will be []byte{1, 0b11}. The first byte indicate that this packetIn2
	// should be sent to NetworkPolicy packetIn handler(PacketInCategoryNP). And the
	// second byte, which is 0b1 & 0b10 indicating that it needs
	// PacketInNPLoggingOperation and PacketInNPRejectOperation.
	// PacketInNPLoggingOperation is used when sending packetIn to NetworkPolicy
	// handler indicating this packet needs logging.
	PacketInNPLoggingOperation = 0b1
	// PacketInNPRejectOperation is used when sending packetIn to controller
	// indicating that this packet should be rejected.
	PacketInNPRejectOperation = 0b10
	// PacketInNPStoreDenyOperation is used when sending packetIn message to controller
	// indicating that the corresponding connection has been dropped or rejected. It
	// can be consumed by the Flow Exporter to export flow records for connections
	// denied by network policy rules.
	PacketInNPStoreDenyOperation = 0b100

	// We use OpenFlow Meter for packetIn rate limiting on OVS side.
	// Meter Entry ID.
	// 1-255 are reserved for Egress QoS. The Egress QoS meterID leverage the same
	// value as the mark allocated to the EgressIP and Antrea limits the number of
	// Egress IPs per Node to 255, hence the reserved meter ID range is 1-255.
	PacketInMeterIDNP  = 256
	PacketInMeterIDTF  = 257
	PacketInMeterIDDNS = 258
)

// RegisterPacketInHandler stores controller handler in a map with category as keys.
func (c *client) RegisterPacketInHandler(packetHandlerCategory uint8, packetInHandler PacketInHandler) {
	c.packetInHandlers[packetHandlerCategory] = packetInHandler
}

// featureStartPacketIn contains packetIn resources specifically for each feature that uses packetIn.
type featureStartPacketIn struct {
	category      uint8
	stopCh        <-chan struct{}
	packetInQueue *openflow.PacketInQueue
}

func newFeatureStartPacketIn(category uint8, stopCh <-chan struct{}, queueSize, queueRate int) *featureStartPacketIn {
	featurePacketIn := featureStartPacketIn{category: category, stopCh: stopCh}
	featurePacketIn.packetInQueue = openflow.NewPacketInQueue(queueSize, rate.Limit(queueRate))

	return &featurePacketIn
}

// StartPacketInHandler is the starting point for processing feature packetIn requests.
func (c *client) StartPacketInHandler(stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 {
		return
	}
	// Iterate through each feature that starts packetIn. Subscribe with their specified category.
	for category := range c.packetInHandlers {
		featurePacketIn := newFeatureStartPacketIn(category, stopCh, c.packetInRate*2, c.packetInRate)
		err := c.subscribeFeaturePacketIn(featurePacketIn)
		if err != nil {
			klog.Errorf("received error %+v while subscribing packetIn for each feature", err)
		}
	}
}

func (c *client) subscribeFeaturePacketIn(featurePacketIn *featureStartPacketIn) error {
	err := c.SubscribePacketIn(featurePacketIn.category, featurePacketIn.packetInQueue)
	if err != nil {
		return fmt.Errorf("subscribe %d packetIn failed %+v", featurePacketIn.category, err)
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
		// Use corresponding handler subscribed to the category to handle packetIn
		if handler, ok := c.packetInHandlers[featurePacketIn.category]; ok {
			klog.V(2).InfoS("Received packetIn", "category", featurePacketIn.category)
			if err := handler.HandlePacketIn(pktIn); err != nil {
				klog.ErrorS(err, "PacketIn handler failed to process packet", "category", featurePacketIn.category)
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

func GetInfoInReg(regMatch *ofctrl.MatchField, rng *openflow15.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be retrieved")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

func GetEthernetPacket(pktIn *ofctrl.PacketIn) (*protocol.Ethernet, error) {
	ethernetPkt := new(protocol.Ethernet)
	if err := ethernetPkt.UnmarshalBinary(pktIn.Data.(*util.Buffer).Bytes()); err != nil {
		return nil, fmt.Errorf("failed to parse ethernet packet from packetIn message: %v", err)
	}
	return ethernetPkt, nil
}
