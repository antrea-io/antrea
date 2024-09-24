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

package packetcapture

import (
	"fmt"
	"time"

	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/google/gopacket"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

// HandlePacketIn processes PacketIn messages from the OFSwitch. If the register value match, it will be counted and captured.
// Once the total number reaches the target, the PacketCapture will be marked as Succeed.
func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	klog.V(4).InfoS("PacketIn for PacketCapture", "PacketIn", pktIn.PacketIn)
	captureState, captureFinished, err := c.parsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("parsePacketIn error: %w", err)
	}
	if captureFinished {
		return nil
	}
	rawData := pktIn.Data.(*util.Buffer).Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(rawData),
		Length:        len(rawData),
	}
	err = captureState.pcapngWriter.WritePacket(ci, rawData)
	if err != nil {
		return fmt.Errorf("couldn't write packet: %w", err)
	}
	reachTarget := captureState.numCapturedPackets == captureState.maxNumCapturedPackets
	// use rate limiter to reduce the times we need to update status.
	if reachTarget || captureState.updateRateLimiter.Allow() {
		pc, err := c.packetCaptureLister.Get(captureState.name)
		if err != nil {
			return fmt.Errorf("get PacketCapture failed: %w", err)
		}
		// if reach the target. flush the file and upload it.
		if reachTarget {
			if err := captureState.pcapngWriter.Flush(); err != nil {
				return err
			}
			if err := c.uploadPackets(pc, captureState.pcapngFile); err != nil {
				return err
			}
		}
		err = c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureRunning, "", captureState.numCapturedPackets)
		if err != nil {
			return fmt.Errorf("failed to update the PacketCapture: %w", err)
		}
		klog.InfoS("Updated PacketCapture", "PacketCapture", klog.KObj(pc), "numCapturedPackets", captureState.numCapturedPackets)
	}
	return nil
}

// parsePacketIn parses the packet-in message. If the value in register match with existing PacketCapture's state(tag),
// it will be counted. If the total count reach the target, the ovs flow will be uninstalled.
func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (_ *packetCaptureState, captureFinished bool, _ error) {
	var tag uint8
	matchers := pktIn.GetMatches()
	match := openflow.GetMatchFieldByRegID(matchers, openflow.PacketCaptureMark.GetRegID())
	if match != nil {
		value, err := openflow.GetInfoInReg(match, openflow.PacketCaptureMark.GetRange().ToNXRange())
		if err != nil {
			return nil, false, fmt.Errorf("failed to get PacketCapture tag from packet-in message: %w", err)
		}
		tag = uint8(value)
	}
	c.runningPacketCapturesMutex.Lock()
	defer c.runningPacketCapturesMutex.Unlock()
	pcState, exists := c.runningPacketCaptures[tag]
	if !exists {
		return nil, false, fmt.Errorf("PacketCapture for dataplane tag %d not found in cache", tag)
	}
	if pcState.numCapturedPackets == pcState.maxNumCapturedPackets {
		return nil, true, nil
	}
	pcState.numCapturedPackets++
	if pcState.numCapturedPackets == pcState.maxNumCapturedPackets {
		err := c.ofClient.UninstallPacketCaptureFlows(tag)
		if err != nil {
			return nil, false, fmt.Errorf("uninstall PacketCapture ovs flow failed: %v", err)
		}
	}
	return pcState, false, nil
}
