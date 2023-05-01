//go:build linux
// +build linux

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

package multicast

import (
	"fmt"
	"net"
	"syscall"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/util/runtime"
)

// parseIGMPMsg parses the kernel version into parsedIGMPMsg. Note we need to consider the change
// after linux 5.9 in the igmpmsg struct when parsing vif. Please check
// https://github.com/torvalds/linux/commit/c8715a8e9f38906e73d6d78764216742db13ba0e.
func (c *MRouteClient) parseIGMPMsg(msg []byte) (*parsedIGMPMsg, error) {
	if len(msg) < SizeofIgmpmsg {
		return nil, fmt.Errorf("failed to parse IGMPMSG: message length should be greater than 19")
	}
	if msg[8] != IGMPMsgNocache {
		return nil, fmt.Errorf("not a IGMPMSG_NOCACHE message: %v", msg)
	}
	// im_mbz in igmpmsg must be zero, as document by
	// https://github.com/torvalds/linux/blob/4634129ad9fdc89d10b597fc6f8f4336fb61e105/include/uapi/linux/mroute.h#L115.
	if msg[9] != 0 {
		return nil, fmt.Errorf("invalid igmpmsg message: im_mbz must be zero")
	}
	kernelVersion, err := runtime.GetKernelVersion()
	if err != nil {
		return nil, err
	}
	var vif uint16
	if kernelVersion.Major >= 5 && kernelVersion.Minor > 9 {
		vif = uint16(msg[10]) + (uint16(msg[11]) << uint16(8))
	} else {
		vif = uint16(msg[10])
	}
	return &parsedIGMPMsg{
		VIF: vif,
		Src: net.IPv4(msg[12], msg[13], msg[14], msg[15]),
		Dst: net.IPv4(msg[16], msg[17], msg[18], msg[19]),
	}, nil
}

func (c *MRouteClient) run(stopCh <-chan struct{}) {
	klog.InfoS("Start running multicast routing daemon")
	go func() {
		for {
			buf := make([]byte, MulticastRecvBufferSize)
			n, _ := syscall.Read(c.socket.GetFD(), buf)
			// When Antrea FlexibleIPAM is enabled, messages received by the socket
			// will be dropped directly because we won't create any route from the upcall igmpmsg messages.
			// In addition, by reading the socket, we can avoid potential errors such as memory bloat.
			if c.flexibleIPAMEnabled {
				klog.V(4).InfoS("Message was received from the multicast routing socket", "message", buf[:n])
				continue
			}
			if n > 0 {
				c.igmpMsgChan <- buf[:n]
			}
		}
	}()

	for i := 0; i < int(workerCount); i++ {
		go c.worker(stopCh)
	}
	<-stopCh
	c.socket.FlushMRoute()
	syscall.Close(c.socket.GetFD())
}
