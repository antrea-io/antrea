// Copyright 2024 Antrea Authors.
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

package capture

import (
	"context"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	// Max packet size for pcap capture.
	maxSnapshotBytes = 65536
)

type pcapCapture struct {
}

func NewPcapCapture() (*pcapCapture, error) {
	return &pcapCapture{}, nil
}

// zeroFilter is a filter that will drop all packets.
// see: https://github.com/antrea-io/antrea/issues/6815 for the user case.
func zeroFilter() []bpf.Instruction {
	return []bpf.Instruction{returnDrop}
}

func (p *pcapCapture) Capture(ctx context.Context, device string, srcIP, dstIP net.IP, packet *crdv1alpha1.Packet) (chan gopacket.Packet, error) {
	// Compile the BPF filter in advance to reduce the time window between starting the capture and applying the filter.
	inst := compilePacketFilter(packet, srcIP, dstIP)
	klog.V(5).InfoS("Generated bpf instructions for PacketCapture", "device", device, "srcIP", srcIP, "dstIP", dstIP, "packetSpec", packet, "bpf", inst)
	rawInst, err := bpf.Assemble(inst)
	if err != nil {
		return nil, err
	}

	zeroRawInst, err := bpf.Assemble(zeroFilter())
	if err != nil {
		return nil, err
	}

	eth, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		return nil, err
	}
	if err = eth.SetPromiscuous(false); err != nil {
		return nil, err
	}
	// Install a BPF filter that won't match any packets
	// see: https://natanyellin.com/posts/ebpf-filtering-done-right/.
	// Packets which don’t match the target BPF can be received after the socket
	// is created and before setsockopt is called. Those packets will remain
	// in the socket’s buffer even after the BPF is applied and will later
	// be transferred to the application via recv. Here we use a zero
	// bpf filter(match no packet), then empty out any packets that arrived
	// before the “zero-BPF” filter was applied. At this point the socket is
	// definitely empty and it can’t fill up with junk because the zero-BPF
	// is in place. Then we replace the zero-BPF with the real BPF we want.
	if err = eth.SetBPF(zeroRawInst); err != nil {
		return nil, err
	}
	if err = eth.SetCaptureLength(maxSnapshotBytes); err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(eth, layers.LinkTypeEthernet, gopacket.WithNoCopy(true))
	packetCh := packetSource.PacketsCtx(ctx)
	// Drain the channel
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-packetCh:
			klog.V(5).InfoS("Found irrelevant packet, discard it", "device", device)
			break
		case <-time.After(50 * time.Millisecond):
			// timeout: channel is drained so socket is drained
			// install the correct BPF filter
			if err := eth.SetBPF(rawInst); err != nil {
				return nil, err
			}
			return packetCh, nil
		}
	}
}
