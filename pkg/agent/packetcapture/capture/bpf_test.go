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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

var (
	testTCPProtocol       = intstr.FromString("TCP")
	testUDPProtocol       = intstr.FromString("UDP")
	testSrcPort     int32 = 80
	testDstPort     int32 = 80
)

func TestCalculateInstructionsSize(t *testing.T) {
	tt := []struct {
		name        string
		packet      *crdv1alpha1.Packet
		count       int
		bidirection bool
	}{
		{
			name: "proto and host and port",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					TCP: &crdv1alpha1.TCPHeader{
						SrcPort: &testSrcPort,
						DstPort: &testDstPort,
					},
				},
			},
			count: 17,
		},
		{
			name: "proto with host",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
			},
			count: 10,
		},
		{
			name: "proto with src port",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					TCP: &crdv1alpha1.TCPHeader{
						SrcPort: &testSrcPort,
					},
				},
			},
			count: 15,
		},
		{
			name: "proto with dst port",
			packet: &crdv1alpha1.Packet{
				Protocol: &testUDPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					UDP: &crdv1alpha1.UDPHeader{
						DstPort: &testDstPort,
					},
				},
			},
			count: 15,
		},

		{
			name:   "any proto",
			packet: &crdv1alpha1.Packet{},
			count:  8,
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			assert.Equal(t, item.count, calculateInstructionsSize(item.packet, item.bidirection))
		})
	}
}

func TestPacketCaptureCompileBPF(t *testing.T) {
	tt := []struct {
		name  string
		srcIP net.IP
		dstIP net.IP
		spec  *crdv1alpha1.PacketCaptureSpec
		inst  []bpf.Instruction
	}{
		{
			name:  "with-proto-and-port",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testTCPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							SrcPort: &testSrcPort,
							DstPort: &testDstPort,
						}},
				},
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 14},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 12}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 3},    // port 23
				bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 1},    // port 23
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "udp-proto-str",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testUDPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						UDP: &crdv1alpha1.UDPHeader{
							SrcPort: &testSrcPort,
							DstPort: &testDstPort,
						}},
				},
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 14},
				bpf.LoadAbsolute{Off: 23, Size: 1},                        // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 12}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 3},    // port 23
				bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 1},    // port 23
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			result := compilePacketFilter(item.spec.Packet, item.srcIP, item.dstIP, item.spec.Bidirection)
			assert.Equal(t, item.inst, result)
		})
	}
}
