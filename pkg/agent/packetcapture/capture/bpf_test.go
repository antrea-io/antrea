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
	"k8s.io/utils/ptr"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)
var (
	testTCPProtocol             = intstr.FromString("TCP")
	testUDPProtocol             = intstr.FromString("UDP")
	testICMPProtocol            = intstr.FromString("ICMP")
	testSrcPort           int32 = 12345
	testDstPort           int32 = 80
	testICMPMsgDstUnreach       = intstr.FromString(string(crdv1alpha1.ICMPMsgTypeDstUnreach))
	testICMPMsgEcho             = intstr.FromString(string(crdv1alpha1.ICMPMsgTypeEcho))
	testICMPMsgEchoReply        = intstr.FromString(string(crdv1alpha1.ICMPMsgTypeEchoReply))
)
func TestCalculateInstructionsSize(t *testing.T) {
	tt := []struct {
		name      string
		packet    *crdv1alpha1.Packet
		count     int
		direction crdv1alpha1.CaptureDirection
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
			count:     17,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
		},
		{
			name: "proto and host and port and DestinationToSource",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					TCP: &crdv1alpha1.TCPHeader{
						SrcPort: &testSrcPort,
						DstPort: &testDstPort,
					},
				},
			},
			count:     17,
			direction: crdv1alpha1.CaptureDirectionDestinationToSource,
		},
		{
			name: "proto and host to port and Both",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					TCP: &crdv1alpha1.TCPHeader{
						SrcPort: &testSrcPort,
						DstPort: &testDstPort,
					},
				},
			},
			count:     28,
			direction: crdv1alpha1.CaptureDirectionBoth,
		},
		{
			name: "proto with host",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
			},
			count:     10,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
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
			count:     15,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
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
			count:     15,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
		},
		{
			name: "proto with dst port and syn or ack flags",
			packet: &crdv1alpha1.Packet{
				Protocol: &testTCPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					TCP: &crdv1alpha1.TCPHeader{
						DstPort: &testDstPort,
						Flags: []crdv1alpha1.TCPFlagsMatcher{
							{Value: 0x2},  // syn
							{Value: 0x10}, // ack
						},
					},
				},
			},
			count:     21,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
		},
		{
			name: "proto with icmp messages echo and destination unreachable (host unreachable)",
			packet: &crdv1alpha1.Packet{
				Protocol: &testICMPProtocol,
				TransportHeader: crdv1alpha1.TransportHeader{
					ICMP: &crdv1alpha1.ICMPHeader{
						Messages: []crdv1alpha1.ICMPMsgMatcher{
							{Type: testICMPMsgDstUnreach, Code: ptr.To(int32(1))},
							{Type: testICMPMsgEcho},
						},
					},
				},
			},
			count:     18,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
		},
		{
			name:      "any proto",
			packet:    &crdv1alpha1.Packet{},
			count:     8,
			direction: crdv1alpha1.CaptureDirectionSourceToDestination,
		},
	}
	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			assert.Equal(t, item.count, calculateInstructionsSize(item.packet, item.direction))
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
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
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
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 3},  // port 12345
				bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 1},    // port 80
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
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
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
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 3},  // port 12345
				bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 1},    // port 80
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-port-DestinationToSource",
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
				Direction: crdv1alpha1.CaptureDirectionDestinationToSource,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 14},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 12}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 3},    // port 80
				bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 1},  // port 12345
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-dstPort-and-Both",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testTCPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: &testDstPort,
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionBoth,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 21},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 19}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 15},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                     // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 13},           // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                              // calculate size of IP header
				bpf.LoadIndirect{Off: 16, Size: 2},                                     // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0, SkipFalse: 10}, // port 80
				bpf.RetConstant{Val: 262144},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 6},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 1},    // port 80
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-port-and-Both",
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
				Direction: crdv1alpha1.CaptureDirectionBoth,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 25},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 23}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 19},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                     // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 17},           // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                              // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                                     // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 14},            // port 12345
				bpf.LoadIndirect{Off: 16, Size: 2},                                     // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0, SkipFalse: 12}, // port 80
				bpf.RetConstant{Val: 262144},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 3},    // port 80
				bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 1},  // port 12345
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-and-flags",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testTCPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							Flags: []crdv1alpha1.TCPFlagsMatcher{
								{Value: 0x2},  // +syn
								{Value: 0x10}, // +ack
							},
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 16},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 14}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 12},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                    // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 8},           // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                             // calculate size of IP header
				bpf.LoadIndirect{Off: 27, Size: 1},                                    // tcp flags
				bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x2},                         // AND with mask
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2, SkipTrue: 3, SkipFalse: 0},  // compare with flag
				bpf.LoadIndirect{Off: 27, Size: 1},                                    // load offset 13
				bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x10},                        // AND with mask
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x10, SkipTrue: 0, SkipFalse: 1}, // compare with flag
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-port-and-flags",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testTCPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: &testDstPort,
							Flags: []crdv1alpha1.TCPFlagsMatcher{
								{Value: 0x12}, // +syn+ack
							},
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 15},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 13}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 11},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 9},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                  // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 7},         // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                           // calculate size of IP header
				bpf.LoadIndirect{Off: 16, Size: 2},                                  // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 4},            // port 80
				bpf.LoadIndirect{Off: 27, Size: 1},                                  // tcp flags
				bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 18},                        // AND with mask
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 18, SkipTrue: 0, SkipFalse: 1}, // compare with flag
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-port-flags-and-Both",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testTCPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							SrcPort: &testSrcPort,
							DstPort: &testDstPort,
							Flags: []crdv1alpha1.TCPFlagsMatcher{
								{Value: 0, Mask: ptr.To(int32(0x10))}, // -ack
							},
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionBoth,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 31},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 29}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 13},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 25},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                     // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 23},           // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                              // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                                     // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 20},            // port 12345
				bpf.LoadIndirect{Off: 16, Size: 2},                                     // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0, SkipFalse: 18}, // port 80
				bpf.LoadIndirect{Off: 27, Size: 1},                                     // tcp flags
				bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 16},                           // AND with mask
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 0, SkipFalse: 15},    // compare with flag
				bpf.RetConstant{Val: 262144},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 13},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 11},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                      // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 9},             // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                               // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                                      // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0, SkipFalse: 6},   // port 80
				bpf.LoadIndirect{Off: 16, Size: 2},                                      // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipTrue: 0, SkipFalse: 4}, // port 12345
				bpf.LoadIndirect{Off: 27, Size: 1},                                      // tcp flags
				bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 16},                            // AND with mask
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 0, SkipFalse: 1},      // compare with flag
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-and-icmp-messages",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testICMPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						ICMP: &crdv1alpha1.ICMPHeader{
							Messages: []crdv1alpha1.ICMPMsgMatcher{
								{Type: testICMPMsgDstUnreach, Code: ptr.To(int32(1))},
								{Type: testICMPMsgEcho},
							},
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 15},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipFalse: 13}, // icmp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 11},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 9},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 7}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: lengthByte},                 // load ICMP type
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3, SkipTrue: 0, SkipFalse: 2},
				bpf.LoadIndirect{Off: 15, Size: lengthByte}, // load ICMP code
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipTrue: 1, SkipFalse: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8, SkipTrue: 0, SkipFalse: 1},
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "with-proto-and-icmp-messages-2",
			srcIP: net.ParseIP("127.0.0.1"),
			dstIP: net.ParseIP("127.0.0.2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					Protocol: &testICMPProtocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						ICMP: &crdv1alpha1.ICMPHeader{
							Messages: []crdv1alpha1.ICMPMsgMatcher{
								{Type: testICMPMsgEcho},
								{Type: testICMPMsgEchoReply},
							},
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 13},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipFalse: 11}, // icmp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 9},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 7},
				bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5}, // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: lengthByte},                 // load ICMP type
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8, SkipTrue: 1, SkipFalse: 0},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 1},
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
	}
	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			result := compilePacketFilter(item.spec.Packet, item.srcIP, item.dstIP, item.spec.Direction)
			assert.Equal(t, item.inst, result)
		})
	}
}
