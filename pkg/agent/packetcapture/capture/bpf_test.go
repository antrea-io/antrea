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
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

var (
	testTCPProtocol             = intstr.FromString("TCP")
	testUDPProtocol             = intstr.FromString("UDP")
	testICMPProtocol            = intstr.FromString("ICMP")
	testICMPv6Protocol          = intstr.FromString("ICMPv6")
	testSrcPort           int32 = 12345
	testDstPort           int32 = 80
	testICMPMsgDstUnreach       = intstr.FromString(string(crdv1alpha1.ICMPMsgTypeDstUnreach))
	testICMPMsgEcho             = intstr.FromString(string(crdv1alpha1.ICMPMsgTypeEcho))
	testICMPMsgEchoReply        = intstr.FromString(string(crdv1alpha1.ICMPMsgTypeEchoReply))

	testICMPv6MsgEcho      = intstr.FromString(string(crdv1alpha1.ICMPv6MsgTypeEcho))
	testICMPv6MsgEchoReply = intstr.FromString(string(crdv1alpha1.ICMPv6MsgTypeEchoReply))
)

func TestPacketCaptureCompileBPF(t *testing.T) {
	tt := []struct {
		name  string
		srcIP net.IP
		dstIP net.IP
		spec  *crdv1alpha1.PacketCaptureSpec
		inst  []bpf.Instruction
	}{
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
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 26},
				bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 24}, // tcp
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000001, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x7f000002, SkipTrue: 0, SkipFalse: 20},
				bpf.LoadAbsolute{Off: 20, Size: 2},                                     // flags+fragment offset, since we need to calc where the src/dst port is
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 18},           // do we have an L4 header?
				bpf.LoadMemShift{Off: 14},                                              // calculate size of IP header
				bpf.LoadIndirect{Off: 14, Size: 2},                                     // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 15},            // port 12345
				bpf.LoadIndirect{Off: 16, Size: 2},                                     // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0, SkipFalse: 13}, // port 80
				bpf.RetConstant{Val: 262144},
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
			name:  "with-ipv6-proto-port-and-Both",
			srcIP: net.ParseIP("fd00:10:244::1"),
			dstIP: net.ParseIP("fd00:10:244::2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					IPFamily: v1.IPv6Protocol,
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
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 44},
				bpf.LoadAbsolute{Off: 20, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 42}, // tcp
				bpf.LoadAbsolute{Off: 22, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfd000010, SkipTrue: 0, SkipFalse: 19},
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2440000, SkipTrue: 0, SkipFalse: 17},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 15},
				bpf.LoadAbsolute{Off: 34, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipTrue: 0, SkipFalse: 13},
				bpf.LoadAbsolute{Off: 38, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfd000010, SkipTrue: 0, SkipFalse: 32},
				bpf.LoadAbsolute{Off: 42, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2440000, SkipTrue: 0, SkipFalse: 30},
				bpf.LoadAbsolute{Off: 46, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 28},
				bpf.LoadAbsolute{Off: 50, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2, SkipTrue: 0, SkipFalse: 26},
				bpf.LoadAbsolute{Off: 54, Size: 2},                          // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 24}, // port 12345
				bpf.LoadAbsolute{Off: 56, Size: 2},                          // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 22},   // port 80
				bpf.RetConstant{Val: 262144},
				bpf.LoadAbsolute{Off: 22, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfd000010, SkipTrue: 0, SkipFalse: 19},
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2440000, SkipTrue: 0, SkipFalse: 17},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 15},
				bpf.LoadAbsolute{Off: 34, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2, SkipTrue: 0, SkipFalse: 13},
				bpf.LoadAbsolute{Off: 38, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfd000010, SkipTrue: 0, SkipFalse: 11},
				bpf.LoadAbsolute{Off: 42, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2440000, SkipTrue: 0, SkipFalse: 9},
				bpf.LoadAbsolute{Off: 46, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 7},
				bpf.LoadAbsolute{Off: 50, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipTrue: 0, SkipFalse: 5},
				bpf.LoadAbsolute{Off: 54, Size: 2},                         // src port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipFalse: 3},   // port 80
				bpf.LoadAbsolute{Off: 56, Size: 2},                         // dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3039, SkipFalse: 1}, // port 12345
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
				bpf.LoadIndirect{Off: 14, Size: 1},                          // load ICMP type
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3, SkipTrue: 0, SkipFalse: 2},
				bpf.LoadIndirect{Off: 15, Size: 1}, // load ICMP code
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
				bpf.LoadIndirect{Off: 14, Size: 1},                          // load ICMP type
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8, SkipTrue: 1, SkipFalse: 0},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 1},
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "ipv6-with-proto-and-icmp-messages-2",
			srcIP: net.ParseIP("fd00:10:244::1"),
			dstIP: net.ParseIP("fd00:10:244::2"),
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet: &crdv1alpha1.Packet{
					IPFamily: v1.IPv6Protocol,
					Protocol: &testICMPv6Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						ICMPv6: &crdv1alpha1.ICMPv6Header{
							Messages: []crdv1alpha1.ICMPv6MsgMatcher{
								{Type: testICMPv6MsgEcho},
								{Type: testICMPv6MsgEchoReply},
							},
						}},
				},
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 22},
				bpf.LoadAbsolute{Off: 22, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfd000010, SkipTrue: 0, SkipFalse: 20},
				bpf.LoadAbsolute{Off: 26, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2440000, SkipTrue: 0, SkipFalse: 18},
				bpf.LoadAbsolute{Off: 30, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 16},
				bpf.LoadAbsolute{Off: 34, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipTrue: 0, SkipFalse: 14},
				bpf.LoadAbsolute{Off: 38, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfd000010, SkipTrue: 0, SkipFalse: 12},
				bpf.LoadAbsolute{Off: 42, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2440000, SkipTrue: 0, SkipFalse: 10},
				bpf.LoadAbsolute{Off: 46, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 0, SkipFalse: 8},
				bpf.LoadAbsolute{Off: 50, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2, SkipTrue: 0, SkipFalse: 6},
				bpf.LoadAbsolute{Off: 20, Size: 1},                       // ip protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x3a, SkipFalse: 4}, // icmpv6
				bpf.LoadAbsolute{Off: 54, Size: 1},                       // load ICMP type
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x80, SkipTrue: 1, SkipFalse: 0},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x81, SkipTrue: 0, SkipFalse: 1},
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			name:  "nil-packetspec",
			srcIP: nil,
			dstIP: nil,
			spec: &crdv1alpha1.PacketCaptureSpec{
				Packet:    nil,
				Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
			},
			inst: []bpf.Instruction{
				bpf.LoadAbsolute{Off: 12, Size: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 1},
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

func TestCalculateSkipFalse(t *testing.T) {
	tt := []struct {
		name      string
		handler   *ipFamilyHandler
		srcIP     net.IP
		dstIP     net.IP
		transport *transportFilters
		expected  uint8
	}{
		{
			name:      "no ip no transport filters",
			handler:   ipv4Handler,
			transport: &transportFilters{},
			expected:  1,
		},
		{
			name:    "ipv4 src and dst ip with src and dst ports",
			handler: ipv4Handler,
			srcIP:   net.ParseIP("10.0.0.1"),
			dstIP:   net.ParseIP("10.0.0.2"),
			transport: &transportFilters{
				srcPort: 12345,
				dstPort: 80,
			},
			expected: 12,
		},
		{
			name:    "ipv6 src ip with multiple tcp flags",
			handler: ipv6Handler,
			srcIP:   net.ParseIP("fd00:10:244::1"),
			transport: &transportFilters{
				tcpFlags: []tcpFlagsFilter{{flag: 0x2, mask: 0x2}, {flag: 0x10, mask: 0x10}},
			},
			expected: 15,
		},
		{
			name:    "icmp filters with and without code",
			handler: ipv6Handler,
			transport: &transportFilters{
				icmp: []icmpFilter{{icmpType: 3, icmpCode: ptr.To[uint32](1)}, {icmpType: 128}},
			},
			expected: 6,
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			assert.Equal(t, item.expected, calculateSkipFalse(item.handler, item.srcIP, item.dstIP, item.transport))
		})
	}
}

// BPFTestCases is the source of truth for BPF equivalence tests.
// Reference BPF bytecode is generated offline using hack/generate-bpf-testdata.sh.
func TestBPFEquivalenceWithTcpdump(t *testing.T) {
	for _, tt := range BPFTestCases {
		t.Run(tt.Name, func(t *testing.T) {
			expectedRaw, ok := generatedBPFTestCases[tt.Name]
			if !ok {
				t.Fatalf("No generated test data found for %q. Did you run ./hack/generate-bpf-testdata.sh?", tt.Name)
			}

			antreaProg := compilePacketFilter(tt.Packet, tt.SrcIP, tt.DstIP, tt.Direction)
			antreaRaw, err := bpf.Assemble(antreaProg)
			if err != nil {
				t.Fatalf("Failed to assemble Antrea BPF: %v", err)
			}

			assert.Equal(t, expectedRaw, antreaRaw,
				"Antrea BPF output does not match tcpdump reference for filter: %s. "+
					"If you modified BPF generation code, regenerate the reference data with: ./hack/generate-bpf-testdata.sh",
				tt.TcpdumpFilter)
		})
	}
}
