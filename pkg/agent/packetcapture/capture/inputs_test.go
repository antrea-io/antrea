// Copyright 2026 Antrea Authors.
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

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

// BPFTestCase represents a single BPF test scenario. It maps a human-readable
// tcpdump filter string to its equivalent Antrea PacketCapture CRD spec.
type BPFTestCase struct {
	Name          string
	TcpdumpFilter string
	Packet        *crdv1alpha1.Packet
	SrcIP         net.IP
	DstIP         net.IP
	Direction     crdv1alpha1.CaptureDirection
}

// ptrInt32 is a test helper to create an *int32.
func ptrInt32(v int32) *int32 {
	return &v
}

// ptrIntOrStringInt32 creates a pointer to an IntOrString int value.
func ptrIntOrStringInt32(v int32) *intstr.IntOrString {
	vv := intstr.FromInt32(v)
	return &vv
}

// BPFTestCases is the generative list of all test inputs.
var BPFTestCases = []BPFTestCase{
	// --- Protocol-only filters (no IPs, no ports) ---
	{
		Name:          "ICMP protocol only",
		TcpdumpFilter: "icmp",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "UDP protocol only",
		TcpdumpFilter: "ip proto 17",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "TCP with dst port 80",
		TcpdumpFilter: "ip proto 6 and dst port 80",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},

	// --- Protocol + IPs + Ports ---
	{
		Name:          "TCP with src+dst IP and src+dst port",
		TcpdumpFilter: "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "TCP with srcIP only and src+dst port",
		TcpdumpFilter: "ip proto 6 and src host 127.0.0.1 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "UDP with dstIP only and src+dst port",
		TcpdumpFilter: "ip proto 17 and dst host 127.0.0.2 and src port 12345 and dst port 80",
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "UDP with src+dst IP and src+dst port",
		TcpdumpFilter: "ip proto 17 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},

	// --- ICMP with type and code ---
	{
		Name:          "ICMP dst-unreachable with code 1",
		TcpdumpFilter: "ip proto 1 and src host 127.0.0.1 and dst host 127.0.0.2 and icmp[0]=3 and icmp[1]=1",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgDstUnreach, Code: ptrInt32(1)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},

	// --- TCP Flags ---
	{
		Name:          "TCP with SYN flag and IPs",
		TcpdumpFilter: "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and (tcp[tcpflags] & tcp-syn == tcp-syn)",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x2}, // SYN
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP with DstPort 80",
		TcpdumpFilter: "ip6 proto 6 and dst port 80",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "ICMPv6 (IPv6 protocol only)",
		TcpdumpFilter: "ip6 proto 58",
		Packet:        &crdv1alpha1.Packet{IPFamily: v1.IPv6Protocol, Protocol: &testICMPv6Protocol},
		Direction:     crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP SrcPort+DstPort",
		TcpdumpFilter: "ip6 proto 6 and src port 12345 and dst port 80",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP with SrcIP+DstIP (no ports)",
		TcpdumpFilter: "ip6 proto 6 and src host fd00:10:244::1 and dst host fd00:10:244::2",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet:        &crdv1alpha1.Packet{IPFamily: v1.IPv6Protocol, Protocol: &testTCPProtocol},
		Direction:     crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "ICMPv6 with type and code",
		TcpdumpFilter: "ip6 proto 58 and icmp6[0]=3 and icmp6[1]=1",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testICMPv6Protocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{
						{Type: intstr.FromInt32(3), Code: ptrInt32(1)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP exact flags (SYN set, ACK cleared)",
		TcpdumpFilter: "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80 and (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x2, Mask: ptrInt32(0x12)}, // SYN bit set (2), but masked with 0x12 (SYN|ACK)
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP exact strict flags (SYN+ACK only) with IP and Port",
		TcpdumpFilter: "ip proto 6 and src host 1.2.3.4 and dst port 443 and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push|tcp-ack) == (tcp-syn|tcp-ack))",
		SrcIP:         net.ParseIP("1.2.3.4"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					DstPort: ptrInt32(443),
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x12, Mask: ptrInt32(0x1F)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 UDP with DstPort only",
		TcpdumpFilter: "ip proto 17 and dst port 53",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					DstPort: ptrInt32(53),
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "ICMP with Type only",
		TcpdumpFilter: "ip proto 1 and icmp[0]=8",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: intstr.FromInt32(8)}, // Echo Request
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP with RST flag",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-rst == tcp-rst)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x04}, // RST
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 IP only without transport",
		TcpdumpFilter: "ip proto 6 and src host 10.0.0.1 and dst host 10.0.0.2",
		SrcIP:         net.ParseIP("10.0.0.1"),
		DstIP:         net.ParseIP("10.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 UDP with SrcPort only",
		TcpdumpFilter: "ip6 proto 17 and src port 12345",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					SrcPort: ptrInt32(12345),
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 UDP full combo with optimized order",
		TcpdumpFilter: "ip6 and src host fd00:10:244::1 and dst host fd00:10:244::2 and proto 17 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					SrcPort: ptrInt32(12345),
					DstPort: ptrInt32(80),
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP with srcIP only and src+dst ports",
		TcpdumpFilter: "ip6 and src host fd00:10:244::1 and proto 6 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP with dstIP only and src+dst ports",
		TcpdumpFilter: "ip6 and dst host fd00:10:244::2 and proto 6 and src port 12345 and dst port 80",
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 UDP with srcIP only and src+dst ports",
		TcpdumpFilter: "ip6 and src host fd00:10:244::1 and proto 17 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 UDP with dstIP only and src+dst ports",
		TcpdumpFilter: "ip6 and dst host fd00:10:244::2 and proto 17 and src port 12345 and dst port 80",
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 ICMPv6 type+code with srcIP only",
		TcpdumpFilter: "ip6 and src host fd00:10:244::1 and proto 58 and icmp6[0]=128 and icmp6[1]=1",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testICMPv6Protocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{{Type: intstr.FromInt32(128), Code: ptrInt32(1)}},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 ICMPv6 type+code with dstIP only",
		TcpdumpFilter: "ip6 and dst host fd00:10:244::2 and proto 58 and icmp6[0]=128 and icmp6[1]=1",
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testICMPv6Protocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{{Type: intstr.FromInt32(128), Code: ptrInt32(1)}},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP src+dst IP and src+dst ports DestinationToSource",
		TcpdumpFilter: "ip6 and src host fd00:10:244::2 and dst host fd00:10:244::1 and proto 6 and src port 80 and dst port 12345",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionDestinationToSource,
	},
	{
		Name:          "IPv6 UDP src+dst IP and src+dst ports DestinationToSource",
		TcpdumpFilter: "ip6 and src host fd00:10:244::2 and dst host fd00:10:244::1 and proto 17 and src port 80 and dst port 12345",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionDestinationToSource,
	},
	{
		Name:          "IPv4 TCP src+dst IP and src+dst ports DestinationToSource alt",
		TcpdumpFilter: "ip proto 6 and src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: ptrIntOrStringInt32(6),
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionDestinationToSource,
	},
	{
		Name:          "IPv4 UDP src+dst IP and src+dst ports DestinationToSource alt",
		TcpdumpFilter: "ip proto 17 and src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: ptrIntOrStringInt32(17),
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionDestinationToSource,
	},
	{
		Name:          "IPv4 ICMP time exceeded with code 0 unique",
		TcpdumpFilter: "ip proto 1 and src host 10.0.0.1 and dst host 10.0.0.2 and icmp[0]=11 and icmp[1]=0",
		SrcIP:         net.ParseIP("10.0.0.1"),
		DstIP:         net.ParseIP("10.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: ptrIntOrStringInt32(1),
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{{Type: intstr.FromInt32(11), Code: ptrInt32(0)}},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 ICMPv6 echo reply with src+dst IP unique",
		TcpdumpFilter: "ip6 and src host fd00:10:244::1 and dst host fd00:10:244::2 and proto 58 and icmp6[0]=129",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: ptrIntOrStringInt32(58),
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{{Type: intstr.FromInt32(129)}},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 numeric protocol 132 only unique",
		TcpdumpFilter: "ip6 proto 132",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: ptrIntOrStringInt32(132),
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
}
