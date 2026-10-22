// Copyright 2026 Antrea Authors
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
	"k8s.io/utils/ptr"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
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
						{Type: testICMPMsgDstUnreach, Code: ptr.To[int32](1)},
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
						{Type: intstr.FromInt32(3), Code: ptr.To[int32](1)},
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
						{Value: 0x2, Mask: ptr.To[int32](0x12)}, // SYN bit set (2), but masked with 0x12 (SYN|ACK)
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP flags cleared (SYN cleared)",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-syn == 0)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0, Mask: ptr.To[int32](2)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP multiple flags cleared (SYN or ACK cleared)",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-syn == 0 or tcp[tcpflags] & tcp-ack == 0)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0, Mask: ptr.To[int32](2)},
						{Value: 0, Mask: ptr.To[int32](16)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP mixed flags set then cleared",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-syn == tcp-syn or tcp[tcpflags] & tcp-ack == 0)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x2},
						{Value: 0, Mask: ptr.To[int32](16)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP mixed flags cleared then set",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-syn == 0 or tcp[tcpflags] & tcp-ack == tcp-ack)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0, Mask: ptr.To[int32](2)},
						{Value: 0x10},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP three flags cleared",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-syn == 0 or tcp[tcpflags] & tcp-ack == 0 or tcp[tcpflags] & tcp-rst == 0)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0, Mask: ptr.To[int32](2)},
						{Value: 0, Mask: ptr.To[int32](16)},
						{Value: 0, Mask: ptr.To[int32](4)},
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
					DstPort: ptr.To[int32](443),
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x12, Mask: ptr.To[int32](0x1F)},
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
					DstPort: ptr.To[int32](53),
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
					SrcPort: ptr.To[int32](12345),
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
					SrcPort: ptr.To[int32](12345),
					DstPort: ptr.To[int32](80),
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
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{{Type: intstr.FromInt32(128), Code: ptr.To[int32](1)}},
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
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{{Type: intstr.FromInt32(128), Code: ptr.To[int32](1)}},
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
			Protocol: ptr.To(intstr.FromInt32(6)),
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
			Protocol: ptr.To(intstr.FromInt32(17)),
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
			Protocol: ptr.To(intstr.FromInt32(1)),
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{{Type: intstr.FromInt32(11), Code: ptr.To[int32](0)}},
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
			Protocol: ptr.To(intstr.FromInt32(58)),
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
			Protocol: ptr.To(intstr.FromInt32(132)),
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv6 TCP with src+dst IP and src+dst ports S2D",
		TcpdumpFilter: "ip6 and src host fd00:10:244::1 and dst host fd00:10:244::2 and proto 6 and src port 12345 and dst port 80",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
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
		Name:          "IPv4 TCP with src+dst IP and src port only",
		TcpdumpFilter: "ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 UDP with src+dst IP and dst port only",
		TcpdumpFilter: "ip proto 17 and src host 127.0.0.1 and dst host 127.0.0.2 and dst port 80",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},

	// --- Both direction (bidirectional) filters ---
	{
		Name:          "IPv4 TCP src+dst IP and src+dst ports Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80) or (src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP src+dst IP and src+dst ports Both",
		TcpdumpFilter: "ip6 proto 6 and ((src host fd00:10:244::1 and dst host fd00:10:244::2 and tcp src port 12345 and tcp dst port 80) or (src host fd00:10:244::2 and dst host fd00:10:244::1 and tcp src port 80 and tcp dst port 12345))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 UDP src+dst IP and src+dst ports Both",
		TcpdumpFilter: "ip proto 17 and ((src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80) or (src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP src+dst IP dstPort only Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst host 127.0.0.2 and dst port 80) or (src host 127.0.0.2 and dst host 127.0.0.1 and src port 80))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 UDP src+dst IP and src+dst ports Both",
		TcpdumpFilter: "ip6 proto 17 and ((src host fd00:10:244::1 and dst host fd00:10:244::2 and udp src port 12345 and udp dst port 80) or (src host fd00:10:244::2 and dst host fd00:10:244::1 and udp src port 80 and udp dst port 12345))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP dstOnly dstPort Both",
		TcpdumpFilter: "ip proto 6 and ((dst host 10.0.0.2 and dst port 443) or (src host 10.0.0.2 and src port 443))",
		DstIP:         net.ParseIP("10.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{DstPort: ptr.To[int32](443)},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP dstOnly src+dst ports Both",
		TcpdumpFilter: "ip6 proto 6 and ((dst host fd00:10:244::2 and tcp src port 12345 and tcp dst port 80) or (src host fd00:10:244::2 and tcp src port 80 and tcp dst port 12345))",
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP src+dst IP dstPort SYN flag Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst host 127.0.0.2 and dst port 80 and (tcp[tcpflags] & tcp-syn == tcp-syn)) or (src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and (tcp[tcpflags] & tcp-syn == tcp-syn)))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					DstPort: &testDstPort,
					Flags:   []crdv1alpha1.TCPFlagsMatcher{{Value: 0x2}},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP srcOnly IP and src+dst ports Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and src port 12345 and dst port 80) or (dst host 127.0.0.1 and src port 80 and dst port 12345))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 UDP src+dst IP srcOnly port Both",
		TcpdumpFilter: "ip proto 17 and ((src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345) or (src host 127.0.0.2 and dst host 127.0.0.1 and dst port 12345))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 UDP src+dst IP dstOnly port Both",
		TcpdumpFilter: "ip6 proto 17 and ((src host fd00:10:244::1 and dst host fd00:10:244::2 and udp dst port 80) or (src host fd00:10:244::2 and dst host fd00:10:244::1 and udp src port 80))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP srcOnly IP only Both (no ports)",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1) or (dst host 127.0.0.1))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP dstOnly IP and src+dst ports Both",
		TcpdumpFilter: "ip proto 6 and ((dst host 127.0.0.2 and src port 12345 and dst port 80) or (src host 127.0.0.2 and src port 80 and dst port 12345))",
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP dstOnly IP and src+dst ports Both",
		TcpdumpFilter: "ip6 proto 6 and ((dst host fd00:10:244::2 and tcp src port 12345 and tcp dst port 80) or (src host fd00:10:244::2 and tcp src port 80 and tcp dst port 12345))",
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP srcOnly IP and src+dst ports Both",
		TcpdumpFilter: "ip6 proto 6 and ((src host fd00:10:244::1 and tcp src port 12345 and tcp dst port 80) or (dst host fd00:10:244::1 and tcp src port 80 and tcp dst port 12345))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP src+dst IP Both (echo and echo-reply)",
		TcpdumpFilter: "ip proto 1 and ((src host 127.0.0.1 and dst host 127.0.0.2 and (icmp[0]=8 or icmp[0]=0)) or (src host 127.0.0.2 and dst host 127.0.0.1 and (icmp[0]=8 or icmp[0]=0)))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgEcho},
						{Type: testICMPMsgEchoReply},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 ICMPv6 src+dst IP Both (echo and echo-reply)",
		TcpdumpFilter: "ip6 proto 58 and ((src host fd00:10:244::1 and dst host fd00:10:244::2 and (icmp6[0]=128 or icmp6[0]=129)) or (src host fd00:10:244::2 and dst host fd00:10:244::1 and (icmp6[0]=128 or icmp6[0]=129)))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testICMPv6Protocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{
						{Type: testICMPv6MsgEcho},
						{Type: testICMPv6MsgEchoReply},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP src+dst IP multiple flags Both (SYN or ACK)",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345 and dst port 80 and ((tcp[tcpflags] & tcp-syn == tcp-syn) or (tcp[tcpflags] & tcp-ack == tcp-ack))) or (src host 127.0.0.2 and dst host 127.0.0.1 and src port 80 and dst port 12345 and ((tcp[tcpflags] & tcp-syn == tcp-syn) or (tcp[tcpflags] & tcp-ack == tcp-ack))))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x2},
						{Value: 0x10},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP srcOnly IP only Both (no ports)",
		TcpdumpFilter: "ip6 proto 6 and ((src host fd00:10:244::1) or (dst host fd00:10:244::1))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP proto-only Both (no IPs, no ports)",
		TcpdumpFilter: "ip proto 6",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP src+dst IP type+code Both",
		TcpdumpFilter: "ip proto 1 and ((src host 127.0.0.1 and dst host 127.0.0.2 and icmp[0]=8 and icmp[1]=0) or (src host 127.0.0.2 and dst host 127.0.0.1 and icmp[0]=8 and icmp[1]=0))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgEcho, Code: ptr.To[int32](0)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP multiple messages with code",
		TcpdumpFilter: "ip proto 1 and ((icmp[0]=3 and icmp[1]=1) or icmp[0]=8)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgDstUnreach, Code: ptr.To[int32](1)},
						{Type: testICMPMsgEcho},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 ICMP multiple messages both direction",
		TcpdumpFilter: "ip proto 1 and ((src host 127.0.0.1 and dst host 127.0.0.2 and ((icmp[0]=3 and icmp[1]=1) or icmp[0]=8)) or (src host 127.0.0.2 and dst host 127.0.0.1 and ((icmp[0]=3 and icmp[1]=1) or icmp[0]=8)))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgDstUnreach, Code: ptr.To[int32](1)},
						{Type: testICMPMsgEcho},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP src+dst IP multiple flags Both (SYN or ACK) no ports",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst host 127.0.0.2 and ((tcp[tcpflags] & tcp-syn == tcp-syn) or (tcp[tcpflags] & tcp-ack == tcp-ack))) or (src host 127.0.0.2 and dst host 127.0.0.1 and ((tcp[tcpflags] & tcp-syn == tcp-syn) or (tcp[tcpflags] & tcp-ack == tcp-ack))))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{
						{Value: 0x2},
						{Value: 0x10},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 ICMPv6 multiple messages both direction",
		TcpdumpFilter: "icmp6 and ((src host fd00:10:244::1 and dst host fd00:10:244::2 and ((icmp6[0]=1 and icmp6[1]=1) or icmp6[0]=128)) or (src host fd00:10:244::2 and dst host fd00:10:244::1 and ((icmp6[0]=1 and icmp6[1]=1) or icmp6[0]=128)))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testICMPv6Protocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{
						{Type: testICMPv6MsgDstUnreach, Code: ptr.To[int32](1)},
						{Type: testICMPv6MsgEcho},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 ICMPv6 multiple messages with code",
		TcpdumpFilter: "icmp6 and ((icmp6[0]=1 and icmp6[1]=1) or icmp6[0]=128)",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testICMPv6Protocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMPv6: &crdv1alpha1.ICMPv6Header{
					Messages: []crdv1alpha1.ICMPv6MsgMatcher{
						{Type: testICMPv6MsgDstUnreach, Code: ptr.To[int32](1)},
						{Type: testICMPv6MsgEcho},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionSourceToDestination,
	},
	{
		Name:          "IPv4 TCP ports Both (no IPs)",
		TcpdumpFilter: "ip proto 6 and ((tcp src port 12345 and tcp dst port 80) or (tcp src port 80 and tcp dst port 12345))",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP ports Both (no IPs)",
		TcpdumpFilter: "ip6 proto 6 and ((tcp src port 12345 and tcp dst port 80) or (tcp src port 80 and tcp dst port 12345))",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 UDP ports Both (no IPs)",
		TcpdumpFilter: "ip proto 17 and ((udp src port 12345 and udp dst port 80) or (udp src port 80 and udp dst port 12345))",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{
					SrcPort: &testSrcPort,
					DstPort: &testDstPort,
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP srcPort only Both (no IPs)",
		TcpdumpFilter: "ip proto 6 and ((src port 12345) or (dst port 12345))",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP dstPort only Both (no IPs)",
		TcpdumpFilter: "ip proto 6 and ((dst port 80) or (src port 80))",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 UDP dstPort only Both (no IPs)",
		TcpdumpFilter: "ip proto 17 and ((dst port 80) or (src port 80))",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 UDP ports Both (no IPs)",
		TcpdumpFilter: "ip6 proto 17 and ((udp src port 12345 and udp dst port 80) or (udp src port 80 and udp dst port 12345))",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testUDPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				UDP: &crdv1alpha1.UDPHeader{SrcPort: &testSrcPort, DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	// --- Edge cases: IP-only bidirectional (no ports) ---
	{
		Name:          "IPv4 TCP dstOnly IP only Both (no ports)",
		TcpdumpFilter: "ip proto 6 and ((dst host 127.0.0.2) or (src host 127.0.0.2))",
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP dstOnly IP only Both (no ports)",
		TcpdumpFilter: "ip6 proto 6 and ((dst host fd00:10:244::2) or (src host fd00:10:244::2))",
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP src+dst IP srcPort only Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst host 127.0.0.2 and src port 12345) or (src host 127.0.0.2 and dst host 127.0.0.1 and dst port 12345))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{SrcPort: &testSrcPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	// --- Edge cases: proto-only bidirectional ---
	{
		Name:          "IPv6 TCP proto-only Both (no IPs, no ports)",
		TcpdumpFilter: "ip6 proto 6",
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 UDP proto-only Both (no IPs, no ports)",
		TcpdumpFilter: "ip proto 17",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testUDPProtocol,
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	// --- Edge cases: flags without IPs ---
	{
		Name:          "IPv4 TCP SYN flag only Both (no IPs, no ports)",
		TcpdumpFilter: "ip proto 6 and (tcp[tcpflags] & tcp-syn == tcp-syn)",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{
					Flags: []crdv1alpha1.TCPFlagsMatcher{{Value: 0x2}},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	// --- Edge cases: srcOnly IP + dstPort only Both ---
	{
		Name:          "IPv4 TCP srcOnly IP dstPort only Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and dst port 80) or (dst host 127.0.0.1 and src port 80))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{DstPort: &testDstPort},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP type only Both (no IPs)",
		TcpdumpFilter: "ip proto 1 and ((icmp[0]=8 or icmp[0]=0) or (icmp[0]=8 or icmp[0]=0))",
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgEcho},
						{Type: testICMPMsgEchoReply},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP srcOnly IP type Both",
		TcpdumpFilter: "ip proto 1 and ((src host 127.0.0.1 and (icmp[0]=8 or icmp[0]=0)) or (dst host 127.0.0.1 and (icmp[0]=8 or icmp[0]=0)))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgEcho},
						{Type: testICMPMsgEchoReply},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP dstOnly IP type Both",
		TcpdumpFilter: "ip proto 1 and ((dst host 127.0.0.2 and (icmp[0]=8 or icmp[0]=0)) or (src host 127.0.0.2 and (icmp[0]=8 or icmp[0]=0)))",
		DstIP:         net.ParseIP("127.0.0.2"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgEcho},
						{Type: testICMPMsgEchoReply},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 TCP srcOnly IP SYN flag Both",
		TcpdumpFilter: "ip proto 6 and ((src host 127.0.0.1 and (tcp[tcpflags] & tcp-syn == tcp-syn)) or (dst host 127.0.0.1 and (tcp[tcpflags] & tcp-syn == tcp-syn)))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{Flags: []crdv1alpha1.TCPFlagsMatcher{{Value: 0x2}}},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv4 ICMP srcOnly IP type+code Both",
		TcpdumpFilter: "ip proto 1 and ((src host 127.0.0.1 and icmp[0]=3 and icmp[1]=1) or (dst host 127.0.0.1 and icmp[0]=3 and icmp[1]=1))",
		SrcIP:         net.ParseIP("127.0.0.1"),
		Packet: &crdv1alpha1.Packet{
			Protocol: &testICMPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				ICMP: &crdv1alpha1.ICMPHeader{
					Messages: []crdv1alpha1.ICMPMsgMatcher{
						{Type: testICMPMsgDstUnreach, Code: ptr.To[int32](1)},
					},
				},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
	{
		Name:          "IPv6 TCP src+dst IP SYN flag Both",
		TcpdumpFilter: "ip6 proto 6 and ((src host fd00:10:244::1 and dst host fd00:10:244::2 and (ip6[40+13] & tcp-syn == tcp-syn)) or (src host fd00:10:244::2 and dst host fd00:10:244::1 and (ip6[40+13] & tcp-syn == tcp-syn)))",
		SrcIP:         net.ParseIP("fd00:10:244::1"),
		DstIP:         net.ParseIP("fd00:10:244::2"),
		Packet: &crdv1alpha1.Packet{
			IPFamily: v1.IPv6Protocol,
			Protocol: &testTCPProtocol,
			TransportHeader: crdv1alpha1.TransportHeader{
				TCP: &crdv1alpha1.TCPHeader{Flags: []crdv1alpha1.TCPFlagsMatcher{{Value: 0x2}}},
			},
		},
		Direction: crdv1alpha1.CaptureDirectionBoth,
	},
}
