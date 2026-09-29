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

package types

const (
	// HostLocalSourceBit is the bit of the iptables fwmark space to mark locally generated packets.
	// Value must be within the range [0, 31], and should not conflict with bits for other purposes.
	HostLocalSourceBit = 31

	// EgressNoEncapReturnToRemoteBit is the bit of the iptables fwmark space to mark the reply Egress packets whose request
	// packets are from remote Pods. It is used in hybrid, noEncap, and WireGuard encryption modes.
	EgressNoEncapReturnToRemoteBit = 30

	// L2DispatchBit is the bit of the fwmark space which marks a packet that the host must send to the MAC address of
	// a peer Node in the local transport subnet, instead of routing it by its destination. This is the l2 dispatch.
	// The bits L2DispatchPeerIndexMinBit to L2DispatchPeerIndexMaxBit hold the index of the peer Node. The bits must
	// not conflict with SNATIPMarkMask, EgressNoEncapReturnToRemoteBit, HostLocalSourceBit, or the bits 14 and 15
	// which kube-proxy uses.
	L2DispatchBit             = 29
	L2DispatchPeerIndexMinBit = 16
	L2DispatchPeerIndexMaxBit = 27
)

var (
	// HostLocalSourceMark is the mark generated from HostLocalSourceBit.
	HostLocalSourceMark = uint32(1 << HostLocalSourceBit)

	// EgressNoEncapReturnToRemoteMark is the mark generated from EgressNoEncapReturnToRemoteBit.
	EgressNoEncapReturnToRemoteMark = uint32(1 << EgressNoEncapReturnToRemoteBit)

	// SNATIPMarkMask is the bits of packet mark that stores the ID of the
	// SNAT IP for a "Pod -> external" egress packet, that is to be SNAT'd.
	SNATIPMarkMask = uint32(0xFF)

	// L2DispatchMark is the mark generated from L2DispatchBit.
	L2DispatchMark = uint32(1 << L2DispatchBit)
	// L2DispatchPeerMarkMask is the bits of the packet mark which identify the peer Node of the l2 dispatch: the
	// dispatch bit and the peer index.
	L2DispatchPeerMarkMask = L2DispatchMark | uint32(MaxL2DispatchPeerIndex)<<L2DispatchPeerIndexMinBit
)

const (
	// MaxL2DispatchPeerIndex is the largest index of a peer Node of the l2 dispatch. Index 0 is never allocated.
	MaxL2DispatchPeerIndex = 1<<(L2DispatchPeerIndexMaxBit-L2DispatchPeerIndexMinBit+1) - 1

	// L2DispatchGuardRulePriority, L2DispatchPeerRulePriority and L2DispatchDropRulePriority are the priorities of the
	// ip rules of the l2 dispatch. The guard rule makes the packets carrying L2DispatchMark skip the main table and
	// jump to the peer rules: a no-op rule, which keeps the jump target present when no peer Node is installed, and
	// one rule per peer Node. The drop rule drops a marked packet that no peer rule matched, instead of letting it
	// reach the main table. The peer rules come after the main table, so the packets without the mark stop at the
	// main table and never evaluate them.
	L2DispatchGuardRulePriority = 32000
	L2DispatchPeerRulePriority  = 40000
	L2DispatchDropRulePriority  = 40001
)

// L2DispatchPeerMark returns the packet mark which makes the host send a packet to the peer Node with the index.
func L2DispatchPeerMark(peerIndex uint32) uint32 {
	return L2DispatchMark | peerIndex<<L2DispatchPeerIndexMinBit
}

// L2DispatchRouteTable returns the route table of the peer Node with the index.
func L2DispatchRouteTable(peerIndex uint32) int {
	return L2DispatchRouteTableBase + int(peerIndex)
}

// IP Route tables
const (
	// MinRequestEgressRouteTable to MaxRequestEgressRouteTable are the route table IDs that can be configured on a Node for Egress traffic.
	// Each distinct subnet uses one route table. 20 subnets should be enough.
	MinRequestEgressRouteTable = 101
	MaxRequestEgressRouteTable = 120

	// ReplyEgressRouteTable is the route table ID which is used to add policy routing rules in hybrid, noEncap, and WireGuard encryption modes.
	ReplyEgressRouteTable = 141

	// L2DispatchRouteTableBase is the base of the route table IDs of the l2 dispatch: the table of the peer Node with
	// index i is L2DispatchRouteTableBase + i. The base itself, for index 0, is never used.
	L2DispatchRouteTableBase = 1001
)
