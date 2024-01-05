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
)

var (
	// HostLocalSourceMark is the mark generated from HostLocalSourceBit.
	HostLocalSourceMark = uint32(1 << HostLocalSourceBit)

	// SNATIPMarkMask is the bits of packet mark that stores the ID of the
	// SNAT IP for a "Pod -> external" egress packet, that is to be SNAT'd.
	SNATIPMarkMask = uint32(0xFF)
)

// IP Route tables
const (
	// MinEgressRouteTable to MaxEgressRouteTable are the route table IDs that can be configured on a Node for Egress traffic.
	// Each distinct subnet uses one route table. 20 subnets should be enough.
	MinEgressRouteTable = 101
	MaxEgressRouteTable = 120
)
