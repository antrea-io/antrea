// Copyright 2025 Antrea Authors
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

package e2e

var (
	protocolICMP   = int32(1)
	protocolTCP    = int32(6)
	protocolUDP    = int32(17)
	protocolICMPv6 = int32(58)
	tcpFlags       = int32(2) // SYN flag set
)

var (
	icmpRequestType  = int32(8)
	icmp6RequestType = int32(128)
	icmpRequestCode  = int32(0)

	igmpQueryType = int32(0x11)
)

var (
	p80   = int32(80)
	p81   = int32(81)
	p6443 = int32(6443)
	p8080 = int32(8080)
	p8082 = int32(8082)
)
