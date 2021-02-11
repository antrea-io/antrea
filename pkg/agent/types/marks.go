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
	// Value must be within the range [0, 31].
	HostLocalSourceBit = 0
)

var (
	// HostLocalSourceMark is the mark generated from HostLocalSourceBit.
	HostLocalSourceMark = uint32(1 << HostLocalSourceBit)
)
