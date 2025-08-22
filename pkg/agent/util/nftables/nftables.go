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

package nftables

import "sigs.k8s.io/knftables"

const antreaTable = "antrea"

func New(enableIPv4, enableIPv6 bool) (knftables.Interface, error) {
	var ipFamily knftables.Family
	if enableIPv4 && enableIPv6 {
		ipFamily = knftables.InetFamily
	} else if enableIPv4 {
		ipFamily = knftables.IPv4Family
	} else if enableIPv6 {
		ipFamily = knftables.IPv6Family
	}

	nft, err := knftables.New(ipFamily, antreaTable)
	if err != nil {
		return nil, err
	}

	return nft, nil
}
