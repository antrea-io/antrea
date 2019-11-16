// Copyright 2019 Antrea Authors
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

package store

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
)

// filter returns whether the provided selectors matches the key and/or the nodeNames.
func filter(selectors *storage.Selectors, key string, nodeNames sets.String) bool {
	// If Key is present in selectors, the provided key must match it.
	if selectors.Key != "" && key != selectors.Key {
		return false
	}
	// If nodeName is present in selectors's Field selector, the provided nodeNames must contain it.
	if nodeName, found := selectors.Field.RequiresExactMatch("nodeName"); found {
		if !nodeNames.Has(nodeName) {
			return false
		}
	}
	return true
}

// IPStrToIPAddress converts an IP string to networkpolicy.IPAddress.
// nil will returned if the IP string is not valid.
func IPStrToIPAddress(ip string) networkpolicy.IPAddress {
	return networkpolicy.IPAddress(net.ParseIP(ip))
}

// CIDRStrToIPNet converts a CIDR (eg. 10.0.0.0/16) to a *networkpolicy.IPNet.
func CIDRStrToIPNet(cidr string) (*networkpolicy.IPNet, error) {
	// Split the cidr to retrieve the IP and prefix.
	s := strings.Split(cidr, "/")
	if len(s) != 2 {
		return nil, fmt.Errorf("invalid format for IPBlock CIDR: %s", cidr)
	}
	// Convert prefix length to int32
	prefixLen64, err := strconv.ParseInt(s[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix length: %s", s[1])
	}
	ipNet := &networkpolicy.IPNet{
		IP:           IPStrToIPAddress(s[0]),
		PrefixLength: int32(prefixLen64),
	}
	return ipNet, nil
}
