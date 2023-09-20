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

package agent

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/util"
)

func randName() string {
	// #nosec G404: random number generator not used for security purposes
	suffix := rand.Uint32()
	return fmt.Sprintf("test%x", suffix)
}

func addrEqual(addr1, addr2 *net.IPNet) bool {
	size1, _ := addr1.Mask.Size()
	size2, _ := addr2.Mask.Size()
	return addr1.IP.Equal(addr2.IP) && size1 == size2
}

func isAddressPresent(addrs []*net.IPNet, addr *net.IPNet) bool {
	for _, a := range addrs {
		if addrEqual(a, addr) {
			return true
		}
	}
	return false
}

func TestConfigureLinkAddresses(t *testing.T) {
	ifaceName := randName()
	createTestInterface(t, ifaceName)
	defer deleteTestInterface(t, ifaceName)
	ifaceIdx := setTestInterfaceUp(t, ifaceName)

	addrs := getTestInterfaceAddresses(t, ifaceName)
	t.Logf("Found the following initial addresses: %v", addrs)
	nAddrs := len(addrs)
	// there can be up to one IPv6 link-local address and one IPv4
	// link-local address (on Windows)
	assert.LessOrEqual(t, nAddrs, 2)

	_, dummyAddr, _ := net.ParseCIDR("192.0.2.0/24")

	addTestInterfaceAddress(t, ifaceName, dummyAddr)
	addrs = getTestInterfaceAddresses(t, ifaceName)
	assert.True(t, isAddressPresent(addrs, dummyAddr), "Dummy IP address was not assigned to test interface")

	_, ipAddr, _ := net.ParseCIDR("192.0.3.0/24")
	err := util.ConfigureLinkAddresses(ifaceIdx, []*net.IPNet{ipAddr})
	require.NoError(t, err)

	addrs = getTestInterfaceAddresses(t, ifaceName)
	assert.True(t, isAddressPresent(addrs, ipAddr), "IP address was not assigned to test interface")
	assert.False(t, isAddressPresent(addrs, dummyAddr), "Dummy IP address should have been removed from test interface")
}
