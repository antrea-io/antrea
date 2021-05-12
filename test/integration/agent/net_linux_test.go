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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"antrea.io/antrea/pkg/agent/util"
)

func createTestInterface(t *testing.T, name string) string {
	t.Logf("Creating dummy test interface '%s'", name)
	gwLink := &netlink.Dummy{}
	gwLink.Name = name
	require.NoError(t, netlink.LinkAdd(gwLink))
	link, _ := netlink.LinkByName(name)
	require.NoError(t, netlink.LinkSetUp(link))
	return name
}

func setTestInterfaceUp(t *testing.T, name string) int {
	_, ifaceIdx, err := util.SetLinkUp(name)
	require.NoError(t, err)
	return ifaceIdx
}

func deleteTestInterface(t *testing.T, name string) {
	t.Logf("Deleting dummy test interface '%s'", name)
	link, _ := netlink.LinkByName(name)
	assert.NoError(t, netlink.LinkDel(link))
}

func getTestInterfaceAddresses(t *testing.T, name string) []*net.IPNet {
	link, _ := netlink.LinkByName(name)
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	require.NoError(t, err)
	var result []*net.IPNet
	for _, addr := range addrs {
		result = append(result, addr.IPNet)
	}
	return result
}

func addTestInterfaceAddress(t *testing.T, name string, addr *net.IPNet) {
	link, _ := netlink.LinkByName(name)
	require.NoError(t, netlink.AddrAdd(link, &netlink.Addr{IPNet: addr}))
}
