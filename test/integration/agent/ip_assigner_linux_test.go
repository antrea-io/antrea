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
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/ipassigner"
)

const dummyDeviceName = "antrea-dummy0"

func TestIPAssigner(t *testing.T) {
	nodeLinkName := nodeIntf.Name
	require.NotNil(t, nodeLinkName, "Get Node link failed")

	ipAssigner, err := ipassigner.NewIPAssigner(nodeLinkName, dummyDeviceName)
	require.NoError(t, err, "Initializing IP assigner failed")

	dummyDevice, err := netlink.LinkByName(dummyDeviceName)
	require.NoError(t, err, "Failed to find the dummy device")
	defer netlink.LinkDel(dummyDevice)

	_, err = ipAssigner.AssignIP("x", false)
	assert.Error(t, err, "Assigning an invalid IP should fail")

	ip1 := "10.10.10.10"
	ip2 := "10.10.10.11"
	ip3 := "2021:124:6020:1006:250:56ff:fea7:36c2"
	desiredIPs := sets.New[string](ip1, ip2, ip3)

	for ip := range desiredIPs {
		_, errAssign := ipAssigner.AssignIP(ip, false)
		cmd := exec.Command("ip", "addr")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("List ip addr error: %v", err)
		}
		assert.NoError(t, errAssign, fmt.Sprintf("Failed to assign a valid IP, ip addrs: %s", string(out)))
	}

	assert.Equal(t, desiredIPs, ipAssigner.AssignedIPs(), "Assigned IPs don't match")

	actualIPs, err := listIPAddresses(dummyDevice)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, desiredIPs, actualIPs, "Actual IPs don't match")

	newIPAssigner, err := ipassigner.NewIPAssigner(nodeLinkName, dummyDeviceName)
	require.NoError(t, err, "Initializing new IP assigner failed")
	assert.Equal(t, sets.New[string](), newIPAssigner.AssignedIPs(), "Assigned IPs don't match")

	ip4 := "2021:124:6020:1006:250:56ff:fea7:36c4"
	newDesiredIPs := sets.New[string](ip1, ip2, ip4)
	err = newIPAssigner.InitIPs(newDesiredIPs)
	require.NoError(t, err, "InitIPs failed")
	assert.Equal(t, newDesiredIPs, newIPAssigner.AssignedIPs(), "Assigned IPs don't match")

	actualIPs, err = listIPAddresses(dummyDevice)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, newDesiredIPs, actualIPs, "Actual IPs don't match")

	for ip := range newDesiredIPs {
		_, err = newIPAssigner.UnassignIP(ip)
		assert.NoError(t, err, "Failed to unassign a valid IP")
	}
	assert.Equal(t, sets.New[string](), newIPAssigner.AssignedIPs(), "Assigned IPs don't match")

	actualIPs, err = listIPAddresses(dummyDevice)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](), actualIPs, "Actual IPs don't match")
}

func listIPAddresses(device netlink.Link) (sets.Set[string], error) {
	addrList, err := netlink.AddrList(device, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	addresses := sets.New[string]()
	for _, addr := range addrList {
		addresses.Insert(addr.IP.String())
	}
	return addresses, nil
}
