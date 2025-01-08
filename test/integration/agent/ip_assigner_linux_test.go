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
	"antrea.io/antrea/pkg/agent/util/sysctl"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

const dummyDeviceName = "antrea-dummy0"

func checkSysctl(t *testing.T, path string, expected int) {
	t.Helper()
	v, err := sysctl.GetSysctlNet(path)
	require.NoError(t, err)
	assert.Equalf(t, expected, v, "Wrong value for %s", path)
}

func checkRPFilterOnInterface(t *testing.T, ifaceName string, expected int) {
	t.Helper()
	checkSysctl(t, fmt.Sprintf("ipv4/conf/%s/rp_filter", ifaceName), expected)
}

func checkPromoteSecondariesOnInterface(t *testing.T, ifaceName string, expected int) {
	t.Helper()
	checkSysctl(t, fmt.Sprintf("ipv4/conf/%s/promote_secondaries", ifaceName), expected)
}

func TestIPAssigner(t *testing.T) {
	nodeLinkName := nodeIntf.Name
	require.NotNil(t, nodeLinkName, "Get Node link failed")

	ipAssigner, err := ipassigner.NewIPAssigner(nodeLinkName, dummyDeviceName, nil)
	require.NoError(t, err, "Initializing IP assigner failed")

	dummyDevice, err := netlink.LinkByName(dummyDeviceName)
	require.NoError(t, err, "Failed to find the dummy device")
	defer netlink.LinkDel(dummyDevice)
	checkPromoteSecondariesOnInterface(t, dummyDeviceName, 1)

	_, err = ipAssigner.AssignIP("x", nil, false)
	assert.Error(t, err, "Assigning an invalid IP should fail")

	ip1 := "10.10.10.10"
	ip2 := "10.10.10.11"
	ip3 := "2021:124:6020:1006:250:56ff:fea7:36c2"
	ip1VLAN20 := "10.10.20.10"
	ip2VLAN20 := "10.10.20.11"
	ip1VLAN30 := "10.10.30.10"
	subnet20 := &crdv1b1.SubnetInfo{PrefixLength: 24, VLAN: 20}
	subnet30 := &crdv1b1.SubnetInfo{PrefixLength: 24, VLAN: 30}
	// These IPs will be assigned to the correct interface, in the specified order.
	ipsToAssign := []struct {
		ip         string
		subnetInfo *crdv1b1.SubnetInfo
	}{
		{
			ip: ip1,
		},
		{
			ip: ip2,
		},
		{
			ip: ip3,
		},
		// ip1VLAN20 and ip2VLAN20 are in the same subnet and will be assigned to the same
		// interface (antrea-ext.20).
		// ip1VLAN20 will be assigned first, which means ip1VLAN20 will be the "primary" IP,
		// while ip2VLAN20 will be the "secondary" IP.
		{
			ip:         ip1VLAN20,
			subnetInfo: subnet20,
		},
		{
			ip:         ip2VLAN20,
			subnetInfo: subnet20,
		},
		{
			ip:         ip1VLAN30,
			subnetInfo: subnet30,
		},
	}

	desiredIPs := make(map[string]*crdv1b1.SubnetInfo)
	for _, assignment := range ipsToAssign {
		ip, subnetInfo := assignment.ip, assignment.subnetInfo
		desiredIPs[ip] = subnetInfo

		_, errAssign := ipAssigner.AssignIP(ip, subnetInfo, false)
		cmd := exec.Command("ip", "addr")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("List ip addr error: %v", err)
		}
		assert.NoError(t, errAssign, fmt.Sprintf("Failed to assign a valid IP, ip addrs: %s", string(out)))
	}

	assert.Equal(t, desiredIPs, ipAssigner.AssignedIPs(), "Assigned IPs don't match")

	vlan20Device, err := netlink.LinkByName("antrea-ext.20")
	require.NoError(t, err, "Failed to find the VLAN 20 device")
	defer netlink.LinkDel(vlan20Device)
	checkRPFilterOnInterface(t, "antrea-ext.20", 2)
	checkPromoteSecondariesOnInterface(t, "antrea-ext.20", 1)
	vlan30Device, err := netlink.LinkByName("antrea-ext.30")
	require.NoError(t, err, "Failed to find the VLAN 30 device")
	defer netlink.LinkDel(vlan30Device)
	checkRPFilterOnInterface(t, "antrea-ext.30", 2)
	checkPromoteSecondariesOnInterface(t, "antrea-ext.30", 1)

	actualIPs, err := listIPAddresses(dummyDevice)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](fmt.Sprintf("%s/32", ip1), fmt.Sprintf("%s/32", ip2), fmt.Sprintf("%s/128", ip3)), actualIPs, "Actual IPs don't match")
	actualIPs, err = listIPAddresses(vlan20Device)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](fmt.Sprintf("%s/%d", ip1VLAN20, subnet20.PrefixLength), fmt.Sprintf("%s/%d", ip2VLAN20, subnet20.PrefixLength)), actualIPs, "Actual IPs don't match")
	actualIPs, err = listIPAddresses(vlan30Device)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](fmt.Sprintf("%s/%d", ip1VLAN30, subnet30.PrefixLength)), actualIPs, "Actual IPs don't match")

	newIPAssigner, err := ipassigner.NewIPAssigner(nodeLinkName, dummyDeviceName, nil)
	require.NoError(t, err, "Initializing new IP assigner failed")
	assert.Equal(t, map[string]*crdv1b1.SubnetInfo{}, newIPAssigner.AssignedIPs(), "Assigned IPs don't match")

	ip4 := "2021:124:6020:1006:250:56ff:fea7:36c4"
	// ip1VLAN20 is omitted, so it will be removed from the antrea-ext.20 interface. Because it
	// is the primary IP address, secondary IPs (in this case ip2VLAN20) in the same subnet will
	// be automatically removed when the primary is removed, unless the promote_secondaries
	// sysctl variable has been set to 1 on the interface, which should be the case.
	// By removing ip1VLAN20 (primary), we can therefore validate that IPAssigner is setting
	// promote_secondaries correctly on the interface, as otherwise ip2VLAN20 will be removed
	// automatically.
	newDesiredIPs := map[string]*crdv1b1.SubnetInfo{ip1: nil, ip2: nil, ip4: nil, ip2VLAN20: subnet20}
	err = newIPAssigner.InitIPs(newDesiredIPs)
	require.NoError(t, err, "InitIPs failed")
	assert.Equal(t, newDesiredIPs, newIPAssigner.AssignedIPs(), "Assigned IPs don't match")

	actualIPs, err = listIPAddresses(dummyDevice)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](fmt.Sprintf("%s/32", ip1), fmt.Sprintf("%s/32", ip2), fmt.Sprintf("%s/128", ip4)), actualIPs, "Actual IPs don't match")
	actualIPs, err = listIPAddresses(vlan20Device)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](fmt.Sprintf("%s/%d", ip2VLAN20, subnet20.PrefixLength)), actualIPs, "Actual IPs don't match")
	_, err = netlink.LinkByName("antrea-ext.30")
	require.Error(t, err, "VLAN 30 device should be deleted but was not")

	for ip := range newDesiredIPs {
		_, err = newIPAssigner.UnassignIP(ip)
		assert.NoError(t, err, "Failed to unassign a valid IP")
	}
	assert.Equal(t, map[string]*crdv1b1.SubnetInfo{}, newIPAssigner.AssignedIPs(), "Assigned IPs don't match")

	actualIPs, err = listIPAddresses(dummyDevice)
	require.NoError(t, err, "Failed to list IP addresses")
	assert.Equal(t, sets.New[string](), actualIPs, "Actual IPs don't match")
	_, err = netlink.LinkByName("antrea-ext.20")
	require.Error(t, err, "VLAN 20 device should be deleted but was not")
}

func listIPAddresses(device netlink.Link) (sets.Set[string], error) {
	addrList, err := netlink.AddrList(device, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	addresses := sets.New[string]()
	for _, addr := range addrList {
		if addr.IP.IsGlobalUnicast() {
			addresses.Insert(addr.IPNet.String())
		}
	}
	return addresses, nil
}
