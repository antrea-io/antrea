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
	"net"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/util"
	ps "antrea.io/antrea/pkg/agent/util/powershell"
)

func adapterName(name string) string {
	return fmt.Sprintf("%s (%s)", util.ContainerVNICPrefix, name)
}

// windowsHyperVEnabled checks if the Hyper-V is enabled on the host.
// Hyper-V feature contains multiple components/sub-features. According to the
// test, OVS requires "Microsoft-Hyper-V" feature to be enabled.
func windowsHyperVEnabled() (bool, error) {
	cmd := "$(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State"
	result, err := ps.RunCommand(cmd)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(result, "Enabled"), nil
}

func skipIfHyperVDisabled(t *testing.T) {
	t.Logf("Checking if Hyper-V feature is enabled")
	enabled, err := windowsHyperVEnabled()
	require.NoError(t, err)
	if !enabled {
		t.Skipf("Skipping test as it requires the Hyper-V feature to be enabled")
	}
}

func skipIfMissingAdapter(t *testing.T, adapterName string) {
	t.Logf("Checking if adapter '%s' exists", adapterName)
	if _, err := net.InterfaceByName(adapterName); err != nil {
		t.Skipf("Skipping test because we cannot verify that adapter '%s' exists", adapterName)
	}
}

func skipIfOVSExtensionNotInstalled(t *testing.T) {
	t.Logf("Checking if the Open vSwitch Extension is installed")
	cmd := `Get-VMSystemSwitchExtension -Name "Open vSwitch Extension"`
	if _, err := ps.RunCommand(cmd); err != nil {
		t.Skipf("Skipping test because we cannot verify that the Open vSwitch Extension is installed")
	}
}

func createTestInterface(t *testing.T, name string) string {
	skipIfHyperVDisabled(t)
	t.Logf("Creating test vSwitch and adapter '%s'", name)
	cmd := fmt.Sprintf("New-VMSwitch %s -SwitchType Internal", name)
	_, err := ps.RunCommand(cmd)
	require.NoError(t, err)
	return adapterName(name)
}

func setTestInterfaceUp(t *testing.T, name string) int {
	_, ifaceIdx, err := util.SetLinkUp(adapterName(name))
	require.NoError(t, err)
	return ifaceIdx
}

func deleteTestInterface(t *testing.T, name string) {
	t.Logf("Deleting test vSwitch '%s'", name)
	cmd := fmt.Sprintf(`Remove-VMSwitch "%s" -Force`, name)
	_, err := ps.RunCommand(cmd)
	assert.NoError(t, err)
}

func getTestInterfaceAddresses(t *testing.T, name string) []*net.IPNet {
	return getAdapterAddresses(t, adapterName(name))
}

func getAdapterAddresses(t *testing.T, name string) []*net.IPNet {
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	addrs, err := iface.Addrs()
	require.NoError(t, err)
	var result []*net.IPNet
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			result = append(result, ipNet)
		}
	}
	return result
}

// getAdapterIPv4Address returns the "first" IPv4 address assigned to the provided adapter.
func getAdapterIPv4Address(t *testing.T, name string) *net.IPNet {
	addrs := getAdapterAddresses(t, name)
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			return addr
		}
	}
	return nil
}

func addTestInterfaceAddress(t *testing.T, name string, addr *net.IPNet) {
	ipStr := strings.Split(addr.String(), "/")
	cmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, adapterName(name), ipStr[0], ipStr[1])
	_, err := ps.RunCommand(cmd)
	require.NoError(t, err)
}

func TestCreateHNSNetwork(t *testing.T) {
	skipIfHyperVDisabled(t)
	skipIfOVSExtensionNotInstalled(t)
	adapterName := "Ethernet0"
	skipIfMissingAdapter(t, adapterName)
	testNet := randName()
	_, err := hcsshim.GetHNSNetworkByName(testNet)
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("Network %s not found", testNet))

	t.Logf("Retrieving IPv4 address for adapter '%s'", adapterName)
	nodeIP := getAdapterIPv4Address(t, adapterName)
	require.NotNil(t, err, "Could not find an IPv4 address for adapter '%s'", adapterName)

	addr, subnet, _ := net.ParseCIDR("172.16.1.1/24")
	adapter, err := net.InterfaceByName(adapterName)
	require.Nil(t, err)
	t.Logf("Creating HNSNetwork '%s'", testNet)
	hnsNet, err := util.CreateHNSNetwork(testNet, subnet, nodeIP, adapter)
	require.Nil(t, err, "No error expected when creating HNSNetwork")
	defer func() {
		t.Logf("Deleting HNSNetwork '%s'", testNet)
		_, err := hnsNet.Delete()
		assert.NoError(t, err)
	}()

	assert.Equal(t, hnsNet.Name, testNet)
	assert.Equal(t, hnsNet.Type, util.HNSNetworkType)
	assert.Len(t, hnsNet.Subnets, 1)
	assert.Equal(t, hnsNet.Subnets[0].AddressPrefix, subnet.String())
	assert.Equal(t, hnsNet.Subnets[0].GatewayAddress, addr.String())
	assert.Equal(t, hnsNet.ManagementIP, nodeIP.String())

	t.Logf("Enabling the Open vSwitch Extension for HNSNetwork '%s'", testNet)
	err = util.EnableHNSNetworkExtension(hnsNet.Id, util.OVSExtensionID)
	require.Nil(t, err, "No error expected when enabling the Open vSwitch Extension for the HNSNetwork")
}
