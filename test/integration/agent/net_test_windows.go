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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

func adapterName(name string) string {
	return fmt.Sprintf("vEthernet (%s)", name)
}

func createTestInterface(t *testing.T, name string) string {
	t.Logf("Checking if Hyper-V feature is enabled")
	enabled, err := util.WindowsHyperVEnabled()
	require.NoError(t, err)
	if !enabled {
		t.Skipf("Skipping test as it requires the Hyper-V feature to be enabled")
	}
	t.Logf("Creating test vSwitch and adapter '%s'", name)
	cmd := fmt.Sprintf("New-VMSwitch %s -SwitchType Internal", name)
	require.NoError(t, util.InvokePSCommand(cmd))
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
	assert.NoError(t, util.InvokePSCommand(cmd))
}

func getTestInterfaceAddresses(t *testing.T, name string) []*net.IPNet {
	iface, err := net.InterfaceByName(adapterName(name))
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

func addTestInterfaceAddress(t *testing.T, name string, addr *net.IPNet) {
	ipStr := strings.Split(addr.String(), "/")
	cmd := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %s`, adapterName(name), ipStr[0], ipStr[1])
	require.NoError(t, util.InvokePSCommand(cmd))
}
