// +build windows

// Copyright 2020 Antrea Authors
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

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

func TestCreateHNSNetwork(t *testing.T) {
	testNet := "test-net"
	hnsNet, err := hcsshim.GetHNSNetworkByName(testNet)
	if err == nil {
		_, err := hnsNet.Delete()
		require.Nil(t, err, "No error expected when deleting existing HNSNetwork")
	} else {
		require.True(t, strings.Contains(err.Error(), fmt.Sprintf("Network %s not found", testNet)))
	}

	_, subnet, _ := net.ParseCIDR("172.16.1.0/24")
	nodeIP, err := getAdapterIPv4Addr("Ethernet0")
	require.Nil(t, err)
	hnsNet, _, err = CreateHNSNetwork(testNet, subnet, nodeIP)
	require.Nil(t, err, "No error expected when creating HNSNetwork")
	defer hnsNet.Delete()

	assert.Equal(t, hnsNet.Name, testNet)
	assert.Equal(t, hnsNet.Type, util.HNSNetworkType)
	assert.Equal(t, len(hnsNet.Subnets), 1)
	assert.Equal(t, hnsNet.Subnets[0].AddressPrefix, subnet.String())
	assert.Equal(t, hnsNet.Subnets[0].GatewayAddress, "172.16.1.1")
	assert.Equal(t, hnsNet.ManagementIP, nodeIP.String())
	OVSExtensionID := "583CC151-73EC-4A6A-8B47-578297AD7623"
	err = changeHNSNetworkExtensionStaus(hnsNet.Id, OVSExtensionID, true)
	require.Nil(t, err, "No error expected when enable HNSNetwork")
}

func getAdapterIPv4Addr(adapterName string) (*net.IPNet, error) {
	adapter, err := net.InterfaceByName(adapterName)
	if err != nil {
		return nil, err
	}
	addrs, err := adapter.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				return ipNet, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP on adapter %s", adapterName)
}
