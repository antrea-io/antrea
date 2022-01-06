//go:build windows
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

package route

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
)

func getNetLinkIndex(dev string) int {
	link, err := net.InterfaceByName(dev)
	if err != nil {
		klog.Fatalf("cannot find dev %s: %v", dev, err)
	}
	return link.Index
}

func TestRouteOperation(t *testing.T) {
	// Leverage loopback interface for testing.
	hostGateway := "Loopback Pseudo-Interface 1"
	gwLink := getNetLinkIndex("Loopback Pseudo-Interface 1")

	peerNodeIP1 := net.ParseIP("10.0.0.2")
	peerNodeIP2 := net.ParseIP("10.0.0.3")
	gwIP1 := net.ParseIP("192.168.2.1")
	_, destCIDR1, _ := net.ParseCIDR("192.168.2.0/24")
	dest2 := "192.168.3.0/24"
	gwIP2 := net.ParseIP("192.168.3.1")
	_, destCIDR2, _ := net.ParseCIDR(dest2)

	client, err := NewClient(&config.NetworkConfig{}, true, false, false, false)
	svcStr1 := "1.1.0.10"
	svcIP1 := net.ParseIP(svcStr1)
	svcIPNet1 := util.NewIPNet(svcIP1)
	svcStr2 := "1.1.0.11"
	svcIP2 := net.ParseIP(svcStr2)
	svcIPNet2 := util.NewIPNet(svcIP2)

	require.Nil(t, err)
	nodeConfig := &config.NodeConfig{
		OVSBridge: "Loopback Pseudo-Interface 1",
		GatewayConfig: &config.GatewayConfig{
			Name:      hostGateway,
			LinkIndex: gwLink,
		},
	}
	called := false
	err = client.Initialize(nodeConfig, func() { called = true })
	require.Nil(t, err)
	require.True(t, called)

	// Add initial routes.
	err = client.AddRoutes(destCIDR1, "node1", peerNodeIP1, gwIP1)
	require.Nil(t, err)
	routes1, err := util.GetNetRoutes(gwLink, destCIDR1)
	require.Nil(t, err)
	assert.Equal(t, 1, len(routes1))

	err = client.AddRoutes(destCIDR2, "node2", peerNodeIP2, gwIP2)
	require.Nil(t, err)
	routes2, err := util.GetNetRoutes(gwLink, destCIDR2)
	require.Nil(t, err)
	assert.Equal(t, 1, len(routes2))

	err = client.AddClusterIPRoute(svcIP1)
	require.Nil(t, err)
	route3, err := util.GetNetRoutes(gwLink, svcIPNet1)
	require.Nil(t, err)
	assert.Equal(t, 1, len(route3))

	err = client.AddClusterIPRoute(svcIP2)
	require.Nil(t, err)
	route4, err := util.GetNetRoutes(gwLink, svcIPNet2)
	require.Nil(t, err)
	assert.Equal(t, 1, len(route4))

	err = client.Reconcile([]string{dest2}, map[string]bool{svcIPNet1.String(): true})
	require.Nil(t, err)

	routes5, err := util.GetNetRoutes(gwLink, destCIDR1)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes5))

	routes6, err := util.GetNetRoutes(gwLink, svcIPNet2)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes6))

	err = client.DeleteRoutes(destCIDR2)
	require.Nil(t, err)
	routes7, err := util.GetNetRoutes(gwLink, destCIDR2)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes7))

	err = client.DeleteClusterIPRoute(svcIP1)
	require.Nil(t, err)
	routes8, err := util.GetNetRoutes(gwLink, svcIPNet1)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes8))
}
