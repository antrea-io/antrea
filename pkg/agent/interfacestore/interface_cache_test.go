// Copyright 2022 Antrea Authors
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

package interfacestore

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	podMAC, _     = net.ParseMAC("11:22:33:44:55:66")
	podIP         = net.ParseIP("1.2.3.4")
	podIPv6       = net.ParseIP("2001:db8::1")
	gwIP          = net.ParseIP("1.2.3.1")
	hostIP        = net.ParseIP("2.2.2.2")
	ipsecTunnelIP = net.ParseIP("2.2.2.3")
	nodeName      = "n1"
	peerNodeName  = "n2"
)

func TestNewInterfaceStore(t *testing.T) {
	t.Run("testContainerInterface", testContainerInterface)
	t.Run("testSecondaryInterface", testSecondaryInterface)
	t.Run("testGatewayInterface", testGatewayInterface)
	t.Run("testTunnelInterface", testTunnelInterface)
	t.Run("testUplinkInterface", testUplinkInterface)
	t.Run("testExternalEntityInterface", testEntityInterface)
}

func testContainerInterface(t *testing.T) {
	store := NewInterfaceStore()
	containerInterface := NewContainerInterface("ns0p0c0", "c0", "p0", "ns0", "eth0", podMAC, []net.IP{podIP, podIPv6}, 2)
	containerInterface.OVSPortConfig = &OVSPortConfig{
		OFPort:   12,
		PortUUID: "1234567890",
	}
	containerInterfaceKey := util.GenerateContainerInterfaceKey(containerInterface.ContainerID, containerInterface.IFDev)
	store.Initialize([]*InterfaceConfig{containerInterface})
	assert.Equal(t, 1, store.Len())
	storedIface, exists := store.GetInterface(containerInterfaceKey)
	assert.True(t, exists)
	assert.Equal(t, containerInterface, storedIface)
	// The name of Container InterfaceConfig is not the key in InterfaceStore
	_, exists = store.GetInterface(containerInterface.InterfaceName)
	assert.False(t, exists)
	_, exists = store.GetInterfaceByName(containerInterface.InterfaceName)
	assert.True(t, exists)
	_, exists = store.GetContainerInterface(containerInterface.ContainerID)
	assert.True(t, exists)
	_, exists = store.GetInterfaceByIP(podIP.String())
	assert.True(t, exists)
	_, exists = store.GetInterfaceByIP(podIPv6.String())
	assert.True(t, exists)
	_, exists = store.GetInterfaceByOFPort(uint32(containerInterface.OVSPortConfig.OFPort))
	assert.True(t, exists)
	ifaces := store.GetContainerInterfacesByPod(containerInterface.PodName, containerInterface.PodNamespace)
	assert.Equal(t, 1, len(ifaces))
	assert.Equal(t, containerInterface, ifaces[0])
	ifaceNames := store.GetInterfaceKeysByType(ContainerInterface)
	assert.Equal(t, 1, len(ifaceNames))
	assert.Equal(t, containerInterfaceKey, ifaceNames[0])
	assert.Equal(t, 1, store.GetContainerInterfaceNum())

	store.DeleteInterface(containerInterface)
	assert.Equal(t, 0, store.GetContainerInterfaceNum())
	_, exists = store.GetContainerInterface(containerInterface.ContainerID)
	assert.False(t, exists)
	_, exists = store.GetInterfaceByIP(containerInterface.IPs[0].String())
	assert.False(t, exists)
	_, exists = store.GetInterfaceByIP(containerInterface.IPs[1].String())
	assert.False(t, exists)

	containerInterface.IPs = nil
	store.AddInterface(containerInterface)
	assert.Equal(t, 1, store.GetContainerInterfaceNum())
	_, exists = store.GetInterfaceByIP(podIP.String())
	assert.False(t, exists)
}

func testSecondaryInterface(t *testing.T) {
	store := NewInterfaceStore()
	// Seondary interface without an IP.
	containerInterface1 := NewContainerInterface("c0-eth1", "c0", "p0", "ns0", "eth1", podMAC, nil, 2)
	containerInterface2 := NewContainerInterface("c0-eth2", "c0", "p0", "ns0", "eth2", podMAC, []net.IP{podIP}, 0)
	store.Initialize([]*InterfaceConfig{containerInterface1, containerInterface2})
	assert.Equal(t, 2, store.Len())

	for _, containerInterface := range []*InterfaceConfig{containerInterface1, containerInterface2} {
		interfaceKey := util.GenerateContainerInterfaceKey(containerInterface.ContainerID, containerInterface.IFDev)
		storedIface, exists := store.GetInterface(interfaceKey)
		assert.True(t, exists)
		assert.Equal(t, containerInterface, storedIface)
		_, exists = store.GetInterface(containerInterface.InterfaceName)
		assert.False(t, exists)
		_, exists = store.GetInterfaceByName(containerInterface.InterfaceName)
		assert.True(t, exists)
		_, exists = store.GetContainerInterface(containerInterface.ContainerID)
		assert.True(t, exists)
		if containerInterface.IPs != nil {
			storedIface, exists = store.GetInterfaceByIP(podIP.String())
			require.True(t, exists)
			assert.Equal(t, containerInterface, storedIface)
		}
		ifaces := store.GetContainerInterfacesByPod(containerInterface.PodName, containerInterface.PodNamespace)
		assert.Equal(t, 2, len(ifaces))
		ifaceNames := store.GetInterfaceKeysByType(ContainerInterface)
		assert.Equal(t, 2, len(ifaceNames))
		assert.Equal(t, 2, store.GetContainerInterfaceNum())

		store.DeleteInterface(containerInterface)
		assert.Equal(t, 1, store.GetContainerInterfaceNum())
		if containerInterface.IPs != nil {
			_, exists = store.GetInterfaceByIP(containerInterface.IPs[0].String())
			assert.False(t, exists)
		}
		store.AddInterface(containerInterface)
		assert.Equal(t, 2, store.GetContainerInterfaceNum())
	}
}

func testGatewayInterface(t *testing.T) {
	gatewayInterface := NewGatewayInterface("antrea-gw0", util.GenerateRandomMAC())
	gatewayInterface.IPs = []net.IP{gwIP}
	gatewayInterface.OVSPortConfig = &OVSPortConfig{
		OFPort:   13,
		PortUUID: "1234567890",
	}
	testGeneralInterface(t, gatewayInterface, GatewayInterface)
}

func testTunnelInterface(t *testing.T) {
	store := NewInterfaceStore()
	tunnelInterface := NewTunnelInterface("antrea-tun0", ovsconfig.GeneveTunnel, 6081, hostIP, false, &OVSPortConfig{
		OFPort:   14,
		PortUUID: "1234567890",
	})
	tunnelInterface.IPs = []net.IP{hostIP}
	ipsecTunnelInterface := NewIPSecTunnelInterface("antrea-ipsec0", ovsconfig.ERSPANTunnel, nodeName, hostIP, "abcdefg", peerNodeName, &OVSPortConfig{
		OFPort:   15,
		PortUUID: "1234567890",
	})
	ipsecTunnelInterface.IPs = []net.IP{ipsecTunnelIP}
	store.Initialize([]*InterfaceConfig{tunnelInterface, ipsecTunnelInterface})
	assert.Equal(t, 2, store.Len())
	for _, tunIface := range []*InterfaceConfig{tunnelInterface, ipsecTunnelInterface} {
		storedIface, exists := store.GetInterfaceByName(tunIface.InterfaceName)
		assert.True(t, exists)
		assert.True(t, reflect.DeepEqual(storedIface, tunIface))
		storedIface, exists = store.GetInterfaceByIP(tunIface.IPs[0].String())
		assert.True(t, exists)
		assert.True(t, reflect.DeepEqual(storedIface, tunIface))
		storedIface, exists = store.GetInterfaceByOFPort(uint32(tunIface.OVSPortConfig.OFPort))
		assert.True(t, exists)
		assert.True(t, reflect.DeepEqual(storedIface, tunIface))
	}

	ipsecTunnelKey := util.GenerateNodeTunnelInterfaceKey(ipsecTunnelInterface.NodeName)
	storedIface, exists := store.GetInterface(ipsecTunnelKey)
	assert.True(t, exists)
	assert.True(t, reflect.DeepEqual(storedIface, ipsecTunnelInterface))
	_, exists = store.GetInterface(ipsecTunnelInterface.InterfaceName)
	assert.False(t, exists)
	storedIface, exists = store.GetInterface(tunnelInterface.InterfaceName)
	assert.True(t, exists)
	assert.True(t, reflect.DeepEqual(storedIface, tunnelInterface))
	storedIface, exists = store.GetNodeTunnelInterface(nodeName)
	assert.True(t, exists)
	assert.True(t, reflect.DeepEqual(storedIface, ipsecTunnelInterface))
	_, exists = store.GetNodeTunnelInterface(peerNodeName)
	assert.False(t, exists)

	ifaceNames := store.GetInterfaceKeysByType(TunnelInterface)
	assert.Equal(t, 1, len(ifaceNames))
	ipsecIfaceNames := store.GetInterfaceKeysByType(IPSecTunnelInterface)
	assert.Equal(t, 1, len(ipsecIfaceNames))
	store.DeleteInterface(ipsecTunnelInterface)
	assert.Equal(t, 0, len(store.GetInterfaceKeysByType(IPSecTunnelInterface)))
	_, exists = store.GetInterfaceByName(ipsecTunnelInterface.InterfaceName)
	assert.False(t, exists)
	store.AddInterface(ipsecTunnelInterface)
	ifaceNames = store.GetInterfaceKeysByType(IPSecTunnelInterface)
	assert.Equal(t, 1, len(ifaceNames))
	_, exists = store.GetInterfaceByName(ipsecTunnelInterface.InterfaceName)
	assert.True(t, exists)
}

func testUplinkInterface(t *testing.T) {
	uplinkInterface := NewUplinkInterface("ens224")
	uplinkInterface.IPs = []net.IP{hostIP}
	uplinkInterface.OVSPortConfig = &OVSPortConfig{
		OFPort:   16,
		PortUUID: "1234567890",
	}
	testGeneralInterface(t, uplinkInterface, UplinkInterface)
}

func testEntityInterface(t *testing.T) {
	store := NewInterfaceStore()
	portConfig := &OVSPortConfig{OFPort: 18, PortUUID: "123456789"}
	uplinkConfig := &OVSPortConfig{OFPort: 19, PortUUID: "987654321"}
	entityIPv4 := net.ParseIP("2.3.4.5")
	entityIPv6 := net.ParseIP("abcd::1234")
	entityIPs := []net.IP{
		entityIPv4,
		entityIPv6,
	}
	entityInterface := newExternalEntityInterface("vm1-ens192", entityIPs, "ens192", "ns2", portConfig, uplinkConfig)
	store.Initialize([]*InterfaceConfig{entityInterface})
	storedIface, exists := store.GetInterface(entityInterface.InterfaceName)
	assert.True(t, exists)
	assert.True(t, reflect.DeepEqual(storedIface, entityInterface))
	assert.Equal(t, entityIPv4, storedIface.GetIPv4Addr())
	assert.Equal(t, entityIPv6, storedIface.GetIPv6Addr())
	_, exists = store.GetInterfaceByName(entityInterface.InterfaceName)
	assert.True(t, exists)
	for _, entityIP := range entityInterface.IPs {
		_, exists = store.GetInterfaceByIP(entityIP.String())
		assert.True(t, exists)
	}
	_, exists = store.GetInterfaceByOFPort(uint32(entityInterface.OVSPortConfig.OFPort))
	assert.True(t, exists)
	_, exists = store.GetInterfaceByOFPort(uint32(entityInterface.UplinkPort.OFPort))
	assert.False(t, exists)
	ifaces := store.GetInterfacesByEntity(entityInterface.EntityName, entityInterface.EntityNamespace)
	assert.Equal(t, 1, len(ifaces))
	assert.True(t, reflect.DeepEqual(ifaces[0], entityInterface))
	ifaceNames := store.GetInterfaceKeysByType(ExternalEntityInterface)
	assert.Equal(t, 1, len(ifaceNames))
	assert.Equal(t, entityInterface.InterfaceName, ifaceNames[0])
	store.DeleteInterface(entityInterface)
	assert.Equal(t, 0, len(store.GetInterfaceKeysByType(ExternalEntityInterface)))
	store.AddInterface(entityInterface)
	assert.Equal(t, 1, len(store.GetInterfaceKeysByType(ExternalEntityInterface)))
}

func testGeneralInterface(t *testing.T, ifaceConfig *InterfaceConfig, ifaceType InterfaceType) {
	store := NewInterfaceStore()
	store.Initialize([]*InterfaceConfig{ifaceConfig})
	storedIface, exists := store.GetInterface(ifaceConfig.InterfaceName)
	assert.True(t, exists)
	assert.True(t, reflect.DeepEqual(storedIface, ifaceConfig))
	_, exists = store.GetInterfaceByName(ifaceConfig.InterfaceName)
	assert.True(t, exists)
	_, exists = store.GetInterfaceByIP(ifaceConfig.IPs[0].String())
	assert.True(t, exists)
	_, exists = store.GetInterfaceByOFPort(uint32(ifaceConfig.OVSPortConfig.OFPort))
	assert.True(t, exists)
	fooPort := uint32(1)
	_, exists = store.GetInterfaceByOFPort(fooPort)
	assert.False(t, exists)
	ifaceNames := store.GetInterfaceKeysByType(ifaceType)
	assert.Equal(t, 1, len(ifaceNames))
	assert.Equal(t, ifaceConfig.InterfaceName, ifaceNames[0])
	store.DeleteInterface(ifaceConfig)
	assert.Equal(t, 0, len(store.GetInterfaceKeysByType(ifaceType)))
	store.AddInterface(ifaceConfig)
	ifaceNames = store.GetInterfaceKeysByType(ifaceType)
	assert.Equal(t, 1, len(ifaceNames))
	assert.Equal(t, ifaceConfig.InterfaceName, ifaceNames[0])
	ifaces := store.GetInterfacesByType(ifaceType)
	assert.Equal(t, 1, len(ifaces))
	assert.Equal(t, ifaceConfig, ifaces[0])
}

func newExternalEntityInterface(name string, entityIPs []net.IP, entityName string, entityNamespace string, ovsPortConfig, uplinkPortConfig *OVSPortConfig) *InterfaceConfig {
	return &InterfaceConfig{
		Type:          ExternalEntityInterface,
		InterfaceName: name,
		IPs:           entityIPs,
		OVSPortConfig: ovsPortConfig,
		EntityInterfaceConfig: &EntityInterfaceConfig{
			EntityName:      entityName,
			EntityNamespace: entityNamespace,
			UplinkPort:      uplinkPortConfig,
		},
	}
}
