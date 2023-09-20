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

package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/util/ip"
)

var (
	ipv6Global      = net.ParseIP("2000::")
	ipv4Public      = net.ParseIP("8.8.8.8")
	ipv4PublicIPNet = net.IPNet{
		IP:   ipv4Public,
		Mask: net.CIDRMask(32, 32),
	}
	ipv4ZeroIPNet = net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(32, 32),
	}

	testMACAddr, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")

	testInvalidErr = fmt.Errorf("invalid")
)

func TestGenerateContainerInterfaceName(t *testing.T) {
	podNamespace := "namespace1"
	podName0 := "pod0"
	containerID0 := "container0"
	iface0 := GenerateContainerInterfaceName(podName0, podNamespace, containerID0)
	if len(iface0) > interfaceNameLength {
		t.Errorf("Failed to ensure length of interface name %s <= %d", iface0, interfaceNameLength)
	}
	if !strings.HasPrefix(iface0, fmt.Sprintf("%s-", podName0)) {
		t.Errorf("failed to use podName as prefix: %s", iface0)
	}
	podName1 := "pod1-abcde-12345"
	iface1 := GenerateContainerInterfaceName(podName1, podNamespace, containerID0)
	if len(iface1) != interfaceNameLength {
		t.Errorf("Failed to ensure length of interface name as %d", interfaceNameLength)
	}
	if !strings.HasPrefix(iface1, "pod1-abc") {
		t.Errorf("failed to use first 8 valid characters")
	}
	containerID1 := "container1"
	iface2 := GenerateContainerInterfaceName(podName1, podNamespace, containerID1)
	if iface1 == iface2 {
		t.Errorf("failed to differentiate interfaces with pods that have the same pod namespace and name")
	}
}

func TestGenerateContainerHostVethName(t *testing.T) {
	podName0 := "pod0"
	podNamespace0 := "ns0"
	containerID0 := "container0"
	eth0 := "eth0"
	ifaceName0 := GenerateContainerHostVethName(podName0, podNamespace0, containerID0, eth0)
	require.LessOrEqual(t, len(ifaceName0), interfaceNameLength)
	require.True(t, strings.HasPrefix(ifaceName0, podName0+"-"))

	tests := []struct {
		name          string
		podName       string
		podNS         string
		containerID   string
		innerName     string
		namePrefix    string
		equalToIface0 bool
	}{
		{
			name:          "should equal iface0",
			podName:       podName0,
			podNS:         podNamespace0,
			containerID:   containerID0,
			innerName:     eth0,
			namePrefix:    podName0 + "-",
			equalToIface0: true,
		},
		{
			name:        "eth1",
			podName:     podName0,
			podNS:       podNamespace0,
			containerID: containerID0,
			innerName:   "eth1",
			namePrefix:  podName0 + "-",
		},
		{
			name:        "pod1",
			podName:     "pod1",
			podNS:       podNamespace0,
			containerID: containerID0,
			innerName:   eth0,
			namePrefix:  "pod1-",
		},
		{
			name:        "pod0 and different container ID",
			podName:     podName0,
			podNS:       podNamespace0,
			containerID: "container1",
			innerName:   eth0,
			namePrefix:  podName0 + "-",
		},
		{
			name:          "pod0 of ns1",
			podName:       podName0,
			podNS:         "ns1",
			containerID:   containerID0,
			innerName:     "eth0",
			namePrefix:    podName0 + "-",
			equalToIface0: true,
		},
		{
			name:        "8-char Pod name",
			podName:     "pod12345",
			podNS:       podNamespace0,
			containerID: containerID0,
			innerName:   eth0,
			namePrefix:  "pod12345" + "-",
		},
		{
			name:        "6-char Pod name",
			podName:     "pod123456",
			podNS:       podNamespace0,
			containerID: containerID0,
			innerName:   eth0,
			namePrefix:  "pod12345" + "-",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ifaceName := GenerateContainerHostVethName(tc.podName, tc.podNS, tc.containerID, tc.innerName)
			assert.True(t, len(ifaceName) <= interfaceNameLength)
			assert.True(t, strings.HasPrefix(ifaceName, tc.namePrefix))
			if tc.equalToIface0 {
				assert.Equal(t, ifaceName, ifaceName0)
			} else {
				assert.NotEqual(t, ifaceName, ifaceName0)
			}
		})
	}
}

func TestGetIPNetDeviceFromIP(t *testing.T) {
	testNetInterfaces := generateNetInterfaces()
	tests := []struct {
		name                string
		localIPs            *ip.DualStackIPs
		ignoredInterfaces   sets.Set[string]
		testNetInterfaceErr error
		wantIPv4IPNet       *net.IPNet
		wantIPv6IPNet       *net.IPNet
	}{
		{
			name:              "IPv4 Interface",
			localIPs:          &ip.DualStackIPs{IPv4: ipv4Public},
			ignoredInterfaces: sets.Set[string]{},
			wantIPv4IPNet:     &ipv4PublicIPNet,
		},
		{
			name:              "IPv6 Interface",
			localIPs:          &ip.DualStackIPs{IPv6: ipv6Global},
			ignoredInterfaces: sets.Set[string]{},
			wantIPv6IPNet: &net.IPNet{
				IP:   ipv6Global,
				Mask: net.CIDRMask(128, 128),
			},
		},
		{
			name: "Exclude IPv6 Interface",
			localIPs: &ip.DualStackIPs{
				IPv4: ipv4Public,
				IPv6: ipv6Global,
			},
			ignoredInterfaces: make(sets.Set[string]).Insert("1"),
			wantIPv4IPNet: &net.IPNet{
				IP:   ipv4Public,
				Mask: net.CIDRMask(32, 32),
			},
		},
		{
			name:                "LocalIP Error",
			testNetInterfaceErr: fmt.Errorf("IPs of localIPs should be on the same device"),
			localIPs: &ip.DualStackIPs{
				IPv4: ipv4Public,
				IPv6: ipv6Global,
			},
			ignoredInterfaces: sets.Set[string]{},
		},
		{
			name:                "Invalid",
			testNetInterfaceErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockNetInterfaceGet(testNetInterfaces, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrsMultiple(testNetInterfaces, true, nil)()
			gotIPv4IPNet, gotIPv6IPNet, _, gotErr := GetIPNetDeviceFromIP(tc.localIPs, tc.ignoredInterfaces)
			assert.Equal(t, tc.wantIPv4IPNet, gotIPv4IPNet)
			assert.Equal(t, tc.wantIPv6IPNet, gotIPv6IPNet)
			assert.Equal(t, tc.testNetInterfaceErr, gotErr)
		})
	}
}

func TestGetAllIPNetsByName(t *testing.T) {
	tests := []struct {
		name                 string
		testNetInterfaceName string
		testNetInterface     net.Interface
		testNetInterfaceErr  error
		wantIPNets           []*net.IPNet
	}{
		{
			name:                 "IPv4",
			testNetInterfaceName: "0",
			wantIPNets:           []*net.IPNet{&ipv4PublicIPNet},
		},
		{
			name:                 "IPv6",
			testNetInterfaceName: "1",
			wantIPNets: []*net.IPNet{
				{
					IP:   ipv6Global,
					Mask: net.CIDRMask(128, 128),
				},
			},
		},
		{
			name:                 "Invalid",
			testNetInterfaceName: "0",
			testNetInterfaceErr:  testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.testNetInterface = generateNetInterface(tc.testNetInterfaceName)
			defer mockNetInterfaceByName(&tc.testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(tc.testNetInterface, nil)()
			gotIPNets, gotErr := GetAllIPNetsByName(tc.name)
			assert.Equal(t, tc.wantIPNets, gotIPNets)
			assert.Equal(t, tc.testNetInterfaceErr, gotErr)
		})
	}
}

func TestGetIPNetDeviceByName(t *testing.T) {
	tests := []struct {
		name                 string
		testNetInterfaceName string
		testNetInterface     net.Interface
		testNetInterfaceErr  error
		wantIPv4IPNet        *net.IPNet
		wantIPv6IPNet        *net.IPNet
	}{
		{
			name:                 "IPv4",
			testNetInterfaceName: "0",
			wantIPv4IPNet:        &ipv4PublicIPNet,
		},
		{
			name:                 "IPv6",
			testNetInterfaceName: "1",
			wantIPv6IPNet: &net.IPNet{
				IP:   ipv6Global,
				Mask: net.CIDRMask(128, 128),
			},
		},
		{
			name:                 "Invalid",
			testNetInterfaceName: "0",
			testNetInterfaceErr:  testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.testNetInterface = generateNetInterface(tc.testNetInterfaceName)
			defer mockNetInterfaceByName(&tc.testNetInterface, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrs(tc.testNetInterface, nil)()
			gotIPv4IPNet, gotIPv6IPNet, gotLink, gotErr := GetIPNetDeviceByName(tc.name)
			assert.Equal(t, tc.wantIPv4IPNet, gotIPv4IPNet)
			assert.Equal(t, tc.wantIPv6IPNet, gotIPv6IPNet)
			if tc.testNetInterfaceErr == nil {
				assert.EqualValues(t, tc.testNetInterface, *gotLink)
			} else {
				assert.Nil(t, gotLink)
			}
			assert.Equal(t, tc.testNetInterfaceErr, gotErr)
		})
	}
}

func TestGetIPNetDeviceByCIDRs(t *testing.T) {
	testNetInterfaces := generateNetInterfacesDual()
	tests := []struct {
		name                string
		cidrsList           []string
		testNetInterfaceErr error
		wantIPv4IPNet       *net.IPNet
		wantIPv6IPNet       *net.IPNet
	}{
		{
			name:          "Dual Stack",
			cidrsList:     []string{"8.8.8.8/30", "2000::/3"},
			wantIPv4IPNet: &ipv4PublicIPNet,
			wantIPv6IPNet: &net.IPNet{
				IP:   ipv6Global,
				Mask: net.CIDRMask(128, 128),
			},
		},
		{
			name:                "Multiple IPv4 CIDRs",
			testNetInterfaceErr: fmt.Errorf("len of cidrs is 2 and they are not configured as dual stack (at least one from each IPFamily)"),
			cidrsList:           []string{"8.8.8.8/30", "0.0.0.0/31"},
		},
		{
			name:                "Exceed Max CIDRs",
			testNetInterfaceErr: fmt.Errorf("length of cidrs is 3 more than max allowed of 2"),
			cidrsList:           []string{"8.8.8.8/30", "0.0.0.0/31", "2000::/64"},
		},
		{
			name:                "Invalid",
			testNetInterfaceErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockNetInterfaceGet(testNetInterfaces, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrsMultiple(testNetInterfaces, true, nil)()
			gotIPv4IPNet, gotIPv6IPNet, _, gotErr := GetIPNetDeviceByCIDRs(tc.cidrsList)
			assert.Equal(t, tc.wantIPv4IPNet, gotIPv4IPNet)
			assert.Equal(t, tc.wantIPv6IPNet, gotIPv6IPNet)
			assert.Equal(t, tc.testNetInterfaceErr, gotErr)
		})
	}
}

func TestGetIPv4Addr(t *testing.T) {
	testIPs := []net.IP{net.IPv4zero, net.IPv6zero}
	gotIP := GetIPv4Addr(testIPs)
	assert.Equal(t, net.IPv4zero, gotIP)

	gotIP = GetIPv4Addr([]net.IP{})
	assert.Nil(t, gotIP)
}

func TestGetIPWithFamily(t *testing.T) {
	tests := []struct {
		name       string
		testIPs    []net.IP
		testFamily uint8
		wantIP     net.IP
		wantErr    error
	}{
		{
			name:       "IPv6 AddressFamily",
			testIPs:    []net.IP{net.IPv4zero, net.IPv6zero},
			testFamily: FamilyIPv6,
			wantIP:     net.IPv6zero,
		},
		{
			name:       "IPv4 AddressFamily",
			testIPs:    []net.IP{net.IPv4zero, net.IPv6zero},
			testFamily: FamilyIPv4,
			wantIP:     net.IPv4zero,
		},
		{
			name:       "IPv6 AddressFamily not found",
			testIPs:    []net.IP{net.IPv4zero},
			testFamily: FamilyIPv6,
			wantErr:    fmt.Errorf("no IP found with IPv6 AddressFamily"),
		},
		{
			name:       "IPv4 AddressFamily not found",
			testIPs:    []net.IP{net.IPv6zero},
			testFamily: FamilyIPv4,
			wantErr:    fmt.Errorf("no IP found with IPv4 AddressFamily"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotIP, err := GetIPWithFamily(tc.testIPs, tc.testFamily)
			assert.Equal(t, tc.wantIP, gotIP)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestExtendCIDRWithIP(t *testing.T) {
	tests := []struct {
		name         string
		cidr         string
		ip           string
		expectedCIDR string
		expectedErr  error
	}{
		{
			name:         "IPv4",
			cidr:         "1.1.1.1/32",
			ip:           "1.1.1.127",
			expectedCIDR: "1.1.1.0/25",
		},
		{
			name:         "IPv6",
			cidr:         "aabb:ccdd::f0/124",
			ip:           "aabb:ccdd::10",
			expectedCIDR: "aabb:ccdd::/120",
		},
		{
			name:        "invalid",
			cidr:        "aabb:ccdd::f0/124",
			ip:          "1.1.1.127",
			expectedErr: fmt.Errorf("invalid common prefix length"),
		},
	}
	for _, tt := range tests {
		_, ipNet, _ := net.ParseCIDR(tt.cidr)
		ip := net.ParseIP(tt.ip)
		gotIPNet, gotErr := ExtendCIDRWithIP(ipNet, ip)
		assert.Equal(t, tt.expectedErr, gotErr)
		_, expectedIPNet, _ := net.ParseCIDR(tt.expectedCIDR)
		assert.Equal(t, expectedIPNet, gotIPNet)
	}
}

func TestGenerateRandomMAC(t *testing.T) {
	validateBits := func(mac net.HardwareAddr) (byte, byte) {
		localBit := mac[0] & 0x2 >> 1
		mcastBit := mac[0] & 0x1
		return localBit, mcastBit
	}
	mac1 := GenerateRandomMAC()
	localBit, mcastBit := validateBits(mac1)
	assert.Equal(t, uint8(1), localBit)
	assert.Equal(t, uint8(0), mcastBit)
}

func TestGetAllNodeAddresses(t *testing.T) {
	testNetInterfaces := generateNetInterfaces()
	tests := []struct {
		name                string
		excludeDevices      []string
		testNetInterfaceErr error
		wantNodeAddrsIPv4   []net.IP
		wantNodeAddrsIPv6   []net.IP
	}{
		{
			name:              "All Node Addrs",
			excludeDevices:    []string{},
			wantNodeAddrsIPv4: []net.IP{ipv4Public},
			wantNodeAddrsIPv6: []net.IP{ipv6Global},
		},
		{
			name:              "Exclude Node Addrs",
			excludeDevices:    []string{"1"},
			wantNodeAddrsIPv4: []net.IP{ipv4Public},
		},
		{
			name:                "Invalid",
			testNetInterfaceErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockNetInterfaceGet(testNetInterfaces, tc.testNetInterfaceErr)()
			defer mockNetInterfaceAddrsMultiple(testNetInterfaces, true, nil)()
			gotNodeAddrsIPv4, gotNodeAddrsIPv6, gotErr := GetAllNodeAddresses(tc.excludeDevices)
			assert.Equal(t, tc.wantNodeAddrsIPv4, gotNodeAddrsIPv4)
			assert.Equal(t, tc.wantNodeAddrsIPv6, gotNodeAddrsIPv6)
			assert.Equal(t, tc.testNetInterfaceErr, gotErr)
		})
	}
}

func TestNewIPNet(t *testing.T) {
	gotIPNet := NewIPNet(net.IPv4allrouter)
	assert.Equal(t, net.IPv4allrouter.To4(), gotIPNet.IP.To4())
	assert.Equal(t, net.CIDRMask(32, 32), gotIPNet.Mask)

	gotIPNet = NewIPNet(net.IPv6linklocalallrouters)
	assert.Equal(t, net.IPv6linklocalallrouters, gotIPNet.IP)
	assert.Equal(t, net.CIDRMask(128, 128), gotIPNet.Mask)
}

func TestPortToUint16(t *testing.T) {
	gotUint16 := PortToUint16(1)
	assert.Equal(t, uint16(1), gotUint16)

	gotUint16 = PortToUint16(-1)
	assert.Equal(t, uint16(0), gotUint16)
}

func TestGenerateUplinkInterfaceName(t *testing.T) {
	testUplinkName := "t0"
	gotName := GenerateUplinkInterfaceName(testUplinkName)
	assert.Equal(t, testUplinkName+bridgedUplinkSuffix, gotName)
}

func TestGetIPNetsByLink(t *testing.T) {
	testNetInterface := generateNetInterface("0")
	tests := []struct {
		name                string
		testNetInterfaceErr error
		wantIPNets          []*net.IPNet
	}{
		{
			name:       "IPv4",
			wantIPNets: []*net.IPNet{&ipv4PublicIPNet},
		},
		{
			name:                "Invalid",
			testNetInterfaceErr: testInvalidErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer mockNetInterfaceAddrs(testNetInterface, tc.testNetInterfaceErr)()
			gotIPNets, gotErr := GetIPNetsByLink(&testNetInterface)
			assert.Equal(t, tc.wantIPNets, gotIPNets)
			assert.Equal(t, tc.testNetInterfaceErr, gotErr)
		})
	}
}

func TestGenerateOVSDatapathID(t *testing.T) {
	tests := []struct {
		name       string
		mac        net.HardwareAddr
		expectedID string
	}{
		{
			name:       "valid MAC",
			mac:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			expectedID: "001122334455",
		},
		{
			name: "empty MAC",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := GenerateOVSDatapathID(tc.mac.String())
			if tc.expectedID != "" {
				assert.Equal(t, "0000"+tc.expectedID, id)
			} else {
				assert.Equal(t, 16, len(id))
				assert.True(t, strings.HasPrefix(id, "0000"))
			}
		})
	}
}

func generateNetInterfaceAddrs(idx int) []net.Addr {
	netAddrsIPv4 := []net.Addr{&ipv4PublicIPNet}
	netAddrsIPv6 := []net.Addr{
		&net.IPNet{
			IP:   ipv6Global,
			Mask: net.CIDRMask(128, 128),
		},
	}
	netAddrsDualStack := []net.Addr{
		&ipv4PublicIPNet,
		&net.IPNet{
			IP:   ipv6Global,
			Mask: net.CIDRMask(128, 128),
		},
	}
	mockNetAddrs := [][]net.Addr{netAddrsIPv4, netAddrsIPv6, netAddrsDualStack}
	return mockNetAddrs[idx]
}

func generateNetInterface(name string) net.Interface {
	testIdx, _ := strconv.Atoi(name)
	testInterface := net.Interface{
		Index:        testIdx,
		Name:         name,
		HardwareAddr: testMACAddr,
	}
	return testInterface
}

func generateNetInterfaces() []net.Interface {
	return []net.Interface{generateNetInterface("0"), generateNetInterface("1")}
}

func generateNetInterfacesDual() []net.Interface {
	return []net.Interface{generateNetInterface("2")}
}

func mockNetInterfaceGet(testNetInterfaces []net.Interface, err error) func() {
	originalNetInterface := netInterfaces
	netInterfaces = func() ([]net.Interface, error) {
		return testNetInterfaces, err
	}
	return func() {
		netInterfaces = originalNetInterface
	}
}

func mockNetInterfaceByName(testNetInterface *net.Interface, err error) func() {
	originalNetInterfaceByName := netInterfaceByName
	netInterfaceByName = func(name string) (*net.Interface, error) {
		return testNetInterface, err
	}
	return func() {
		netInterfaceByName = originalNetInterfaceByName
	}
}

func mockNetInterfaceByIndex(testNetInterface *net.Interface, err error) func() {
	originalNetInterfaceByIndex := netInterfaceByIndex
	netInterfaceByIndex = func(index int) (*net.Interface, error) {
		return testNetInterface, err
	}
	return func() {
		netInterfaceByIndex = originalNetInterfaceByIndex
	}
}

func mockNetInterfaceAddrsMultiple(testNetInterfaces []net.Interface, valid bool, err error) func() {
	originalNetInterfaceAddrs := netInterfaceAddrs
	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		if valid {
			for _, itf := range testNetInterfaces {
				if itf.Name == i.Name {
					return generateNetInterfaceAddrs(itf.Index), err
				}
			}
		}
		return []net.Addr{}, err
	}
	return func() {
		netInterfaceAddrs = originalNetInterfaceAddrs
	}
}

func mockNetInterfaceAddrs(testNetInterface net.Interface, err error) func() {
	originalNetInterfaceAddrs := netInterfaceAddrs
	netInterfaceAddrs = func(i *net.Interface) ([]net.Addr, error) {
		if i != nil {
			return generateNetInterfaceAddrs(testNetInterface.Index), err
		}
		return nil, err
	}
	return func() {
		netInterfaceAddrs = originalNetInterfaceAddrs
	}
}
