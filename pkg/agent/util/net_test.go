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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/util/ip"
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

func TestGetDefaultLocalNodeAddr(t *testing.T) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr).IP

	nodeIPs := &ip.DualStackIPs{IPv4: localAddr}
	_, _, dev, err := GetIPNetDeviceFromIP(nodeIPs, sets.NewString())
	if err != nil {
		t.Error(err)
	}
	t.Logf("IP obtained %s, %v", localAddr, dev)
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
