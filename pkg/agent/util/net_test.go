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

func TestGenerateMacAddr(t *testing.T) {
	testcases := []struct {
		// input
		key string
		// expectations
		expectedMac net.HardwareAddr
	}{
		{
			key: "192.168.0.1",
			expectedMac: net.HardwareAddr([]byte{0x26, 0xed, 0x8b, 0xba, 0xbb, 0x59}),
		},
		{
			key: "pod1-abcde-12345",
			expectedMac: net.HardwareAddr([]byte{0xba, 0x76, 0x6, 0x49, 0xfb, 0xf8}),
		},
	}
	for _, tc := range testcases {
		parsedMac := GenerateMacAddr(tc.key)
		assert.Equal(t, tc.expectedMac, parsedMac)
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
	_, _, dev, err := GetIPNetDeviceFromIP(nodeIPs)
	if err != nil {
		t.Error(err)
	}
	t.Logf("IP obtained %s, %v", localAddr, dev)
}
