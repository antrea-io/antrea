// Copyright 2019 OKN Authors
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

	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"

	"okn/pkg/ovs/ovsconfig"
	ovsconfigtest "okn/pkg/ovs/ovsconfig/testing"
)

func TestInitCache(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	mockOVSBridgeClient.EXPECT().GetPortList().Return(nil, ovsconfig.NewTransactionError(fmt.Errorf("Failed to list OVS ports"), true))

	cache := NewInterfaceStore()
	err := cache.Initialize(mockOVSBridgeClient, "", "")
	if err == nil {
		t.Errorf("Failed to handle OVS return error")
	}

	uuid1 := uuid.New().String()
	p1Mac := "11:22:33:44:55:66"
	p1IP := "1.1.1.1"
	ovsPort1 := ovsconfig.OVSPortData{UUID: uuid.New().String(), Name: "p1", IFName: "p1", OFPort: 1,
		ExternalIDs: map[string]string{OVSExternalIDContainerID: uuid1,
			OVSExternalIDMAC: p1Mac, OVSExternalIDIP: p1IP, OVSExternalIDPodName: "pod1", OVSExternalIDPodNamespace: "test"}}
	uuid2 := uuid.New().String()
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid.New().String(), Name: "p2", IFName: "p2", OFPort: 2,
		ExternalIDs: map[string]string{OVSExternalIDContainerID: uuid2,
			OVSExternalIDMAC: "11:22:33:44:55:77", OVSExternalIDIP: "1.1.1.2", OVSExternalIDPodName: "pod2", OVSExternalIDPodNamespace: "test"}}
	initOVSPorts := []ovsconfig.OVSPortData{ovsPort1, ovsPort2}

	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, ovsconfig.NewTransactionError(fmt.Errorf("Failed to list OVS ports"), true))
	err = cache.Initialize(mockOVSBridgeClient, "", "")
	if cache.Len() != 0 {
		t.Errorf("Failed to load OVS port in initCache")
	}

	ovsPort2.OFPort = 2
	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, nil)
	err = cache.Initialize(mockOVSBridgeClient, "", "")
	if cache.Len() != 2 {
		t.Errorf("Failed to load OVS port in initCache")
	}
	container1, found1 := cache.GetInterface("p1")
	if !found1 {
		t.Errorf("Failed to load OVS port into local cache")
	} else if container1.OFPort != 1 || container1.IP.String() != p1IP || container1.MAC.String() != p1Mac || container1.IfaceName != "p1" {
		t.Errorf("Failed to load OVS port configuration into local cache")
	}
	_, found2 := cache.GetInterface("p2")
	if !found2 {
		t.Errorf("Failed to load OVS port into local cache")
	}
}

func TestParseContainerAttachInfo(t *testing.T) {
	containerID := uuid.New().String()
	containerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	containerIP := net.ParseIP("10.1.2.100")
	containerConfig := NewContainerInterface(containerID, "test-1", "t1", "", containerMAC, containerIP)
	externalIds := BuildOVSPortExternalIDs(containerConfig)
	parsedIP, existed := externalIds[OVSExternalIDIP]
	if !existed || parsedIP != "10.1.2.100" {
		t.Errorf("Failed to parse container configuration")
	}
	parsedMac, existed := externalIds[OVSExternalIDMAC]
	if !existed || parsedMac != containerMAC.String() {
		t.Errorf("Failed to parse container configuration")
	}
	parsedID, existed := externalIds[OVSExternalIDContainerID]
	if !existed || parsedID != containerID {
		t.Errorf("Failed to parse container configuration")
	}
}

func TestGenerateContainerInterfaceName(t *testing.T) {
	podNamespace := "namespace1"
	podName0 := "pod0"
	iface0 := GenerateContainerInterfaceName(podName0, podNamespace)
	if len(iface0) != hostVethLength {
		t.Errorf("Failed to ensure length of interface name %s as %d", iface0, hostVethLength)
	}
	if !strings.HasPrefix(iface0, fmt.Sprintf("%s-", podName0)) {
		t.Errorf("failed to use podName as prefix: %s", iface0)
	}
	podName1 := "pod1-abcde-12345"
	iface1 := GenerateContainerInterfaceName(podName1, podNamespace)
	if len(iface1) != hostVethLength {
		t.Errorf("Failed to ensure length of interface name as %d", hostVethLength)
	}
	if !strings.HasPrefix(iface1, "pod1abcd") {
		t.Errorf("failed to use first 8 valid characters")
	}
	podName2 := "pod1-abcde-54321"
	iface2 := GenerateContainerInterfaceName(podName2, podNamespace)
	if iface1 == iface2 {
		t.Errorf("failed to differentiate interfaces with pods has the same prefix")
	}
}
