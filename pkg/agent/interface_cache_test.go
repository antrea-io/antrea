package agent

import (
	"net"
	"testing"

	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"okn/pkg/ovs/ovsconfig"
	"okn/pkg/test"
	"okn/pkg/test/mocks"
)

func TestInitCache(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSdbClient := mocks.NewMockOVSdbClient(controller)

	mockOVSdbClient.EXPECT().GetPortList().Return(nil, test.NewDummyOVSConfigError("Failed to list OVS ports", true, true))

	cache := NewInterfaceStore()
	err := cache.Initialize(mockOVSdbClient, "", "")
	if err == nil {
		t.Errorf("Failed to handle OVS return error")
	}

	uuid1 := uuid.New().String()
	p1Mac := "11:22:33:44:55:66"
	p1IP := "1.1.1.1"
	ovsPort1 := ovsconfig.OVSPortData{UUID: uuid.New().String(), Name: "p1", IFName: "p1", OFPort: 1,
		ExternalIDs: map[string]string{OVSExternalIDContainerID: uuid1,
			OVSExternalIDMAC: p1Mac, OVSExternalIDIP: p1IP}}
	uuid2 := uuid.New().String()
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid.New().String(), Name: "p2", IFName: "p2", OFPort: 2,
		ExternalIDs: map[string]string{OVSExternalIDContainerID: uuid2,
			OVSExternalIDMAC: "11:22:33:44:55:77", OVSExternalIDIP: "1.1.1.2"}}
	initOVSPorts := []ovsconfig.OVSPortData{ovsPort1, ovsPort2}

	mockOVSdbClient.EXPECT().GetPortList().Return(initOVSPorts, test.NewDummyOVSConfigError("Failed to list OVS ports", true, true))
	err = cache.Initialize(mockOVSdbClient, "", "")
	if cache.Len() != 0 {
		t.Errorf("Failed to load OVS port in initCache")
	}

	ovsPort2.OFPort = 2
	mockOVSdbClient.EXPECT().GetPortList().Return(initOVSPorts, nil)
	err = cache.Initialize(mockOVSdbClient, "", "")
	if cache.Len() != 2 {
		t.Errorf("Failed to load OVS port in initCache")
	}
	container1, found1 := cache.GetInterface(uuid1)
	if !found1 {
		t.Errorf("Failed to load OVS port into local cache")
	} else if container1.OFPort != 1 || container1.IP.String() != p1IP || container1.MAC.String() != p1Mac || container1.IfaceName != "p1" {
		t.Errorf("Failed to load OVS port configuration into local cache")
	}
	_, found2 := cache.GetInterface(uuid2)
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
