package ovsconfig

import (
	"testing"
)

func TestOVSBridge(t *testing.T) {
	br, err := NewOVSBridge("br1", NewOVSDBConnectionUDS(""))
	if err != nil {
		t.Error("Failed to create bridge: ", err)
		return
	}

	savedUUID := br.uuid
	if found, _ := br.lookupByName(); !found {
		t.Error("Could not look up the bridge")
	}
	if savedUUID != br.uuid {
		t.Error("Returned UUID does not match bridge UUID")
	}

	deleteAllPorts(br, t)

	uuid1 := testCreatePort(br, "p1", "internal", t)
	uuid2 := testCreatePort(br, "p2", "", t)
	uuid3 := testCreatePort(br, "p3", "vxlan", t)
	uuid4 := testCreatePort(br, "p4", "geneve", t)
	testDeletePort(br, uuid1, t)
	testDeletePort(br, uuid2, t)
	testDeletePort(br, uuid3, t)
	testDeletePort(br, uuid4, t)

	testCreatePort(br, "p1", "internal", t)
	testCreatePort(br, "p2", "", t)
	testCreatePort(br, "p3", "vxlan", t)
	testCreatePort(br, "p4", "geneve", t)
	deleteAllPorts(br, t)

	var portList []string
	portList, err = br.getPortUUIDList()
	if err != nil {
		t.Error("Failed to get ports: ", err)
	}
	if len(portList) > 0 {
		t.Error("Port list not empty after deleting all ports")
	}

	err = br.Delete()
	if err != nil {
		t.Error("Failed to delete bridge: ", err)
	}
	if found, _ := br.lookupByName(); found {
		t.Error("Bridge still exists after deletion")
	}
}

func deleteAllPorts(br *OVSBridge, t *testing.T) {
	portList, err := br.getPortUUIDList()
	if err == nil {
		err = br.DeletePorts(portList)
	}
	if err != nil {
		t.Error("Failed to delete ports: ", err)
	}
}

var ofPortRequest int32 = 1

func testCreatePort(br *OVSBridge, name string, ifType string, t *testing.T) string {
	var uuid string
	var err error
	var externalIDs map[string]interface{}
	var ofPort int32
	var ifName string = name

	switch ifType {
	case "":
		externalIDs = map[string]interface{}{"k1": "v1", "k2": "v2"}
		uuid, err = br.CreatePort(name, name, externalIDs)
	case "internal":
		externalIDs = map[string]interface{}{"k1": "v1", "k2": "v2"}
		uuid, err = br.CreateInternalPort(name, ofPortRequest, externalIDs)
	case "vxlan":
		externalIDs = map[string]interface{}{}
		uuid, err = br.CreateVXLANPort(name, ofPortRequest, "")
	case "geneve":
		externalIDs = map[string]interface{}{}
		uuid, err = br.CreateGenevePort(name, ofPortRequest, "")
	}

	if err != nil {
		t.Errorf("Failed to create %s port: %s", ifType, err)
		return ""
	}

	ofPort, err = br.GetOFPort(name)
	if err != nil {
		t.Error("Failed to get ofport: ", err)
	}
	if ifType != "" {
		if err == nil && ofPort != ofPortRequest {
			t.Error("ofport does not match the requested value")
		}
		ofPortRequest++
	} else {
		// -1 will be assigned to a port without a valid interface
		// backing.
		ofPort = -1
	}

	var port *OVSPortData
	port, err = br.GetPortData(uuid, ifName)
	if err != nil {
		t.Error("Failed to get port: ", err)
	} else if port == nil {
		t.Error("Port could not be found")
	} else {
		if port.Name != name || port.IFName != ifName || port.OFPort != ofPort {
			t.Error("Returned port attributes do not match the requested")
		} else {
			for k, v := range externalIDs {
				if rv, ok := port.ExternalIDs[k]; !ok {
					t.Errorf("Returned port does not include the requested external ID: %s:%s", k, v)
				} else if rv != v.(string) {
					t.Errorf("Returned port has an external ID does not match the requested value: %s:%s", k, v)
				}
			}
		}
	}

	var portList []OVSPortData
	portList, err = br.GetPortList()
	if err != nil {
		t.Error("Failed to get ports: ", err)
	} else {
		found := false
		for _, p := range portList {
			if p.UUID == uuid {
				found = true
				break
			}
		}
		if !found {
			t.Error("Failed to find port")
		}
	}

	return uuid
}

func testDeletePort(br *OVSBridge, uuid string, t *testing.T) {
	var err error

	if uuid == "" {
		return
	}

	err = br.DeletePort(uuid)
	if err != nil {
		t.Error("Failed to delete port: ", err)
		return
	}

	var uuidList []string
	uuidList, err = br.getPortUUIDList()
	if err != nil {
		t.Error("Failed to get ports: ", err)
		return
	}

	found := false
	for _, u := range uuidList {
		if u == uuid {
			found = true
			break
		}
	}
	if found {
		t.Error("Found deleted port")
	}
}
