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
	testDeletePort(br, uuid1, t)
	testDeletePort(br, uuid2, t)

	testCreatePort(br, "p1", "internal", t)
	testCreatePort(br, "p2", "", t)
	deleteAllPorts(br, t)

	var portList []string
	portList, err = br.GetPortUUIDList()
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
	portList, err := br.GetPortUUIDList()
	if err == nil {
		err = br.DeletePorts(portList)
	}
	if err != nil {
		t.Error("Failed to delete ports: ", err)
	}
}

func testCreatePort(br *OVSBridge, name string, ifType string, t *testing.T) string {
	var uuid string
	var err error
	externalIDs := map[string]interface{}{"k1": "v1", "k2": "v2"}

	if ifType == "" {
		uuid, err = br.CreatePort(name, name, externalIDs)
	} else if ifType == "internal" {
		uuid, err = br.CreateInternalPort(name, externalIDs)
	}
	if err != nil {
		t.Errorf("Failed to create %s port: %s", ifType, err)
		return ""
	}

	var uuidList []string
	uuidList, err = br.GetPortUUIDList()
	if err != nil {
		t.Error("Failed to get ports: ", err)
		return uuid
	}

	found := false
	for _, u := range uuidList {
		if u == uuid {
			found = true
			break
		}
	}
	if !found {
		t.Error("Failed to find port")
	}

	return uuid
}

func testDeletePort(br *OVSBridge, uuid string, t *testing.T) {
	var err error

	err = br.DeletePort(uuid)
	if err != nil {
		t.Error("Failed to delete port: ", err)
		return
	}

	var uuidList []string
	uuidList, err = br.GetPortUUIDList()
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
