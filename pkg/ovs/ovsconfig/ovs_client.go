package ovsconfig

import (
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/dbtransaction"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/helpers"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovshelper"
	"k8s.io/klog"
)

type OVSBridge struct {
	ovsdb *ovsdb.OVSDB
	name  string
	uuid  string
}

const defaultUDSAddress = "/run/openvswitch/db.sock"

const openvSwitchSchema = "Open_vSwitch"

// Connects to the ovsdb server on the UNIX domain socket specified by address.
// If address is set to "", the default UNIX domain socket path
// "/run/openvswitch/db.sock" will be used.
// Returns the OVSDB struct on success.
func NewOVSDBConnectionUDS(address string) *ovsdb.OVSDB {
	if address == "" {
		address = defaultUDSAddress
	}
	return ovsdb.Dial([][]string{{"unix", address}}, nil, nil)
}

// Create and return OVSBridge.
// If the bridge with name bridgeName does not exist, it will be created.
func NewOVSBridge(bridgeName string, ovsdb *ovsdb.OVSDB) (*OVSBridge, error) {
	bridge := &OVSBridge{ovsdb, bridgeName, ""}
	if exits, err := bridge.lookupByName(); err != nil {
		return nil, err
	} else if exits {
		klog.Info("Bridge exits: ", bridge.uuid)
	} else if err = bridge.create(); err != nil {
		return nil, err
	} else {
		klog.Info("Created bridge: ", bridge.uuid)
	}

	return bridge, nil
}

func (br *OVSBridge) lookupByName() (bool, error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"_uuid"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})
	res, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return false, err
	}

	if len(res[0].Rows) == 0 {
		return false, nil
	}

	br.uuid = res[0].Rows[0].(map[string]interface{})["_uuid"].([]interface{})[1].(string)
	return true, nil
}

func (br *OVSBridge) create() error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	bridge := ovshelper.Bridge{
		Name: br.name,
	}
	namedUUID := tx.Insert(dbtransaction.Insert{
		Table: "Bridge",
		Row:   bridge,
	})

	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"named-uuid": []string{namedUUID},
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Open_vSwitch",
		Mutations: [][]interface{}{{"bridges", "insert", mutateSet}},
	})

	res, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return err
	}

	br.uuid = res[0].UUID[1]
	return nil
}

func (br *OVSBridge) Delete() error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"uuid": []string{br.uuid},
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Open_vSwitch",
		Mutations: [][]interface{}{{"bridges", "delete", mutateSet}},
	})

	_, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
	}

	return err
}

// Return all UUIDs of all ports on the bridge
func (br *OVSBridge) GetPortUUIDList() ([]string, error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"ports"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})

	res, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, err
	}

	portRes := res[0].Rows[0].(map[string]interface{})["ports"].([]interface{})
	return helpers.GetIdListFromOVSDBSet(portRes), nil
}

// Delete ports in portUUIDList on the bridge
func (br *OVSBridge) DeletePorts(portUUIDList []string) error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"uuid": portUUIDList,
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Bridge",
		Mutations: [][]interface{}{{"ports", "delete", mutateSet}},
	})

	_, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
	}

	return err
}

func (br *OVSBridge) DeletePort(portUUID string) error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"uuid": []string{portUUID},
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Bridge",
		Mutations: [][]interface{}{{"ports", "delete", mutateSet}},
	})

	_, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
	}

	return err
}

// Creates an internal port with the specified name on the bridge.
// If externalIDs is passed, the map key/value pairs will be set to the port's
// external_ids.
func (br *OVSBridge) CreateInternalPort(name string, externalIDs map[string]interface{}) (string, error) {
	var externalIDMap []interface{}
	if externalIDs != nil {
		externalIDMap = helpers.MakeOVSDBMap(externalIDs)
	}
	return br.createPort(name, name, "internal", externalIDMap)
}

// Creates a port with the specified name on the bridge, and connects interface
// specified by ifDev to the port.
// If externalIDs is passed, the map key/value pairs will be set to the port's
// external_ids.
func (br *OVSBridge) CreatePort(name string, ifDev string, externalIDs map[string]interface{}) (string, error) {
	var externalIDMap []interface{}
	if externalIDs != nil {
		externalIDMap = helpers.MakeOVSDBMap(externalIDs)
	}
	return br.createPort(name, ifDev, "", externalIDMap)
}

func (br *OVSBridge) createPort(name string, ifName string, ifType string, externalIDs []interface{}) (string, error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	interf := Interface{
		BaseInterface: BaseInterface{Name: ifName},
		Type:          ifType,
	}
	ifNamedUUID := tx.Insert(dbtransaction.Insert{
		Table: "Interface",
		Row:   interf,
	})

	port := Port{
		BasePort: BasePort{
			Name: name,
			Interfaces: helpers.MakeOVSDBSet(map[string]interface{}{
				"named-uuid": []string{ifNamedUUID},
			}),
		},
		ExternalIDs: externalIDs,
	}
	portNamedUUID := tx.Insert(dbtransaction.Insert{
		Table: "Port",
		Row:   port,
	})

	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"named-uuid": []string{portNamedUUID},
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Bridge",
		Mutations: [][]interface{}{{"ports", "insert", mutateSet}},
		Where:     [][]interface{}{{"name", "==", br.name}},
	})

	res, err, _ := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return "", err
	}

	return res[1].UUID[1], nil
}
