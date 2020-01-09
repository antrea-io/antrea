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

package ovsconfig

import (
	"fmt"
	"net"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/dbtransaction"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/helpers"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"k8s.io/klog"
)

type OVSBridge struct {
	ovsdb        *ovsdb.OVSDB
	name         string
	datapathType string
	uuid         string
}

type OVSPortData struct {
	UUID string
	Name string
	// Interface type.
	IFType      string
	IFName      string
	OFPort      int32
	ExternalIDs map[string]string
	Options     map[string]string
}

const (
	openvSwitchSchema = "Open_vSwitch"
	// Openflow protocol version 1.0.
	openflowProtoVersion10 = "OpenFlow10"
	// Openflow protocol version 1.3.
	openflowProtoVersion13 = "OpenFlow13"
	// Maximum allowed value of ofPortRequest.
	ofPortRequestMax = 65279
)

// NewOVSDBConnectionUDS connects to the OVSDB server on the UNIX domain socket
// specified by address.
// If address is set to "", the default UNIX domain socket path
// "/run/openvswitch/db.sock" will be used.
// Returns the OVSDB struct on success.
func NewOVSDBConnectionUDS(address string) (*ovsdb.OVSDB, Error) {
	if address == "" {
		address = defaultConnAddress
	}
	klog.Infof("Connecting to OVSDB at address %s", address)

	// For the sake of debugging, we keep logging messages until the
	// connection is successful. We use exponential backoff to determine the
	// sleep duration between two successive log messages (up to
	// maxBackoffTime).
	const maxBackoffTime = 8 * time.Second
	success := make(chan bool, 1)
	go func() {
		backoff := 1 * time.Second
		for {
			select {
			case <-success:
				return
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoffTime {
					backoff = maxBackoffTime
				}
				klog.Infof("Not connected yet, will try again in %v", backoff)
			}
		}
	}()

	db := ovsdb.Dial([][]string{{defaultConnNetwork, address}}, nil, nil)
	success <- true
	return db, nil
}

// NewOVSBridge creates and returns a new OVSBridge struct.
func NewOVSBridge(bridgeName string, ovsDatapathType string, ovsdb *ovsdb.OVSDB) *OVSBridge {
	return &OVSBridge{ovsdb, bridgeName, ovsDatapathType, ""}
}

// Create looks up or creates the bridge. If the bridge with name bridgeName
// does not exist, it will be created. Openflow protocol version 1.0 and 1.3
// will be enabled for the bridge.
func (br *OVSBridge) Create() Error {
	if exists, err := br.lookupByName(); err != nil {
		return err
	} else if exists {
		klog.Info("Bridge exists: ", br.uuid)
		// Update OpenFlow protocol versions on existent bridge.
		if err := br.updateProtocols(); err != nil {
			return err
		}
	} else if err = br.create(); err != nil {
		return err
	} else {
		klog.Info("Created bridge: ", br.uuid)
	}

	return nil
}

func (br *OVSBridge) lookupByName() (bool, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"_uuid"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})
	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return false, NewTransactionError(err, temporary)
	}

	if len(res[0].Rows) == 0 {
		return false, nil
	}

	br.uuid = res[0].Rows[0].(map[string]interface{})["_uuid"].([]interface{})[1].(string)
	return true, nil
}

func (br *OVSBridge) updateProtocols() Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	// Use Openflow protocol version 1.0 and 1.3.
	tx.Update(dbtransaction.Update{
		Table: "Bridge",
		Where: [][]interface{}{{"name", "==", br.name}},
		Row: map[string]interface{}{
			"protocols": makeOVSDBSetFromList([]string{openflowProtoVersion10,
				openflowProtoVersion13}),
		},
	})
	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

func (br *OVSBridge) create() Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	bridge := Bridge{
		Name: br.name,
		// Use Openflow protocol version 1.0 and 1.3.
		Protocols: makeOVSDBSetFromList([]string{openflowProtoVersion10,
			openflowProtoVersion13}),
		DatapathType: br.datapathType,
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

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}

	br.uuid = res[0].UUID[1]
	return nil
}

func (br *OVSBridge) Delete() Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"uuid": []string{br.uuid},
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Open_vSwitch",
		Mutations: [][]interface{}{{"bridges", "delete", mutateSet}},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

// GetExternalIDs returns the external IDs of the bridge.
func (br *OVSBridge) GetExternalIDs() (map[string]string, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"external_ids"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}

	extIDRes := res[0].Rows[0].(map[string]interface{})["external_ids"].([]interface{})
	return buildMapFromOVSDBMap(extIDRes), nil
}

// SetExternalIDs sets the provided external IDs to the bridge.
func (br *OVSBridge) SetExternalIDs(externalIDs map[string]interface{}) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Update(dbtransaction.Update{
		Table: "Bridge",
		Where: [][]interface{}{{"name", "==", br.name}},
		Row: map[string]interface{}{
			"external_ids": helpers.MakeOVSDBMap(externalIDs),
		},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

// GetPortUUIDList returns UUIDs of all ports on the bridge.
func (br *OVSBridge) GetPortUUIDList() ([]string, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"ports"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}

	portRes := res[0].Rows[0].(map[string]interface{})["ports"].([]interface{})
	return helpers.GetIdListFromOVSDBSet(portRes), nil
}

// DeletePorts deletes ports in portUUIDList on the bridge
func (br *OVSBridge) DeletePorts(portUUIDList []string) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"uuid": portUUIDList,
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Bridge",
		Mutations: [][]interface{}{{"ports", "delete", mutateSet}},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

// DeletePort deletes the port with the provided portUUID.
// If the port does not exist no change will be done.
func (br *OVSBridge) DeletePort(portUUID string) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	mutateSet := helpers.MakeOVSDBSet(map[string]interface{}{
		"uuid": []string{portUUID},
	})
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Bridge",
		Mutations: [][]interface{}{{"ports", "delete", mutateSet}},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

// CreateInternalPort creates an internal port with the specified name on the
// bridge.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateInternalPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error) {
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}
	return br.createPort(name, name, "internal", ofPortRequest, externalIDs, nil)
}

// CreateTunnelPort creates a tunnel port with the specified name and type on
// the bridge.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateTunnelPort(name string, tunnelType TunnelType, ofPortRequest int32) (string, Error) {
	return br.createTunnelPort(name, tunnelType, ofPortRequest, "", "", nil)
}

// CreateTunnelPortExt creates a tunnel port with the specified name and type
// on the bridge.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
// If remoteIP is not empty, it will be set to the tunnel port interface
// options; otherwise flow based tunneling will be configured.
// psk is for the pre-shared key of IPSec ESP tunnel. If it is not empty, it
// will be set to the tunnel port interface options. Flow based IPSec tunnel is
// not supported, so remoteIP must be provided too when psk is not empty.
// If externalIDs is not nill, the IDs in it will be added to the port's
// external_ids.
func (br *OVSBridge) CreateTunnelPortExt(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	remoteIP string,
	psk string,
	externalIDs map[string]interface{}) (string, Error) {
	if psk != "" && remoteIP == "" {
		return "", newInvalidArgumentsError("IPSec tunnel can not be flow based. remoteIP must be set")
	}
	return br.createTunnelPort(name, tunnelType, ofPortRequest, remoteIP, psk, externalIDs)
}

func (br *OVSBridge) createTunnelPort(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	remoteIP string,
	psk string,
	externalIDs map[string]interface{}) (string, Error) {

	if tunnelType != VXLANTunnel && tunnelType != GeneveTunnel && tunnelType != GRETunnel && tunnelType != STTTunnel {
		return "", newInvalidArgumentsError("unsupported tunnel type: " + string(tunnelType))
	}
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}

	options := make(map[string]interface{}, 2)
	if remoteIP != "" {
		options["remote_ip"] = remoteIP
	} else {
		// Flow based tunnel.
		options["key"] = "flow"
		options["remote_ip"] = "flow"
	}

	if psk != "" {
		options["psk"] = psk
	}

	return br.createPort(name, name, string(tunnelType), ofPortRequest, externalIDs, options)
}

// ParseTunnelInterfaceOptions reads remote IP and IPSec PSK from the tunnel
// interface options and returns them.
func ParseTunnelInterfaceOptions(portData *OVSPortData) (net.IP, string) {
	if portData.Options == nil {
		return nil, ""
	}

	var ok bool
	var remoteIPStr, psk string
	var remoteIP net.IP

	if remoteIPStr, ok = portData.Options["remote_ip"]; ok {
		if remoteIPStr != "flow" {
			remoteIP = net.ParseIP(remoteIPStr)
		}
	}

	psk = portData.Options["psk"]
	return remoteIP, psk
}

// CreatePort creates a port with the specified name on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
func (br *OVSBridge) CreatePort(name, ifDev string, externalIDs map[string]interface{}) (string, Error) {
	return br.createPort(name, ifDev, "", 0, externalIDs, nil)
}

func (br *OVSBridge) createPort(name, ifName, ifType string, ofPortRequest int32, externalIDs, options map[string]interface{}) (string, Error) {
	var externalIDMap []interface{}
	var optionMap []interface{}

	if externalIDs != nil {
		externalIDMap = helpers.MakeOVSDBMap(externalIDs)
	}
	if options != nil {
		optionMap = helpers.MakeOVSDBMap(options)
	}

	tx := br.ovsdb.Transaction(openvSwitchSchema)

	interf := Interface{
		Name:          ifName,
		Type:          ifType,
		OFPortRequest: ofPortRequest,
		Options:       optionMap,
	}
	ifNamedUUID := tx.Insert(dbtransaction.Insert{
		Table: "Interface",
		Row:   interf,
	})

	port := Port{
		Name: name,
		Interfaces: helpers.MakeOVSDBSet(map[string]interface{}{
			"named-uuid": []string{ifNamedUUID},
		}),
		ExternalIDs: externalIDMap,
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

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return "", NewTransactionError(err, temporary)
	}

	return res[1].UUID[1], nil
}

// GetOFPort retrieves the ofport value of an interface given the interface name.
// The function will invoke OVSDB "wait" operation with 1 second timeout to wait
// the ofport is set on the interface, and so could be blocked for 1 second. If
// the "wait" operation timeout, value 0 will be returned.
func (br *OVSBridge) GetOFPort(ifName string) (int32, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	tx.Wait(dbtransaction.Wait{
		Table:   "Interface",
		Timeout: uint64(defaultGetPortTimeout / time.Millisecond), // The unit of timeout is millisecond
		Columns: []string{"ofport"},
		Until:   "!=",
		Rows: []interface{}{map[string]interface{}{
			"ofport": helpers.MakeOVSDBSet(map[string]interface{}{}),
		}},
		Where: [][]interface{}{{"name", "==", ifName}},
	})
	tx.Select(dbtransaction.Select{
		Table:   "Interface",
		Columns: []string{"ofport"},
		Where:   [][]interface{}{{"name", "==", ifName}},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return 0, NewTransactionError(err, temporary)
	}

	if len(res) < 2 || len(res[1].Rows) == 0 {
		return 0, NewTransactionError(fmt.Errorf("interface %s not found", ifName), false)
	}
	ofport := int32(res[1].Rows[0].(map[string]interface{})["ofport"].(float64))
	return ofport, nil
}

func makeOVSDBSetFromList(list []string) []interface{} {
	return []interface{}{"set", list}
}

func buildMapFromOVSDBMap(data []interface{}) map[string]string {
	if data[0] == "map" {
		ret := make(map[string]string)
		for _, pair := range data[1].([]interface{}) {
			ret[pair.([]interface{})[0].(string)] = pair.([]interface{})[1].(string)
		}
		return ret
	} else { // Should not be possible
		return map[string]string{}
	}
}

func buildPortDataCommon(port, intf map[string]interface{}, portData *OVSPortData) {
	portData.Name = port["name"].(string)
	portData.ExternalIDs = buildMapFromOVSDBMap(port["external_ids"].([]interface{}))
	portData.Options = buildMapFromOVSDBMap(intf["options"].([]interface{}))
	portData.IFType = intf["type"].(string)
	if ofPort, ok := intf["ofport"].(float64); ok {
		portData.OFPort = int32(ofPort)
	} else { // ofport not assigned by OVS yet
		portData.OFPort = 0
	}
}

// GetPortData retrieves port data given the OVS port UUID and interface name.
// nil is returned, if the port or interface could not be found, or the
// interface is not attached to the port.
// The port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortData(portUUID, ifName string) (*OVSPortData, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Port",
		Columns: []string{"name", "external_ids", "interfaces"},
		Where:   [][]interface{}{{"_uuid", "==", []string{"uuid", portUUID}}},
	})
	tx.Select(dbtransaction.Select{
		Table:   "Interface",
		Columns: []string{"_uuid", "type", "ofport", "options"},
		Where:   [][]interface{}{{"name", "==", ifName}},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}
	if len(res[0].Rows) == 0 {
		return nil, NewTransactionError(fmt.Errorf("port %s not found", portUUID), false)
	}
	if len(res[1].Rows) == 0 {
		return nil, NewTransactionError(fmt.Errorf("interface %s not found", ifName), false)
	}

	port := res[0].Rows[0].(map[string]interface{})
	intf := res[1].Rows[0].(map[string]interface{})
	ifUUID := intf["_uuid"].([]interface{})[1].(string)
	ifUUIDList := helpers.GetIdListFromOVSDBSet(port["interfaces"].([]interface{}))

	found := false
	for _, uuid := range ifUUIDList {
		if uuid == ifUUID {
			found = true
			break
		}
	}
	if !found {
		return nil, NewTransactionError(fmt.Errorf("interface %s not attached to port %s", ifName, portUUID),
			false)
	}

	portData := OVSPortData{UUID: portUUID, IFName: ifName}
	buildPortDataCommon(port, intf, &portData)
	return &portData, nil
}

// GetPortList returns all ports on the bridge.
// A port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortList() ([]OVSPortData, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"ports"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})
	tx.Select(dbtransaction.Select{
		Table:   "Port",
		Columns: []string{"_uuid", "name", "external_ids", "interfaces"},
	})
	tx.Select(dbtransaction.Select{
		Table:   "Interface",
		Columns: []string{"_uuid", "type", "name", "ofport", "options"},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}

	if len(res[0].Rows) == 0 {
		klog.Warning("Could not find bridge")
		return []OVSPortData{}, nil
	}
	portUUIDList := helpers.GetIdListFromOVSDBSet(res[0].Rows[0].(map[string]interface{})["ports"].([]interface{}))

	portMap := make(map[string]map[string]interface{})
	for _, row := range res[1].Rows {
		uuid := row.(map[string]interface{})["_uuid"].([]interface{})[1].(string)
		portMap[uuid] = row.(map[string]interface{})
	}

	ifMap := make(map[string]map[string]interface{})
	for _, row := range res[2].Rows {
		uuid := row.(map[string]interface{})["_uuid"].([]interface{})[1].(string)
		ifMap[uuid] = row.(map[string]interface{})
	}

	portList := make([]OVSPortData, len(portUUIDList))
	for i, uuid := range portUUIDList {
		portList[i].UUID = uuid
		port := portMap[uuid]
		ifUUIDList := helpers.GetIdListFromOVSDBSet(port["interfaces"].([]interface{}))
		// Port should have one interface
		intf := ifMap[ifUUIDList[0]]
		portList[i].IFName = intf["name"].(string)
		buildPortDataCommon(port, intf, &portList[i])
	}

	return portList, nil
}

func (br *OVSBridge) SetInterfaceMTU(name string, MTU int) error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	tx.Update(dbtransaction.Update{
		Table: "Interface",
		Where: [][]interface{}{{"name", "==", name}},
		Row: map[string]interface{}{
			"mtu_request": MTU,
		},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}

	return nil
}

func (br *OVSBridge) GetOVSVersion() (string, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	tx.Select(dbtransaction.Select{
		Table:   openvSwitchSchema,
		Columns: []string{"ovs_version"},
	})

	res, err, temporary := tx.Commit()

	if err != nil {
		klog.Error("Transaction failed: ", err)
		return "", NewTransactionError(err, temporary)
	}
	if len(res[0].Rows) == 0 {
		klog.Warning("Could not find ovs_version")
		return "", nil
	}

	return res[0].Rows[0].(map[string]interface{})["ovs_version"].(string), nil
}
