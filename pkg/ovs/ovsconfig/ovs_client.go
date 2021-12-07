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
	"strconv"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/dbtransaction"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/helpers"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"k8s.io/klog/v2"
)

const defaultOVSDBFile = "db.sock"

type OVSBridge struct {
	ovsdb                    *ovsdb.OVSDB
	name                     string
	datapathType             OVSDatapathType
	uuid                     string
	isHardwareOffloadEnabled bool
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
	hardwareOffload  = "hw-offload"
)

// NewOVSDBConnectionUDS connects to the OVSDB server on the UNIX domain socket
// specified by address.
// If address is set to "", the default UNIX domain socket path
// "/run/openvswitch/db.sock" will be used.
// Returns the OVSDB struct on success.
func NewOVSDBConnectionUDS(address string) (*ovsdb.OVSDB, Error) {
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
func NewOVSBridge(bridgeName string, ovsDatapathType OVSDatapathType, ovsdb *ovsdb.OVSDB) *OVSBridge {
	return &OVSBridge{ovsdb, bridgeName, ovsDatapathType, "", false}
}

// Create looks up or creates the bridge. If the bridge with name bridgeName
// does not exist, it will be created. Openflow protocol version 1.0 and 1.3
// will be enabled for the bridge.
func (br *OVSBridge) Create() Error {
	var err Error
	var exists bool
	if exists, err = br.lookupByName(); err != nil {
		return err
	} else if exists {
		klog.Info("Bridge exists: ", br.uuid)
		// Update OpenFlow protocol versions and datapath type on existent bridge.
		if err := br.updateBridgeConfiguration(); err != nil {
			return err
		}
	} else if err = br.create(); err != nil {
		return err
	} else {
		klog.Info("Created bridge: ", br.uuid)
	}
	br.isHardwareOffloadEnabled, err = br.getHardwareOffload()
	if err != nil {
		klog.Warning("Failed to get hardware offload: ", err)
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

func (br *OVSBridge) updateBridgeConfiguration() Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	// Use Openflow protocol version 1.0 and 1.3.
	tx.Update(dbtransaction.Update{
		Table: "Bridge",
		Where: [][]interface{}{{"name", "==", br.name}},
		Row: map[string]interface{}{
			"protocols": makeOVSDBSetFromList([]string{openflowProtoVersion10,
				openflowProtoVersion13}),
			"datapath_type": br.datapathType,
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
		DatapathType: string(br.datapathType),
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

// SetDatapathID sets the provided datapath ID to the bridge.
// If datapath ID is not configured, reconfigure bridge(add/delete port or set different Mac address for local port)
// will change its datapath ID. And the change of datapath ID and interrupt OpenFlow connection.
// See question "My bridge disconnects from my controller on add-port/del-port" in：
// http://openvswitch.org/support/dist-docs-2.5/FAQ.md.html
func (br *OVSBridge) SetDatapathID(datapathID string) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	otherConfig := map[string]interface{}{"datapath-id": datapathID}
	tx.Update(dbtransaction.Update{
		Table: "Bridge",
		Where: [][]interface{}{{"name", "==", br.name}},
		Row: map[string]interface{}{
			"other_config": helpers.MakeOVSDBMap(otherConfig),
		},
	})
	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

func (br *OVSBridge) GetDatapathID() (string, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"datapath_id"},
		Where:   [][]interface{}{{"name", "==", br.name}},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return "", NewTransactionError(err, temporary)
	}
	datapathID := res[0].Rows[0].(map[string]interface{})["datapath_id"]
	switch datapathID.(type) {
	case string:
		return datapathID.(string), nil
	default:
		return "", nil
	}
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
	return br.createTunnelPort(name, tunnelType, ofPortRequest, false, "", "", "", nil)
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
	csum bool,
	localIP string,
	remoteIP string,
	psk string,
	externalIDs map[string]interface{}) (string, Error) {
	if psk != "" && remoteIP == "" {
		return "", newInvalidArgumentsError("IPSec tunnel can not be flow based. remoteIP must be set")
	}
	return br.createTunnelPort(name, tunnelType, ofPortRequest, csum, localIP, remoteIP, psk, externalIDs)
}

func (br *OVSBridge) createTunnelPort(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	csum bool,
	localIP string,
	remoteIP string,
	psk string,
	externalIDs map[string]interface{}) (string, Error) {

	if tunnelType != VXLANTunnel && tunnelType != GeneveTunnel && tunnelType != GRETunnel && tunnelType != STTTunnel {
		return "", newInvalidArgumentsError("unsupported tunnel type: " + string(tunnelType))
	}
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}

	options := make(map[string]interface{}, 3)
	if remoteIP != "" {
		options["remote_ip"] = remoteIP
	} else {
		// Flow based tunnel.
		options["key"] = "flow"
		options["remote_ip"] = "flow"
	}
	if localIP != "" {
		options["local_ip"] = localIP
	}

	if psk != "" {
		options["psk"] = psk
	}
	if csum {
		options["csum"] = "true"
	}

	return br.createPort(name, name, string(tunnelType), ofPortRequest, externalIDs, options)
}

// GetInterfaceOptions returns the options of the provided interface.
func (br *OVSBridge) GetInterfaceOptions(name string) (map[string]string, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Interface",
		Where:   [][]interface{}{{"name", "==", name}},
		Columns: []string{"options"},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}

	optionsRes := res[0].Rows[0].(map[string]interface{})["options"].([]interface{})
	return buildMapFromOVSDBMap(optionsRes), nil
}

// SetInterfaceOptions sets the specified options of the provided interface.
func (br *OVSBridge) SetInterfaceOptions(name string, options map[string]interface{}) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	tx.Update(dbtransaction.Update{
		Table: "Interface",
		Where: [][]interface{}{{"name", "==", name}},
		Row: map[string]interface{}{
			"options": helpers.MakeOVSDBMap(options),
		},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

// ParseTunnelInterfaceOptions reads remote IP, local IP, IPSec PSK, and csum
// from the tunnel interface options and returns them.
func ParseTunnelInterfaceOptions(portData *OVSPortData) (net.IP, net.IP, string, bool) {
	if portData.Options == nil {
		return nil, nil, "", false
	}

	var ok bool
	var remoteIPStr, localIPStr, psk string
	var remoteIP, localIP net.IP
	var csum bool

	if remoteIPStr, ok = portData.Options["remote_ip"]; ok {
		if remoteIPStr != "flow" {
			remoteIP = net.ParseIP(remoteIPStr)
		}
	}
	if localIPStr, ok = portData.Options["local_ip"]; ok {
		localIP = net.ParseIP(localIPStr)
	}

	psk = portData.Options["psk"]
	if csumStr, ok := portData.Options["csum"]; ok {
		csum, _ = strconv.ParseBool(csumStr)
	}
	return remoteIP, localIP, psk, csum
}

// CreateUplinkPort creates uplink port.
func (br *OVSBridge) CreateUplinkPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error) {
	return br.createPort(name, name, "", ofPortRequest, externalIDs, nil)
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
// The function will invoke OVSDB "wait" operation with 5 seconds timeout to
// wait the ofport is set on the interface, and so could be blocked for 5
// seconds. If the "wait" operation times out or the interface is not found, or
// the ofport is invalid, value 0 and an error will be returned.
// If waitUntilValid is true, the function will wait the ofport is not -1 with
// 5 seconds timeout. This parameter is used after the interface type is changed
// by the client.
func (br *OVSBridge) GetOFPort(ifName string, waitUntilValid bool) (int32, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	// If an OVS port is newly created, the ofport field is expected to change from empty to a int value.
	invalidRow := map[string]interface{}{
		"ofport": helpers.MakeOVSDBSet(map[string]interface{}{}),
	}
	// If an OVS port is updated from invalid status to valid, the ofport field is expected to change from "-1" to a
	// value that is larger than 0.
	if waitUntilValid {
		invalidRow = map[string]interface{}{
			"ofport": []interface{}{"set", []int32{-1}},
		}
	}
	tx.Wait(dbtransaction.Wait{
		Table:   "Interface",
		Timeout: uint64(defaultGetPortTimeout / time.Millisecond), // The unit of timeout is millisecond
		Columns: []string{"ofport"},
		Until:   "!=",
		Rows:    []interface{}{invalidRow},
		Where:   [][]interface{}{{"name", "==", ifName}},
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
	// ofport value -1 means that the interface could not be created due to an error.
	if ofport <= 0 {
		return 0, NewTransactionError(fmt.Errorf("invalid ofport %d", ofport), false)
	}
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
	}
	// Should not be possible
	return map[string]string{}
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

// GetOVSVersion either returns the version of OVS, or an error.
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
		klog.Warning("Could not find ovs_version in the OVS query result")
		return "", NewTransactionError(fmt.Errorf("no results from OVS query"), false)
	}
	return parseOvsVersion(res[0].Rows[0])
}

// parseOvsVersion parses the version from an interface type, which can be a map of string[interface] or string[string], and returns it as a string, we have special logic here so that a panic doesn't happen.
func parseOvsVersion(ovsReturnRow interface{}) (string, Error) {
	errorMessage := fmt.Errorf("unexpected transaction result when querying OVSDB %v", defaultOvsVersionMessage)
	switch obj := ovsReturnRow.(type) {
	case map[string]string:
		if _, ok := obj["ovs_version"]; ok {
			return obj["ovs_version"], nil
		}
	case map[string]interface{}:
		if _, ok := obj["ovs_version"]; ok {
			return obj["ovs_version"].(string), nil
		}
	}
	return "", NewTransactionError(errorMessage, false)
}

// AddOVSOtherConfig adds the given configs to the "other_config" column of
// the single record of the "Open_vSwitch" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddOVSOtherConfig(configs map[string]interface{}) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	mutateSet := helpers.MakeOVSDBMap(configs)
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Open_vSwitch",
		Mutations: [][]interface{}{{"other_config", "insert", mutateSet}},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

func (br *OVSBridge) GetOVSOtherConfig() (map[string]string, Error) {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	tx.Select(dbtransaction.Select{
		Table:   "Open_vSwitch",
		Columns: []string{"other_config"},
	})

	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}
	if len(res[0].Rows) == 0 {
		klog.Warning("Could not find other_config")
		return nil, nil
	}
	otherConfigs := res[0].Rows[0].(map[string]interface{})["other_config"].([]interface{})
	return buildMapFromOVSDBMap(otherConfigs), nil
}

// DeleteOVSOtherConfig deletes the given configs from the "other_config" column of
// the single record of the "Open_vSwitch" table.
// For each config, it will only be deleted if its key exists and its value matches the stored one.
// No error is returned if configs don't exist or don't match.
func (br *OVSBridge) DeleteOVSOtherConfig(configs map[string]interface{}) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	mutateSet := helpers.MakeOVSDBMap(configs)
	tx.Mutate(dbtransaction.Mutate{
		Table:     "Open_vSwitch",
		Mutations: [][]interface{}{{"other_config", "delete", mutateSet}},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

func (br *OVSBridge) GetBridgeName() string {
	return br.name
}

func (br *OVSBridge) IsHardwareOffloadEnabled() bool {
	return br.isHardwareOffloadEnabled
}

func (br *OVSBridge) getHardwareOffload() (bool, Error) {
	otherConfig, err := br.GetOVSOtherConfig()
	if err != nil {
		return false, err
	}
	for configKey, configValue := range otherConfig {
		if configKey == hardwareOffload {
			boolConfigVal, err := strconv.ParseBool(configValue)
			if err != nil {
				return boolConfigVal, newInvalidArgumentsError(fmt.Sprint("invalid hardwareOffload value: ", boolConfigVal))
			}
			return boolConfigVal, nil
		}
	}
	return false, nil
}

func (br *OVSBridge) GetOVSDatapathType() OVSDatapathType {
	return br.datapathType
}

// SetInterfaceType modifies the OVS Interface type to the given ifType.
// This function is used on Windows when the Pod interface is created after the OVS port creation.
func (br *OVSBridge) SetInterfaceType(name, ifType string) Error {
	// Update Interface type, and the caller ensures the host Interface exists.
	tx1 := br.ovsdb.Transaction(openvSwitchSchema)
	tx1.Update(dbtransaction.Update{
		Table: "Interface",
		Where: [][]interface{}{{"name", "==", name}},
		Row: map[string]interface{}{
			"type": ifType,
		},
	})
	_, err, temporary := tx1.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

func (br *OVSBridge) SetPortExternalIDs(portName string, externalIDs map[string]interface{}) Error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)
	tx.Update(dbtransaction.Update{
		Table: "Port",
		Where: [][]interface{}{{"name", "==", portName}},
		Row: map[string]interface{}{
			"external_ids": helpers.MakeOVSDBMap(externalIDs),
		},
	})
	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}
