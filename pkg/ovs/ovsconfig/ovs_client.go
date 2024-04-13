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
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-logr/stdr"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdbmodel "github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

const defaultOVSDBFile = "db.sock"

type OVSBridge struct {
	ovsdb                    libovsdbclient.Client
	name                     string
	datapathType             OVSDatapathType
	uuid                     string
	isHardwareOffloadEnabled bool
	allocatedOFPorts         []int32
}

type OVSPortData struct {
	UUID   string
	Name   string
	VLANID uint16
	// Interface type.
	IFType      string
	IFName      string
	OFPort      int32
	ExternalIDs map[string]string
	Options     map[string]string
	MAC         net.HardwareAddr
}

const (
	openvSwitchSchema = "Open_vSwitch"
	// Openflow protocol version 1.0.
	openflowProtoVersion10 = "OpenFlow10"
	// Openflow protocol version 1.5.
	openflowProtoVersion15 = "OpenFlow15"
	// Maximum allowed value of ofPortRequest.
	ofPortRequestMax = 65279
	hardwareOffload  = "hw-offload"
)

// NewOVSDBConnectionUDS connects to the OVSDB server on the UNIX domain socket
// or named pipe (on Windows) specified by address, never using any SSL connection option.
// If address is set to "", the default UNIX domain socket path
// "/run/openvswitch/db.sock" will be used.
// Returns the OVSDB struct on success.
func NewOVSDBConnectionUDS(address string) (libovsdbclient.Client, Error) {
	klog.Infof("Connecting to OVSDB at address %s", address)

	// For the sake of debugging, we keep logging messages until the
	// connection is successful. We use exponential backoff to determine the
	// sleep duration between two successive log messages (up to
	// maxBackoffTime).
	const maxBackoffTime = 8 * time.Second
	success := make(chan bool, 1)
	go func() {
		backoffDuration := 1 * time.Second
		for {
			select {
			case <-success:
				return
			case <-time.After(backoffDuration):
				backoffDuration *= 2
				if backoffDuration > maxBackoffTime {
					backoffDuration = maxBackoffTime
				}
				klog.Infof("Not connected yet, will try again in %v", backoffDuration)
			}
		}
	}()

	model, err := libovsdbmodel.NewClientDBModel(openvSwitchSchema,
		map[string]libovsdbmodel.Model{
			TableNameOpenVSwitch: &OpenvSwitch{},
			TableNameBridge:      &Bridge{},
			TableNamePort:        &Port{},
			TableNameInterface:   &Interface{},
		})

	if err != nil {
		klog.ErrorS(err, "Failed to initialize libovsdb model")
		return nil, NewTransactionError(err, false)
	}

	stdr.SetVerbosity(3)
	logr := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})
	db, err := libovsdbclient.NewOVSDBClient(model,
		libovsdbclient.WithEndpoint(fmt.Sprintf("%s:%s", defaultConnNetwork, address)),
		libovsdbclient.WithInactivityCheck(2*time.Second, 1*time.Second, &backoff.ZeroBackOff{}),
		libovsdbclient.WithLogger(&logr),
	)
	if err != nil {
		klog.ErrorS(err, "Failed to initialize libovsdb client")
		return nil, NewTransactionError(err, false)
	}

	ctx := context.Background()
	if err = db.Connect(ctx); err != nil {
		klog.ErrorS(err, "Failed to connect to unix domain socket")
		return nil, NewTransactionError(err, false)
	}
	if _, err = db.Monitor(ctx, db.NewMonitor(
		libovsdbclient.WithTable(&OpenvSwitch{}),
		libovsdbclient.WithTable(&Bridge{}),
		libovsdbclient.WithTable(&Port{}),
		libovsdbclient.WithTable(&Interface{}),
	)); err != nil {
		klog.ErrorS(err, "Failed to setup libovsdb monitor")
		return nil, NewTransactionError(err, false)
	}

	success <- true
	return db, nil
}

// NewOVSBridge creates and returns a new OVSBridge struct.
func NewOVSBridge(bridgeName string, ovsDatapathType OVSDatapathType, ovsdb libovsdbclient.Client) OVSBridgeClient {
	return &OVSBridge{ovsdb, bridgeName, ovsDatapathType, "", false, []int32{}}
}

// Create looks up or creates the bridge. If the bridge with name bridgeName
// does not exist, it will be created. Openflow protocol version 1.0 and 1.5
// will be enabled for the bridge.
func (br *OVSBridge) Create() Error {
	var err Error
	exists := true

	bridge := &Bridge{Name: br.name}
	if err = get(br.ovsdb, bridge); err != nil {
		if err.Error() == libovsdbclient.ErrNotFound.Error() {
			exists = false
		} else {
			klog.ErrorS(err, "Failed to get bridge", "name", br.name)
			return err
		}
	}

	if exists {
		br.uuid = bridge.UUID
		// update OpenFlow protocol versions and datapath type on existent bridge.
		klog.InfoS("Bridge exists", "name", br.name, "uuid", br.uuid)
		if err = update(br.ovsdb, &Bridge{Name: br.name}, &Bridge{
			Protocols:    []string{openflowProtoVersion10, openflowProtoVersion15},
			DatapathType: string(br.datapathType),
		}); err != nil {
			return err
		}
		klog.InfoS("Bridge updated", "name", br.name, "uuid", br.uuid)
	} else {
		if err = br.create(); err != nil {
			return err
		}
		klog.InfoS("Bridge created", "name", br.name, "uuid", br.uuid)
	}

	br.isHardwareOffloadEnabled, err = br.getHardwareOffload()
	if err != nil {
		klog.Warning("Failed to get hardware offload: ", err)
		return err
	}
	return nil
}

func (br *OVSBridge) create() Error {
	var err error
	bridge := Bridge{
		// NamedUUID is used to add multiple related Operations in a single Transact operation
		UUID: "bridgeToInsert",
		Name: br.name,
		// Use Openflow protocol version 1.0 and 1.5.
		Protocols:    []string{openflowProtoVersion10, openflowProtoVersion15},
		DatapathType: string(br.datapathType),
	}

	insertOp, err := br.ovsdb.Create(&bridge)
	if err != nil {
		return NewTransactionError(err, false)
	}

	ovsRow := OpenvSwitch{}
	mutateOps, err := br.ovsdb.
		WhereCache(func(_ *OpenvSwitch) bool { return true }).
		Mutate(&ovsRow, libovsdbmodel.Mutation{
			Field:   &ovsRow.Bridges,
			Mutator: libovsdb.MutateOperationInsert,
			Value:   []string{bridge.UUID},
		})
	if err != nil {
		return NewTransactionError(err, false)
	}
	operations := append(insertOp, mutateOps...)
	result, err := br.ovsdb.Transact(context.Background(), operations...)
	if err != nil {
		return NewTransactionError(err, false)
	}

	br.uuid = result[0].UUID.GoUUID
	return nil
}

func (br *OVSBridge) Delete() Error {
	ovsRow := OpenvSwitch{}
	mutateOps, err := br.ovsdb.
		WhereCache(func(_ *OpenvSwitch) bool { return true }).
		Mutate(&ovsRow, libovsdbmodel.Mutation{
			Field:   &ovsRow.Bridges,
			Mutator: libovsdb.MutateOperationDelete,
			Value:   []string{br.uuid},
		})
	if err != nil {
		return NewTransactionError(err, false)
	}
	if _, err = br.ovsdb.Transact(context.TODO(), mutateOps...); err != nil {
		return NewTransactionError(err, false)
	}
	return nil
}

// GetExternalIDs returns the external IDs of the bridge.
func (br *OVSBridge) GetExternalIDs() (map[string]string, Error) {
	bridge := &Bridge{Name: br.name}
	if err := get(br.ovsdb, bridge); err != nil {
		return nil, err
	}
	return bridge.ExternalIDs, nil
}

// SetExternalIDs sets the provided external IDs to the bridge.
func (br *OVSBridge) SetExternalIDs(externalIDs map[string]interface{}) Error {
	return update(br.ovsdb, &Bridge{Name: br.name}, &Bridge{
		ExternalIDs: asMapStrStr(externalIDs),
	})
}

// SetDatapathID sets the provided datapath ID to the bridge.
// If datapath ID is not configured, reconfigure bridge(add/delete port or set different Mac address for local port)
// will change its datapath ID. And the change of datapath ID and interrupt OpenFlow connection.
// See question "My bridge disconnects from my controller on add-port/del-port" in：
// http://openvswitch.org/support/dist-docs-2.5/FAQ.md.html
func (br *OVSBridge) SetDatapathID(datapathID string) Error {
	return update(br.ovsdb, &Bridge{Name: br.name}, &Bridge{
		DatapathID: ptr.To(datapathID),
	})
}

func (br *OVSBridge) GetDatapathID() (string, Error) {
	bridge := &Bridge{Name: br.name}
	if err := get(br.ovsdb, bridge); err != nil {
		return "", err
	}
	return *bridge.DatapathID, nil
}

// GetPortUUIDList returns UUIDs of all ports on the bridge.
func (br *OVSBridge) GetPortUUIDList() ([]string, Error) {
	bridge := &Bridge{Name: br.name}
	if err := get(br.ovsdb, bridge); err != nil {
		return nil, err
	}
	return bridge.Ports, nil
}

// DeletePorts deletes ports in portUUIDList on the bridge
func (br *OVSBridge) DeletePorts(portUUIDList []string) Error {
	if len(portUUIDList) == 0 {
		return nil
	}
	bridge := &Bridge{Name: br.name}
	if err := mutate(br.ovsdb, bridge, libovsdbmodel.Mutation{
		Field:   &bridge.Ports,
		Mutator: libovsdb.MutateOperationDelete,
		Value:   portUUIDList,
	}); err != nil {
		return err
	}
	return nil
}

// DeletePort deletes the port with the provided portUUID.
// If the port does not exist no change will be done.
func (br *OVSBridge) DeletePort(portUUID string) Error {
	return br.DeletePorts([]string{portUUID})
}

// CreateInternalPort creates an internal port with the specified name on the
// bridge.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateInternalPort(name string, ofPortRequest int32, mac string, externalIDs map[string]interface{}) (string, Error) {
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}
	return br.createPort(name, name, "internal", ofPortRequest, 0, mac, externalIDs, nil)
}

// CreateTunnelPort creates a tunnel port with the specified name and type on
// the bridge.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateTunnelPort(name string, tunnelType TunnelType, ofPortRequest int32) (string, Error) {
	return br.createTunnelPort(name, tunnelType, ofPortRequest, false, "", "", "", "", nil, nil)
}

// CreateTunnelPortExt creates a tunnel port with the specified name and type
// on the bridge.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
// If remoteIP is not empty, it will be set to the tunnel port interface
// options; otherwise flow based tunneling will be configured.
// psk is for the pre-shared key of IPsec ESP tunnel. If it is not empty, it
// will be set to the tunnel port interface options. Flow based IPsec tunnel is
// not supported, so remoteIP must be provided too when psk is not empty.
// If externalIDs is not nil, the IDs in it will be added to the port's
// external_ids.
func (br *OVSBridge) CreateTunnelPortExt(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	csum bool,
	localIP string,
	remoteIP string,
	remoteName string,
	psk string,
	extraOptions map[string]interface{},
	externalIDs map[string]interface{}) (string, Error) {
	if psk != "" && remoteIP == "" {
		return "", newInvalidArgumentsError("IPsec tunnel can not be flow based. remoteIP must be set")
	}
	if psk != "" && remoteName != "" {
		return "", newInvalidArgumentsError("Cannot set psk and remoteName together")
	}
	return br.createTunnelPort(name, tunnelType, ofPortRequest, csum, localIP, remoteIP, remoteName, psk, extraOptions, externalIDs)
}

func (br *OVSBridge) createTunnelPort(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	csum bool,
	localIP string,
	remoteIP string,
	remoteName string,
	psk string,
	extraOptions map[string]interface{},
	externalIDs map[string]interface{}) (string, Error) {

	if tunnelType != VXLANTunnel &&
		tunnelType != GeneveTunnel &&
		tunnelType != GRETunnel &&
		tunnelType != STTTunnel &&
		tunnelType != ERSPANTunnel {
		return "", newInvalidArgumentsError("unsupported tunnel type: " + string(tunnelType))
	}
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}

	options := make(map[string]interface{})
	for k, v := range extraOptions {
		options[k] = v
	}

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
	if remoteName != "" {
		options["remote_name"] = remoteName
	}
	if psk != "" {
		options["psk"] = psk
	}
	if csum {
		options["csum"] = "true"
	}

	return br.createPort(name, name, string(tunnelType), ofPortRequest, 0, "", externalIDs, options)
}

// GetInterfaceOptions returns the options of the provided interface.
func (br *OVSBridge) GetInterfaceOptions(name string) (map[string]string, Error) {
	intf := &Interface{Name: name}
	if err := get(br.ovsdb, intf); err != nil {
		return nil, err
	}
	return intf.Options, nil
}

// SetInterfaceOptions sets the specified options of the provided interface.
func (br *OVSBridge) SetInterfaceOptions(name string, options map[string]interface{}) Error {
	return update(br.ovsdb, &Interface{Name: name}, &Interface{
		Options: asMapStrStr(options),
	})
}

// ParseTunnelInterfaceOptions reads remote IP, local IP, IPsec PSK, and csum
// from the tunnel interface options and returns them.
func ParseTunnelInterfaceOptions(portData *OVSPortData) (net.IP, net.IP, int32, string, string, bool) {
	if portData.Options == nil {
		return nil, nil, 0, "", "", false
	}

	var ok bool
	var remoteIPStr, localIPStr, psk, remoteName string
	var remoteIP, localIP net.IP
	var csum bool
	var destinationPort int64

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
	remoteName = portData.Options["remote_name"]
	if destinationPortStr, ok := portData.Options["dst_port"]; ok {
		destinationPort, _ = strconv.ParseInt(destinationPortStr, 10, 32)
	}
	return remoteIP, localIP, int32(destinationPort), psk, remoteName, csum
}

// CreateUplinkPort creates uplink port.
func (br *OVSBridge) CreateUplinkPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error) {
	return br.createPort(name, name, "", ofPortRequest, 0, "", externalIDs, nil)
}

// CreatePort creates a port with the specified name on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
func (br *OVSBridge) CreatePort(name, ifDev string, externalIDs map[string]interface{}) (string, Error) {
	return br.createPort(name, ifDev, "", 0, 0, "", externalIDs, nil)
}

// CreateAccessPort creates a port with the specified name and VLAN ID on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// vlanID=0 will perform same behavior as CreatePort.
func (br *OVSBridge) CreateAccessPort(name, ifDev string, externalIDs map[string]interface{}, vlanID uint16) (string, Error) {
	return br.createPort(name, ifDev, "", 0, vlanID, "", externalIDs, nil)
}

func (br *OVSBridge) createPort(name, ifName, ifType string, ofPortRequest int32, vlanID uint16, mac string, externalIDs, options map[string]interface{}) (string, Error) {
	interf := Interface{
		UUID:    "interfaceToInsert",
		Name:    ifName,
		Type:    ifType,
		Options: asMapStrStr(options),
	}
	if mac != "" {
		interf.MAC = ptr.To(mac)
	}
	if ofPortRequest > 0 {
		interf.OfportRequest = ptr.To(int(ofPortRequest))
	}
	var operations []libovsdb.Operation
	insertOp, err := br.ovsdb.Create(&interf)
	if err != nil {
		return "", NewTransactionError(err, false)
	}
	operations = append(operations, insertOp...)
	port := Port{
		UUID:        "portToInsert",
		Name:        name,
		Interfaces:  []string{"interfaceToInsert"},
		ExternalIDs: asMapStrStr(externalIDs),
	}
	if vlanID > 0 {
		port.Tag = ptr.To(int(vlanID))
	}
	insertOp, err = br.ovsdb.Create(&port)
	if err != nil {
		return "", NewTransactionError(err, false)
	}
	operations = append(operations, insertOp...)

	bridge := Bridge{Name: br.name}
	mutateOps, err := br.ovsdb.
		Where(&bridge).
		Mutate(&bridge, libovsdbmodel.Mutation{
			Field:   &bridge.Ports,
			Mutator: libovsdb.MutateOperationInsert,
			Value:   []string{"portToInsert"},
		})
	if err != nil {
		return "", NewTransactionError(err, false)
	}
	operations = append(operations, mutateOps...)
	if result, err := br.ovsdb.Transact(context.Background(), operations...); err != nil {
		return "", NewTransactionError(err, false)
	} else {
		return result[1].UUID.GoUUID, nil
	}

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
	// If an OVS port is newly created, the ofport field is expected to change from empty to a int value.
	// If an OVS port is updated from invalid status to valid, the ofport field is expected to change from "-1" to a
	// value that is larger than 0.
	var waitOperations []libovsdb.Operation
	var err error
	condAPI := br.ovsdb.Where(&Interface{Name: ifName})
	if waitUntilValid {
		waitOperations, err = condAPI.Wait(
			libovsdb.WaitConditionNotEqual,
			ptr.To(int(defaultGetPortTimeout.Milliseconds())),
			&Interface{Ofport: ptr.To(-1)},
		)
	} else {
		waitOperations, err = condAPI.Wait(
			libovsdb.WaitConditionEqual,
			ptr.To(int(defaultGetPortTimeout.Milliseconds())),
			&Interface{},
		)
	}
	if err != nil {
		return 0, NewTransactionError(err, false)
	}

	_, err = br.ovsdb.Transact(context.TODO(), waitOperations...)
	if err != nil {
		return 0, NewTransactionError(err, false)
	}

	intf := &Interface{Name: ifName}
	if err = get(br.ovsdb, intf); err != nil {
		return 0, NewTransactionError(err, false)
	}

	// ofport value nil means that the interface could not be created due to an error.
	if intf.Ofport == nil || *intf.Ofport <= 0 {
		return 0, NewTransactionError(fmt.Errorf("invalid ofport"), false)
	}
	return int32(*intf.Ofport), nil
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

func buildPortDataCommon(port *Port, intf *Interface, portData *OVSPortData) {
	portData.Name = port.Name
	portData.ExternalIDs = port.ExternalIDs
	if port.Tag != nil {
		portData.VLANID = uint16(*port.Tag)
	}
	portData.Options = intf.Options
	portData.IFType = intf.Type
	if intf.Ofport != nil {
		portData.OFPort = int32(*intf.Ofport)
	}

	if intf.MAC != nil {
		if mac, err := net.ParseMAC(*intf.MAC); err == nil {
			portData.MAC = mac
		}
	}
}

// GetPortData retrieves port data given the OVS port UUID and interface name.
// nil is returned, if the port or interface could not be found, or the
// interface is not attached to the port.
// The port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortData(portUUID, ifName string) (*OVSPortData, Error) {
	port := &Port{UUID: portUUID}
	if err := get(br.ovsdb, port); err != nil {
		return nil, err
	}

	intf := &Interface{Name: ifName}
	if err := get(br.ovsdb, intf); err != nil {
		return nil, err
	}

	found := false
	for _, uuid := range port.Interfaces {
		if uuid == intf.UUID {
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
	bridge := &Bridge{Name: br.name}
	if err := get(br.ovsdb, bridge); err != nil {
		klog.Warning("Could not find bridge")
		return []OVSPortData{}, nil
	}

	portMap := br.ovsdb.Cache().Table(TableNamePort).Rows()
	ifMap := br.ovsdb.Cache().Table(TableNameInterface).Rows()

	portList := make([]OVSPortData, len(bridge.Ports))
	for i, uuid := range bridge.Ports {
		portList[i].UUID = uuid
		port := portMap[uuid].(*Port)
		ifUUIDList := port.Interfaces
		// Port should have one interface
		intf := ifMap[ifUUIDList[0]].(*Interface)
		portList[i].IFName = intf.Name
		buildPortDataCommon(port, intf, &portList[i])
	}
	return portList, nil
}

// AllocateOFPort returns an OpenFlow port number which is not allocated or used by any existing OVS port. Note that,
// the returned port number is cached locally but not saved in OVSDB yet before the real port is created, so it might
// introduce an issue of conflict if the OFPort is occupied by another port creation.
func (br *OVSBridge) AllocateOFPort(startPort int) (int32, error) {
	existingOFPorts := sets.New[int32]()
	for _, allocatedOFPort := range br.allocatedOFPorts {
		existingOFPorts.Insert(allocatedOFPort)
	}
	ports, err := br.GetPortList()
	if err != nil {
		return 0, err
	}
	for _, p := range ports {
		existingOFPorts.Insert(p.OFPort)
	}
	port := int32(startPort)
	for ; ; port++ {
		if !existingOFPorts.Has(port) {
			break
		}
	}
	br.allocatedOFPorts = append(br.allocatedOFPorts, port)
	return port, nil
}

// GetOVSVersion either returns the version of OVS, or an error.
func (br *OVSBridge) GetOVSVersion() (string, Error) {
	ovs := &OpenvSwitch{}
	if err := get(br.ovsdb, ovs); err != nil {
		return "", err
	}
	return *ovs.OVSVersion, nil
}

// AddOVSOtherConfig adds the given configs to the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddOVSOtherConfig(configs map[string]interface{}) Error {
	ovs := &OpenvSwitch{}
	return mutate(br.ovsdb, ovs, libovsdbmodel.Mutation{
		Field:   &ovs.OtherConfig,
		Mutator: libovsdb.MutateOperationInsert,
		Value:   asMapStrStr(configs),
	})
}

func (br *OVSBridge) GetOVSOtherConfig() (map[string]string, Error) {
	ovs := &OpenvSwitch{}
	if err := get(br.ovsdb, ovs); err != nil {
		return nil, err
	}
	return ovs.OtherConfig, nil
}

// UpdateOVSOtherConfig updates the given configs to the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will be updated if the existing value does not match the given one,
// and it will be added if its key does not exist.
// It the configs are already up to date, this function will be a no-op.
func (br *OVSBridge) UpdateOVSOtherConfig(configs map[string]interface{}) Error {
	var keysToDelete []string
	for key, _ := range configs {
		keysToDelete = append(keysToDelete, key)
	}

	var mutations []libovsdbmodel.Mutation
	ovs := &OpenvSwitch{}
	if len(keysToDelete) > 0 {
		mutations = append(mutations, libovsdbmodel.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: libovsdb.MutateOperationDelete,
			Value:   keysToDelete,
		})
	}
	if len(configs) > 0 {
		mutations = append(mutations, libovsdbmodel.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: libovsdb.MutateOperationInsert,
			Value:   asMapStrStr(configs),
		})
	}
	if len(mutations) > 0 {
		return mutate(br.ovsdb, ovs, mutations...)
	}
	return nil
}

// DeleteOVSOtherConfig deletes the given configs from the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will be deleted if its key exists and the given value is empty string or
// its value matches the given one. No error is returned if configs don't exist or don't match.
func (br *OVSBridge) DeleteOVSOtherConfig(configs map[string]interface{}) Error {
	var keysToDelete []string
	configsToDelete := make(map[string]string)

	for key, val := range configs {
		v := val.(string)
		if v == "" {
			keysToDelete = append(keysToDelete, key)
		} else {
			configsToDelete[key] = v
		}
	}

	var mutations []libovsdbmodel.Mutation
	ovs := &OpenvSwitch{}
	if len(keysToDelete) > 0 {
		mutations = append(mutations, libovsdbmodel.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: libovsdb.MutateOperationDelete,
			Value:   keysToDelete,
		})
	}
	if len(configsToDelete) > 0 {
		mutations = append(mutations, libovsdbmodel.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: libovsdb.MutateOperationDelete,
			Value:   configsToDelete,
		})
	}
	if len(mutations) > 0 {
		return mutate(br.ovsdb, ovs, mutations...)
	}
	return nil
}

// AddBridgeOtherConfig adds the given configs to the "other_config" column of
// the single record in the "Bridge" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddBridgeOtherConfig(configs map[string]interface{}) Error {
	if len(configs) > 0 {
		bridge := &Bridge{Name: br.name}
		return mutate(br.ovsdb, bridge, libovsdbmodel.Mutation{
			Field:   &bridge.OtherConfig,
			Mutator: libovsdb.MutateOperationInsert,
			Value:   asMapStrStr(configs),
		})
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
	return update(br.ovsdb, &Interface{Name: name}, &Interface{
		Type: ifType,
	})
}

func (br *OVSBridge) SetPortExternalIDs(name string, externalIDs map[string]interface{}) Error {
	return update(br.ovsdb, &Port{Name: name}, &Port{
		ExternalIDs: asMapStrStr(externalIDs),
	})
}

func (br *OVSBridge) SetInterfaceMTU(name string, MTU int) error {
	return update(br.ovsdb, &Interface{Name: name}, &Interface{
		MTU: ptr.To(MTU),
	})
}

func (br *OVSBridge) SetInterfaceMAC(name string, mac net.HardwareAddr) Error {
	return update(br.ovsdb, &Interface{Name: name}, &Interface{
		MAC: ptr.To(mac.String()),
	})
}

func mutate(client libovsdbclient.Client, whereModel libovsdbmodel.Model, mutations ...libovsdbmodel.Mutation) Error {
	var cond libovsdbclient.ConditionalAPI

	switch whereModel.(type) {
	case *OpenvSwitch:
		cond = client.WhereCache(func(_ *OpenvSwitch) bool { return true })
	case *Bridge, *Port, *Interface:
		cond = client.Where(whereModel)
	}

	mutateOps, err := cond.Mutate(whereModel, mutations...)
	if err != nil {
		klog.ErrorS(err, "Failed to generate mutation operations")
		return NewTransactionError(err, false)
	}
	if _, err = client.Transact(context.TODO(), mutateOps...); err != nil {
		klog.ErrorS(err, "Failed to mutate model")
		return NewTransactionError(err, false)
	}
	return nil
}

func update(client libovsdbclient.Client, whereModel, updateModel libovsdbmodel.Model) Error {
	var cond libovsdbclient.ConditionalAPI

	switch whereModel.(type) {
	case *OpenvSwitch:
		cond = client.WhereCache(func(_ *OpenvSwitch) bool { return true })
	case *Bridge, *Port, *Interface:
		cond = client.Where(whereModel)
	}

	updateOps, err := cond.Update(updateModel)
	if err != nil {
		klog.ErrorS(err, "Failed to generate update operations")
		return NewTransactionError(err, false)
	}

	if _, err = client.Transact(context.TODO(), updateOps...); err != nil {
		klog.ErrorS(err, "Failed to update model")
		return NewTransactionError(err, false)
	}
	return nil
}

func get(client libovsdbclient.Client, model libovsdbmodel.Model) Error {
	var err error
	switch model.(type) {
	case *OpenvSwitch:
		var res []*OpenvSwitch
		if err = client.List(context.TODO(), &res); err != nil {
			klog.ErrorS(err, "Failed to list models")
			return NewTransactionError(err, false)
		}

		// update underlying concrete class
		if _, ok := model.(*OpenvSwitch); ok {
			fromValue := reflect.ValueOf(res[0]).Elem()
			toValue := reflect.ValueOf(model).Elem()
			for i := 0; i < toValue.NumField(); i++ {
				toValue.Field(i).Set(fromValue.Field(i))
			}
		}
		model = res[0]
	case *Bridge, *Interface, *Port:
		if err = client.Get(context.TODO(), model); err != nil {
			klog.ErrorS(err, "Failed to get model")
			return NewTransactionError(err, false)
		}
	}
	return nil
}

func asMapStrStr(in map[string]interface{}) map[string]string {
	out := make(map[string]string)
	for k, v := range in {
		out[k] = v.(string)
	}
	return out
}
