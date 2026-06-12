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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"k8s.io/klog/v2"
)

const defaultOVSDBFile = "db.sock"

type OVSBridge struct {
	ovsdb                    client.Client
	name                     string
	datapathType             OVSDatapathType
	mcastSnoopingEnable      bool
	uuid                     string
	isHardwareOffloadEnabled bool
	requiredPortExternalIDs  []string
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
	OpenvSwitchTable = "Open_vSwitch"
	bridgeTable      = "Bridge"
	portTable        = "Port"
	interfaceTable   = "Interface"

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
// If address is set to "", the default OVSDB socket path or named pipe will be used.
// Returns the OVSDB client on success.
func NewOVSDBConnectionUDS(ctx context.Context, address string) (client.Client, Error) {
	klog.InfoS("Connecting to OVSDB at address", "address", address)

	var endpoint string
	if address == "" {
		endpoint = defaultConnNetwork + ":" + GetConnAddress(DefaultOVSRunDir)
	} else {
		endpoint = defaultConnNetwork + ":" + address
	}

	dbModel, err := model.NewClientDBModel(OpenvSwitchTable, map[string]model.Model{
		OpenvSwitchTable: &OpenvSwitch{},
		bridgeTable:      &Bridge{},
		portTable:        &Port{},
		interfaceTable:   &Interface{},
	})
	if err != nil {
		return nil, newInvalidArgumentsError(err.Error())
	}
	db, err := client.NewOVSDBClient(dbModel,
		client.WithEndpoint(endpoint),
		client.WithReconnect(2*time.Second, backoff.NewConstantBackOff(1*time.Second)))
	if err != nil {
		return nil, newInvalidArgumentsError(err.Error())
	}

	// We use a synchronous retry loop for the initial connection instead of a background
	// asynchronous dial. This has several advantages:
	// 1. Prevents Race Conditions: By returning only when the connection is truly established,
	//    we guarantee that callers (like the Agent initialization) receive a ready-to-use DB handle,
	//    avoiding unexpected timeouts or failures on their first queries.
	// 2. Enables Immediate Cache Sync: A successful connection is a prerequisite for calling
	//    MonitorAll(), which populates our local in-memory cache and makes subsequent Get/List
	//    operations extremely fast and network-free.
	// 3. Reliable Reconnections: Once the initial connection is established, libovsdb's
	//    WithReconnect option automatically handles any future transient network disconnects
	//    or OVS restarts in the background.
	const maxBackoffTime = 8 * time.Second
	retryBackoff := 2 * time.Second
	for {
		connCtx, cancel := context.WithTimeout(ctx, retryBackoff)
		err = db.Connect(connCtx)
		cancel()
		if err == nil {
			break
		}

		klog.InfoS("Not connected yet", "error", err, "retryBackoff", retryBackoff)
		select {
		case <-ctx.Done():
			db.Close()
			return nil, NewTransactionError(ctx.Err(), true)
		case <-time.After(retryBackoff):
		}

		retryBackoff *= 2
		if retryBackoff > maxBackoffTime {
			retryBackoff = maxBackoffTime
		}
	}

	// MonitorAll initiates the OVSDB monitor protocol on all tables configured in the ClientDBModel.
	// This performs the crucial task of downloading the current state of the database and keeping
	// a local in-memory cache synchronized with the OVSDB server in real-time.
	// As a result, subsequent read operations (like Get and List) can be served instantly from
	// the local cache without incurring any network or RPC overhead.
	if _, err = db.MonitorAll(ctx); err != nil {
		db.Close()
		return nil, NewTransactionError(err, isTemporaryError(err))
	}

	return db, nil
}

type OVSBridgeOption func(*OVSBridge)

func WithRequiredPortExternalIDs(keys ...string) OVSBridgeOption {
	return func(br *OVSBridge) {
		br.requiredPortExternalIDs = append(br.requiredPortExternalIDs, keys...)
	}
}

func WithMcastSnooping() OVSBridgeOption {
	return func(br *OVSBridge) {
		br.mcastSnoopingEnable = true
	}
}

// NewOVSBridge creates and returns a new OVSBridge struct.
func NewOVSBridge(bridgeName string, ovsDatapathType OVSDatapathType, ovsdb client.Client, options ...OVSBridgeOption) OVSBridgeClient {
	br := &OVSBridge{
		ovsdb:        ovsdb,
		name:         bridgeName,
		datapathType: ovsDatapathType,
	}
	for _, option := range options {
		option(br)
	}
	return br
}

// Create looks up or creates the bridge. If the bridge with name bridgeName
// does not exist, it will be created. Openflow protocol version 1.0 and 1.5
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
		klog.ErrorS(err, "Failed to get hardware offload")
	}
	return nil
}

func (br *OVSBridge) lookupByName() (bool, Error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return false, nil
		}
		return false, NewTransactionError(err, isTemporaryError(err))
	}

	br.uuid = bridge.UUID
	return true, nil
}

func (br *OVSBridge) updateBridgeConfiguration() Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Bridge record.
	bridge, err := br.getBridge(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}
	// Use Openflow protocol version 1.0 and 1.5.
	bridge.Protocols = []string{openflowProtoVersion10, openflowProtoVersion15}
	bridge.DatapathType = string(br.datapathType)
	bridge.McastSnoopingEnable = br.mcastSnoopingEnable

	// Construct an update operation for the Bridge. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Update(
		bridge,
		&bridge.Protocols,
		&bridge.DatapathType,
		&bridge.McastSnoopingEnable,
	)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "update bridge configuration")
}

func (br *OVSBridge) create() Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Generate a "named-uuid" to insert the new Bridge record. This temporary ID allows us
	// to reference the uncommitted Bridge in other operations within the same atomic transaction.
	bridge := &Bridge{
		UUID: namedUUID(),
		Name: br.name,
		// Use Openflow protocol version 1.0 and 1.5.
		Protocols:           []string{openflowProtoVersion10, openflowProtoVersion15},
		DatapathType:        string(br.datapathType),
		McastSnoopingEnable: br.mcastSnoopingEnable,
	}
	ops, err := br.ovsdb.Create(bridge)
	if err != nil {
		klog.ErrorS(err, "Failed to construct create operation for bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}

	// Fetch the root Open_vSwitch table.
	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	// Update the root Open_vSwitch table to reference the newly created Bridge's named-uuid.
	// This linkage must be established in the same atomic transaction to prevent the OVSDB server
	// from garbage collecting the newly created Bridge.
	mutation := model.Mutation{
		Field:   &ovs.Bridges,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{ops[0].UUIDName},
	}
	ops2, err := br.ovsdb.Where(&OpenvSwitch{UUID: ovs.UUID}).Mutate(ovs, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Open_vSwitch", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	ops = append(ops, ops2...)

	// Submit the batched operations in a single atomic transaction. Once successful, OVSDB will
	// resolve the named-uuid to a real physical UUID and return it.
	res, err := br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.ErrorS(err, "Failed to execute transaction to create bridge", "bridge", br.name)
		return NewTransactionError(err, isTemporaryError(err))
	}

	br.uuid = res[0].UUID.GoUUID
	return nil
}

func (br *OVSBridge) Delete() Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Construct a delete operation to remove the Bridge record with the matching UUID.
	bridge := &Bridge{UUID: br.uuid, Name: br.name}
	ops, err := br.ovsdb.Where(bridge).Delete()
	if err != nil {
		klog.ErrorS(err, "Failed to construct delete operations for bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}

	// Fetch the root Open_vSwitch table.
	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	// Update the root Open_vSwitch table to remove the reference to this Bridge.
	// This linkage cleanup is necessary to keep the 'bridges' reference list consistent in OVSDB.
	mutation := model.Mutation{
		Field:   &ovs.Bridges,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{br.uuid},
	}
	ops2, err := br.ovsdb.Where(&OpenvSwitch{UUID: ovs.UUID}).Mutate(ovs, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Open_vSwitch", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	ops = append(ops2, ops...)

	// Submit the batched operations in a single atomic transaction to safely delete the bridge.
	return br.transact(ctx, ops, "delete bridge")
}

// GetExternalIDs returns the external IDs of the bridge.
func (br *OVSBridge) GetExternalIDs() (map[string]string, Error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}

	return bridge.ExternalIDs, nil
}

// SetExternalIDs sets the provided external IDs to the bridge.
func (br *OVSBridge) SetExternalIDs(externalIDs map[string]interface{}) Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Bridge record.
	bridge, err := br.getBridge(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	bridge.ExternalIDs, err = toStringMap(externalIDs)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}

	// Construct an update operation for the Bridge. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Update(bridge, &bridge.ExternalIDs)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction to set external IDs.
	return br.transact(ctx, ops, "set external IDs")
}

// SetDatapathID sets the provided datapath ID to the bridge.
// If datapath ID is not configured, reconfigure bridge(add/delete port or set different Mac address for local port)
// will change its datapath ID. And the change of datapath ID and interrupt OpenFlow connection.
// See question "My bridge disconnects from my controller on add-port/del-port" in：
// http://openvswitch.org/support/dist-docs-2.5/FAQ.md.html
func (br *OVSBridge) SetDatapathID(datapathID string) Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Bridge record.
	bridge, err := br.getBridge(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	if bridge.OtherConfig == nil {
		bridge.OtherConfig = make(map[string]string)
	}
	bridge.OtherConfig[OVSOtherConfigDatapathIDKey] = datapathID

	// Construct an update operation for the Bridge. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Update(bridge, &bridge.OtherConfig)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}

	// Submit the batched operations in a single atomic transaction to set datapath ID.
	return br.transact(ctx, ops, "set datapath ID")
}

func (br *OVSBridge) GetDatapathID() (string, Error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		return "", NewTransactionError(err, isTemporaryError(err))
	}
	if bridge.DatapathID == nil {
		return "", nil
	}
	return *bridge.DatapathID, nil
}

func (br *OVSBridge) WaitForDatapathID(timeout time.Duration) (string, Error) {
	// TODO: use ctx from parent context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return "", NewTransactionError(fmt.Errorf("timeout waiting for datapath_id"), true)
		default:
		}

		bridge, err := br.getBridge(ctx)
		if err != nil {
			return "", NewTransactionError(err, isTemporaryError(err))
		}

		if bridge.DatapathID != nil && *bridge.DatapathID != "" {
			return *bridge.DatapathID, nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// GetPortUUIDList returns UUIDs of all ports on the bridge.
func (br *OVSBridge) GetPortUUIDList() ([]string, Error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}
	return bridge.Ports, nil
}

// DeletePorts deletes ports in portUUIDList on the bridge
func (br *OVSBridge) DeletePorts(portUUIDList []string) Error {
	if len(portUUIDList) == 0 {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	bridge := &Bridge{UUID: br.uuid}
	mutation := model.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   portUUIDList,
	}
	ops, err := br.ovsdb.Where(bridge).Mutate(bridge, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}

	return br.transact(ctx, ops, "delete ports")
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
	// TODO: use ctx from parent context
	intf, err := br.getInterface(context.TODO(), name)
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}
	return intf.Options, nil
}

// SetInterfaceOptions sets the specified options of the provided interface.
func (br *OVSBridge) SetInterfaceOptions(name string, options map[string]interface{}) Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	intf.Options, err = toStringMap(options)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}

	// Construct an update operation for the Interface. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf, &intf.Options)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for interface", "interface", name)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "set interface options")
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
	// TODO: use ctx from parent context
	ctx := context.TODO()

	for _, id := range br.requiredPortExternalIDs {
		if _, ok := externalIDs[id]; !ok {
			return "", newInvalidArgumentsError(fmt.Sprintf("missing required externalID '%s' for port '%s'", id, name))
		}
	}

	intf := &Interface{
		UUID: namedUUID(),
		Name: ifName,
		Type: ifType,
	}
	if mac != "" {
		intf.MAC = &mac
	}
	if ofPortRequest != 0 {
		ofp := int(ofPortRequest)
		intf.OFPortRequest = &ofp
	}
	if options != nil {
		var err error
		intf.Options, err = toStringMap(options)
		if err != nil {
			return "", newInvalidArgumentsError(err.Error())
		}
	}

	// Construct a create operation for the new Interface.
	ops, err := br.ovsdb.Create(intf)
	if err != nil {
		klog.ErrorS(err, "Failed to construct create operation for interface", "interface", ifName)
		return "", newInvalidArgumentsError(err.Error())
	}
	ifNamedUUID := ops[0].UUIDName

	port := &Port{
		UUID:       namedUUID(),
		Name:       name,
		Interfaces: []string{ifNamedUUID},
	}
	if externalIDs != nil {
		port.ExternalIDs, err = toStringMap(externalIDs)
		if err != nil {
			return "", newInvalidArgumentsError(err.Error())
		}
	}
	if vlanID > 0 {
		tag := int(vlanID)
		port.Tag = &tag
	}

	// Construct a create operation for the new Port, linking it to the Interface.
	ops2, err := br.ovsdb.Create(port)
	if err != nil {
		klog.ErrorS(err, "Failed to construct create operation for port", "port", name)
		return "", newInvalidArgumentsError(err.Error())
	}
	ops = append(ops, ops2...)
	portNamedUUID := ops2[0].UUIDName

	bridge := &Bridge{UUID: br.uuid}
	mutation := model.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{portNamedUUID},
	}
	// Update the Bridge record to include the newly created Port.
	ops3, err := br.ovsdb.Where(bridge).Mutate(bridge, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for bridge", "bridge", br.name)
		return "", newInvalidArgumentsError(err.Error())
	}
	ops = append(ops, ops3...)

	// Submit the batched operations in a single atomic transaction.
	// We cannot use transact() helper here because we need the returned UUID
	// of the newly created interface and port.
	res, err := br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.ErrorS(err, "Failed to execute transaction to create port", "port", name)
		return "", NewTransactionError(err, isTemporaryError(err))
	}

	return res[1].UUID.GoUUID, nil
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
	// TODO: use ctx from parent context
	ctx, cancel := context.WithTimeout(context.Background(), defaultGetPortTimeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return 0, NewTransactionError(fmt.Errorf("timeout waiting for ofport for %s", ifName), true)
		default:
		}

		intf, err := br.getInterface(ctx, ifName)
		if err != nil {
			return 0, NewTransactionError(err, isTemporaryError(err))
		}

		if intf.OFPort != nil {
			ofport := *intf.OFPort
			if waitUntilValid {
				if ofport > 0 {
					return int32(ofport), nil
				}
			} else {
				if ofport > 0 {
					return int32(ofport), nil
				} else if ofport < 0 {
					return 0, NewTransactionError(fmt.Errorf("invalid ofport %d", ofport), false)
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func buildPortDataCommon(port *Port, intf *Interface, portData *OVSPortData) {
	portData.Name = port.Name
	portData.ExternalIDs = port.ExternalIDs
	if port.Tag != nil {
		portData.VLANID = uint16(*port.Tag)
	}
	portData.Options = intf.Options
	portData.IFType = intf.Type
	if intf.OFPort != nil {
		portData.OFPort = int32(*intf.OFPort)
	} else { // ofport not assigned by OVS yet
		portData.OFPort = 0
	}
	if intf.MAC != nil && *intf.MAC != "" {
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
	// TODO: use ctx from parent context
	ctx := context.TODO()

	port, err := br.getPort(ctx, "", portUUID)
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}

	intf, err := br.getInterface(ctx, ifName)
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}

	found := false
	for _, uuid := range port.Interfaces {
		if uuid == intf.UUID {
			found = true
			break
		}
	}
	if !found {
		return nil, NewTransactionError(fmt.Errorf("interface %s not attached to port %s", ifName, portUUID), false)
	}

	portData := OVSPortData{UUID: portUUID, IFName: ifName}
	buildPortDataCommon(port, intf, &portData)
	return &portData, nil
}

// GetPortList returns all ports on the bridge.
// A port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortList() ([]OVSPortData, Error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the target Bridge record to get the exact list of port UUIDs it owns.
	bridge, err := br.getBridge(ctx)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			klog.InfoS("Could not find bridge", "bridge", br.name)
			return []OVSPortData{}, nil
		}
		return nil, NewTransactionError(err, isTemporaryError(err))
	}

	// Bulk fetch all Port records from the database in a single query.
	var ports []Port
	if err := br.ovsdb.List(ctx, &ports); err != nil {
		klog.ErrorS(err, "Failed to list Port table", "bridge", br.name)
		return nil, NewTransactionError(err, isTemporaryError(err))
	}
	// Build an in-memory index of all Ports by UUID for fast lookup.
	portMap := make(map[string]*Port)
	for i := range ports {
		portMap[ports[i].UUID] = &ports[i]
	}

	// Bulk fetch all Interface records from the database in a single query.
	var intfs []Interface
	if err := br.ovsdb.List(ctx, &intfs); err != nil {
		klog.ErrorS(err, "Failed to list Interface table", "bridge", br.name)
		return nil, NewTransactionError(err, isTemporaryError(err))
	}
	// Build an in-memory index of all Interfaces by UUID for fast lookup.
	intfMap := make(map[string]*Interface)
	for i := range intfs {
		intfMap[intfs[i].UUID] = &intfs[i]
	}

	// Assemble the result by iterating only over the ports belonging to this bridge.
	portList := make([]OVSPortData, 0, len(bridge.Ports))
	for _, portUUID := range bridge.Ports {
		// Look up the port from the in-memory map.
		port, ok := portMap[portUUID]
		if !ok {
			klog.InfoS("Failed to get port", "port", portUUID)
			continue
		}
		if len(port.Interfaces) == 0 {
			continue
		}
		// Look up the corresponding interface from the in-memory map.
		intf, ok := intfMap[port.Interfaces[0]]
		if !ok {
			klog.InfoS("Failed to get interface", "interface", port.Interfaces[0])
			continue
		}

		// Construct the final OVSPortData from the retrieved Port and Interface records.
		portData := OVSPortData{UUID: portUUID, IFName: intf.Name}
		buildPortDataCommon(port, intf, &portData)
		portList = append(portList, portData)
	}

	return portList, nil
}

// GetOVSVersion either returns the version of OVS, or an error.
func (br *OVSBridge) GetOVSVersion() (string, Error) {
	// TODO: use ctx from parent context
	ovs, err := br.getOpenvSwitch(context.TODO())
	if err != nil {
		return "", NewTransactionError(err, isTemporaryError(err))
	}

	if ovs.OvsVersion != nil {
		return *ovs.OvsVersion, nil
	}
	return "", nil
}

// AddOVSOtherConfig adds the given configs to the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddOVSOtherConfig(configs map[string]interface{}) Error {
	if len(configs) == 0 {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the root Open_vSwitch table.
	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	mutateMap, err := toStringMap(configs)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}
	mutation := model.Mutation{
		Field:   &ovs.OtherConfig,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   mutateMap,
	}
	// Construct a mutate operation for the Open_vSwitch record.
	ops, err := br.ovsdb.Where(&OpenvSwitch{UUID: ovs.UUID}).Mutate(ovs, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Open_vSwitch", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "add OVS other config")
}

func (br *OVSBridge) GetOVSOtherConfig() (map[string]string, Error) {
	// TODO: use ctx from parent context
	ovs, err := br.getOpenvSwitch(context.TODO())
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}
	return ovs.OtherConfig, nil
}

// UpdateOVSOtherConfig updates the given configs to the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will be updated if the existing value does not match the given one,
// and it will be added if its key does not exist.
// It the configs are already up to date, this function will be a no-op.
func (br *OVSBridge) UpdateOVSOtherConfig(configs map[string]interface{}) Error {
	if len(configs) == 0 {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the root Open_vSwitch table.
	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	mutateMap, err := toStringMap(configs)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}
	var keys []string
	for k := range mutateMap {
		keys = append(keys, k)
	}
	mutations := []model.Mutation{
		{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   keys,
		},
		{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   mutateMap,
		},
	}
	// Construct a mutate operation for the Open_vSwitch record.
	ops, err := br.ovsdb.Where(&OpenvSwitch{UUID: ovs.UUID}).Mutate(ovs, mutations...)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "update OVS other config")
}

// DeleteOVSOtherConfig deletes the given configs from the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will be deleted if its key exists and the given value is empty string or
// its value matches the given one. No error is returned if configs don't exist or don't match.
func (br *OVSBridge) DeleteOVSOtherConfig(configs map[string]interface{}) Error {
	if len(configs) == 0 {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the root Open_vSwitch table.
	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	if ovs.OtherConfig == nil {
		return nil
	}

	stringConfigs, err := toStringMap(configs)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}
	var deleteList []string
	deleteMap := make(map[string]string)
	for k, val := range stringConfigs {
		if val == "" {
			deleteList = append(deleteList, k)
		} else {
			deleteMap[k] = val
		}
	}

	var mutations []model.Mutation
	if len(deleteList) > 0 {
		mutations = append(mutations, model.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   deleteList,
		})
	}
	if len(deleteMap) > 0 {
		mutations = append(mutations, model.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   deleteMap,
		})
	}

	// Construct a mutate operation for the Open_vSwitch record.
	ops, err := br.ovsdb.Where(&OpenvSwitch{UUID: ovs.UUID}).Mutate(ovs, mutations...)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Openv_Switch", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "delete OVS other config")
}

// AddBridgeOtherConfig adds the given configs to the "other_config" column of
// the single record in the "Bridge" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddBridgeOtherConfig(configs map[string]interface{}) Error {
	if len(configs) == 0 {
		return nil
	}
	mutateMap, err := toStringMap(configs)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}

	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Bridge record.
	bridge, err := br.getBridge(ctx)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	mutation := model.Mutation{
		Field:   &bridge.OtherConfig,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   mutateMap,
	}
	// Construct a mutate operation for the Bridge record.
	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Mutate(bridge, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Bridge", "bridge", br.name)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "add Bridge other config")
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
	// TODO: use ctx from parent context
	ctx := context.TODO()

	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	intf.Type = ifType
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf, &intf.Type)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Interface", "interface", name)
		return newInvalidArgumentsError(err.Error())
	}

	return br.transact(ctx, ops, "set interface type")
}

func (br *OVSBridge) SetPortExternalIDs(portName string, externalIDs map[string]interface{}) Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Port record.
	port, err := br.getPort(ctx, portName, "")
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	port.ExternalIDs, err = toStringMap(externalIDs)
	if err != nil {
		return newInvalidArgumentsError(err.Error())
	}

	// Construct an update operation for the Port. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Port{UUID: port.UUID}).Update(port, &port.ExternalIDs)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Port", "port", portName)
		return newInvalidArgumentsError(err.Error())
	}
	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "set port external IDs")
}

func (br *OVSBridge) GetPortExternalIDs(portName string) (map[string]string, Error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	port, err := br.getPort(ctx, portName, "")
	if err != nil {
		return nil, NewTransactionError(err, isTemporaryError(err))
	}

	return port.ExternalIDs, nil
}

func (br *OVSBridge) SetInterfaceMTU(name string, MTU int) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Interface record.
	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return err
	}

	mtu := MTU
	intf.MTURequest = &mtu
	// Construct an update operation for the Interface. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf, &intf.MTURequest)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Interface", "interface", name)
		return newInvalidArgumentsError(err.Error())
	}

	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "set interface MTU")
}

func (br *OVSBridge) SetInterfaceMAC(name string, mac net.HardwareAddr) Error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the Interface record.
	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return NewTransactionError(err, isTemporaryError(err))
	}

	macStr := mac.String()
	intf.MAC = &macStr
	// Construct an update operation for the Interface. By default, all the non-default values contained in model will be
	// updated. Optional fields can be passed (pointer to fields in the model) to select the fields to be updated.
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf, &intf.MAC)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Interface", "interface", name)
		return newInvalidArgumentsError(err.Error())
	}

	// Submit the batched operations in a single atomic transaction.
	return br.transact(ctx, ops, "set interface MAC")

}

func (br *OVSBridge) GetBridgeMcastSnoopingEnable() (bool, Error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	bridge, err := br.getBridge(ctx)
	if err != nil {
		return false, NewTransactionError(err, isTemporaryError(err))
	}

	return bridge.McastSnoopingEnable, nil
}

// isTemporaryError dynamically analyzes a libovsdb or network error to determine
// if it represents a transient/temporary issue that is safe to retry.
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// If it's libovsdb's ErrNotConnected, it's transient
	if errors.Is(err, client.ErrNotConnected) {
		return true
	}

	// If it's a context timeout or cancellation, it's transient
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	// If it's a network layer error (e.g. refused connection, connection reset)
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// Fallback: parse string representation for transient network errors
	errMsg := strings.ToLower(err.Error())
	temporaryKeywords := []string{
		"timed out",
		"deadline exceeded",
		"connection refused",
		"connection reset",
		"broken pipe",
		"not connected",
		"i/o timeout",
	}
	for _, kw := range temporaryKeywords {
		if strings.Contains(errMsg, kw) {
			return true
		}
	}

	return false
}

// namedUUID generates a temporary named-uuid for inserting uncommitted records
// into OVSDB within an atomic transaction.
func namedUUID() string {
	u, err := uuid.NewV4()
	if err != nil {
		return fmt.Sprintf("row%d", time.Now().UnixNano())
	}
	return "row" + strings.ReplaceAll(u.String(), "-", "")
}

// getOpenvSwitch is a helper function to fetch the root Open_vSwitch record from OVSDB.
// It logs an error and returns it if the record cannot be found or another error occurs.
func (br *OVSBridge) getOpenvSwitch(ctx context.Context) (*OpenvSwitch, error) {
	var ovsList []OpenvSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			klog.ErrorS(err, "Failed to list Open_vSwitch table", "bridge", br.name)
		} else {
			klog.V(4).InfoS("Open_vSwitch table not found", "bridge", br.name)
		}
		return nil, err
	}
	if len(ovsList) == 0 {
		err = fmt.Errorf("Open_vSwitch record not found")
		klog.ErrorS(err, "Failed to find the root Open_vSwitch record", "bridge", br.name)
		return nil, err
	}
	return &ovsList[0], nil
}

// getBridge is a helper function to fetch the Bridge record from OVSDB.
// It logs an error and returns it if the bridge cannot be found or another error occurs.
func (br *OVSBridge) getBridge(ctx context.Context) (*Bridge, error) {
	bridge := &Bridge{Name: br.name}
	err := br.ovsdb.Get(ctx, bridge)
	if err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			klog.ErrorS(err, "Failed to get bridge", "bridge", br.name)
		} else {
			klog.V(4).InfoS("Bridge not found", "bridge", br.name)
		}
		return nil, err
	}
	return bridge, nil
}

// getPort is a helper function to fetch the Port record from OVSDB.
// It logs an error and returns it if the port cannot be found or another error occurs.
func (br *OVSBridge) getPort(ctx context.Context, name, uuid string) (*Port, error) {
	port := &Port{UUID: uuid, Name: name}
	err := br.ovsdb.Get(ctx, port)
	if err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			klog.ErrorS(err, "Failed to get port", "portName", name, "portUUID", uuid)
		} else {
			klog.V(4).InfoS("Port not found", "portName", name, "portUUID", uuid)
		}
		return nil, err
	}
	return port, nil
}

// getInterface is a helper function to fetch the Interface record from OVSDB.
// It logs an error and returns it if the interface cannot be found or another error occurs.
func (br *OVSBridge) getInterface(ctx context.Context, name string) (*Interface, error) {
	intf := &Interface{Name: name}
	err := br.ovsdb.Get(ctx, intf)
	if err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			klog.ErrorS(err, "Failed to get interface", "interface", name)
		} else {
			klog.V(4).InfoS("Interface not found", "interface", name)
		}
		return nil, err
	}
	return intf, nil
}

// toStringMap is a helper function to convert a map[string]interface{} to a map[string]string.
// It returns an error if any value in the input map is not a string.
func toStringMap(in map[string]interface{}) (map[string]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		val, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for %s: expected string, got %T", k, v)
		}
		out[k] = val
	}
	return out, nil
}

// transact is a helper function to execute an OVSDB transaction, log any error
// with the provided action description, and wrap it into a proper custom Error.
func (br *OVSBridge) transact(ctx context.Context, ops []ovsdb.Operation, action string) Error {
	_, err := br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.ErrorS(err, fmt.Sprintf("Failed to execute transaction to %s", action), "bridge", br.name)
		return NewTransactionError(err, isTemporaryError(err))
	}
	return nil
}
