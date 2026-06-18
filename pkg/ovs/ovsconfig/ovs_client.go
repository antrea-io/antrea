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
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

const (
	defaultOVSDBFile = "db.sock"

	// We use the "unix" scheme here because the underlying libovsdb client handles
	// it transparently across platforms: it connects to a Unix domain socket on
	// Linux, and to a named pipe (via go-winio) on Windows.
	defaultConnNetwork = "unix"
)

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
	openvSwitchTable = "Open_vSwitch"
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
func NewOVSDBConnectionUDS(ctx context.Context, address string) (client.Client, error) {
	klog.InfoS("Connecting to OVSDB at address", "address", address)

	var endpoint string
	if address == "" {
		endpoint = defaultConnNetwork + ":" + GetConnAddress(DefaultOVSRunDir)
	} else {
		endpoint = defaultConnNetwork + ":" + address
	}

	dbModel, err := model.NewClientDBModel(openvSwitchTable, map[string]model.Model{
		openvSwitchTable: &OpenvSwitch{},
		bridgeTable:      &Bridge{},
		portTable:        &Port{},
		interfaceTable:   &Interface{},
	})
	if err != nil {
		return nil, err
	}
	db, err := client.NewOVSDBClient(dbModel,
		client.WithEndpoint(endpoint),
		client.WithReconnect(2*time.Second, backoff.NewConstantBackOff(1*time.Second)))
	if err != nil {
		return nil, err
	}

	// We use a synchronous retry loop for the initial connection instead of a background
	// asynchronous dial. This has the advantages:
	// - Enables Immediate Cache Sync: A successful connection is a prerequisite for calling
	//   MonitorAll(), which populates our local in-memory cache and makes subsequent Get/List
	//   operations extremely fast and network-free.
	// - Reliable Reconnections: Once the initial connection is established, libovsdb's
	//   WithReconnect option automatically handles any future transient network disconnects
	//   or OVS restarts in the background.
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
			return nil, ctx.Err()
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
		return nil, err
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
func (br *OVSBridge) Create() error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	var err error
	var exists bool
	if exists, err = br.lookupByName(ctx); err != nil {
		return err
	} else if exists {
		klog.InfoS("Bridge exists", "bridge", br.name, "uuid", br.uuid)
		// Update OpenFlow protocol versions and datapath type on existent bridge.
		if err := br.updateBridgeConfiguration(ctx); err != nil {
			return err
		}
	} else if err = br.create(ctx); err != nil {
		return err
	} else {
		klog.InfoS("Created bridge", "bridge", br.name, "uuid", br.uuid)
	}
	br.isHardwareOffloadEnabled, err = br.getHardwareOffload()
	if err != nil {
		klog.ErrorS(err, "Failed to get hardware offload")
	}
	return nil
}

func (br *OVSBridge) lookupByName(ctx context.Context) (bool, error) {
	bridge, err := br.getBridge(ctx)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return false, nil
		}
		return false, err
	}

	br.uuid = bridge.UUID
	return true, nil
}

func (br *OVSBridge) updateBridgeConfiguration(ctx context.Context) error {
	update := &Bridge{
		// Use Openflow protocol version 1.0 and 1.5.
		Protocols:           []string{openflowProtoVersion10, openflowProtoVersion15},
		DatapathType:        string(br.datapathType),
		McastSnoopingEnable: br.mcastSnoopingEnable,
	}

	ops, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Update(
		update,
		&update.Protocols,
		&update.DatapathType,
		&update.McastSnoopingEnable,
	)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for bridge", "bridge", br.name)
		return err
	}
	_, err = br.transact(ctx, ops, "update bridge configuration")
	return err
}

func (br *OVSBridge) create(ctx context.Context) error {
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
		return err
	}

	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return err
	}

	// Update the root Open_vSwitch table to reference the newly created Bridge's named-uuid.
	// This linkage must be established in the same atomic transaction to prevent the OVSDB server
	// from garbage collecting the newly created Bridge.
	mOVS := &OpenvSwitch{}
	mutation := model.Mutation{
		Field:   &mOVS.Bridges,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{ops[0].UUIDName},
	}
	ops2, err := br.ovsdb.Where(OVSWithUUID(ovs.UUID)).Mutate(mOVS, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Open_vSwitch", "bridge", br.name)
		return err
	}
	ops = append(ops, ops2...)

	// Resolve the named-uuid to a real physical UUID and return it.
	res, err := br.transact(ctx, ops, "create bridge configuration")
	if err != nil {
		return err
	}
	br.uuid = res[0].UUID.GoUUID
	return nil
}

func (br *OVSBridge) Delete() error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	ops, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Delete()
	if err != nil {
		klog.ErrorS(err, "Failed to construct delete operations for bridge", "bridge", br.name)
		return err
	}

	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return err
	}

	// Update the root Open_vSwitch table to remove the reference to this Bridge.
	// This linkage cleanup is necessary to keep the 'bridges' reference list consistent in OVSDB.
	mOVS := &OpenvSwitch{}
	mutation := model.Mutation{
		Field:   &mOVS.Bridges,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{br.uuid},
	}
	ops2, err := br.ovsdb.Where(OVSWithUUID(ovs.UUID)).Mutate(mOVS, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Open_vSwitch", "bridge", br.name)
		return err
	}
	ops = append(ops2, ops...)

	_, err = br.transact(ctx, ops, "delete bridge")
	return err
}

// GetExternalIDs returns the external IDs of the bridge.
func (br *OVSBridge) GetExternalIDs() (map[string]string, error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		return nil, err
	}
	return maps.Clone(bridge.ExternalIDs), nil
}

// SetExternalIDs sets the provided external IDs to the bridge.
func (br *OVSBridge) SetExternalIDs(externalIDs map[string]string) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	updateBridge := &Bridge{ExternalIDs: externalIDs}
	ops, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Update(updateBridge, &updateBridge.ExternalIDs)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for bridge", "bridge", br.name)
		return err
	}
	_, err = br.transact(ctx, ops, "set external IDs")
	return err
}

// SetDatapathID sets the provided datapath ID to the bridge.
// If datapath ID is not configured, reconfigure bridge(add/delete port or set different Mac address for local port)
// will change its datapath ID. And the change of datapath ID and interrupt OpenFlow connection.
// See question "My bridge disconnects from my controller on add-port/del-port" in：
// http://openvswitch.org/support/dist-docs-2.5/FAQ.md.html
func (br *OVSBridge) SetDatapathID(datapathID string) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	mBridge := &Bridge{}
	mutations := []model.Mutation{
		{
			// MutateOperationInsert on an OVSDB map DOES NOT act as an Upsert.
			// To update an existing key, we MUST perform a Delete operation followed by an Insert operation.
			Field:   &mBridge.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{OVSOtherConfigDatapathIDKey},
		},
		{
			Field:   &mBridge.OtherConfig,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   map[string]string{OVSOtherConfigDatapathIDKey: datapathID},
		},
	}
	ops, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Mutate(mBridge, mutations...)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operations for bridge", "bridge", br.name)
		return err
	}

	_, err = br.transact(ctx, ops, "set datapath ID")
	return err
}

func (br *OVSBridge) GetDatapathID() (string, error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		return "", err
	}
	if bridge.DatapathID == nil {
		return "", nil
	}
	return *bridge.DatapathID, nil
}

// WaitForDatapathID waits until OVS assigns a datapath ID to the bridge.
// It returns the datapath ID immediately if it is already available. Otherwise,
// it uses an OVSDB wait operation and returns an error if the wait times out or
// the Bridge row cannot be found.
func (br *OVSBridge) WaitForDatapathID(timeout time.Duration) (string, error) {
	// TODO: use ctx from parent context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	bridge, err := br.getBridge(ctx)
	if err != nil {
		return "", err
	}

	if bridge.DatapathID != nil && *bridge.DatapathID != "" {
		return *bridge.DatapathID, nil
	}

	timeoutMs := int(timeout.Milliseconds())
	mBridge := &Bridge{}
	ops, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Wait(ovsdb.WaitConditionNotEqual, &timeoutMs, mBridge, &mBridge.DatapathID)
	if err != nil {
		return "", err
	}
	// Append a select operation to return the updated row atomically.
	// This prevents cache synchronization race conditions (RAW: read-after-write) and ensures consistency.
	ops = append(ops, newSelectOperation(bridgeTable, "_uuid", ovsdb.UUID{GoUUID: br.uuid}, "datapath_id"))

	results, err := br.transact(ctx, ops, "wait for datapath ID")
	if err != nil {
		return "", err
	}

	if len(results) < 2 || len(results[1].Rows) == 0 {
		return "", fmt.Errorf("unexpected OVSDB transaction result: no rows returned for bridge %s", br.name)
	}

	if dpIDRaw, ok := results[1].Rows[0]["datapath_id"]; ok {
		// DatapathID may be returned as a primitive string or an OvsSet containing strings.
		// Helper extracts the first underlying string safely.
		if dpID, ok := extractOVSDBValue[string](dpIDRaw); ok && dpID != "" {
			return dpID, nil
		}
	}
	return "", fmt.Errorf("failed to parse a valid datapath_id from OVSDB result for bridge %s", br.name)
}

// GetPortUUIDList returns UUIDs of all ports on the bridge.
func (br *OVSBridge) GetPortUUIDList() ([]string, error) {
	// TODO: use ctx from parent context
	bridge, err := br.getBridge(context.TODO())
	if err != nil {
		return nil, err
	}
	return slices.Clone(bridge.Ports), nil
}

// DeletePort deletes the port with the provided portUUID.
// If the port does not exist no change will be done.
func (br *OVSBridge) DeletePort(portUUID string) error {
	if portUUID == "" {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	mBridge := &Bridge{}
	mutation := model.Mutation{
		Field:   &mBridge.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{portUUID},
	}
	ops, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Mutate(mBridge, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for bridge", "bridge", br.name)
		return err
	}

	_, err = br.transact(ctx, ops, "delete port")
	return err
}

// CreateInternalPort creates an internal port with the specified name on the
// bridge.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateInternalPort(name string, ofPortRequest int32, mac string, externalIDs map[string]string) (string, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", fmt.Errorf("invalid ofPortRequest value: %v", ofPortRequest)
	}
	return br.createPort(ctx, name, name, "internal", ofPortRequest, 0, mac, externalIDs, nil)
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
	extraOptions map[string]string,
	externalIDs map[string]string) (string, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()
	if psk != "" && remoteIP == "" {
		return "", fmt.Errorf("IPSec tunnel can not be flow based. remoteIP must be set")
	}
	if psk != "" && remoteName != "" {
		return "", fmt.Errorf("can not set psk and remoteName together")
	}
	return br.createTunnelPort(ctx,
		name,
		tunnelType,
		ofPortRequest,
		csum,
		localIP,
		remoteIP,
		remoteName,
		psk,
		extraOptions,
		externalIDs)
}

func (br *OVSBridge) createTunnelPort(
	ctx context.Context,
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	csum bool,
	localIP string,
	remoteIP string,
	remoteName string,
	psk string,
	extraOptions map[string]string,
	externalIDs map[string]string) (string, error) {

	if tunnelType != VXLANTunnel &&
		tunnelType != GeneveTunnel &&
		tunnelType != GRETunnel &&
		tunnelType != STTTunnel &&
		tunnelType != ERSPANTunnel {
		return "", fmt.Errorf("unsupported tunnel type: %s", string(tunnelType))
	}
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", fmt.Errorf("invalid ofPortRequest value: %v", ofPortRequest)
	}

	options := make(map[string]string)
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

	return br.createPort(ctx, name, name, string(tunnelType), ofPortRequest, 0, "", externalIDs, options)
}

// GetInterfaceOptions returns the options of the provided interface.
func (br *OVSBridge) GetInterfaceOptions(name string) (map[string]string, error) {
	// TODO: use ctx from parent context
	intf, err := br.getInterface(context.TODO(), name)
	if err != nil {
		return nil, err
	}
	return maps.Clone(intf.Options), nil
}

// SetInterfaceOptions sets the specified options of the provided interface.
func (br *OVSBridge) SetInterfaceOptions(name string, options map[string]string) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	updateIntf := &Interface{Options: options}
	ops, err := br.ovsdb.Where(interfaceWithName(name)).Update(updateIntf, &updateIntf.Options)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operations for interface", "interface", name)
		return err
	}
	_, err = br.transact(ctx, ops, "set interface options")
	return err
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
func (br *OVSBridge) CreateUplinkPort(name string, ofPortRequest int32, externalIDs map[string]string) (string, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()
	return br.createPort(ctx, name, name, "", ofPortRequest, 0, "", externalIDs, nil)
}

// CreatePort creates a port with the specified name on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
func (br *OVSBridge) CreatePort(name, ifDev string, externalIDs map[string]string) (string, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()
	return br.createPort(ctx, name, ifDev, "", 0, 0, "", externalIDs, nil)
}

// CreateAccessPort creates a port with the specified name and VLAN ID on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// vlanID=0 will perform same behavior as CreatePort.
func (br *OVSBridge) CreateAccessPort(name, ifDev string, externalIDs map[string]string, vlanID uint16) (string, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()
	return br.createPort(ctx, name, ifDev, "", 0, vlanID, "", externalIDs, nil)
}

func (br *OVSBridge) createPort(ctx context.Context,
	name string,
	ifName string,
	ifType string,
	ofPortRequest int32,
	vlanID uint16,
	mac string,
	externalIDs map[string]string,
	options map[string]string) (string, error) {
	for _, id := range br.requiredPortExternalIDs {
		if _, ok := externalIDs[id]; !ok {
			return "", fmt.Errorf("missing required externalID '%s' for port '%s'", id, name)
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
		intf.Options = options
	}

	// Construct a create operation for the new Interface.
	ops, err := br.ovsdb.Create(intf)
	if err != nil {
		klog.ErrorS(err, "Failed to construct create operation for interface", "interface", ifName)
		return "", err
	}
	ifNamedUUID := ops[0].UUIDName

	port := &Port{
		UUID:       namedUUID(),
		Name:       name,
		Interfaces: []string{ifNamedUUID},
	}
	if externalIDs != nil {
		port.ExternalIDs = maps.Clone(externalIDs)
	}
	if vlanID > 0 {
		tag := int(vlanID)
		port.Tag = &tag
	}

	// Construct a create operation for the new Port, linking it to the Interface.
	ops2, err := br.ovsdb.Create(port)
	if err != nil {
		klog.ErrorS(err, "Failed to construct create operation for port", "port", name)
		return "", err
	}
	ops = append(ops, ops2...)
	portNamedUUID := ops2[0].UUIDName

	mBridge := &Bridge{}
	mutation := model.Mutation{
		Field:   &mBridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{portNamedUUID},
	}
	// Update the Bridge record to include the newly created Port.
	ops3, err := br.ovsdb.Where(bridgeWithUUID(br.uuid)).Mutate(mBridge, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for bridge", "bridge", br.name)
		return "", err
	}
	ops = append(ops, ops3...)

	res, err := br.transact(ctx, ops, "create port")
	if err != nil {
		return "", err
	}

	return res[1].UUID.GoUUID, nil
}

// GetOFPort retrieves the ofport value of an interface given its name.
// It returns the cached ofport immediately if OVS has already assigned a valid one (>0).
// If OVS has assigned an invalid ofport (<0, typically indicating an error during
// port creation), it returns an error immediately.
// Otherwise, it waits for OVS to assign an ofport (either valid or invalid) using
// an OVSDB wait operation with a 5-second timeout. If the wait operation times out,
// or the assigned ofport is invalid, an error will be returned.
func (br *OVSBridge) GetOFPort(ifName string) (int32, error) {
	// TODO: use ctx from parent context
	ctx, cancel := context.WithTimeout(context.Background(), defaultGetPortTimeout)
	defer cancel()

	intf, err := br.getInterface(ctx, ifName)
	if err != nil {
		return 0, err
	}

	if intf.OFPort != nil {
		ofport := *intf.OFPort
		if ofport > 0 {
			return int32(ofport), nil
		} else if ofport < 0 {
			return 0, fmt.Errorf("invalid ofport %d", ofport)
		}
	}

	deadline, _ := ctx.Deadline()
	timeoutMs := int(time.Until(deadline).Milliseconds())
	if timeoutMs <= 0 {
		return 0, fmt.Errorf("timeout waiting for ofport for %s", ifName)
	}

	mIntf := &Interface{}
	// We use WaitConditionNotEqual to wait for the ofport to be assigned by OVS (including invalid value -1).
	// We wait for the ofport to become NotEqual to empty set (nil). This guarantees the wait completes immediately when
	// OVS assigns a valid port number (>0), or fails the port creation and assigns an error value (<0, e.g., -1).
	ops, err := br.ovsdb.Where(interfaceWithName(ifName)).Wait(ovsdb.WaitConditionNotEqual, &timeoutMs, mIntf, &mIntf.OFPort)
	if err != nil {
		return 0, err
	}

	// Append a select operation to return the updated row atomically.
	// This prevents cache synchronization race conditions (RAW: read-after-write) and ensures consistency.
	ops = append(ops, newSelectOperation(interfaceTable, "name", ifName, "ofport"))

	results, err := br.transact(ctx, ops, "wait for ofport")
	if err != nil {
		return 0, err
	}

	if len(results) < 2 || len(results[1].Rows) == 0 {
		return 0, fmt.Errorf("unexpected OVSDB transaction result: no rows returned for interface %s", ifName)
	}
	if ofportRaw, ok := results[1].Rows[0]["ofport"]; ok {
		var ofport int
		parsed := false
		// Raw OVSDB select results are map[string]any. OVSDB integer values may be decoded as float64 from JSON, while
		// typed model paths use int.
		if floatVal, ok := extractOVSDBValue[float64](ofportRaw); ok {
			ofport = int(floatVal)
			parsed = true
		} else if intVal, ok := extractOVSDBValue[int](ofportRaw); ok {
			ofport = intVal
			parsed = true
		}
		if parsed {
			if ofport > 0 {
				return int32(ofport), nil
			}
			if ofport < 0 {
				return 0, fmt.Errorf("invalid ofport %d", ofport)
			}
		}
	}

	return 0, fmt.Errorf("failed to parse a valid ofport from OVSDB result for interface %s", ifName)
}

func buildPortDataCommon(port *Port, intf *Interface, portData *OVSPortData) {
	portData.Name = port.Name
	portData.ExternalIDs = maps.Clone(port.ExternalIDs)
	if port.Tag != nil {
		portData.VLANID = uint16(*port.Tag)
	}
	portData.Options = maps.Clone(intf.Options)
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
func (br *OVSBridge) GetPortData(portUUID, ifName string) (*OVSPortData, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	port, err := br.getPort(ctx, "", portUUID)
	if err != nil {
		return nil, err
	}

	intf, err := br.getInterface(ctx, ifName)
	if err != nil {
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
		return nil, fmt.Errorf("interface %s not attached to port %s", ifName, portUUID)
	}

	portData := OVSPortData{UUID: portUUID, IFName: ifName}
	buildPortDataCommon(port, intf, &portData)
	return &portData, nil
}

// GetPortList returns all ports on the bridge.
// A port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortList() ([]OVSPortData, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	// Fetch the target Bridge record to get the exact list of port UUIDs it owns.
	bridge, err := br.getBridge(ctx)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			klog.InfoS("Could not find bridge", "bridge", br.name, "uuid", br.uuid)
			return []OVSPortData{}, nil
		}
		return nil, err
	}
	portUUIDs := sets.New[string](bridge.Ports...)

	// Fetch only Port records that belong to this bridge.
	var ports []Port
	if err := br.ovsdb.WhereCache(func(p *Port) bool {
		return portUUIDs.Has(p.UUID)
	}).List(ctx, &ports); err != nil {
		klog.ErrorS(err, "Failed to list Port table", "bridge", br.name)
		return nil, err
	}

	ifUUIDs := sets.New[string]()
	for i := range ports {
		if len(ports[i].Interfaces) > 0 {
			ifUUIDs.Insert(ports[i].Interfaces[0])
		}
	}

	// Fetch only Interface records that belong to the ports.
	var intfs []Interface
	if err := br.ovsdb.WhereCache(func(i *Interface) bool {
		return ifUUIDs.Has(i.UUID)
	}).List(ctx, &intfs); err != nil {
		klog.ErrorS(err, "Failed to list Interface table", "bridge", br.name)
		return nil, err
	}
	// Build an in-memory index of the fetched Interfaces by UUID for fast lookup.
	intfMap := make(map[string]*Interface)
	for i := range intfs {
		intfMap[intfs[i].UUID] = &intfs[i]
	}

	// Assemble the result by iterating over the ports.
	portList := make([]OVSPortData, 0, len(ports))
	for i := range ports {
		port := &ports[i]
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
		portData := OVSPortData{UUID: port.UUID, IFName: intf.Name}
		buildPortDataCommon(port, intf, &portData)
		portList = append(portList, portData)
	}

	return portList, nil
}

// GetOVSVersion either returns the version of OVS, or an error.
func (br *OVSBridge) GetOVSVersion() (string, error) {
	// TODO: use ctx from parent context
	ovs, err := br.getOpenvSwitch(context.TODO())
	if err != nil {
		return "", err
	}

	if ovs.OvsVersion != nil {
		return *ovs.OvsVersion, nil
	}
	return "", errors.New(defaultOvsVersionMessage)
}

func (br *OVSBridge) GetOVSOtherConfig() (map[string]string, error) {
	// TODO: use ctx from parent context
	ovs, err := br.getOpenvSwitch(context.TODO())
	if err != nil {
		return nil, err
	}
	return maps.Clone(ovs.OtherConfig), nil
}

// UpdateOVSOtherConfig updates the given configs in the "other_config" column
// of the single record in the "Open_vSwitch" table.
// MutateOperationInsert on an OVSDB map DOES NOT act as an Upsert. To update an existing key,
// we MUST perform a Delete operation followed by an Insert operation. Therefore, for each config,
// the key is first deleted and then inserted with the provided value so existing values are
// overwritten while unrelated keys are preserved.
func (br *OVSBridge) UpdateOVSOtherConfig(configs map[string]string) error {
	if len(configs) == 0 {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return err
	}

	var keys []string
	for k := range configs {
		keys = append(keys, k)
	}
	mOVS := &OpenvSwitch{}
	mutations := []model.Mutation{
		{
			Field:   &mOVS.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   keys,
		},
		{
			Field:   &mOVS.OtherConfig,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   configs,
		},
	}
	// Construct a mutate operation for the Open_vSwitch record.
	ops, err := br.ovsdb.Where(OVSWithUUID(ovs.UUID)).Mutate(mOVS, mutations...)
	if err != nil {
		return err
	}
	_, err = br.transact(ctx, ops, "update OVS other config")
	return err
}

// DeleteOVSOtherConfig deletes the given configs from the "other_config" column of
// the single record in the "Open_vSwitch" table.
// If the configs exist, they will be deleted. No error is returned if configs don't exist.
func (br *OVSBridge) DeleteOVSOtherConfig(keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	// TODO: use ctx from parent context
	ctx := context.TODO()

	ovs, err := br.getOpenvSwitch(ctx)
	if err != nil {
		return err
	}

	if ovs.OtherConfig == nil {
		return nil
	}

	mOVS := &OpenvSwitch{}
	mutation := model.Mutation{
		Field:   &mOVS.OtherConfig,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   keys,
	}

	// Construct a mutate operation for the Open_vSwitch record.
	ops, err := br.ovsdb.Where(OVSWithUUID(ovs.UUID)).Mutate(mOVS, mutation)
	if err != nil {
		klog.ErrorS(err, "Failed to construct mutate operation for Open_vSwitch", "bridge", br.name)
		return err
	}
	_, err = br.transact(ctx, ops, "delete OVS other config")
	return err
}

func (br *OVSBridge) GetBridgeName() string {
	return br.name
}

func (br *OVSBridge) IsHardwareOffloadEnabled() bool {
	return br.isHardwareOffloadEnabled
}

func (br *OVSBridge) getHardwareOffload() (bool, error) {
	otherConfig, err := br.GetOVSOtherConfig()
	if err != nil {
		return false, err
	}
	for configKey, configValue := range otherConfig {
		if configKey == hardwareOffload {
			boolConfigVal, err := strconv.ParseBool(configValue)
			if err != nil {
				return boolConfigVal, fmt.Errorf("invalid hardwareOffload value: %s", configValue)
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
func (br *OVSBridge) SetInterfaceType(name, ifType string) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return err
	}

	updateIntf := &Interface{Type: ifType}
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(updateIntf, &updateIntf.Type)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Interface", "interface", name)
		return err
	}

	_, err = br.transact(ctx, ops, "set interface type")
	return err

}

func (br *OVSBridge) SetPortExternalIDs(portName string, externalIDs map[string]string) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	port, err := br.getPort(ctx, portName, "")
	if err != nil {
		return err
	}

	updatePort := &Port{ExternalIDs: externalIDs}
	ops, err := br.ovsdb.Where(&Port{UUID: port.UUID}).Update(updatePort, &updatePort.ExternalIDs)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Port", "port", portName)
		return err
	}
	_, err = br.transact(ctx, ops, "set port external IDs")
	return err
}

func (br *OVSBridge) GetPortExternalIDs(portName string) (map[string]string, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	port, err := br.getPort(ctx, portName, "")
	if err != nil {
		return nil, err
	}

	return maps.Clone(port.ExternalIDs), nil
}

func (br *OVSBridge) SetInterfaceMTU(name string, MTU int) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return err
	}

	mtu := MTU
	updateIntf := &Interface{MTURequest: &mtu}
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(updateIntf, &updateIntf.MTURequest)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Interface", "interface", name)
		return err
	}

	_, err = br.transact(ctx, ops, "set interface MTU")
	return err
}

func (br *OVSBridge) SetInterfaceMAC(name string, mac net.HardwareAddr) error {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	intf, err := br.getInterface(ctx, name)
	if err != nil {
		return err
	}

	macStr := mac.String()
	updateIntf := &Interface{MAC: &macStr}
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(updateIntf, &updateIntf.MAC)
	if err != nil {
		klog.ErrorS(err, "Failed to construct update operation for Interface", "interface", name)
		return err
	}

	_, err = br.transact(ctx, ops, "set interface MAC")
	return err

}

func (br *OVSBridge) GetBridgeMcastSnoopingEnable() (bool, error) {
	// TODO: use ctx from parent context
	ctx := context.TODO()

	bridge, err := br.getBridge(ctx)
	if err != nil {
		return false, err
	}

	return bridge.McastSnoopingEnable, nil
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
// We handle two different "not found" scenarios here. The distinction based on libovsdb's
// implementation in client/api.go:
//  1. client.ErrNotFound: The cache table itself is nil (tableCache == nil).
//     This means the local cache hasn't synced the Open_vSwitch table schema yet.
//  2. len(ovsList) == 0: The cache table exists, the query succeeded (err == nil),
//     but tableCache.Rows() returned 0 rows. Since Open_vSwitch is the root table,
//     0 rows implies an uninitialized or broken OVSDB state on the server.
func (br *OVSBridge) getOpenvSwitch(ctx context.Context) (*OpenvSwitch, error) {
	var ovsList []OpenvSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			klog.ErrorS(err, "Failed to list Open_vSwitch table")
		}
		return nil, err
	}
	if len(ovsList) == 0 {
		return nil, fmt.Errorf("root Open_vSwitch record not found")
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
		}
		return nil, err
	}
	return intf, nil
}

// transact is a helper function to execute an OVSDB transaction and log any error
// with the provided action description.
func (br *OVSBridge) transact(ctx context.Context, ops []ovsdb.Operation, action string) ([]ovsdb.OperationResult, error) {
	results, err := br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.ErrorS(err, "Failed to execute transaction to", "action", action, "bridge", br.name)
		return nil, err
	}
	opErrs, err := ovsdb.CheckOperationResults(results, ops)
	if err != nil {
		return nil, convertOVSDBErrors(opErrs, err)
	}
	return results, nil
}

// extractOVSDBValue is a generic helper function to parse typed fields from raw
// operation results, handling both direct values and wrapped OvsSet types.
func extractOVSDBValue[T any](val interface{}) (T, bool) {
	var zero T
	switch v := val.(type) {
	case T:
		return v, true
	case ovsdb.OvsSet:
		if len(v.GoSet) > 0 {
			if typedVal, ok := v.GoSet[0].(T); ok {
				return typedVal, true
			}
		}
	}
	return zero, false
}

// newSelectOperation is a helper function to construct an OVSDB select operation.
// It retrieves the specified returnColumns from the given table where the condition matches.
//
// This is typically used in conjunction with a Wait operation to prevent cache synchronization
// race conditions (RAW: read-after-write) and maintain strict consistency. OVSDB's Wait operation
// merely returns success when the condition is met on the server. If we immediately query the local
// cache afterward, the local monitor cache might not have been updated yet due to asynchronous network
// delays, leading to reading stale data. By executing a Select operation in the same OVSDB transaction
// as the Wait, the server guarantees returning the freshly updated value directly in the transaction
// result, completely bypassing the local cache.
func newSelectOperation(table, column string, value interface{}, returnColumns ...string) ovsdb.Operation {
	return ovsdb.Operation{
		Op:    ovsdb.OperationSelect,
		Table: table,
		Where: []ovsdb.Condition{
			{Column: column, Function: ovsdb.ConditionEqual, Value: value},
		},
		Columns: returnColumns,
	}
}

func bridgeWithUUID(uuid string) *Bridge       { return &Bridge{UUID: uuid} }
func interfaceWithName(name string) *Interface { return &Interface{Name: name} }
func OVSWithUUID(uuid string) *OpenvSwitch     { return &OpenvSwitch{UUID: uuid} }
