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

package ovs

import (
	"flag"
	"os"
	"testing"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	defaultBridgeName     = "br-antrea-test"
	defaultConnectTimeout = 5 * time.Second
)

var UDSAddress string
var bridgeName string

type testData struct {
	ovsdb *ovsdb.OVSDB
	br    *ovsconfig.OVSBridge
}

func (data *testData) setup(t *testing.T) {
	var err error
	// ensure that we timeout after a reasonable time duration if we cannot connect to the Unix
	// socket.
	connectErrorCh := make(chan error, 0)
	connect := func() {
		data.ovsdb, err = ovsconfig.NewOVSDBConnectionUDS(UDSAddress)
		connectErrorCh <- err
	}
	go connect()
	select {
	case err := <-connectErrorCh:
		require.Nil(t, err, "Failed to open OVSDB connection")
	case <-time.After(defaultConnectTimeout):
		t.Fatalf("Could not establish connection to %s after %s", UDSAddress, defaultConnectTimeout)
	}

	data.br = ovsconfig.NewOVSBridge(bridgeName, "system", data.ovsdb)
	err = data.br.Create()
	require.Nil(t, err, "Failed to create bridge %s", bridgeName)
}

func (data *testData) teardown(t *testing.T) {
	if err := data.br.Delete(); err != nil {
		t.Errorf("Error when deleting bridge: %v", err)
	}
	data.ovsdb.Close()
}

func TestOVSBridge(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	checkPorts := func(expectedCount int) {
		portList, err := data.br.GetPortUUIDList()
		require.Nil(t, err, "Error when retrieving port list")
		assert.Equal(t, expectedCount, len(portList))
	}

	deleteAllPorts(t, data.br)
	checkPorts(0)

	uuid1 := testCreatePort(t, data.br, "p1", "internal")
	uuid2 := testCreatePort(t, data.br, "p2", "")
	uuid3 := testCreatePort(t, data.br, "p3", "vxlan")
	uuid4 := testCreatePort(t, data.br, "p4", "geneve")

	checkPorts(4)

	testDeletePort(t, data.br, uuid1)
	testDeletePort(t, data.br, uuid2)
	testDeletePort(t, data.br, uuid3)
	testDeletePort(t, data.br, uuid4)

	checkPorts(0)

	testCreatePort(t, data.br, "p1", "internal")
	testCreatePort(t, data.br, "p2", "")
	testCreatePort(t, data.br, "p3", "vxlan")
	testCreatePort(t, data.br, "p4", "geneve")

	checkPorts(4)

	deleteAllPorts(t, data.br)

	checkPorts(0)
}

// TestOVSDeletePortIdempotent verifies that calling DeletePort on a non-existent port does not
// produce an error.
func TestOVSDeletePortIdempotent(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	deleteAllPorts(t, data.br)

	uuid := testCreatePort(t, data.br, "p1", "internal")
	testDeletePort(t, data.br, uuid)
	testDeletePort(t, data.br, uuid)
}

// TestOVSBridgeExternalIDs tests getting and setting external IDs of the OVS
// bridge.
func TestOVSBridgeExternalIDs(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	returnedIDs, err := data.br.GetExternalIDs()
	require.Nil(t, err, "Failed to get external IDs of the bridge")
	assert.Empty(t, returnedIDs)

	providedIDs := map[string]interface{}{"k1": "v1", "k2": "v2"}
	err = data.br.SetExternalIDs(providedIDs)
	require.Nil(t, err, "Failed to set external IDs to the bridge")

	returnedIDs, err = data.br.GetExternalIDs()
	require.Nil(t, err, "Failed to get external IDs of the bridge")
	for k, v := range providedIDs {
		rv, ok := returnedIDs[k]
		if !assert.Truef(t, ok, "Returned external IDs do not include the expected ID: %s:%s", k, v) {
			continue
		}
		assert.Equalf(t, v.(string), rv, "Returned external IDs include an ID with an unexpected value: %s:%s", k, v)
	}
}

func deleteAllPorts(t *testing.T, br *ovsconfig.OVSBridge) {
	portList, err := br.GetPortUUIDList()
	require.Nil(t, err, "Error when retrieving port list")
	err = br.DeletePorts(portList)
	require.Nil(t, err, "Error when deleting ports")
}

var ofPortRequest int32 = 1

func testCreatePort(t *testing.T, br *ovsconfig.OVSBridge, name string, ifType string) string {
	var err error
	var uuid string
	var externalIDs map[string]interface{}
	var ifName = name

	switch ifType {
	case "":
		externalIDs = map[string]interface{}{"k1": "v1", "k2": "v2"}
		uuid, err = br.CreatePort(name, name, externalIDs)
	case "internal":
		externalIDs = map[string]interface{}{"k1": "v1", "k2": "v2"}
		uuid, err = br.CreateInternalPort(name, ofPortRequest, externalIDs)
	case "vxlan":
		externalIDs = map[string]interface{}{}
		uuid, err = br.CreateTunnelPort(name, ovsconfig.VXLANTunnel, ofPortRequest)
	case "geneve":
		externalIDs = map[string]interface{}{}
		uuid, err = br.CreateTunnelPort(name, ovsconfig.GeneveTunnel, ofPortRequest)
	}

	require.Nilf(t, err, "Failed to create %s port: %s", ifType, err)

	ofPort, err := br.GetOFPort(name)
	require.Nilf(t, err, "Failed to get ofport for %s port: %s", ifType, err)
	if ifType != "" {
		assert.Equal(t, ofPortRequest, ofPort, "ofport does not match the requested value for %s port", ifType)
		ofPortRequest++
	} else {
		// -1 will be assigned to a port without a valid interface backing.
		assert.Equal(t, int32(-1), ofPort)
	}

	port, err := br.GetPortData(uuid, ifName)
	require.Nilf(t, err, "Failed to get port (%s, %s)", uuid, ifName)
	require.NotNilf(t, port, "Port (%s, %s) not found", uuid, ifName)

	assert.Equal(t, name, port.Name)
	assert.Equal(t, ifName, port.IFName)
	assert.Equal(t, ofPort, port.OFPort)

	for k, v := range externalIDs {
		rv, ok := port.ExternalIDs[k]
		if !assert.Truef(t, ok, "Returned port does not include the expected external id: %s:%s", k, v) {
			continue
		}
		assert.Equalf(t, v.(string), rv, "Returned port has an external id with an unexpected value: %s:%s", k, v)
	}

	portList, err := br.GetPortList()
	require.Nil(t, err, "Failed to get ports")
	uuids := make([]string, len(portList))
	for _, p := range portList {
		uuids = append(uuids, p.UUID)
	}
	assert.Contains(t, uuids, uuid, "Did not find port UUID in port list")

	return uuid
}

func testDeletePort(t *testing.T, br *ovsconfig.OVSBridge, uuid string) {
	if uuid == "" {
		t.Logf("Cannot delete port with empty uuid")
		return
	}

	err := br.DeletePort(uuid)
	require.Nil(t, err, "Failed to delete port")

	uuidList, err := br.GetPortUUIDList()
	require.Nil(t, err, "Error when retrieving port list")

	assert.NotContains(t, uuidList, uuid, "Found deleted port in port list")
}

func TestMain(m *testing.M) {
	flag.StringVar(&UDSAddress, "ovsdb-socket", defaultOVSDBAddress, "Unix domain server socket named file for OVSDB")
	flag.StringVar(&bridgeName, "br-name", defaultBridgeName, "Bridge name to use for tests")
	os.Exit(m.Run())
}
