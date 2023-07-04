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
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
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

	// using the netdev datapath type does not impact test coverage but
	// ensures that the integration tests can be run with Docker Desktop on
	// macOS.
	brClient := ovsconfig.NewOVSBridge(bridgeName, "netdev", data.ovsdb)
	data.br = brClient.(*ovsconfig.OVSBridge)
	err = data.br.Create()
	require.Nil(t, err, "Failed to create bridge %s", bridgeName)
}

func (data *testData) teardown(t *testing.T) {
	if err := data.br.Delete(); err != nil {
		t.Errorf("Error when deleting bridge: %v", err)
	}
	data.ovsdb.Close()
}

func randomDatapathID() (string, error) {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x", buf), nil
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

	// Test set fixed datapath ID
	expectedDatapathID, err := randomDatapathID()
	require.Nilf(t, err, "Failed to generate datapath ID: %s", err)
	err = data.br.SetDatapathID(expectedDatapathID)
	require.Nilf(t, err, "Set datapath id failed: %s", err)
	var datapathID string
	for retry := 0; retry < 3; retry++ {
		datapathID, _ = data.br.GetDatapathID()
		if datapathID == expectedDatapathID {
			break
		}
		time.Sleep(time.Second)
	}
	assert.Equal(t, expectedDatapathID, datapathID)
	vlanID := uint16(100)

	deleteAllPorts(t, data.br)
	checkPorts(0)

	uuid1 := testCreatePort(t, data.br, "p1", "internal", 0)
	uuid2 := testCreatePort(t, data.br, "p2", "", 0)
	uuid3 := testCreatePort(t, data.br, "p3", "vxlan", 0)
	uuid4 := testCreatePort(t, data.br, "p4", "geneve", 0)
	uuid5 := testCreatePort(t, data.br, "p5", "", vlanID)

	checkPorts(5)

	testDeletePort(t, data.br, uuid1)
	testDeletePort(t, data.br, uuid2)
	testDeletePort(t, data.br, uuid3)
	testDeletePort(t, data.br, uuid4)
	testDeletePort(t, data.br, uuid5)

	checkPorts(0)

	testCreatePort(t, data.br, "p1", "internal", 0)
	testCreatePort(t, data.br, "p2", "", 0)
	testCreatePort(t, data.br, "p3", "vxlan", 0)
	testCreatePort(t, data.br, "p4", "geneve", 0)
	testCreatePort(t, data.br, "p5", "", vlanID)

	checkPorts(5)

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

	uuid := testCreatePort(t, data.br, "p1", "internal", 0)
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

func TestOVSOtherConfig(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	otherConfigs := map[string]interface{}{"flow-restore-wait": "true", "foo1": "bar1"}
	err := data.br.AddOVSOtherConfig(otherConfigs)
	require.Nil(t, err, "Error when adding OVS other_config")

	gotOtherConfigs, err := data.br.GetOVSOtherConfig()
	require.Nil(t, err, "Error when getting OVS other_config")
	require.Equal(t, map[string]string{"flow-restore-wait": "true", "foo1": "bar1"}, gotOtherConfigs, "other_config mismatched")

	// Expect only the new config "foo2: bar2" will be added.
	err = data.br.AddOVSOtherConfig(map[string]interface{}{"flow-restore-wait": "false", "foo2": "bar2"})
	require.Nil(t, err, "Error when adding OVS other_config")

	gotOtherConfigs, err = data.br.GetOVSOtherConfig()
	require.Nil(t, err, "Error when getting OVS other_config")
	require.Equal(t, map[string]string{"flow-restore-wait": "true", "foo1": "bar1", "foo2": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect to modify existing values and insert new values
	err = data.br.UpdateOVSOtherConfig(map[string]interface{}{"foo2": "bar3", "foo3": "bar2"})
	require.Nil(t, err, "Error when updating OVS other_config")
	gotOtherConfigs, err = data.br.GetOVSOtherConfig()
	require.Nil(t, err, "Error when getting OVS other_config")
	require.Equal(t, map[string]string{"flow-restore-wait": "true", "foo1": "bar1", "foo2": "bar3", "foo3": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect only the matched config "flow-restore-wait: true" will be deleted.
	err = data.br.DeleteOVSOtherConfig(map[string]interface{}{"flow-restore-wait": "true", "foo1": "bar2", "foo2": "bar1"})
	require.Nil(t, err, "Error when deleting OVS other_config")

	gotOtherConfigs, err = data.br.GetOVSOtherConfig()
	require.Nil(t, err, "Error when getting OVS other_config")
	require.Equal(t, map[string]string{"foo1": "bar1", "foo2": "bar3", "foo3": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect "foo1" will be deleted
	err = data.br.DeleteOVSOtherConfig(map[string]interface{}{"foo1": "", "foo2": "bar4"})
	require.Nil(t, err, "Error when deleting OVS other_config")

	gotOtherConfigs, err = data.br.GetOVSOtherConfig()
	require.Nil(t, err, "Error when getting OVS other_config")
	require.Equal(t, map[string]string{"foo2": "bar3", "foo3": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect "foo2" will be deleted
	err = data.br.DeleteOVSOtherConfig(map[string]interface{}{"foo2": "", "foo4": ""})
	require.Nil(t, err, "Error when deleting OVS other_config")

	gotOtherConfigs, err = data.br.GetOVSOtherConfig()
	require.Nil(t, err, "Error when getting OVS other_config")
	require.Equal(t, map[string]string{"foo3": "bar2"}, gotOtherConfigs, "other_config mismatched")
}

func TestTunnelOptionCsum(t *testing.T) {
	testCases := map[string]struct {
		initialCsum bool
		updatedCsum bool
	}{
		"initial false, kept false": {
			initialCsum: false,
			updatedCsum: false,
		},
		"initial false, updated to true": {
			initialCsum: false,
			updatedCsum: true,
		},
		"initial true, kept true": {
			initialCsum: true,
			updatedCsum: true,
		},
		"initial true, updated to false": {
			initialCsum: true,
			updatedCsum: false,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			data := &testData{}
			data.setup(t)
			defer data.teardown(t)

			name := "vxlan0"
			_, err := data.br.CreateTunnelPortExt(name, ovsconfig.VXLANTunnel, ofPortRequest, testCase.initialCsum, "", "", "", "", nil, nil)
			require.Nil(t, err, "Error when creating tunnel port")
			options, err := data.br.GetInterfaceOptions(name)
			require.Nil(t, err, "Error when getting interface options")
			actualInitialCsum, _ := strconv.ParseBool(options["csum"])
			require.Equal(t, testCase.initialCsum, actualInitialCsum)

			updatedOptions := map[string]interface{}{}
			for k, v := range options {
				updatedOptions[k] = v
			}
			updatedOptions["csum"] = strconv.FormatBool(testCase.updatedCsum)
			err = data.br.SetInterfaceOptions(name, updatedOptions)
			require.Nil(t, err, "Error when setting interface options")
			options, err = data.br.GetInterfaceOptions(name)
			require.Nil(t, err, "Error when getting interface options")
			actualCsum, _ := strconv.ParseBool(options["csum"])
			require.Equal(t, testCase.updatedCsum, actualCsum)
		})
	}
}

func TestTunnelOptionTunnelPort(t *testing.T) {
	testCases := map[string]struct {
		initialTunnelPort int32
		updatedTunnelPort int32
	}{
		"initial zero, kept zero": {
			initialTunnelPort: 0,
			updatedTunnelPort: 0,
		},
		"initial zero, updated to 8472": {
			initialTunnelPort: 0,
			updatedTunnelPort: 8472,
		},
		"initial 8472, kept 8473": {
			initialTunnelPort: 8472,
			updatedTunnelPort: 8473,
		},
		"initial 8472, updated to zero": {
			initialTunnelPort: 8472,
			updatedTunnelPort: 0,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			data := &testData{}
			data.setup(t)
			defer data.teardown(t)

			name := "vxlan0"
			extraOptions := map[string]interface{}{}
			if testCase.initialTunnelPort != 0 {
				extraOptions["dst_port"] = strconv.Itoa(int(testCase.initialTunnelPort))
			}
			_, err := data.br.CreateTunnelPortExt(name, ovsconfig.VXLANTunnel, ofPortRequest, true, "", "", "", "", extraOptions, nil)
			require.Nil(t, err, "Error when creating tunnel port")
			options, err := data.br.GetInterfaceOptions(name)
			require.Nil(t, err, "Error when getting interface options")
			dstPort, exists := options["dst_port"]
			if testCase.initialTunnelPort != 0 {
				actualInitialTunnelPort, _ := strconv.ParseInt(dstPort, 10, 32)
				require.Equal(t, testCase.initialTunnelPort, int32(actualInitialTunnelPort))
			} else {
				require.Equal(t, exists, false)
			}

			updatedOptions := map[string]interface{}{}
			for k, v := range options {
				updatedOptions[k] = v
			}
			if testCase.updatedTunnelPort != 0 {
				updatedOptions["dst_port"] = strconv.Itoa(int(testCase.updatedTunnelPort))
			} else if _, ok := updatedOptions["dst_port"]; ok {
				delete(updatedOptions, "dst_port")
			}
			err = data.br.SetInterfaceOptions(name, updatedOptions)
			require.Nil(t, err, "Error when setting interface options")
			options, err = data.br.GetInterfaceOptions(name)
			require.Nil(t, err, "Error when getting interface options")
			dstPort, exists = options["dst_port"]
			if testCase.updatedTunnelPort != 0 {
				actualTunnelPort, _ := strconv.ParseInt(dstPort, 10, 32)
				require.Equal(t, testCase.updatedTunnelPort, int32(actualTunnelPort))
			} else {
				require.Equal(t, exists, false)
			}
		})
	}
}

func deleteAllPorts(t *testing.T, br *ovsconfig.OVSBridge) {
	portList, err := br.GetPortUUIDList()
	require.Nil(t, err, "Error when retrieving port list")
	err = br.DeletePorts(portList)
	require.Nil(t, err, "Error when deleting ports")
}

var ofPortRequest int32 = 1

func testCreatePort(t *testing.T, br *ovsconfig.OVSBridge, name string, ifType string, vlanID uint16) string {
	var err error
	var uuid string
	var externalIDs map[string]interface{}
	var ifName = name

	switch ifType {
	case "":
		externalIDs = map[string]interface{}{"k1": "v1", "k2": "v2"}
		if vlanID == 0 {
			uuid, err = br.CreatePort(name, name, externalIDs)
		} else {
			uuid, err = br.CreateAccessPort(name, name, externalIDs, vlanID)
		}
	case "internal":
		externalIDs = map[string]interface{}{"k1": "v1", "k2": "v2"}
		uuid, err = br.CreateInternalPort(name, ofPortRequest, "", externalIDs)
	case "vxlan":
		externalIDs = map[string]interface{}{}
		uuid, err = br.CreateTunnelPort(name, ovsconfig.VXLANTunnel, ofPortRequest)
	case "geneve":
		externalIDs = map[string]interface{}{}
		uuid, err = br.CreateTunnelPort(name, ovsconfig.GeneveTunnel, ofPortRequest)
	}

	require.Nilf(t, err, "Failed to create %s port: %s", ifType, err)

	ofPort, err := br.GetOFPort(name, false)
	if ifType != "" {
		require.NoErrorf(t, err, "Failed to get ofport for %s port: %s", ifType, err)
		assert.Equal(t, ofPortRequest, ofPort, "ofport does not match the requested value for %s port", ifType)
		ofPortRequest++
	} else {
		require.Error(t, err, "GetOFPort should return an error for a port without a valid interface backing")
	}

	port, err := br.GetPortData(uuid, ifName)
	require.Nilf(t, err, "Failed to get port (%s, %s)", uuid, ifName)
	require.NotNilf(t, port, "Port (%s, %s) not found", uuid, ifName)

	assert.Equal(t, name, port.Name)
	assert.Equal(t, ifName, port.IFName)
	if ifType != "" {
		assert.Equal(t, ofPort, port.OFPort)
	}
	assert.Equal(t, vlanID, port.VLANID)

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
