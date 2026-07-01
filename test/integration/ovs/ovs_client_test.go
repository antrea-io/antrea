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
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

const (
	defaultBridgeName     = "br-antrea-test"
	defaultConnectTimeout = 5 * time.Second
)

var UDSAddress string
var bridgeName string

type testData struct {
	requiredPortExternalIDs []string
	enableMcastSnooping     bool

	ovsdb client.Client
	br    *ovsconfig.OVSBridge
}

func (data *testData) setup(t *testing.T) {
	var err error
	// ensure that we timeout after a reasonable time duration if we cannot connect to the Unix
	// socket.
	ctx, cancel := context.WithTimeout(context.Background(), defaultConnectTimeout)
	defer cancel()
	data.ovsdb, err = ovsconfig.NewOVSDBConnectionUDS(ctx, UDSAddress)
	require.Nil(t, err, "Failed to open OVSDB connection")

	brOptions := []ovsconfig.OVSBridgeOption{}
	if len(data.requiredPortExternalIDs) > 0 {
		brOptions = append(brOptions, ovsconfig.WithRequiredPortExternalIDs(data.requiredPortExternalIDs...))
	}
	if data.enableMcastSnooping {
		brOptions = append(brOptions, ovsconfig.WithMcastSnooping())
	}
	// using the netdev datapath type does not impact test coverage but
	// ensures that the integration tests can be run with Docker Desktop on
	// macOS.
	brClient := ovsconfig.NewOVSBridge(bridgeName, "netdev", data.ovsdb, brOptions...)
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

	var err error

	start := time.Now()
	datapathID, err := data.br.WaitForDatapathID(3 * time.Second)
	end := time.Now()
	require.NoError(t, err)
	require.NotEmpty(t, datapathID)
	t.Logf("Waited %v for datapath ID to be assigned", end.Sub(start))

	// Test set fixed datapath ID
	expectedDatapathID, err := randomDatapathID()
	require.Nilf(t, err, "Failed to generate datapath ID: %s", err)
	err = data.br.SetDatapathID(expectedDatapathID)
	require.Nilf(t, err, "Set datapath id failed: %s", err)
	assert.Eventually(t, func() bool {
		datapathID, _ := data.br.GetDatapathID()
		return datapathID == expectedDatapathID
	}, 5*time.Second, 1*time.Second)

	vlanID := uint16(100)

	checkPorts := func(expectedCount int) {
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			portList, err := data.br.GetPortUUIDList()
			require.Nil(t, err, "Error when retrieving port list")
			assert.Equal(t, expectedCount, len(portList))
		}, 5*time.Second, 100*time.Millisecond)
	}

	deleteAllPorts(t, data.br)
	checkPorts(0)

	p1Name := "p1-" + uuid.Must(uuid.NewV4()).String()[:8]
	p2Name := "p2-" + uuid.Must(uuid.NewV4()).String()[:8]
	p3Name := "p3-" + uuid.Must(uuid.NewV4()).String()[:8]
	p4Name := "p4-" + uuid.Must(uuid.NewV4()).String()[:8]
	p5Name := "p5-" + uuid.Must(uuid.NewV4()).String()[:8]

	uuid1 := testCreatePort(t, data.br, p1Name, "internal", 0)
	uuid2 := testCreatePort(t, data.br, p2Name, "", 0)
	uuid3 := testCreatePort(t, data.br, p3Name, "vxlan", 0)
	uuid4 := testCreatePort(t, data.br, p4Name, "geneve", 0)
	uuid5 := testCreatePort(t, data.br, p5Name, "", vlanID)

	checkPorts(5)

	testDeletePort(t, data.br, uuid1)
	testDeletePort(t, data.br, uuid2)
	testDeletePort(t, data.br, uuid3)
	testDeletePort(t, data.br, uuid4)
	testDeletePort(t, data.br, uuid5)

	checkPorts(0)

	testCreatePort(t, data.br, p1Name, "internal", 0)
	testCreatePort(t, data.br, p2Name, "", 0)
	testCreatePort(t, data.br, p3Name, "vxlan", 0)
	testCreatePort(t, data.br, p4Name, "geneve", 0)
	testCreatePort(t, data.br, p5Name, "", vlanID)

	checkPorts(5)

	deleteAllPorts(t, data.br)

	checkPorts(0)
}

// TestOVSCreatePortRequiredExternalIDs verifies that port creation fails when a required externalID
// (the list is provided when creating the bridge client) is missing.
func TestOVSCreatePortRequiredExternalIDs(t *testing.T) {
	data := &testData{
		requiredPortExternalIDs: []string{"k1"},
	}
	data.setup(t)
	defer data.teardown(t)

	name := "p1"
	externalIDs := map[string]string{}
	_, err := data.br.CreatePort(name, name, externalIDs)
	require.ErrorContains(t, err, "missing required externalID")

	externalIDs["k1"] = "v1"
	_, err = data.br.CreatePort(name, name, externalIDs)
	assert.NoError(t, err)

	deleteAllPorts(t, data.br)
}

// TestOVSMcastSnooping verifies that multicast snooping is correctly enabled/disabled based on bridge configuration.
func TestOVSMcastSnooping(t *testing.T) {
	data := &testData{
		enableMcastSnooping: true,
	}
	data.setup(t)
	defer data.teardown(t)

	enabled, err := data.br.GetBridgeMcastSnoopingEnable()
	require.NoError(t, err)
	assert.True(t, enabled)

	data = &testData{
		enableMcastSnooping: false,
	}
	data.setup(t)

	enabled, err = data.br.GetBridgeMcastSnoopingEnable()
	require.NoError(t, err)
	assert.False(t, enabled)
}

// TestOVSPortExternalIDs tests getting and setting external IDs of OVS ports.
func TestOVSPortExternalIDs(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	name := "p1"
	externalIDs := map[string]string{
		"k1": "v1",
	}
	// Create an access port with VLAN ID 100 to ensure we have another mutable field populated
	portUUID, err := data.br.CreateAccessPort(name, name, externalIDs, 100)
	require.NoError(t, err)

	actualExternalIDs, err := data.br.GetPortExternalIDs(name)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"k1": "v1",
	}, actualExternalIDs)

	externalIDs["k2"] = "v2"

	require.NoError(t, data.br.SetPortExternalIDs(name, externalIDs))

	actualExternalIDs, err = data.br.GetPortExternalIDs(name)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"k1": "v1",
		"k2": "v2",
	}, actualExternalIDs)

	// Verify that partial updates did not overwrite other mutable fields like Tag (RAW safety check)
	assert.Eventually(t, func() bool {
		port := &ovsconfig.Port{UUID: portUUID}
		err = data.ovsdb.Get(context.Background(), port)
		if err != nil {
			return false
		}
		return port.Tag != nil && *port.Tag == 100
	}, 2*time.Second, 50*time.Millisecond, "Partial port updates should not overwrite other mutable fields like Tag")

	deleteAllPorts(t, data.br)
}

// TestOVSDeletePortIdempotent verifies that calling DeletePort on a non-existent port does not
// produce an error.
func TestOVSDeletePortIdempotent(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	deleteAllPorts(t, data.br)

	p1Name := "p1-" + uuid.Must(uuid.NewV4()).String()[:8]
	uuid := testCreatePort(t, data.br, p1Name, "internal", 0)
	testDeletePort(t, data.br, uuid)
	testDeletePort(t, data.br, uuid)
}

func TestOVSSchemaFields(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	uuid, err := data.br.CreateInternalPort("p-schema-test", 1, "", nil)
	require.NoError(t, err)

	// Wait for the port to be fully instantiated by OVS (ofport populated)
	_, err = data.br.GetOFPort("p-schema-test")
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		intf := &ovsconfig.Interface{Name: "p-schema-test"}
		err := data.ovsdb.Get(ctx, intf)
		require.NoError(c, err)
		assert.NotNil(c, intf.Status, "Interface Status should not be nil")
		if intf.Status != nil {
			assert.NotEmpty(c, intf.Status["driver_name"], "Interface driver_name should not be empty")
		}
		assert.NotNil(c, intf.Statistics, "Interface Statistics should not be nil")
		assert.NotNil(c, intf.MACInUse, "Interface MACInUse should not be nil")
		assert.NotNil(c, intf.AdminState, "Interface AdminState should not be nil")
		assert.NotNil(c, intf.LinkState, "Interface LinkState should not be nil")
		assert.NotNil(c, intf.IfIndex, "Interface IfIndex should not be nil")
		assert.NotNil(c, intf.MTU, "Interface MTU should not be nil")

		port := &ovsconfig.Port{Name: "p-schema-test"}
		err = data.ovsdb.Get(ctx, port)
		require.NoError(c, err)
		assert.Equal(c, uuid, port.UUID)

		bridge := &ovsconfig.Bridge{Name: data.br.GetBridgeName()}
		err = data.ovsdb.Get(ctx, bridge)
		require.NoError(c, err)
	}, 5*time.Second, 100*time.Millisecond)

	testDeletePort(t, data.br, uuid)
}

// TestOVSBridgeExternalIDs tests getting and setting external IDs of the OVS
// bridge.
func TestOVSBridgeExternalIDs(t *testing.T) {
	data := &testData{
		enableMcastSnooping: true,
	}
	data.setup(t)
	defer data.teardown(t)

	returnedIDs, err := data.br.GetExternalIDs()
	require.Nil(t, err, "Failed to get external IDs of the bridge")
	assert.Empty(t, returnedIDs)

	providedIDs := map[string]string{"k1": "v1", "k2": "v2"}
	err = data.br.SetExternalIDs(providedIDs)
	require.Nil(t, err, "Failed to set external IDs to the bridge")

	returnedIDs, err = data.br.GetExternalIDs()
	require.Nil(t, err, "Failed to get external IDs of the bridge")
	for k, v := range providedIDs {
		rv, ok := returnedIDs[k]
		if !assert.Truef(t, ok, "Returned external IDs do not include the expected ID: %s:%s", k, v) {
			continue
		}
		assert.Equalf(t, v, rv, "Returned external IDs include an ID with an unexpected value: %s:%s", k, v)
	}

	// Verify that partial updates did not overwrite other mutable fields like McastSnoopingEnable (RAW safety check)
	assert.Eventually(t, func() bool {
		bridge := &ovsconfig.Bridge{Name: data.br.GetBridgeName()}
		err = data.ovsdb.Get(context.Background(), bridge)
		if err != nil {
			return false
		}
		return bridge.McastSnoopingEnable
	}, 2*time.Second, 50*time.Millisecond, "Partial bridge updates should not overwrite other mutable fields like McastSnoopingEnable")
}

func TestMutateMapUpdatePattern(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	// This test proves that MutateOperationInsert on an OVSDB map DOES NOT act as an Upsert.
	// To update an existing key, we MUST perform a Delete operation followed by an Insert operation.
	mBridge := &ovsconfig.Bridge{
		Name: data.br.GetBridgeName(),
	}

	// Initial Insert
	mutations := []model.Mutation{
		{
			Field:   &mBridge.ExternalIDs,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   map[string]string{"upsert-key": "initial-value"},
		},
	}
	ops, err := data.ovsdb.Where(mBridge).Mutate(mBridge, mutations...)
	require.NoError(t, err)
	reply, err := data.ovsdb.Transact(context.Background(), ops...)
	require.NoError(t, err)
	_, err = ovsdb.CheckOperationResults(reply, ops)
	require.NoError(t, err)

	// Verify initial state
	require.Eventually(t, func() bool {
		bridge := &ovsconfig.Bridge{Name: data.br.GetBridgeName()}
		if err = data.ovsdb.Get(context.Background(), bridge); err != nil {
			return false
		}
		return bridge.ExternalIDs["upsert-key"] == "initial-value"
	}, 2*time.Second, 100*time.Millisecond)

	// Mutate with Insert ONLY for the existing key (Prove that it does NOT upsert)
	mutations = []model.Mutation{
		{
			Field:   &mBridge.ExternalIDs,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   map[string]string{"upsert-key": "updated-value"},
		},
	}

	ops, err = data.ovsdb.Where(mBridge).Mutate(mBridge, mutations...)
	require.NoError(t, err)

	reply, err = data.ovsdb.Transact(context.Background(), ops...)
	require.NoError(t, err)
	_, err = ovsdb.CheckOperationResults(reply, ops)
	require.NoError(t, err)

	// Verify that the value was NOT updated (proving direct insert does not act as upsert for existing keys)
	require.Eventually(t, func() bool {
		bridge := &ovsconfig.Bridge{Name: data.br.GetBridgeName()}
		if err = data.ovsdb.Get(context.Background(), bridge); err != nil {
			return false
		}
		return bridge.ExternalIDs["upsert-key"] == "initial-value"
	}, 2*time.Second, 100*time.Millisecond, "MutateOperationInsert does NOT overwrite existing keys in OVSDB")

	// Mutate with Delete AND Insert (The correct way to update an existing key)
	mutations = []model.Mutation{
		{
			Field:   &mBridge.ExternalIDs,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{"upsert-key"},
		},
		{
			Field:   &mBridge.ExternalIDs,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   map[string]string{"upsert-key": "updated-value"},
		},
	}

	ops, err = data.ovsdb.Where(mBridge).Mutate(mBridge, mutations...)
	require.NoError(t, err)

	reply, err = data.ovsdb.Transact(context.Background(), ops...)
	require.NoError(t, err)
	_, err = ovsdb.CheckOperationResults(reply, ops)
	require.NoError(t, err)

	// Verify that the value WAS updated this time
	require.Eventually(t, func() bool {
		bridge := &ovsconfig.Bridge{Name: data.br.GetBridgeName()}
		if err = data.ovsdb.Get(context.Background(), bridge); err != nil {
			return false
		}
		return bridge.ExternalIDs["upsert-key"] == "updated-value"
	}, 2*time.Second, 100*time.Millisecond, "Delete followed by Insert should correctly update the key")
}

func TestOVSOtherConfig(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	// First, ensure that we save existing other_config and delete them, to start from an empty map.
	// We will restore the saved other_config at the end of the test
	gotOtherConfigs, err := data.br.GetOVSOtherConfig()
	require.NoError(t, err)
	var savedOtherConfigKeys []string
	savedOtherConfigMap := make(map[string]string)
	for k, v := range gotOtherConfigs {
		savedOtherConfigKeys = append(savedOtherConfigKeys, k)
		savedOtherConfigMap[k] = v
	}
	require.NoError(t, data.br.DeleteOVSOtherConfig(savedOtherConfigKeys))
	restoreOtherConfigs := func() error {
		otherConfigs, err := data.br.GetOVSOtherConfig()
		if err != nil {
			return err
		}
		var currentKeys []string
		for k := range otherConfigs {
			currentKeys = append(currentKeys, k)
		}
		if err := data.br.DeleteOVSOtherConfig(currentKeys); err != nil {
			return err
		}
		return data.br.UpdateOVSOtherConfig(savedOtherConfigMap)
	}
	defer func() {
		require.NoError(t, restoreOtherConfigs(), "Error when restoring original OVS other_config, subsequent tests may fail")
	}()

	otherConfigs := map[string]string{"flow-restore-wait": "true", "foo1": "bar1"}
	err = data.br.UpdateOVSOtherConfig(otherConfigs)
	require.NoError(t, err, "Error when updating OVS other_config")

	require.Eventually(t, func() bool {
		gotOtherConfigs, err = data.br.GetOVSOtherConfig()
		if err != nil {
			return false
		}
		if len(gotOtherConfigs) != 2 {
			return false
		}
		return gotOtherConfigs["foo1"] == "bar1"
	}, 2*time.Second, 100*time.Millisecond)
	require.Equal(t, map[string]string{"flow-restore-wait": "true", "foo1": "bar1"}, gotOtherConfigs, "other_config mismatched")

	// Expect existing values to be updated and new values to be added.
	err = data.br.UpdateOVSOtherConfig(map[string]string{"flow-restore-wait": "false", "foo2": "bar2"})
	require.NoError(t, err, "Error when updating OVS other_config")

	require.Eventually(t, func() bool {
		gotOtherConfigs, err = data.br.GetOVSOtherConfig()
		if err != nil {
			return false
		}
		return gotOtherConfigs["foo2"] == "bar2"
	}, 2*time.Second, 100*time.Millisecond)
	require.Equal(t, map[string]string{"flow-restore-wait": "false", "foo1": "bar1", "foo2": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect to modify existing values and insert new values
	err = data.br.UpdateOVSOtherConfig(map[string]string{"foo2": "bar3", "foo3": "bar2"})
	require.NoError(t, err, "Error when updating OVS other_config")

	require.Eventually(t, func() bool {
		gotOtherConfigs, err = data.br.GetOVSOtherConfig()
		if err != nil {
			return false
		}
		return gotOtherConfigs["foo2"] == "bar3"
	}, 2*time.Second, 100*time.Millisecond)
	require.Equal(t, map[string]string{"flow-restore-wait": "false", "foo1": "bar1", "foo2": "bar3", "foo3": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect all keys in the map to be deleted, regardless of values.
	err = data.br.DeleteOVSOtherConfig([]string{"flow-restore-wait", "foo1", "foo2"})
	require.NoError(t, err, "Error when deleting OVS other_config")

	require.Eventually(t, func() bool {
		gotOtherConfigs, err = data.br.GetOVSOtherConfig()
		if err != nil {
			return false
		}
		_, exists := gotOtherConfigs["flow-restore-wait"]
		return !exists
	}, 2*time.Second, 100*time.Millisecond)
	require.Equal(t, map[string]string{"foo3": "bar2"}, gotOtherConfigs, "other_config mismatched")

	// Expect "foo3" will be deleted using empty string value pattern
	err = data.br.DeleteOVSOtherConfig([]string{"foo3", "foo4"})
	require.NoError(t, err, "Error when deleting OVS other_config")

	require.Eventually(t, func() bool {
		gotOtherConfigs, err = data.br.GetOVSOtherConfig()
		if err != nil {
			return false
		}
		_, exists := gotOtherConfigs["foo3"]
		return !exists
	}, 2*time.Second, 100*time.Millisecond)
	require.Empty(t, gotOtherConfigs, "other_config mismatched")
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

			name := "vxlan-" + uuid.Must(uuid.NewV4()).String()[:8]
			_, err := data.br.CreateTunnelPortExt(name, ovsconfig.VXLANTunnel, ofPortRequest, testCase.initialCsum, "", "", "", "", nil, nil)
			require.Nil(t, err, "Error when creating tunnel port")
			options, err := data.br.GetInterfaceOptions(name)
			require.Nil(t, err, "Error when getting interface options")
			actualInitialCsum, _ := strconv.ParseBool(options["csum"])
			require.Equal(t, testCase.initialCsum, actualInitialCsum)

			updatedOptions := map[string]string{}
			for k, v := range options {
				updatedOptions[k] = v
			}
			updatedOptions["csum"] = strconv.FormatBool(testCase.updatedCsum)
			err = data.br.SetInterfaceOptions(name, updatedOptions)
			require.Nil(t, err, "Error when setting interface options")
			require.Eventually(t, func() bool {
				options, err = data.br.GetInterfaceOptions(name)
				if err != nil {
					return false
				}
				actualCsum, _ := strconv.ParseBool(options["csum"])
				return testCase.updatedCsum == actualCsum
			}, 2*time.Second, 100*time.Millisecond)
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

			name := "vxlan-" + uuid.Must(uuid.NewV4()).String()[:8]
			extraOptions := make(map[string]string)
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

			updatedOptions := make(map[string]string)
			for k, v := range options {
				updatedOptions[k] = v
			}
			if testCase.updatedTunnelPort != 0 {
				updatedOptions["dst_port"] = strconv.Itoa(int(testCase.updatedTunnelPort))
			} else {
				delete(updatedOptions, "dst_port")
			}
			err = data.br.SetInterfaceOptions(name, updatedOptions)
			require.Nil(t, err, "Error when setting interface options")
			require.Eventually(t, func() bool {
				options, err = data.br.GetInterfaceOptions(name)
				if err != nil {
					return false
				}
				dstPort, exists = options["dst_port"]
				if testCase.updatedTunnelPort != 0 {
					actualTunnelPort, _ := strconv.ParseInt(dstPort, 10, 32)
					return int32(actualTunnelPort) == testCase.updatedTunnelPort
				} else {
					return !exists
				}
			}, 2*time.Second, 100*time.Millisecond)
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
	for _, port := range portList {
		err = br.DeletePort(port)
		require.Nil(t, err, "Error when deleting port %s", port)
	}
}

func TestOVSInterfaceUpdate(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	name := "p1-update-" + uuid.Must(uuid.NewV4()).String()[:8]
	externalIDs := map[string]string{"k1": "v1", "k2": "v2"}
	portUUID, err := data.br.CreateInternalPort(name, 0, "", externalIDs)
	require.NoError(t, err)

	// Test SetInterfaceMTU
	err = data.br.SetInterfaceMTU(name, 1400)
	assert.NoError(t, err)

	// Test SetInterfaceMAC
	mac, err := net.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err)
	err = data.br.SetInterfaceMAC(name, mac)
	assert.NoError(t, err)

	// Test SetInterfaceType
	err = data.br.SetInterfaceType(name, "dummy")
	assert.NoError(t, err)

	// Test SetInterfaceOptions
	options := map[string]string{"opt1": "val1"}
	err = data.br.SetInterfaceOptions(name, options)
	assert.NoError(t, err)

	// Verify that partial updates do not overwrite each other (RAW safety check)
	assert.Eventually(t, func() bool {
		intf := &ovsconfig.Interface{Name: name}
		err = data.ovsdb.Get(context.Background(), intf)
		if err != nil {
			return false
		}
		return intf.MTURequest != nil && *intf.MTURequest == 1400 &&
			intf.MAC != nil && *intf.MAC == "00:11:22:33:44:55" &&
			intf.Type == "dummy" &&
			intf.Options != nil && intf.Options["opt1"] == "val1"
	}, 2*time.Second, 50*time.Millisecond, "Partial interface updates should not overwrite other mutable fields")

	// Verify NotFound errors for non-existent interface
	err = data.br.SetInterfaceMTU("non-existent-port", 1400)
	assert.ErrorIs(t, err, client.ErrNotFound)

	err = data.br.SetInterfaceMAC("non-existent-port", mac)
	assert.ErrorIs(t, err, client.ErrNotFound)

	err = data.br.SetInterfaceType("non-existent-port", "dummy")
	assert.ErrorIs(t, err, client.ErrNotFound)

	err = data.br.SetInterfaceOptions("non-existent-port", options)
	assert.NoError(t, err)

	testDeletePort(t, data.br, portUUID)
}

func TestOVSGetOFPortNotFound(t *testing.T) {
	data := &testData{}
	data.setup(t)
	defer data.teardown(t)

	_, err := data.br.GetOFPort("non-existent")
	assert.ErrorIs(t, err, client.ErrNotFound)
}

var ofPortRequest int32 = 1

func testCreatePort(t *testing.T, br *ovsconfig.OVSBridge, name string, ifType string, vlanID uint16) string {
	var err error
	var uuid string
	var externalIDs map[string]string
	var ifName = name

	switch ifType {
	case "":
		externalIDs = map[string]string{"k1": "v1", "k2": "v2"}
		if vlanID == 0 {
			uuid, err = br.CreatePort(name, name, externalIDs)
		} else {
			uuid, err = br.CreateAccessPort(name, name, externalIDs, vlanID)
		}
	case "internal":
		externalIDs = map[string]string{"k1": "v1", "k2": "v2"}
		uuid, err = br.CreateInternalPort(name, ofPortRequest, "", externalIDs)
	case "vxlan":
		externalIDs = map[string]string{}
		uuid, err = br.CreateTunnelPortExt(name, ovsconfig.VXLANTunnel, ofPortRequest, false, "", "", "", "", nil, externalIDs)
	case "geneve":
		externalIDs = map[string]string{}
		uuid, err = br.CreateTunnelPortExt(name, ovsconfig.GeneveTunnel, ofPortRequest, false, "", "", "", "", nil, externalIDs)
	}

	require.Nilf(t, err, "Failed to create %s port: %s", ifType, err)

	ofPort, err := br.GetOFPort(name)
	if ifType != "" {
		require.NoErrorf(t, err, "Failed to get ofport for %s port: %s", ifType, err)
		assert.Equal(t, ofPortRequest, ofPort, "ofport does not match the requested value for %s port", ifType)
		ofPortRequest++
	} else {
		require.Error(t, err, "GetOFPort should return an error for a port without a valid interface backing")
	}

	if ifType != "" {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			p, err := br.GetPortData(uuid, ifName)
			if err != nil {
				c.Errorf("Failed to get port (%s, %s): %v", uuid, ifName, err)
				return
			}
			if p == nil {
				c.Errorf("Port (%s, %s) not found", uuid, ifName)
				return
			}
			if p.OFPort == 0 {
				c.Errorf("OFPort is 0")
				return
			}
			assert.Equal(c, ofPort, p.OFPort)
		}, 5*time.Second, 100*time.Millisecond)
	} else {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			p, err := br.GetPortData(uuid, ifName)
			if err != nil {
				c.Errorf("Failed to get port (%s, %s): %v", uuid, ifName, err)
				return
			}
			if p == nil {
				c.Errorf("Port (%s, %s) not found", uuid, ifName)
				return
			}
		}, 5*time.Second, 100*time.Millisecond)
	}

	var port *ovsconfig.OVSPortData
	port, err = br.GetPortData(uuid, ifName)
	require.NoError(t, err)

	if port == nil {
		t.Fatalf("Port data was not populated in cache")
	}

	assert.Equal(t, name, port.Name)
	assert.Equal(t, ifName, port.IFName)
	assert.Equal(t, vlanID, port.VLANID)

	for k, v := range externalIDs {
		rv, ok := port.ExternalIDs[k]
		if !assert.Truef(t, ok, "Returned port does not include the expected external id: %s:%s", k, v) {
			continue
		}
		assert.Equalf(t, v, rv, "Returned port has an external id with an unexpected value: %s:%s", k, v)
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

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		uuidList, err := br.GetPortUUIDList()
		require.Nil(c, err, "Error when retrieving port list")
		assert.NotContains(c, uuidList, uuid, "Found deleted port in port list")
	}, 5*time.Second, 100*time.Millisecond)
}

func TestMain(m *testing.M) {
	flag.StringVar(&UDSAddress, "ovsdb-socket", defaultOVSDBAddress, "Unix domain server socket named file for OVSDB")
	flag.StringVar(&bridgeName, "br-name", defaultBridgeName, "Bridge name to use for tests")
	os.Exit(m.Run())
}
