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

package agent

import (
	"fmt"
	"net"
	"os"
	"testing"

	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"

	"github.com/vmware-tanzu/antrea/pkg/agent/cniserver"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig/testing"
)

func TestGetNodeName(t *testing.T) {
	hostName, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to retrieve hostname, %v", err)
	}
	testTable := map[string]string{
		"node1":     "node1",
		"node_12":   "node_12",
		"":          hostName,
		"node-1234": "node-1234",
	}

	for k, v := range testTable {
		compareNodeName(k, v, t)
	}
}

func compareNodeName(k, v string, t *testing.T) {
	if k != "" {
		_ = os.Setenv(NodeNameEnvKey, k)
		defer os.Unsetenv(NodeNameEnvKey)
	}
	nodeName, err := getNodeName()
	if err != nil {
		t.Errorf("Failure with expected name %s, %v", k, err)
		return
	}
	if nodeName != v {
		t.Errorf("Failed to retrieve nodename, want: %s, get: %s", v, nodeName)
	}
}

func newAgentInitializer(ovsBridgeClient ovsconfig.OVSBridgeClient, ifaceStore interfacestore.InterfaceStore) *Initializer {
	return &Initializer{ovsBridgeClient: ovsBridgeClient, ifaceStore: ifaceStore, hostGateway: "gw0"}
}

func convertExternalIDMap(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v.(string)
	}
	return out
}

func TestInitstore(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	mockOVSBridgeClient.EXPECT().GetPortList().Return(nil, ovsconfig.NewTransactionError(fmt.Errorf("Failed to list OVS ports"), true))

	store := interfacestore.NewInterfaceStore()
	initializer := newAgentInitializer(mockOVSBridgeClient, store)

	err := initializer.initInterfaceStore()
	if err == nil {
		t.Errorf("Failed to handle OVS return error")
	}

	uuid1 := uuid.New().String()
	uuid2 := uuid.New().String()
	p1MAC := "11:22:33:44:55:66"
	p1IP := "1.1.1.1"
	p2MAC := "11:22:33:44:55:77"
	p2IP := "1.1.1.2"
	p1NetMAC, _ := net.ParseMAC(p1MAC)
	p1NetIP := net.ParseIP(p1IP)
	p2NetMAC, _ := net.ParseMAC(p2MAC)
	p2NetIP := net.ParseIP(p2IP)

	ovsPort1 := ovsconfig.OVSPortData{UUID: uuid1, Name: "p1", IFName: "p1", OFPort: 1,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p1", uuid1, "pod1", "ns1", p1NetMAC, p1NetIP)))}
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid2, Name: "p2", IFName: "p2", OFPort: 2,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p2", uuid2, "pod2", "ns2", p2NetMAC, p2NetIP)))}
	initOVSPorts := []ovsconfig.OVSPortData{ovsPort1, ovsPort2}

	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, ovsconfig.NewTransactionError(fmt.Errorf("Failed to list OVS ports"), true))
	err = initializer.initInterfaceStore()
	if store.Len() != 0 {
		t.Errorf("Failed to load OVS port in store")
	}

	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, nil)
	err = initializer.initInterfaceStore()
	if store.Len() != 2 {
		t.Errorf("Failed to load OVS port in store")
	}
	container1, found1 := store.GetInterface("p1")
	if !found1 {
		t.Errorf("Failed to load OVS port into local store")
	} else if container1.OFPort != 1 || container1.IP.String() != p1IP || container1.MAC.String() != p1MAC || container1.InterfaceName != "p1" {
		t.Errorf("Failed to load OVS port configuration into local store")
	}
	_, found2 := store.GetInterface("p2")
	if !found2 {
		t.Errorf("Failed to load OVS port into local store")
	}
}
