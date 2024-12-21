//go:build linux
// +build linux

// Copyright 2023 Antrea Authors
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

package secondarynetwork

import (
	"fmt"
	"net"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn = net.InterfaceByName
)

// Initialize sets up OVS bridges.
func (c *Controller) Initialize() error {
	// We only support moving and restoring of interface configuration to OVS Bridge for the single physical interface case.
	if len(c.secNetConfig.OVSBridges) != 0 {
		phyInterfaces := make([]string, len(c.secNetConfig.OVSBridges[0].PhysicalInterfaces))
		copy(phyInterfaces, c.secNetConfig.OVSBridges[0].PhysicalInterfaces)
		if len(phyInterfaces) == 1 {
			bridgedName, _, err := util.PrepareHostInterfaceConnection(
				c.ovsBridgeClient,
				phyInterfaces[0],
				0,
				map[string]interface{}{
					interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
				},
				0, // do not request a specific MTU
			)
			if err != nil {
				return err
			}
			phyInterfaces[0] = bridgedName
		}
		if err := connectPhyInterfacesToOVSBridge(c.ovsBridgeClient, phyInterfaces); err != nil {
			return err
		}
	}
	return nil
}

// Restore restores interface configuration from secondary-bridge back to host-interface.
func (c *Controller) Restore() {
	if len(c.secNetConfig.OVSBridges) != 0 && len(c.secNetConfig.OVSBridges[0].PhysicalInterfaces) == 1 {
		util.RestoreHostInterfaceConfiguration(c.secNetConfig.OVSBridges[0].BridgeName, c.secNetConfig.OVSBridges[0].PhysicalInterfaces[0])
	}
}

func connectPhyInterfacesToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []string) error {
	for _, phyInterface := range phyInterfaces {
		if _, err := interfaceByNameFn(phyInterface); err != nil {
			return fmt.Errorf("failed to get interface %s: %v", phyInterface, err)
		}
	}

	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	for i, phyInterface := range phyInterfaces {
		if _, err := ovsBridgeClient.GetOFPort(phyInterface, false); err == nil {
			klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skip the configuration", "device", phyInterface)
			continue
		}

		if _, err := ovsBridgeClient.CreateUplinkPort(phyInterface, int32(i), externalIDs); err != nil {
			return fmt.Errorf("failed to create OVS uplink port %s: %v", phyInterface, err)
		}
		klog.InfoS("Physical interface added to secondary OVS bridge", "device", phyInterface)
	}
	return nil
}
