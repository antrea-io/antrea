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
	"antrea.io/antrea/pkg/agent/interfacestore"
	secondaryutil "antrea.io/antrea/pkg/agent/secondarynetwork/util"
	"antrea.io/antrea/pkg/agent/util"
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
		if err := secondaryutil.ConnectPhyInterfacesToOVSBridge(c.ovsBridgeClient, phyInterfaces); err != nil {
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
