//go:build linux
// +build linux

// Copyright 2026 Antrea Authors
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

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

// findManagedSecondaryBridge queries OVSDB for a bridge whose external_ids
// contain antrea-type=secondary-bridge, and returns its name.
// It returns an empty string when no such bridge exists.
func findManagedSecondaryBridge(ovsdbConn *ovsdb.OVSDB) (string, error) {
	bridges, err := ovsconfig.ListOVSBridges(ovsdbConn)
	if err != nil {
		return "", fmt.Errorf("failed to query OVSDB Bridge table: %w", err)
	}

	var managedBrName string
	for _, bridge := range bridges {
		if bridge.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaSecondaryBridge {
			if managedBrName != "" {
				return "", fmt.Errorf("found multiple Antrea-managed secondary OVS bridges: %s and %s", managedBrName, bridge.Name)
			}
			managedBrName = bridge.Name
		}
	}
	return managedBrName, nil
}

func adoptSecondaryBridge(bridgeCfg *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
	if bridgeCfg == nil {
		return "", nil
	}
	externalIDs, exists, err := ovsconfig.GetOVSBridgeExternalIDs(ovsdbConn, bridgeCfg.BridgeName)
	if err != nil {
		return "", fmt.Errorf("failed to query OVSDB Bridge table for bridge %s: %w", bridgeCfg.BridgeName, err)
	}
	if !exists {
		return "", nil
	}

	updatedExternalIDs := ovsconfig.MergeExternalIDs(externalIDs, map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaSecondaryBridge,
	})
	if err := ovsconfig.SetOVSBridgeExternalIDs(ovsdbConn, bridgeCfg.BridgeName, updatedExternalIDs); err != nil {
		return "", fmt.Errorf("failed to mark OVS bridge %s as an Antrea-managed secondary bridge: %w", bridgeCfg.BridgeName, err)
	}

	klog.InfoS("Adopted existing secondary OVS bridge from static configuration", "bridge", bridgeCfg.BridgeName)
	return bridgeCfg.BridgeName, nil
}
