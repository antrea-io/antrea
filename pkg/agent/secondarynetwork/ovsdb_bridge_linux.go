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

	"github.com/ovn-kubernetes/libovsdb/client"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

// findStartupSecondaryBridge returns the secondary bridge which already exists
// when the Agent starts. A managed bridge takes precedence over a legacy bridge
// matching the desired name. The boolean return value indicates that the legacy
// bridge must be marked as managed when its client is initialized.
func findStartupSecondaryBridge(ovsdbClient client.Client, desiredBridgeName string) (string, bool, error) {
	bridges, err := ovsconfig.ListOVSBridges(ovsdbClient)
	if err != nil {
		return "", false, fmt.Errorf("failed to query OVSDB Bridge table: %w", err)
	}
	return selectStartupSecondaryBridge(bridges, desiredBridgeName)
}

func selectStartupSecondaryBridge(bridges []ovsconfig.OVSBridgeData, desiredBridgeName string) (string, bool, error) {
	var managedBrNames []string
	legacyDesiredExists := false
	for _, bridge := range bridges {
		if bridge.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaSecondaryBridge {
			managedBrNames = append(managedBrNames, bridge.Name)
		}
		if bridge.Name == desiredBridgeName {
			legacyDesiredExists = true
		}
	}

	if len(managedBrNames) == 1 {
		return managedBrNames[0], false, nil
	}
	if len(managedBrNames) > 1 {
		for _, name := range managedBrNames {
			if name == desiredBridgeName {
				klog.Warningf("Found multiple Antrea-managed secondary OVS bridges (%v), using %q as it matches the desired bridge name", managedBrNames, desiredBridgeName)
				return desiredBridgeName, false, nil
			}
		}
		klog.Warningf("Found multiple Antrea-managed secondary OVS bridges (%v) with none matching the desired bridge name %q; not adopting any", managedBrNames, desiredBridgeName)
		// Fall through to legacy check.
	}
	if legacyDesiredExists {
		return desiredBridgeName, true, nil
	}
	return "", false, nil
}
