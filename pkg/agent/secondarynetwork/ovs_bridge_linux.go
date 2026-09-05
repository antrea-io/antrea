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
	"errors"
	"fmt"

	"github.com/ovn-kubernetes/libovsdb/client"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/agent/util"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

// findStartupSecondaryBridge returns the secondary bridge which already exists
// when the Agent starts. A managed bridge takes precedence over a legacy bridge
// matching the desired name.
func findStartupSecondaryBridge(ovsdbClient client.Client, desiredBridgeName string) (string, error) {
	bridges, err := ovsconfig.ListOVSBridges(ovsdbClient)
	if err != nil {
		return "", fmt.Errorf("failed to query OVSDB Bridge table: %w", err)
	}
	return selectStartupSecondaryBridge(bridges, desiredBridgeName)
}

func selectStartupSecondaryBridge(bridges []ovsconfig.OVSBridgeData, desiredBridgeName string) (string, error) {
	var managedBrName string
	legacyDesiredExists := false
	for _, bridge := range bridges {
		if bridge.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaSecondaryBridge {
			if managedBrName != "" {
				return "", fmt.Errorf(
					"found multiple Antrea-managed secondary OVS bridges: %s and %s",
					managedBrName,
					bridge.Name,
				)
			}
			managedBrName = bridge.Name
		}
		if bridge.Name == desiredBridgeName {
			legacyDesiredExists = true
		}
	}
	if managedBrName != "" {
		return managedBrName, nil
	}
	if legacyDesiredExists {
		return desiredBridgeName, nil
	}
	return "", nil
}

// clearStaleTrunks calls SetPortTrunks(nil) for any port that has a non-empty
// trunk list in OVS but whose desired config carries no AllowedVLANs. This
// handles the agent-restart scenario where the OVS port was previously configured
// as a trunk but the current desired config no longer requires it.
// portList and existingPorts come from the caller's GetPortList result; the
// latter skips ports already removed earlier in the same reconciliation.
func clearStaleTrunks(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []agenttypes.PhysicalInterfaceConfig, portList []ovsconfig.OVSPortData, existingPorts map[string]ovsconfig.OVSPortData) error {
	// Build a set of interfaces that should NOT have trunk VLANs.
	noTrunkDesired := sets.New[string]()
	for _, pi := range phyInterfaces {
		if len(pi.AllowedVLANs) == 0 {
			noTrunkDesired.Insert(pi.Name)
		}
	}
	if noTrunkDesired.Len() == 0 {
		return nil
	}

	for _, p := range portList {
		if _, exists := existingPorts[p.IFName]; !exists {
			continue
		}
		// Match by IFName (interface name) against the desired set, but use p.Name
		// (Port name) for SetPortTrunks which filters the Port table by port name.
		// For standard uplink ports the two names are identical; being explicit here
		// avoids any confusion if they ever diverge.
		if !noTrunkDesired.Has(p.IFName) {
			continue
		}
		if len(p.Trunks) == 0 {
			continue
		}
		if err := ovsBridgeClient.SetPortTrunks(p.Name, nil); err != nil {
			return fmt.Errorf("failed to clear stale trunk VLANs for OVS port %s: %w", p.Name, err)
		}
		klog.InfoS("Cleared trunk VLAN list on secondary OVS bridge port", "device", p.Name)
	}
	return nil
}

// createOVSBridge creates or attaches to an OVS bridge with the given name.
// The bridge is always marked as an Antrea-managed secondary bridge: Create()
// sets the external ID on an existing bridge as well, which is how a legacy
// bridge gets converted into a managed one. Create() does not touch multicast
// snooping on an existing bridge; the desired setting is applied explicitly by
// the caller with SetMcastSnooping.
func createOVSBridge(
	bridgeName string,
	ovsdbClient client.Client,
) (ovsconfig.OVSBridgeClient, error) {
	bridgeClient := newOVSBridgeFn(bridgeName, ovsconfig.OVSDatapathSystem, ovsdbClient,
		ovsconfig.WithExternalIDs(map[string]string{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaSecondaryBridge,
		}))
	if err := bridgeClient.Create(); err != nil {
		return nil, fmt.Errorf("failed to create OVS bridge %s: %w", bridgeName, err)
	}
	klog.InfoS("OVS bridge ready", "bridge", bridgeName)
	return bridgeClient, nil
}

// deleteBridge tears down any host-connection interfaces found on the
// bridge and deletes it. PodController keeps the bridge in draining mode until
// this function succeeds, preventing new container Ports from being added before
// bridge deletion.
func deleteBridge(client ovsconfig.OVSBridgeClient) error {
	brName := client.GetBridgeName()
	// Query OVSDB to find and restore host-connection interfaces before
	// deleting the bridge. These host/uplink ports are not Pod secondary
	// interfaces and are not loaded into PodController's interfaceStore, which
	// tracks antrea-type=container ports only; OVSDB is the source of truth
	// after an agent restart.
	// A host-connection is identified by an internal port with antrea-type=host,
	// which covers the single-interface path where PrepareHostInterfaceConnection
	// renamed the kernel NIC.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list ports on bridge %s before deletion: %w", brName, err)
	}
	for _, p := range portList {
		if p.IFType == "internal" && p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaHost {
			klog.InfoS("Restoring host interface before bridge deletion",
				"interface", p.IFName, "bridge", brName)
			if err := restoreHostInterfaceConfigFn(brName, p.IFName); err != nil {
				return fmt.Errorf("failed to restore host interface %s before deleting bridge %s: %w",
					p.IFName, brName, err)
			}
		}
	}
	if err := client.Delete(); err != nil {
		return fmt.Errorf("failed to delete OVS bridge %s: %w", brName, err)
	}
	klog.InfoS("OVS bridge deleted", "bridge", brName)
	return nil
}

func updatePhysicalInterfaces(client ovsconfig.OVSBridgeClient, desired *agenttypes.OVSBridgeConfig) error {
	// Build a map of currently present ports on the bridge, keyed by interface name.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %w", desired.BridgeName, err)
	}
	existingPorts := make(map[string]ovsconfig.OVSPortData, len(portList))
	for _, p := range portList {
		existingPorts[p.IFName] = p
	}

	if err := restoreStaleHostConnections(desired, portList, existingPorts); err != nil {
		return err
	}

	bridgePhysInterfaces, prepareErr := prepareBridgePhysicalInterfaces(client, desired, existingPorts)
	if prepareErr != nil {
		return prepareErr
	}

	desiredBridgeIfaces := sets.New[string]()
	for _, pi := range bridgePhysInterfaces {
		desiredBridgeIfaces.Insert(pi.Name)
	}

	// Step 1: remove Antrea-managed uplink ports observed in OVSDB but no longer desired.
	// Host-connection pairs are restored above instead of being deleted as raw OVS ports.
	var toRemoveUUIDs []string
	var toRemoveNames []string
	for _, p := range portList {
		if _, stillExists := existingPorts[p.IFName]; !stillExists {
			continue
		}
		if p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaUplink {
			continue
		}
		if desiredBridgeIfaces.Has(p.IFName) {
			continue
		}
		toRemoveUUIDs = append(toRemoveUUIDs, p.UUID)
		toRemoveNames = append(toRemoveNames, p.IFName)
	}
	if len(toRemoveUUIDs) > 0 {
		if err := client.DeletePorts(toRemoveUUIDs); err != nil {
			return fmt.Errorf("failed to remove OVS ports %v from bridge %s: %w",
				toRemoveNames, desired.BridgeName, err)
		}
		for _, name := range toRemoveNames {
			klog.InfoS("Physical interface removed from secondary OVS bridge", "device", name)
			// Keep existingPorts in sync so Step 3 does not skip re-adding an interface
			// that was just removed (remove-then-re-add scenario).
			delete(existingPorts, name)
		}
	}

	// Step 2: clear trunk VLANs on existing ports whose desired config has no AllowedVLANs.
	// clearStaleTrunks only calls SetPortTrunks when the port genuinely has trunks set,
	// so it is safe to call unconditionally.
	if err := clearStaleTrunks(client, bridgePhysInterfaces, portList, existingPorts); err != nil {
		return fmt.Errorf("failed to reconcile trunk configuration on secondary OVS bridge %s: %w",
			desired.BridgeName, err)
	}

	// Step 3: add new ports and update the trunk VLAN list on existing ports that
	// have AllowedVLANs.  connectPhyInterfacesToOVSBridge creates the port when it
	// does not yet exist, and calls SetPortTrunks when it does and AllowedVLANs is
	// non-empty.
	var toConnect []agenttypes.PhysicalInterfaceConfig
	for _, pi := range bridgePhysInterfaces {
		if _, alreadyExists := existingPorts[pi.Name]; !alreadyExists || len(pi.AllowedVLANs) > 0 {
			toConnect = append(toConnect, pi)
		}
	}
	if len(toConnect) > 0 {
		if err := connectPhyInterfacesToOVSBridge(client, toConnect); err != nil {
			return fmt.Errorf("failed to connect physical interfaces to secondary OVS bridge %s: %w",
				desired.BridgeName, err)
		}
		klog.InfoS("Connected physical interfaces to secondary OVS bridge",
			"bridge", desired.BridgeName, "interfaces", toConnect)
	}
	return nil
}

// restoreStaleHostConnections restores Antrea-managed host-connection port pairs
// (e.g. "eth1" internal host port + "eth1~" uplink) observed in OVSDB to their
// original host form. A single-interface bridge moves the host IP to the internal
// host port and renames the kernel interface to "eth1~"; a multi-interface bridge
// attaches the host interfaces as plain uplink ports instead. Any leftover
// host-connection pair (from a previous single-interface config or a
// single-interface to multi-interface migration) must therefore be restored:
// RestoreHostInterfaceConfiguration removes both OVS ports and renames "eth1~"
// back to "eth1" on the host. The restored interfaces are removed from
// existingPorts, so the caller does not re-add them later.
func restoreStaleHostConnections(
	desired *agenttypes.OVSBridgeConfig,
	portList []ovsconfig.OVSPortData,
	existingPorts map[string]ovsconfig.OVSPortData,
) error {
	desiredIfaces := sets.New[string]()
	for _, pi := range desired.PhysicalInterfaces {
		desiredIfaces.Insert(pi.Name)
	}
	keepSingleHostConnection := len(desired.PhysicalInterfaces) == 1

	portsByName := make(map[string]ovsconfig.OVSPortData, len(portList))
	for _, p := range portList {
		portsByName[p.IFName] = p
	}
	for _, p := range portList {
		if p.IFType != "internal" ||
			p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaHost {
			continue
		}
		bridgedName := util.GenerateUplinkInterfaceName(p.IFName)
		sibling, siblingExists := portsByName[bridgedName]
		// When there is a single desired physical interface which is already connected
		// to the bridge as a host connection, the connection is the desired state and
		// does not need to be restored.
		if !siblingExists ||
			sibling.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaUplink ||
			keepSingleHostConnection && desiredIfaces.Has(p.IFName) {
			continue
		}
		klog.InfoS("Detected stale host-connection interface, restoring it before re-adding as uplink",
			"interface", p.IFName, "bridge", desired.BridgeName)
		if err := restoreHostInterfaceConfigFn(desired.BridgeName, p.IFName); err != nil {
			return fmt.Errorf("failed to restore stale host-connection interface %s on bridge %s: %w",
				p.IFName, desired.BridgeName, err)
		}
		delete(existingPorts, p.IFName)
		delete(existingPorts, bridgedName)
	}
	return nil
}

func prepareBridgePhysicalInterfaces(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
	existingPorts map[string]ovsconfig.OVSPortData,
) ([]agenttypes.PhysicalInterfaceConfig, error) {
	if len(desired.PhysicalInterfaces) == 1 {
		iface := desired.PhysicalInterfaces[0]
		bridgedName := util.GenerateUplinkInterfaceName(iface.Name)
		// Recover from a partially completed host-interface setup where the
		// kernel interface was renamed but the OVS ports were never created.
		if _, interfacePortExists := existingPorts[iface.Name]; !interfacePortExists {
			if _, uplinkPortExists := existingPorts[bridgedName]; !uplinkPortExists {
				if _, err := interfaceByNameFn(iface.Name); err != nil {
					if _, err := interfaceByNameFn(bridgedName); err == nil {
						klog.InfoS("Recovering stale renamed host interface",
							"bridge", desired.BridgeName,
							"interface", iface.Name,
							"uplink", bridgedName,
						)
						if err := renameInterfaceFn(bridgedName, iface.Name); err != nil {
							return nil, fmt.Errorf("failed to restore host interface %s from %s: %w",
								iface.Name, bridgedName, err)
						}
					}
				}
			}
		}
		if _, exists := existingPorts[bridgedName]; exists {
			return []agenttypes.PhysicalInterfaceConfig{
				{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
			}, nil
		}
		// PrepareHostInterfaceConnection creates the internal host port before the
		// physical uplink port is added to OVS. A failure between these operations
		// leaves a valid host connection with the renamed kernel uplink but no OVS
		// uplink port. Resume from that state instead of trying to rename the host
		// interface a second time.
		if port, exists := existingPorts[iface.Name]; exists &&
			port.IFType == "internal" &&
			port.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaHost {
			if _, err := interfaceByNameFn(bridgedName); err == nil {
				klog.InfoS("Resuming incomplete host interface connection",
					"bridge", desired.BridgeName, "interface", iface.Name, "uplink", bridgedName,
					"internalPortPresent", true, "kernelUplinkPresent", true, "ovsUplinkPortPresent", false)
				return []agenttypes.PhysicalInterfaceConfig{
					{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
				}, nil
			}
		}
		if port, exists := existingPorts[iface.Name]; exists && port.IFType != "internal" {
			if err := ovsBridgeClient.DeletePorts([]string{port.UUID}); err != nil {
				return nil, fmt.Errorf("failed to remove OVS port %s from bridge %s before host connection setup: %w",
					iface.Name, desired.BridgeName, err)
			}
			// Keep the caller's observed-port maps in sync with the OVSDB change so
			// updatePhysicalInterfaces can add the generated uplink port later in
			// the same reconciliation.
			delete(existingPorts, iface.Name)
			klog.InfoS("Physical interface removed from secondary OVS bridge before host connection setup",
				"device", iface.Name, "bridge", desired.BridgeName)
		}

		klog.InfoS("Preparing host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", iface.Name, "uplink", bridgedName)
		bridgedName, alreadyExists, err := prepareHostInterfaceConnectionFn(
			ovsBridgeClient,
			iface.Name,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare host interface %s for secondary OVS bridge %s: %w",
				iface.Name, desired.BridgeName, err)
		}
		klog.InfoS("Prepared host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", iface.Name,
			"uplink", bridgedName, "alreadyExists", alreadyExists)
		return []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
		}, nil
	}

	return desired.PhysicalInterfaces, nil
}

// connectPhyInterfacesToOVSBridge connects each physical interface to the OVS
// bridge as an uplink port, creating it if absent and updating its trunk VLAN
// list when AllowedVLANs is non-empty.
func connectPhyInterfacesToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []agenttypes.PhysicalInterfaceConfig) error {
	for _, pi := range phyInterfaces {
		if _, err := interfaceByNameFn(pi.Name); err != nil {
			return fmt.Errorf("failed to get interface %s: %w", pi.Name, err)
		}
	}

	externalIDs := map[string]string{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	for _, pi := range phyInterfaces {
		_, err := ovsBridgeClient.GetOFPort(pi.Name)
		if err != nil && !errors.Is(err, client.ErrNotFound) {
			return fmt.Errorf("failed to get OFPort for interface %s: %w", pi.Name, err)
		}
		notConnected := errors.Is(err, client.ErrNotFound)

		if len(pi.AllowedVLANs) > 0 {
			if notConnected {
				// Pass ofPortRequest=0 so OVS auto-assign the OF port number.
				// Pinning a number derived from the loop index would collide across
				// reconciliation cycles when the interface list is a filtered subset.
				if _, err := ovsBridgeClient.CreateTrunkPort(pi.Name, 0, pi.AllowedVLANs, externalIDs); err != nil {
					return fmt.Errorf("failed to create OVS trunk port %s: %w", pi.Name, err)
				}
				klog.InfoS("Physical interface added to secondary OVS bridge in trunk mode", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			} else {
				if err := ovsBridgeClient.SetPortTrunks(pi.Name, pi.AllowedVLANs); err != nil {
					return fmt.Errorf("failed to update trunk VLANs for OVS port %s: %w", pi.Name, err)
				}
				klog.InfoS("Updated trunk VLAN list on secondary OVS bridge port", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			}
			continue
		}

		if notConnected {
			// Pass ofPortRequest=0 so OVS auto-assign the OF port number.
			if _, err := ovsBridgeClient.CreateUplinkPort(pi.Name, 0, externalIDs); err != nil {
				return fmt.Errorf("failed to create OVS uplink port %s: %w", pi.Name, err)
			}
			klog.InfoS("Physical interface added to secondary OVS bridge", "device", pi.Name)
		} else {
			klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skipping", "device", pi.Name)
		}
	}
	return nil
}
