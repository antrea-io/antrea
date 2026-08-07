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

type restoredHostConnection struct {
	hostIFName   string
	uplinkIFName string
}

// restoreStaleHostConnections detects and tears down Antrea-managed host-connection
// port pairs (e.g. "eth1" internal host port + "eth1~" uplink) that were created
// by a previous single-interface setup but are no longer needed. A multi-interface
// bridge does not move the host IP to the bridge: the host interfaces are attached
// as plain uplink ports, so any leftover host-connection pair (from an earlier
// single-interface config or from a single-interface to multi-interface migration)
// must be restored to its original host form. It calls
// RestoreHostInterfaceConfiguration for each such interface, which removes both
// OVS ports and renames "eth1~" back to "eth1" on the host.
func restoreStaleHostConnections(bridgeName string, ovsBridgeClient ovsconfig.OVSBridgeClient) error {
	portList, err := ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", bridgeName, err)
	}

	_, restoreErr := restoreStaleHostConnectionsFromPortList(bridgeName, portList, nil)
	return restoreErr
}

func restoreStaleHostConnectionsFromPortList(
	bridgeName string,
	portList []ovsconfig.OVSPortData,
	shouldSkip func(hostIFName string) bool,
) ([]restoredHostConnection, error) {
	portsByName := make(map[string]ovsconfig.OVSPortData, len(portList))
	for _, p := range portList {
		portsByName[p.IFName] = p
	}

	var restored []restoredHostConnection
	for _, p := range portList {
		if p.IFType != "internal" ||
			p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaHost {
			continue
		}
		bridgedName := util.GenerateUplinkInterfaceName(p.IFName)
		sibling, siblingExists := portsByName[bridgedName]
		if !siblingExists ||
			sibling.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaUplink ||
			shouldSkip != nil && shouldSkip(p.IFName) {
			continue
		}
		klog.InfoS("Detected stale host-connection interface, restoring it before re-adding as uplink",
			"interface", p.IFName, "bridge", bridgeName)
		if err := restoreHostInterfaceConfigFn(bridgeName, p.IFName); err != nil {
			return nil, fmt.Errorf("failed to restore stale host-connection interface %s on bridge %s: %w",
				p.IFName, bridgeName, err)
		}
		restored = append(restored, restoredHostConnection{hostIFName: p.IFName, uplinkIFName: bridgedName})
	}
	return restored, nil
}

// clearStaleTrunks reads the actual OVS port state and calls SetPortTrunks(nil) for any
// port that has a non-empty trunk list in OVS but whose desired config carries no
// AllowedVLANs.  This handles the agent-restart scenario where the OVS port was
// previously configured as a trunk but the current desired config no longer requires it.
func clearStaleTrunks(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []agenttypes.PhysicalInterfaceConfig) error {
	// Build a set of interfaces that should NOT have trunk VLANs.
	noTrunkDesired := make(map[string]struct{}, len(phyInterfaces))
	for _, pi := range phyInterfaces {
		if len(pi.AllowedVLANs) == 0 {
			noTrunkDesired[pi.Name] = struct{}{}
		}
	}
	if len(noTrunkDesired) == 0 {
		return nil
	}

	portList, err := ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports: %v", err)
	}
	for _, p := range portList {
		// Match by IFName (interface name) against the desired set, but use p.Name
		// (Port name) for SetPortTrunks which filters the Port table by port name.
		// For standard uplink ports the two names are identical; being explicit here
		// avoids any confusion if they ever diverge.
		if _, ok := noTrunkDesired[p.IFName]; !ok {
			continue
		}
		if len(p.Trunks) == 0 {
			continue
		}
		if err := ovsBridgeClient.SetPortTrunks(p.Name, nil); err != nil {
			return fmt.Errorf("failed to clear stale trunk VLANs for OVS port %s: %v", p.Name, err)
		}
		klog.InfoS("Cleared trunk VLAN list on secondary OVS bridge port", "device", p.Name)
	}
	return nil
}

// createOVSBridge creates or attaches to an OVS bridge with the given name.
// The bridge is always marked as an Antrea-managed secondary bridge: Create()
// merges the external ID into an existing bridge as well, which is how a legacy
// bridge gets converted into a managed one. enableMulticastSnooping is applied
// to both new and existing bridges.
func createOVSBridge(
	bridgeName string,
	ovsdbClient client.Client,
	enableMulticastSnooping bool,
) (ovsconfig.OVSBridgeClient, error) {
	var options []ovsconfig.OVSBridgeOption
	if enableMulticastSnooping {
		options = append(options, ovsconfig.WithMcastSnooping())
	}
	options = append(options, ovsconfig.WithExternalIDs(map[string]string{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaSecondaryBridge,
	}))
	bridgeClient := newOVSBridgeFn(bridgeName, ovsconfig.OVSDatapathSystem, ovsdbClient, options...)
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

// connectBridgePhysicalInterfaces reconciles the physical interfaces when the Controller
// attaches to a bridge for the first time.
func connectBridgePhysicalInterfaces(
	client ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
) error {
	physInterfaces := desired.PhysicalInterfaces
	if len(physInterfaces) == 1 {
		interfaceName := physInterfaces[0].Name
		klog.InfoS("Preparing host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", interfaceName,
			"uplink", util.GenerateUplinkInterfaceName(interfaceName))
		bridgedName, alreadyExists, err := prepareHostInterfaceConnectionFn(
			client,
			interfaceName,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return fmt.Errorf("failed to prepare host interface %s for secondary OVS bridge %s: %w",
				interfaceName, desired.BridgeName, err)
		}
		klog.InfoS("Prepared host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", interfaceName,
			"uplink", bridgedName, "alreadyExists", alreadyExists)
		physInterfaces = []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: desired.PhysicalInterfaces[0].AllowedVLANs},
		}
	} else if len(physInterfaces) > 1 {
		// The OVS bridge may already exist (Create is a no-op) with stale host-connection
		// ports from a prior single-interface config. No restore is needed for a
		// single-interface config: the host connection it prepares is the desired state.
		if err := restoreStaleHostConnections(desired.BridgeName, client); err != nil {
			return err
		}
	}

	klog.InfoS("Reconciling physical uplinks on secondary OVS bridge",
		"bridge", desired.BridgeName, "interfaces", physInterfaces)
	if err := connectPhyInterfacesToOVSBridge(client, physInterfaces); err != nil {
		return fmt.Errorf("failed to connect physical uplinks to secondary OVS bridge %s: %w",
			desired.BridgeName, err)
	}
	klog.InfoS("Reconciled physical uplinks on secondary OVS bridge",
		"bridge", desired.BridgeName, "interfaces", physInterfaces)
	// Pre-existing ports may still carry trunk VLANs from an old config while the new
	// desired config has no AllowedVLANs; connectPhyInterfacesToOVSBridge skips plain
	// uplinks that are already present (unlike updatePhysicalInterfaces).
	if err := clearStaleTrunks(client, physInterfaces); err != nil {
		return fmt.Errorf("failed to reconcile trunk configuration on secondary OVS bridge %s: %w",
			desired.BridgeName, err)
	}
	return nil
}

func updatePhysicalInterfaces(
	client ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
) error {
	// Build a map of currently present ports on the bridge: interface name → UUID,
	// and a map of IFName → IFType for the host-connection sibling check below.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", desired.BridgeName, err)
	}
	existingPorts := make(map[string]string, len(portList))   // IFName → UUID
	existingIFTypes := make(map[string]string, len(portList)) // IFName → IFType
	existingAntreaTypes := make(map[string]string, len(portList))
	for _, p := range portList {
		existingPorts[p.IFName] = p.UUID
		existingIFTypes[p.IFName] = p.IFType
		existingAntreaTypes[p.IFName] = p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey]
	}

	// restoreStaleHostConnectionsConditionally removes the restored host-connection
	// interfaces (including stale uplink ports) from existingPorts, so they are not
	// treated as desired ports or re-added below.
	if err := restoreStaleHostConnectionsConditionally(desired, portList, existingPorts, existingIFTypes); err != nil {
		return err
	}

	bridgePhysInterfaces, prepareErr := prepareBridgePhysicalInterfaces(
		client, desired, existingPorts, existingIFTypes, existingAntreaTypes)
	if prepareErr != nil {
		return prepareErr
	}

	desiredBridgeIfaces := make(map[string]struct{}, len(bridgePhysInterfaces))
	for _, pi := range bridgePhysInterfaces {
		desiredBridgeIfaces[pi.Name] = struct{}{}
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
		if _, desired := desiredBridgeIfaces[p.IFName]; desired {
			continue
		}
		toRemoveUUIDs = append(toRemoveUUIDs, p.UUID)
		toRemoveNames = append(toRemoveNames, p.IFName)
	}
	if len(toRemoveUUIDs) > 0 {
		if err := client.DeletePorts(toRemoveUUIDs); err != nil {
			return fmt.Errorf("failed to remove OVS ports %v from bridge %s: %v",
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
	// clearStaleTrunks reads the actual OVS port state and only calls SetPortTrunks
	// when the port genuinely has trunks set, so it is safe to call unconditionally.
	if err := clearStaleTrunks(client, bridgePhysInterfaces); err != nil {
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
		klog.InfoS("Reconciling physical uplinks on secondary OVS bridge",
			"bridge", desired.BridgeName, "interfaces", toConnect)
		if err := connectPhyInterfacesToOVSBridge(client, toConnect); err != nil {
			return fmt.Errorf("failed to connect physical uplinks to secondary OVS bridge %s: %w",
				desired.BridgeName, err)
		}
		klog.InfoS("Reconciled physical uplinks on secondary OVS bridge",
			"bridge", desired.BridgeName, "interfaces", toConnect)
	}
	return nil
}

// restoreStaleHostConnectionsConditionally restores stale host-connection pairs
// observed in OVSDB, skipping the host connection of the current single-interface
// config, which is not stale. It removes the restored interfaces from existingPorts
// and existingIFTypes, so the caller does not re-add them later.
func restoreStaleHostConnectionsConditionally(
	desired *agenttypes.OVSBridgeConfig,
	portList []ovsconfig.OVSPortData,
	existingPorts map[string]string,
	existingIFTypes map[string]string,
) error {
	desiredIfaces := sets.New[string]()
	for _, pi := range desired.PhysicalInterfaces {
		desiredIfaces.Insert(pi.Name)
	}
	keepSingleHostConnection := len(desired.PhysicalInterfaces) == 1

	restored, err := restoreStaleHostConnectionsFromPortList(desired.BridgeName, portList, func(hostIFName string) bool {
		// The host connection of the current single-interface config is not stale:
		// the bridge is expected to keep the internal host port and the renamed uplink.
		isDesired := desiredIfaces.Has(hostIFName)
		return keepSingleHostConnection && isDesired
	})
	if err != nil {
		return err
	}
	for _, conn := range restored {
		delete(existingPorts, conn.hostIFName)
		delete(existingPorts, conn.uplinkIFName)
		delete(existingIFTypes, conn.hostIFName)
		delete(existingIFTypes, conn.uplinkIFName)
	}
	return nil
}

func prepareBridgePhysicalInterfaces(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
	existingPorts map[string]string,
	existingIFTypes map[string]string,
	existingAntreaTypes map[string]string,
) ([]agenttypes.PhysicalInterfaceConfig, error) {
	if len(desired.PhysicalInterfaces) == 1 {
		iface := desired.PhysicalInterfaces[0]
		bridgedName := util.GenerateUplinkInterfaceName(iface.Name)
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
		if existingIFTypes[iface.Name] == "internal" &&
			existingAntreaTypes[iface.Name] == interfacestore.AntreaHost {
			if _, err := interfaceByNameFn(bridgedName); err == nil {
				klog.InfoS("Resuming incomplete host interface connection",
					"bridge", desired.BridgeName, "interface", iface.Name, "uplink", bridgedName,
					"internalPortPresent", true, "kernelUplinkPresent", true, "ovsUplinkPortPresent", false)
				return []agenttypes.PhysicalInterfaceConfig{
					{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
				}, nil
			}
		}
		if uuid, exists := existingPorts[iface.Name]; exists && existingIFTypes[iface.Name] != "internal" {
			if err := ovsBridgeClient.DeletePorts([]string{uuid}); err != nil {
				return nil, fmt.Errorf("failed to remove OVS port %s from bridge %s before host connection setup: %v",
					iface.Name, desired.BridgeName, err)
			}
			// Keep the caller's observed-port maps in sync with the OVSDB change so
			// updatePhysicalInterfaces can add the generated uplink port later in
			// the same reconciliation.
			delete(existingPorts, iface.Name)
			delete(existingIFTypes, iface.Name)
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

// connectPhyInterfacesToOVSBridge adds each physical interface to the OVS bridge
// as an uplink port.  When AllowedVLANs is set the port is created or updated in
// trunk mode with those VLAN IDs; otherwise a plain uplink port is created.
// If the port already exists and AllowedVLANs is non-empty, the trunk VLAN list is
// always updated to match the desired config.
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
