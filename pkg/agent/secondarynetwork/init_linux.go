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
	"reflect"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn            = net.InterfaceByName
	restoreHostInterfaceConfigFn = util.RestoreHostInterfaceConfiguration // func(brName, ifName string) error
)

// Initialize sets up OVS bridges at agent start-up.
// It reconciles the current OVS bridge state with the effective bridge config:
//   - rule 1: if the effective bridge has the same name as the previous bridge,
//     keep the bridge and update the physical interfaces (add/remove ports).
//   - rule 2: if the effective bridge name differs from the previous bridge,
//     delete the old bridge and recreate with the new config.
//   - rule 3: when allowedVLANs are set on a physical interface, configure the
//     OVS port in trunk mode with the specified VLAN IDs.
func (c *Controller) Initialize() error {
	c.mu.RLock()
	bridgeCfg := c.effectiveBridgeCfg
	c.mu.RUnlock()

	if bridgeCfg == nil {
		return nil
	}

	// Only single-interface host-connection migration is supported.
	if len(bridgeCfg.PhysicalInterfaces) == 1 {
		iface := bridgeCfg.PhysicalInterfaces[0]
		bridgedName, _, err := util.PrepareHostInterfaceConnection(
			c.ovsBridgeClient,
			iface.Name,
			0,
			map[string]interface{}{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return err
		}
		phyInterfaces := []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
		}
		if err := connectPhyInterfacesToOVSBridge(c.ovsBridgeClient, phyInterfaces); err != nil {
			return err
		}
		return clearStaleTrunks(c.ovsBridgeClient, phyInterfaces)
	}

	// Multi-interface path: before connecting ports, tear down any stale
	// host-connection setup left from a previous single-interface run.  A stale
	// setup is identified by finding an OVS port whose interface type is
	// "internal" AND whose kernel-rename sibling (GenerateUplinkInterfaceName)
	// also exists as a port on the bridge.  In that case RestoreHostInterface-
	// Configuration undoes the rename and removes both OVS ports so that the
	// interface can be re-added as a plain uplink below.
	if err := restoreStaleHostConnections(c.ovsBridgeClient, bridgeCfg); err != nil {
		return err
	}

	if err := connectPhyInterfacesToOVSBridge(c.ovsBridgeClient, bridgeCfg.PhysicalInterfaces); err != nil {
		return err
	}
	return clearStaleTrunks(c.ovsBridgeClient, bridgeCfg.PhysicalInterfaces)
}

// restoreStaleHostConnections detects and tears down host-connection port pairs
// (e.g. "eth1" internal + "eth1~" uplink) that were created by a previous
// single-interface run but are no longer needed because the desired config now
// lists that interface as a plain uplink in a multi-interface setup.
// It calls RestoreHostInterfaceConfiguration for each such interface, which
// removes both OVS ports and renames "eth1~" back to "eth1" on the host.
func restoreStaleHostConnections(ovsBridgeClient ovsconfig.OVSBridgeClient, bridgeCfg *agenttypes.OVSBridgeConfig) error {
	// Build a set of desired physical interface names for quick lookup.
	desiredNames := make(map[string]struct{}, len(bridgeCfg.PhysicalInterfaces))
	for _, pi := range bridgeCfg.PhysicalInterfaces {
		desiredNames[pi.Name] = struct{}{}
	}

	portList, err := ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", bridgeCfg.BridgeName, err)
	}

	// Index all port IFTypes by their IFName for the sibling check below.
	portTypes := make(map[string]string, len(portList)) // IFName → IFType
	for _, p := range portList {
		portTypes[p.IFName] = p.IFType
	}

	for _, p := range portList {
		// We are looking for ports that:
		//   (a) are desired as plain uplinks in the new config, AND
		//   (b) are currently OVS internal ports (created by PrepareHostInterfaceConnection), AND
		//   (c) have a sibling uplink port named GenerateUplinkInterfaceName(p.IFName)
		//       still present on the bridge.
		if _, desired := desiredNames[p.IFName]; !desired {
			continue
		}
		if p.IFType != "internal" {
			continue
		}
		bridgedName := util.GenerateUplinkInterfaceName(p.IFName)
		if _, siblingExists := portTypes[bridgedName]; !siblingExists {
			continue
		}
		klog.InfoS("Detected stale host-connection setup, restoring interface before re-adding as uplink",
			"interface", p.IFName, "bridge", bridgeCfg.BridgeName)
		if err := restoreHostInterfaceConfigFn(bridgeCfg.BridgeName, p.IFName); err != nil {
			return fmt.Errorf("failed to restore stale host-connection interface %s on bridge %s: %w",
				p.IFName, bridgeCfg.BridgeName, err)
		}
	}
	return nil
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

// Restore restores interface configuration from the secondary bridge back to the host interface.
func (c *Controller) Restore() {
	c.mu.RLock()
	bridgeCfg := c.effectiveBridgeCfg
	c.mu.RUnlock()

	if bridgeCfg == nil {
		return
	}
	if len(bridgeCfg.PhysicalInterfaces) == 1 {
		if err := util.RestoreHostInterfaceConfiguration(bridgeCfg.BridgeName, bridgeCfg.PhysicalInterfaces[0].Name); err != nil {
			klog.ErrorS(err, "Failed to restore host interface configuration on shutdown",
				"interface", bridgeCfg.PhysicalInterfaces[0].Name, "bridge", bridgeCfg.BridgeName)
		}
	}
}

// reconcileBridge is called by the work queue worker whenever a relevant change is detected
// (Node label change or AntreaNodeConfig add/update/delete). It re-computes the desired
// bridge configuration and reconciles the OVS state accordingly:
//
//   - rule 1: same bridge name as current → keep bridge, update physical interfaces.
//   - rule 2: different bridge name → delete old bridge first, then create the new bridge.
//   - rule 3: interfaces with allowedVLANs are configured as OVS trunk ports.
//
// State-update discipline: after any destructive operation (bridge deletion) the controller
// state is immediately cleared under the mutex so that a subsequent retry does not attempt to
// delete an already-deleted bridge.
func (c *Controller) reconcileBridge() error {
	c.mu.RLock()
	node := c.node
	prev := c.effectiveBridgeCfg
	c.mu.RUnlock()

	desired := resolveEffectiveBridgeConfig(node, c.ancLister, c.secNetConfig)

	// No change — nothing to do.
	if reflect.DeepEqual(prev, desired) {
		return nil
	}

	klog.InfoS("Reconciling secondary network bridge configuration",
		"previous", bridgeName(prev), "desired", bridgeName(desired))

	// Case: no bridge desired — delete the existing one.
	if desired == nil {
		if err := c.deleteBridge(prev); err != nil {
			return err
		}
		// Clear state immediately after successful deletion so that a retry
		// does not attempt to delete an already-removed bridge.
		c.mu.Lock()
		c.effectiveBridgeCfg = nil
		c.ovsBridgeClient = nil
		c.mu.Unlock()
		// Notify PodController that the bridge is gone.
		if err := c.podController.UpdateOVSBridge(nil); err != nil {
			return err
		}
		return nil
	}

	// Case: new bridge desired when none existed before.
	if prev == nil {
		return c.createAndConnectBridge(desired)
	}

	// Case: bridge name changed (rule 2).
	// The old bridge MUST be deleted before the new one is created.  State is
	// cleared under the mutex immediately after the deletion succeeds so that if
	// createAndConnectBridge subsequently fails the next retry starts from a clean
	// "no bridge" state rather than trying to delete the already-gone old bridge.
	if prev.BridgeName != desired.BridgeName {
		klog.InfoS("Secondary OVS bridge name changed, deleting old bridge before creating new one",
			"old", prev.BridgeName, "new", desired.BridgeName)
		if err := c.deleteBridge(prev); err != nil {
			return err
		}
		// Old bridge is gone — clear state before proceeding.
		c.mu.Lock()
		c.effectiveBridgeCfg = nil
		c.ovsBridgeClient = nil
		c.mu.Unlock()
		return c.createAndConnectBridge(desired)
	}

	// Case: same bridge name (rule 1) — update physical interfaces in-place.
	// effectiveBridgeCfg is updated incrementally inside updatePhysicalInterfaces
	// after each mutating step, so a retry always sees accurate state.
	klog.InfoS("Secondary OVS bridge name unchanged, updating physical interfaces",
		"bridge", desired.BridgeName)
	return c.updatePhysicalInterfaces(prev, desired)
}

// deleteBridge tears down the single-interface host connection (if applicable) and deletes the
// OVS bridge.
func (c *Controller) deleteBridge(cfg *agenttypes.OVSBridgeConfig) error {
	if cfg == nil {
		return nil
	}
	// Restore host interface first (only supported for the single-interface case).
	if len(cfg.PhysicalInterfaces) == 1 {
		if err := util.RestoreHostInterfaceConfiguration(cfg.BridgeName, cfg.PhysicalInterfaces[0].Name); err != nil {
			return fmt.Errorf("failed to restore host interface %s before deleting bridge %s: %w",
				cfg.PhysicalInterfaces[0].Name, cfg.BridgeName, err)
		}
	}
	if c.ovsBridgeClient != nil {
		if err := c.ovsBridgeClient.Delete(); err != nil {
			return fmt.Errorf("failed to delete OVS bridge %s: %v", cfg.BridgeName, err)
		}
		klog.InfoS("OVS bridge deleted", "bridge", cfg.BridgeName)
	}
	return nil
}

// createAndConnectBridge creates a fresh OVS bridge for the desired config, connects all
// physical interfaces to it, and updates the controller state.
func (c *Controller) createAndConnectBridge(desired *agenttypes.OVSBridgeConfig) error {
	newClient, err := createOVSBridgeClient(desired.BridgeName, desired.EnableMulticastSnooping, c.ovsdbConn)
	if err != nil {
		return err
	}

	physInterfaces := desired.PhysicalInterfaces
	if len(physInterfaces) == 1 {
		bridgedName, _, err := util.PrepareHostInterfaceConnection(
			newClient,
			physInterfaces[0].Name,
			0,
			map[string]interface{}{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return err
		}
		physInterfaces = []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: desired.PhysicalInterfaces[0].AllowedVLANs},
		}
	}

	if err := connectPhyInterfacesToOVSBridge(newClient, physInterfaces); err != nil {
		return err
	}

	c.mu.Lock()
	c.ovsBridgeClient = newClient
	c.effectiveBridgeCfg = desired
	c.mu.Unlock()

	// Notify PodController of the new bridge so it uses the correct OVS client
	// for future Pod interface operations and reloads its interface store.
	return c.podController.UpdateOVSBridge(newClient)
}

// updatePhysicalInterfaces reconciles OVS ports on an existing bridge to match the
// desired config.  effectiveBridgeCfg is committed once per step under a single lock
// acquisition so that, if a later step fails, the next reconciliation retry sees an
// accurate picture of what is actually present on the bridge.
func (c *Controller) updatePhysicalInterfaces(prev, desired *agenttypes.OVSBridgeConfig) error {
	// Build a set of desired interface names.
	desiredIfaces := make(map[string]agenttypes.PhysicalInterfaceConfig, len(desired.PhysicalInterfaces))
	for _, pi := range desired.PhysicalInterfaces {
		desiredIfaces[pi.Name] = pi
	}

	// Build a map of currently present ports on the bridge: interface name → UUID,
	// and a map of IFName → IFType for the host-connection sibling check below.
	portList, err := c.ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", desired.BridgeName, err)
	}
	existingPorts := make(map[string]string, len(portList))   // IFName → UUID
	existingIFTypes := make(map[string]string, len(portList)) // IFName → IFType
	for _, p := range portList {
		existingPorts[p.IFName] = p.UUID
		existingIFTypes[p.IFName] = p.IFType
	}

	// Step 1: remove ports that were in the previous config but are no longer desired.
	//
	// When an interface was connected via PrepareHostInterfaceConnection (single-interface
	// host-connection path), the kernel interface was renamed eth1 → eth1~, an internal
	// OVS port "eth1" was created, and an uplink port "eth1~" was added.  In that case
	// prev records the original name "eth1", but the bridge holds TWO ports: "eth1"
	// (internal) and "eth1~" (uplink).  Simply deleting the "eth1" port via DeletePorts
	// would leave "eth1~" orphaned on the bridge and the host kernel interface stranded
	// under the renamed name.  We must call RestoreHostInterfaceConfiguration instead,
	// which removes both ports and renames eth1~ back to eth1 on the host.
	//
	// For plain uplink ports (no sibling) the normal DeletePorts path is used.  Those
	// are batched into a single OVSDB transaction for atomicity.
	var toRemoveUUIDs []string
	var toRemoveNames []string
	for _, pi := range prev.PhysicalInterfaces {
		if _, ok := desiredIfaces[pi.Name]; ok {
			continue
		}
		bridgedName := util.GenerateUplinkInterfaceName(pi.Name)
		if existingIFTypes[pi.Name] == "internal" {
			if _, siblingExists := existingPorts[bridgedName]; siblingExists {
				// Host-connection pair: restore via the utility that removes both
				// OVS ports and renames the kernel interface back.
				klog.InfoS("Restoring host interface before removing from bridge",
					"device", pi.Name, "bridge", desired.BridgeName)
				if err := restoreHostInterfaceConfigFn(desired.BridgeName, pi.Name); err != nil {
					return fmt.Errorf("failed to restore host interface %s on bridge %s: %w",
						pi.Name, desired.BridgeName, err)
				}
				// Keep existingPorts in sync so Step 3 does not skip re-adding
				// an interface that was just restored (remove-then-re-add scenario).
				delete(existingPorts, pi.Name)
				delete(existingPorts, bridgedName)
				continue
			}
		}
		if uuid, exists := existingPorts[pi.Name]; exists {
			toRemoveUUIDs = append(toRemoveUUIDs, uuid)
			toRemoveNames = append(toRemoveNames, pi.Name)
		}
		// Also remove the sibling uplink port if present (e.g. eth1~ left over from
		// a partially-restored host-connection setup).
		if uuid, exists := existingPorts[bridgedName]; exists {
			toRemoveUUIDs = append(toRemoveUUIDs, uuid)
			toRemoveNames = append(toRemoveNames, bridgedName)
		}
	}
	if len(toRemoveUUIDs) > 0 {
		if err := c.ovsBridgeClient.DeletePorts(toRemoveUUIDs); err != nil {
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
	// Build the post-deletion effective config: drop all interfaces not in desired
	// (whether just deleted or already absent) so the next retry does not re-attempt them.
	current := prev.DeepCopy()
	for _, pi := range prev.PhysicalInterfaces {
		if _, ok := desiredIfaces[pi.Name]; !ok {
			current = current.WithoutInterface(pi.Name)
		}
	}
	c.mu.Lock()
	c.effectiveBridgeCfg = current
	c.mu.Unlock()

	// Step 2: clear trunk VLANs on existing ports whose desired config has no AllowedVLANs.
	// clearStaleTrunks reads the actual OVS port state and only calls SetPortTrunks
	// when the port genuinely has trunks set, so it is safe to call unconditionally.
	if err := clearStaleTrunks(c.ovsBridgeClient, desired.PhysicalInterfaces); err != nil {
		return err
	}
	// Reflect the cleared trunk state for any interface whose desired config now
	// carries no AllowedVLANs, then commit once for the whole step.
	c.mu.Lock()
	c.effectiveBridgeCfg = current.WithClearedTrunks(desired.PhysicalInterfaces)
	c.mu.Unlock()

	// Step 3: add new ports and update the trunk VLAN list on existing ports that
	// have AllowedVLANs.  connectPhyInterfacesToOVSBridge creates the port when it
	// does not yet exist, and calls SetPortTrunks when it does and AllowedVLANs is
	// non-empty.
	var toConnect []agenttypes.PhysicalInterfaceConfig
	for _, pi := range desired.PhysicalInterfaces {
		if _, alreadyExists := existingPorts[pi.Name]; !alreadyExists || len(pi.AllowedVLANs) > 0 {
			toConnect = append(toConnect, pi)
		}
	}
	if len(toConnect) > 0 {
		if err := connectPhyInterfacesToOVSBridge(c.ovsBridgeClient, toConnect); err != nil {
			return err
		}
	}
	// All steps succeeded; record the fully-desired config.
	c.mu.Lock()
	c.effectiveBridgeCfg = desired
	c.mu.Unlock()
	return nil
}

// connectPhyInterfacesToOVSBridge adds each physical interface to the OVS bridge
// as an uplink port.  When AllowedVLANs is set the port is created or updated in
// trunk mode with those VLAN IDs (rule 3); otherwise a plain uplink port is created.
// If the port already exists and AllowedVLANs is non-empty, the trunk VLAN list is
// always updated to match the desired config.
func connectPhyInterfacesToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []agenttypes.PhysicalInterfaceConfig) error {
	for _, pi := range phyInterfaces {
		if _, err := interfaceByNameFn(pi.Name); err != nil {
			return fmt.Errorf("failed to get interface %s: %v", pi.Name, err)
		}
	}

	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	for _, pi := range phyInterfaces {
		_, notConnected := ovsBridgeClient.GetOFPort(pi.Name, false)

		if len(pi.AllowedVLANs) > 0 {
			if notConnected != nil {
				// Pass ofPortRequest=0 so OVS auto-assigns the OF port number.
				// Pinning a number derived from the loop index would collide across
				// reconciliation cycles when the interface list is a filtered subset.
				if _, err := ovsBridgeClient.CreateTrunkPort(pi.Name, 0, pi.AllowedVLANs, externalIDs); err != nil {
					return fmt.Errorf("failed to create OVS trunk port %s: %v", pi.Name, err)
				}
				klog.InfoS("Physical interface added to secondary OVS bridge in trunk mode", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			} else {
				if err := ovsBridgeClient.SetPortTrunks(pi.Name, pi.AllowedVLANs); err != nil {
					return fmt.Errorf("failed to update trunk VLANs for OVS port %s: %v", pi.Name, err)
				}
				klog.InfoS("Updated trunk VLAN list on secondary OVS bridge port", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			}
			continue
		}

		if notConnected != nil {
			// Pass ofPortRequest=0 so OVS auto-assigns the OF port number.
			if _, err := ovsBridgeClient.CreateUplinkPort(pi.Name, 0, externalIDs); err != nil {
				return fmt.Errorf("failed to create OVS uplink port %s: %v", pi.Name, err)
			}
			klog.InfoS("Physical interface added to secondary OVS bridge", "device", pi.Name)
		} else {
			klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skipping", "device", pi.Name)
		}
	}
	return nil
}

// bridgeName returns the bridge name from a config, or "<none>" for nil.
func bridgeName(cfg *agenttypes.OVSBridgeConfig) string {
	if cfg == nil {
		return "<none>"
	}
	return cfg.BridgeName
}
