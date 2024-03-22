//go:build linux
// +build linux

// Copyright 2020 Antrea Authors
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
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	utilip "antrea.io/antrea/pkg/util/ip"
)

var (
	// getInterfaceByName is meant to be overridden for testing.
	getInterfaceByName = net.InterfaceByName

	// getAllIPNetsByName is meant to be overridden for testing.
	getAllIPNetsByName = util.GetAllIPNetsByName

	// setInterfaceARPAnnounce is meant to be overridden for testing.
	setInterfaceARPAnnounce = util.EnsureARPAnnounceOnInterface
)

// prepareHostNetwork returns immediately on Linux.
func (i *Initializer) prepareHostNetwork() error {
	return nil
}

// Assuming a page cache of 4096, based on Suricata source code from L1752-L1798
// at https://github.com/OISF/suricata/blob/49713ebaa0b8edb057d60f1cfe9126946645a848/src/source-af-packet.c#L1757C2-L1777C129.
// The maximum supported MTU by Suricata is 32678 after calculation.
const maxMTUSupportedBySuricata = 32678

// prepareOVSBridgeForK8sNode returns immediately on Linux if connectUplinkToBridge is false.
func (i *Initializer) prepareOVSBridgeForK8sNode() error {
	if !i.connectUplinkToBridge {
		return nil
	}
	klog.Infof("Preparing OVS bridge for AntreaFlexibleIPAM")
	// Get uplink network configuration.
	// TODO(gran): support IPv6
	_, _, adapter, err := i.getNodeInterfaceFromIP(&utilip.DualStackIPs{IPv4: i.nodeConfig.NodeIPv4Addr.IP})
	if err != nil {
		return err
	}
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkNetConfig.Name = adapter.Name
	uplinkNetConfig.MAC = adapter.HardwareAddr
	uplinkIPs, err := getAllIPNetsByName(adapter.Name)
	if err != nil {
		return fmt.Errorf("failed to get uplink IPs: %w", err)
	}
	uplinkNetConfig.IPs = uplinkIPs
	uplinkNetConfig.Index = adapter.Index
	// Gateway and DNSServers are not configured at adapter in Linux
	// Limitation: dynamic DNS servers will be lost after DHCP lease expired
	uplinkNetConfig.Gateway = ""
	uplinkNetConfig.DNSServers = ""
	// Save routes which are configured on the uplink interface.
	// The routes on the host will be lost when moving the network configuration of the uplink interface
	// to the OVS bridge local interface. The saved routes will be restored on host after that.
	if err = i.saveHostRoutes(); err != nil {
		return err
	}

	// Set datapathID of OVS bridge.
	// If no datapathID configured explicitly, the reconfiguration operation will change OVS bridge datapathID
	// and break the OpenFlow channel.
	datapathID := util.GenerateOVSDatapathID(uplinkNetConfig.MAC.String())

	if err = i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		return fmt.Errorf("failed to set datapath_id %s: err=%w", datapathID, err)
	}

	if hostOFPort, err := i.ovsBridgeClient.GetOFPort(uplinkNetConfig.Name, false); err == nil {
		klog.Infof("OVS bridge local port %s already exists", uplinkNetConfig.Name)
		i.nodeConfig.HostInterfaceOFPort = uint32(hostOFPort)
		// If local port exists, get the real uplink interface.
		// This branch is used when antrea-agent had a hard restart (e.g. SIGKILL)
		bridgedUplinkName := util.GenerateUplinkInterfaceName(uplinkNetConfig.Name)
		if uplinkOFPort, err := i.ovsBridgeClient.GetOFPort(bridgedUplinkName, false); err != nil {
			return fmt.Errorf("cannot find uplink port %s: err=%w", bridgedUplinkName, err)
		} else {
			uplinkNetConfig.OFPort = uint32(uplinkOFPort)
		}
		if adapter, err := getInterfaceByName(bridgedUplinkName); err != nil {
			return fmt.Errorf("cannot find uplink interface %s: err=%w", bridgedUplinkName, err)
		} else {
			uplinkNetConfig.Index = adapter.Index
		}
		klog.InfoS("Found uplink", "Name", adapter.Name, "Index", uplinkNetConfig.Index, "OFPort", uplinkNetConfig.OFPort)
	} else {
		freePort, err := i.ovsBridgeClient.AllocateOFPort(config.UplinkOFPort)
		if err != nil {
			return err
		}
		uplinkNetConfig.OFPort = uint32(freePort)
		klog.InfoS("Set OpenFlow port in UplinkNetConfig", "ofport", uplinkNetConfig.OFPort)
		freePort, err = i.ovsBridgeClient.AllocateOFPort(config.UplinkOFPort)
		if err != nil {
			return err
		}
		i.nodeConfig.HostInterfaceOFPort = uint32(freePort)
		klog.InfoS("Set host interface", "ofport", i.nodeConfig.HostInterfaceOFPort)
	}
	return nil
}

// getTunnelLocalIP returns local_ip of tunnel port.
// On linux platform, local_ip option is not needed.
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return nil
}

func getTransportIPNetDeviceByName(ifaceName string, ovsBridgeName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
	return util.GetIPNetDeviceByName(ifaceName)
}

// saveHostRoutes saves the routes which were configured on the uplink interface
// before the interface is configured as the OVS brdige uplink. These routes
// will be moved to the bridge interface together with the interface IP
// configuration.
func (i *Initializer) saveHostRoutes() error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.LinkIndex != i.nodeConfig.UplinkNetConfig.Index {
			klog.V(2).Infof("Skipped host route not on uplink: %+v", route)
			continue
		}
		// Skip IPv6 routes until we support IPv6 stack.
		// TODO(gran): support IPv6
		if route.Gw.To4() == nil {
			klog.V(2).Infof("Skipped IPv6 host route: %+v", route)
			continue
		}
		klog.Infof("Got host route=%+v", route)
		i.nodeConfig.UplinkNetConfig.Routes = append(i.nodeConfig.UplinkNetConfig.Routes, route)
	}
	return nil
}

// restoreHostRoutes restores the host routes which are lost when moving the IP
// configuration of uplink interface to the OVS bridge interface during
// the Antrea bridge initialization stage.
// The backup routes are restored after the IP configuration changes.
func (i *Initializer) restoreHostRoutes() error {
	return i.restoreHostRoutesToInterface(i.nodeConfig.UplinkNetConfig.Name)
}

func (i *Initializer) restoreHostRoutesToInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	for _, routeInterface := range i.nodeConfig.UplinkNetConfig.Routes {
		route := routeInterface.(netlink.Route)
		newRoute := route
		newRoute.LinkIndex = iface.Index
		if err := netlink.RouteReplace(&newRoute); err != nil {
			return err
		}
	}
	return nil
}

func (i *Initializer) ConnectUplinkToOVSBridge() error {
	// Return immediately on Linux if connectUplinkToBridge is false.
	if !i.connectUplinkToBridge {
		return nil
	}
	klog.InfoS("Bridging uplink to OVS bridge")
	var err error
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkName := uplinkNetConfig.Name
	bridgedUplinkName := util.GenerateUplinkInterfaceName(uplinkNetConfig.Name)
	uplinkIPs := uplinkNetConfig.IPs

	// If the uplink port already exists, just return.
	if uplinkOFPort, err := i.ovsBridgeClient.GetOFPort(bridgedUplinkName, false); err == nil {
		klog.InfoS("Uplink already exists, skip the configuration", "uplink", bridgedUplinkName, "port", uplinkOFPort)
		return nil
	}

	if err := util.RenameInterface(uplinkName, bridgedUplinkName); err != nil {
		return fmt.Errorf("failed to change uplink interface name: err=%w", err)
	}

	// Create uplink port.
	uplinkPortUUID, err := i.ovsBridgeClient.CreateUplinkPort(bridgedUplinkName, int32(uplinkNetConfig.OFPort), map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink})
	if err != nil {
		return fmt.Errorf("failed to add uplink port %s: err=%w", bridgedUplinkName, err)
	}
	// Add newly created uplinkInterface to interface cache.
	uplinkInterface := interfacestore.NewUplinkInterface(bridgedUplinkName)
	uplinkOFPort, err := i.ovsBridgeClient.GetOFPort(bridgedUplinkName, false)
	if err != nil {
		return fmt.Errorf("failed to get uplink ofport %s: err=%w", bridgedUplinkName, err)
	}
	klog.InfoS("Allocated OpenFlow port for uplink interface", "port", bridgedUplinkName, "ofPort", uplinkOFPort)
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUID, uplinkOFPort} //nolint: govet
	i.ifaceStore.AddInterface(uplinkInterface)

	// Create local port.
	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
	}
	if _, err = i.ovsBridgeClient.CreateInternalPort(uplinkName, int32(i.nodeConfig.HostInterfaceOFPort), uplinkNetConfig.MAC.String(), externalIDs); err != nil {
		return fmt.Errorf("cannot create host interface port %s: err=%w", uplinkName, err)
	}

	// Move network configuration of uplink interface to OVS bridge local interface.
	// The net configuration of uplink will be restored by RestoreOVSBridge when shutting down.
	wait.PollUntilContextTimeout(context.TODO(), 100*time.Millisecond, 10000*time.Millisecond, true,
		func(ctx context.Context) (bool, error) {
			// Wait a few seconds for OVS bridge local port.
			link, err := netlink.LinkByName(uplinkName)
			if err != nil {
				klog.V(4).InfoS("OVS bridge local port is not ready", "port", uplinkName, "err", err)
				return false, nil
			}
			klog.InfoS("OVS bridge local port is ready", "type", link.Type(), "attrs", link.Attrs())
			return true, nil
		})
	localLink, err := netlink.LinkByName(uplinkName)
	if err != nil {
		return err
	}
	if _, _, err = util.SetLinkUp(uplinkName); err != nil {
		return err
	}

	// Check if uplink is configured with an IPv6 address: if it is, we need to ensure that IPv6
	// is enabled on the OVS internal port as we need to move all IP addresses over.
	uplinkHasIPv6Address := false
	for _, ip := range uplinkIPs {
		if ip.IP.To4() == nil {
			uplinkHasIPv6Address = true
			break
		}
	}
	if uplinkHasIPv6Address {
		klog.InfoS("Uplink has IPv6 address, ensuring that IPv6 is enabled on bridge local port", "port", uplinkName)
		if err := util.EnsureIPv6EnabledOnInterface(uplinkName); err != nil {
			klog.ErrorS(err, "Failed to ensure that IPv6 is enabled on bridge local port, moving uplink IPs to bridge is likely to fail", "port", uplinkName)
		}
	}

	if err = util.ConfigureLinkAddresses(localLink.Attrs().Index, uplinkIPs); err != nil {
		return err
	}
	if err = util.ConfigureLinkAddresses(uplinkNetConfig.Index, nil); err != nil {
		return err
	}
	// Restore the host routes which are lost when moving the network configuration of the
	// uplink interface to OVS bridge interface.
	if err = i.restoreHostRoutes(); err != nil {
		return err
	}

	return nil
}

// RestoreOVSBridge returns immediately on Linux if connectUplinkToBridge is false.
// OVS is managed by Antrea in Linux, network config must be restored to uplink before Antrea Agent shutdown.
func (i *Initializer) RestoreOVSBridge() {
	if !i.connectUplinkToBridge {
		return
	}
	klog.InfoS("Restoring bridge config to uplink...")
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkName := ""
	bridgedUplinkName := ""
	if uplinkNetConfig != nil {
		uplinkName = uplinkNetConfig.Name
		bridgedUplinkName = util.GenerateUplinkInterfaceName(uplinkName)
	}
	brName := i.ovsBridge

	if uplinkName != "" {
		uplinkIPs := uplinkNetConfig.IPs
		if err := util.DeleteOVSPort(brName, uplinkName); err != nil {
			klog.ErrorS(err, "Delete OVS port failed", "port", uplinkName)
		}
		if err := util.DeleteOVSPort(brName, bridgedUplinkName); err != nil {
			klog.ErrorS(err, "Delete OVS port failed", "port", bridgedUplinkName)
		}
		if err := util.RenameInterface(bridgedUplinkName, uplinkName); err != nil {
			klog.ErrorS(err, "Restore uplink name failed", "uplink", bridgedUplinkName)
		}
		if err := util.ConfigureLinkAddresses(uplinkNetConfig.Index, uplinkIPs); err != nil {
			klog.ErrorS(err, "Configure IP to uplink failed", "uplink", uplinkName)
		}
		if err := i.restoreHostRoutesToInterface(uplinkName); err != nil {
			klog.ErrorS(err, "Configure route to uplink interface failed", "uplink", uplinkName)
		}
	}
	klog.InfoS("Finished to restore bridge config to uplink...")
}

func (i *Initializer) setInterfaceMTU(iface string, mtu int) error {
	return i.ovsBridgeClient.SetInterfaceMTU(iface, mtu)
}

func (i *Initializer) setVMNodeConfig(en *v1alpha1.ExternalNode, nodeName string) error {
	i.nodeConfig = &config.NodeConfig{
		Name:      nodeName,
		Type:      config.ExternalNode,
		OVSBridge: i.ovsBridge,
	}
	return nil
}

func (i *Initializer) prepareOVSBridgeForVM() error {
	return i.setOVSDatapath()
}

func (i *Initializer) installVMInitialFlows() error {
	return nil
}

// prepareL7EngineInterfaces creates two OVS internal ports. An application-aware engine will connect to OVS
// through these two ports.
func (i *Initializer) prepareL7EngineInterfaces() error {
	trafficControlPortExternalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTrafficControl,
	}

	for _, portName := range []string{config.L7RedirectTargetPortName, config.L7RedirectReturnPortName} {
		_, exists := i.ifaceStore.GetInterface(portName)
		if exists {
			continue
		}
		portUUID, err := i.ovsBridgeClient.CreateInternalPort(portName, 0, "", trafficControlPortExternalIDs)
		if err != nil {
			return err
		}
		if pollErr := wait.PollUntilContextTimeout(context.TODO(), time.Second, 5*time.Second, true, func(ctx context.Context) (bool, error) {
			_, _, err := util.SetLinkUp(portName)
			if err == nil {
				return true, nil
			}
			if _, ok := err.(util.LinkNotFound); ok {
				return false, nil
			}
			return false, err
		}); pollErr != nil {
			return pollErr
		}

		ofPort, err := i.ovsBridgeClient.GetOFPort(portName, false)
		if err != nil {
			return err
		}

		itf := interfacestore.NewTrafficControlInterface(portName, &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort})
		i.ifaceStore.AddInterface(itf)
	}

	targetPort, _ := i.ifaceStore.GetInterfaceByName(config.L7RedirectTargetPortName)
	returnPort, _ := i.ifaceStore.GetInterfaceByName(config.L7RedirectReturnPortName)
	i.l7NetworkPolicyConfig.TargetOFPort = uint32(targetPort.OFPort)
	i.l7NetworkPolicyConfig.ReturnOFPort = uint32(returnPort.OFPort)
	// Set the ports with no-flood to reject ARP flood packets at every startup.
	if err := i.ovsCtlClient.SetPortNoFlood(int(targetPort.OFPort)); err != nil {
		return fmt.Errorf("failed to set port %s with no-flood config: %w", config.L7RedirectTargetPortName, err)
	}
	if err := i.ovsCtlClient.SetPortNoFlood(int(returnPort.OFPort)); err != nil {
		return fmt.Errorf("failed to set port %s with no-flood config: %w", config.L7RedirectReturnPortName, err)
	}
	// Set MTU of the ports to the calculated MTU value at every startup.
	if err := i.setInterfaceMTU(config.L7RedirectTargetPortName, i.networkConfig.InterfaceMTU); err != nil {
		return err
	}
	if err := i.setInterfaceMTU(config.L7RedirectReturnPortName, i.networkConfig.InterfaceMTU); err != nil {
		return err
	}
	// Currently, the maximum of MTU supported by L7 NetworkPolicy engine Suricata is 32678 (assuming that the page size
	// is 4096). If the calculated MTU value is greater than 32678, Suricata may fail to start.
	if i.networkConfig.InterfaceMTU > maxMTUSupportedBySuricata {
		klog.ErrorS(nil, "L7 NetworkPolicy engine Suricata may fail to start since the interface MTU is greater than the maximum MTU supported by Suricata", "interfaceMTU", i.networkConfig.InterfaceMTU, "maximumMTU", maxMTUSupportedBySuricata)
	}
	return nil
}
