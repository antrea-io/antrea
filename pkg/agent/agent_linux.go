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
	"fmt"
	"net"
	"strings"
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

// prepareHostNetwork returns immediately on Linux.
func (i *Initializer) prepareHostNetwork() error {
	return nil
}

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
	uplinkNetConfig.IPs = []*net.IPNet{i.nodeConfig.NodeIPv4Addr}
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
	// The length of datapathID is 64 bits, the lower 48-bits are for a MAC address, while the upper 16-bits are
	// implementer-defined. Antrea uses "0x0000" for the upper 16-bits.
	datapathID := strings.Replace(uplinkNetConfig.MAC.String(), ":", "", -1)
	datapathID = "0000" + datapathID
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
		if adapter, err := net.InterfaceByName(bridgedUplinkName); err != nil {
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

func GetTransportIPNetDeviceByName(ifaceName string, ovsBridgeName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
	return util.GetIPNetDeviceByName(ifaceName)
}

// saveHostRoutes saves routes which are configured on uplink interface before
// the interface the configured as the uplink of antrea network.
// The routes will be restored on OVS bridge interface after the IP configuration
// is moved to the OVS bridge.
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
		// Skip IPv6 routes before we support IPv6 stack.
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
// the antrea network initialize stage.
// The backup routes are restored after the IP configuration change.
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
	klog.Infof("Bridging uplink to OVS bridge")
	var err error
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkName := uplinkNetConfig.Name
	bridgedUplinkName := util.GenerateUplinkInterfaceName(uplinkNetConfig.Name)

	// If uplink is already exists, return.
	if uplinkOFPort, err := i.ovsBridgeClient.GetOFPort(bridgedUplinkName, false); err == nil {
		klog.InfoS("Uplink already exists, skip the configuration", "uplink", bridgedUplinkName, "port", uplinkOFPort)
		return nil
	}
	uplinkIPs, err := util.GetAllIPNetsByName(uplinkName)
	if err != nil {
		return fmt.Errorf("failed to get uplink IPs: err=%w", err)
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
	wait.PollImmediate(100*time.Millisecond, 10000*time.Millisecond, func() (bool, error) {
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
	if err = util.ConfigureLinkAddresses(localLink.Attrs().Index, uplinkIPs); err != nil {
		return err
	}
	if err = util.ConfigureLinkAddresses(uplinkNetConfig.Index, nil); err != nil {
		return err
	}
	// Restore the host routes which are lost when moving the network configuration of the uplink interface to OVS bridge interface.
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
	klog.Infof("Restoring bridge config to uplink...")
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkName := ""
	bridgedUplinkName := ""
	if uplinkNetConfig != nil {
		uplinkName = uplinkNetConfig.Name
		bridgedUplinkName = util.GenerateUplinkInterfaceName(uplinkName)
	}
	brName := i.ovsBridge

	if uplinkName != "" {
		uplinkIPs, err := util.GetAllIPNetsByName(uplinkName)
		if err != nil {
			klog.ErrorS(err, "Failed to get uplink IPs")
		}
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
	klog.Infof("Finished to restore bridge config to uplink...")
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

// prepareL7NetworkPolicyInterfaces creates two OVS internal ports. An application-aware engine will connect to OVS
// through these two ports.
func (i *Initializer) prepareL7NetworkPolicyInterfaces() error {
	trafficControlPortExternalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTrafficControl,
	}

	for _, portName := range []string{config.L7NetworkPolicyTargetPortName, config.L7NetworkPolicyReturnPortName} {
		_, exists := i.ifaceStore.GetInterface(portName)
		if exists {
			continue
		}

		portUUID, err := i.ovsBridgeClient.CreateInternalPort(portName, 0, "", trafficControlPortExternalIDs)
		if err != nil {
			return err
		}
		if pollErr := wait.PollImmediate(time.Second, 5*time.Second, func() (bool, error) {
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

		itf := interfacestore.NewTrafficControlInterface(portName)
		itf.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
		i.ifaceStore.AddInterface(itf)
	}

	targetPort, _ := i.ifaceStore.GetInterfaceByName(config.L7NetworkPolicyTargetPortName)
	returnPort, _ := i.ifaceStore.GetInterfaceByName(config.L7NetworkPolicyReturnPortName)
	i.l7NetworkPolicyConfig.TargetOFPort = uint32(targetPort.OFPort)
	i.l7NetworkPolicyConfig.ReturnOFPort = uint32(returnPort.OFPort)
	// Set the ports with no-flood to reject ARP flood packets.
	if err := i.ovsCtlClient.SetPortNoFlood(int(targetPort.OFPort)); err != nil {
		return fmt.Errorf("failed to set port %s with no-flood config: %w", config.L7NetworkPolicyTargetPortName, err)
	}
	if err := i.ovsCtlClient.SetPortNoFlood(int(returnPort.OFPort)); err != nil {
		return fmt.Errorf("failed to set port %s with no-flood config: %w", config.L7NetworkPolicyReturnPortName, err)
	}

	return nil
}
