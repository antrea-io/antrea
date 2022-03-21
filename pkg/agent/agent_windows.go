//go:build windows
// +build windows

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

	"github.com/Microsoft/hcsshim"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/ip"
)

// prepareHostNetwork creates HNS Network for containers.
func (i *Initializer) prepareHostNetwork() error {
	// If the HNS Network already exists, return immediately.
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err == nil {
		// Enable RSC for existing vSwitch.
		if err = util.EnableRSCOnVSwitch(util.LocalHNSNetwork); err != nil {
			return err
		}
		// Save the uplink adapter name to check if the OVS uplink port has been created in prepareOVSBridge stage.
		i.nodeConfig.UplinkNetConfig.Name = hnsNetwork.NetworkAdapterName
		return nil
	}
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	// Get uplink network configuration. The uplink interface is the one used for transporting Pod traffic across Nodes.
	// Use the interface specified with "transportInterface" in the configuration if configured, otherwise the interface
	// configured with NodeIP is used as uplink.
	_, _, adapter, err := i.getNodeInterfaceFromIP(&ip.DualStackIPs{IPv4: i.nodeConfig.NodeTransportIPv4Addr.IP})
	if err != nil {
		return err
	}
	// To forward container traffic to physical network, Transparent HNSNetwork must have a physical adapter attached,
	// otherwise creating it would fail with "The parameter is incorrect" if the provided adapter is virtual or "An
	// adapter was not found" if no adapter is provided and no physical adapter is available on the host.
	// If the discovered adapter is virtual, it likely means the physical adapter is already attached to another
	// HNSNetwork. For example, docker may create HNSNetworks which attach to the physical adapter.
	isVirtual, err := util.IsVirtualAdapter(adapter.Name)
	if err != nil {
		return err
	}
	if isVirtual {
		klog.Errorf("Transparent HNSNetwork requires a physical adapter while the uplink interface \"%s\" is virtual, please detach it from other HNSNetworks and try again", adapter.Name)
		return fmt.Errorf("uplink \"%s\" is not a physical adapter", adapter.Name)
	}
	i.nodeConfig.UplinkNetConfig.Name = adapter.Name
	i.nodeConfig.UplinkNetConfig.MAC = adapter.HardwareAddr
	i.nodeConfig.UplinkNetConfig.IP = i.nodeConfig.NodeTransportIPv4Addr
	i.nodeConfig.UplinkNetConfig.Index = adapter.Index
	defaultGW, err := util.GetDefaultGatewayByInterfaceIndex(adapter.Index)
	if err != nil {
		if strings.Contains(err.Error(), "No matching MSFT_NetRoute objects found") {
			klog.InfoS("No default gateway found on interface", "interface", adapter.Name)
			defaultGW = ""
		} else {
			return err
		}
	}
	i.nodeConfig.UplinkNetConfig.Gateway = defaultGW
	dnsServers, err := util.GetDNServersByInterfaceIndex(adapter.Index)
	if err != nil {
		return err
	}
	i.nodeConfig.UplinkNetConfig.DNSServers = dnsServers
	// Save routes which are configured on the uplink interface, and configure them on the management virtual adapter
	// if Windows host doesn't move the configuration automatically.
	if err = i.saveHostRoutes(); err != nil {
		return err
	}
	// Create HNS network.
	subnetCIDR := i.nodeConfig.PodIPv4CIDR
	if subnetCIDR == nil {
		return fmt.Errorf("failed to find valid IPv4 PodCIDR")
	}
	return util.PrepareHNSNetwork(subnetCIDR, i.nodeConfig.NodeTransportIPv4Addr, adapter, i.nodeConfig.UplinkNetConfig.Gateway, dnsServers, i.nodeConfig.UplinkNetConfig.Routes, i.ovsBridge)
}

// prepareOVSBridge adds local port and uplink to ovs bridge.
// This function will delete OVS bridge and HNS network created by antrea on failure.
func (i *Initializer) prepareOVSBridge() error {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	defer func() {
		// prepareOVSBridge only works on windows platform. The operation has a chance to fail on the first time agent
		// starts up when OVS bridge uplink and local interface have not been configured. If the operation fails, the
		// host can not communicate with external network. To make sure the agent can connect to API server in
		// next retry, this step deletes OVS bridge and HNS network created previously which will restore the
		// host network.
		if err == nil {
			return
		}
		if err := i.ovsBridgeClient.Delete(); err != nil {
			klog.Errorf("Failed to delete OVS bridge: %v", err)
		}
		if err := util.DeleteHNSNetwork(util.LocalHNSNetwork); err != nil {
			klog.Errorf("Failed to cleanup host networking: %v", err)
		}
	}()
	if err != nil {
		return err
	}

	// Set datapathID of OVS bridge.
	// If no datapathID configured explicitly, the reconfiguration operation will change OVS bridge datapathID
	// and break the OpenFlow channel.
	// The length of datapathID is 64 bits, the lower 48-bits are for a MAC address, while the upper 16-bits are
	// implementer-defined. Antrea uses "0x0000" for the upper 16-bits.
	datapathID := strings.Replace(hnsNetwork.SourceMac, ":", "", -1)
	datapathID = "0000" + datapathID
	if err = i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		klog.Errorf("Failed to set datapath_id %s: %v", datapathID, err)
		return err
	}

	// Create local port.
	brName := i.ovsBridgeClient.GetBridgeName()
	if _, err = i.ovsBridgeClient.GetOFPort(brName, false); err == nil {
		klog.Infof("OVS bridge local port %s already exists, skip the configuration", brName)
	} else {
		// OVS does not receive "ofport_request" param when creating local port, so here use config.AutoAssignedOFPort=0
		// to ignore this param.
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
		}
		if _, err = i.ovsBridgeClient.CreateInternalPort(brName, config.AutoAssignedOFPort, externalIDs); err != nil {
			return err
		}
	}

	// If uplink is already exists, return.
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplink := uplinkNetConfig.Name
	if _, err = i.ovsBridgeClient.GetOFPort(uplink, false); err == nil {
		klog.Infof("Uplink %s already exists, skip the configuration", uplink)
		return err
	}
	// Create uplink port.
	var uplinkPortUUID string
	uplinkPortUUID, err = i.ovsBridgeClient.CreateUplinkPort(uplink, config.UplinkOFPort, nil)
	if err != nil {
		klog.Errorf("Failed to add uplink port %s: %v", uplink, err)
		return err
	}
	uplinkInterface := interfacestore.NewUplinkInterface(uplink)
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUID, config.UplinkOFPort} //nolint: govet
	i.ifaceStore.AddInterface(uplinkInterface)
	ovsCtlClient := ovsctl.NewClient(i.ovsBridge)

	// Set the uplink with "no-flood" config, so that the IP of local Pods and "antrea-gw0" will not be leaked to the
	// underlay network by the "normal" flow entry.
	if err = ovsCtlClient.SetPortNoFlood(config.UplinkOFPort); err != nil {
		klog.Errorf("Failed to set the uplink port with no-flood config: %v", err)
		return err
	}
	return nil
}

// initHostNetworkFlows installs Openflow flows between bridge local port and uplink port to support
// host networking.
func (i *Initializer) initHostNetworkFlows() error {
	if err := i.ofClient.InstallBridgeUplinkFlows(); err != nil {
		return err
	}
	return nil
}

// getTunnelLocalIP returns local_ip of tunnel port
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return i.nodeConfig.NodeTransportIPv4Addr.IP
}

// saveHostRoutes saves routes which are configured on uplink interface before
// the interface the configured as the uplink of antrea HNS network.
// The routes will be restored on OVS bridge interface after the IP configuration
// is moved to the OVS bridge.
func (i *Initializer) saveHostRoutes() error {
	routes, err := util.GetNetRoutesAll()
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.LinkIndex != i.nodeConfig.UplinkNetConfig.Index {
			continue
		}
		if route.GatewayAddress.String() != i.nodeConfig.UplinkNetConfig.Gateway {
			continue
		}
		// Skip IPv6 routes before we support IPv6 stack.
		if route.DestinationSubnet.IP.To4() == nil {
			continue
		}
		// Skip default route. The default route will be added automatically when
		// configuring IP address on OVS bridge interface.
		if route.DestinationSubnet.IP.IsUnspecified() {
			continue
		}
		klog.V(4).Infof("Got host route: %v", route)
		i.nodeConfig.UplinkNetConfig.Routes = append(i.nodeConfig.UplinkNetConfig.Routes, route)
	}
	return nil
}

// restoreHostRoutes restores the host routes which are lost when moving the IP
// configuration of uplink interface to the OVS bridge interface during
// the antrea network initialize stage.
// The backup routes are restored after the IP configuration change.
func (i *Initializer) restoreHostRoutes() error {
	brInterface, err := net.InterfaceByName(i.ovsBridge)
	if err != nil {
		return nil
	}
	for _, route := range i.nodeConfig.UplinkNetConfig.Routes {
		rt := route.(util.Route)
		newRt := util.Route{
			LinkIndex:         brInterface.Index,
			DestinationSubnet: rt.DestinationSubnet,
			GatewayAddress:    rt.GatewayAddress,
			RouteMetric:       rt.RouteMetric,
		}
		if err := util.NewNetRoute(&newRt); err != nil {
			return err
		}
	}
	return nil
}

func GetTransportIPNetDeviceByName(ifaceName string, ovsBridgeName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
	// Find transport Interface in the order: ifaceName -> "vEthernet (ifaceName)" -> br-int. Return immediately if
	// an interface using the specified name exists. Using "vEthernet (ifaceName)" or br-int is for restart agent case.
	for _, name := range []string{ifaceName, util.VirtualAdapterName(ifaceName), ovsBridgeName} {
		ipNet, _, link, err := util.GetIPNetDeviceByName(name)
		if err == nil {
			return ipNet, nil, link, nil
		}
		if !strings.Contains(err.Error(), "no such network interface") {
			return nil, nil, nil, err
		}
	}
	return nil, nil, nil, fmt.Errorf("unable to find local IP and device")
}

// BridgeUplinkToOVSBridge returns immediately on Windows.
func (i *Initializer) BridgeUplinkToOVSBridge() error { return nil }

// RestoreOVSBridge returns immediately in Windows.
// OVS is managed by system in Windows, network config can be retained after Antrea shutdown.
func (i *Initializer) RestoreOVSBridge() {}
