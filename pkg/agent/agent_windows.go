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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

// prepareHostNetwork creates HNS Network for containers.
func (i *Initializer) prepareHostNetwork() error {
	// If the HNS Network already exists, return immediately.
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err == nil {
		// Save the uplink adapter name to check if the OVS uplink port has been created in prepareOVSBridge stage.
		i.nodeConfig.UplinkNetConfig.Name = hnsNetwork.NetworkAdapterName
		return nil
	}
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	// Get uplink network configuration.
	_, adapter, err := util.GetIPNetDeviceFromIP(i.nodeConfig.NodeIPAddr.IP)
	if err != nil {
		return err
	}
	i.nodeConfig.UplinkNetConfig.Name = adapter.Name
	i.nodeConfig.UplinkNetConfig.MAC = adapter.HardwareAddr
	i.nodeConfig.UplinkNetConfig.IP = i.nodeConfig.NodeIPAddr
	i.nodeConfig.UplinkNetConfig.Index = adapter.Index
	defaultGW, err := util.GetDefaultGatewayByInterfaceIndex(adapter.Index)
	if err != nil {
		return err
	}
	i.nodeConfig.UplinkNetConfig.Gateway = defaultGW
	dnsServers, err := util.GetDNServersByInterfaceIndex(adapter.Index)
	if err != nil {
		return err
	}
	i.nodeConfig.UplinkNetConfig.DNSServers = dnsServers
	// Save routes which are configured on the uplink interface.
	// The routes on the host will be lost when moving the network configuration of the uplink interface
	// to the OVS bridge local interface. The saved routes will be restored on host after that.
	if err = i.saveHostRoutes(); err != nil {
		return err
	}
	// Create HNS network.
	subnetCIDR := i.nodeConfig.PodIPv4CIDR
	if subnetCIDR == nil {
		return fmt.Errorf("Failed to find valid IPv4 PodCIDR")
	}
	return util.PrepareHNSNetwork(subnetCIDR, i.nodeConfig.NodeIPAddr, adapter)
}

// prepareOVSBridge adds local port and uplink to ovs bridge.
// This function will delete OVS bridge and HNS network created by antrea on failure.
func (i *Initializer) prepareOVSBridge() error {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	defer func() {
		// prepareOVSBridge only works on windows platform. The operation has a chance to fail on the first time agent
		// starts up when OVS bridge uplink and local inteface have not been configured. If the operation fails, the
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
	if _, err = i.ovsBridgeClient.GetOFPort(brName); err == nil {
		klog.Infof("OVS bridge local port %s already exists, skip the configuration", brName)
	} else {
		// OVS does not receive "ofport_request" param when creating local port, so here use config.AutoAssignedOFPort=0
		// to ignore this param.
		if _, err = i.ovsBridgeClient.CreateInternalPort(brName, config.AutoAssignedOFPort, nil); err != nil {
			return err
		}
	}

	// If uplink is already exists, return.
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplink := uplinkNetConfig.Name
	if _, err := i.ovsBridgeClient.GetOFPort(uplink); err == nil {
		klog.Infof("Uplink %s already exists, skip the configuration", uplink)
		return err
	}
	// Create uplink port.
	uplinkPortUUId, err := i.ovsBridgeClient.CreateUplinkPort(uplink, config.UplinkOFPort, nil)
	if err != nil {
		klog.Errorf("Failed to add uplink port %s: %v", uplink, err)
		return err
	}
	uplinkInterface := interfacestore.NewUplinkInterface(uplink)
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUId, config.UplinkOFPort} //nolint: govet
	i.ifaceStore.AddInterface(uplinkInterface)
	ovsCtlClient := ovsctl.NewClient(i.ovsBridge)

	// Move network configuration of uplink interface to OVS bridge local interface.
	// - The net configuration of uplink will be restored by OS if the attached HNS network is deleted.
	// - When ovs-switchd is down, antrea-agent will disable OVS Extension. The OVS bridge local interface will work
	//   like a normal interface on host and is responsible for forwarding host traffic.
	if err = util.EnableHostInterface(brName); err != nil {
		return err
	}
	if err = util.SetAdapterMACAddress(brName, &uplinkNetConfig.MAC); err != nil {
		return err
	}
	// TODO: Configure IPv6 Address.
	if err = util.ConfigureInterfaceAddressWithDefaultGateway(brName, uplinkNetConfig.IP, uplinkNetConfig.Gateway); err != nil {
		if !strings.Contains(err.Error(), "Instance MSFT_NetIPAddress already exists") {
			return err
		}
		err = nil
		klog.V(4).Infof("Address: %s already exists when configuring IP on interface %s", uplinkNetConfig.IP.String(), brName)
	}
	// Restore the host routes which are lost when moving the network configuration of the uplink interface to OVS bridge interface.
	if err = i.restoreHostRoutes(); err != nil {
		return err
	}

	if uplinkNetConfig.DNSServers != "" {
		if err = util.SetAdapterDNSServers(brName, uplinkNetConfig.DNSServers); err != nil {
			return err
		}
	}
	// Set the uplink with "no-flood" config, so that the IP of local Pods and "antrea-gw0" will not be leaked to the
	// underlay network by the "normal" flow entry.
	if err := ovsCtlClient.SetPortNoFlood(config.UplinkOFPort); err != nil {
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

// initExternalConnectivityFlows installs OpenFlow entries to SNAT Pod traffic
// using Node IP, and then Pod could communicate to the external IP addresses.
func (i *Initializer) initExternalConnectivityFlows() error {
	if i.nodeConfig.PodIPv4CIDR == nil {
		return fmt.Errorf("Failed to find valid IPv4 PodCIDR")
	}
	// Install OpenFlow entries on the OVS to enable Pod traffic to communicate to external IP addresses.
	if err := i.ofClient.InstallExternalFlows(); err != nil {
		return err
	}
	return nil
}

// getTunnelLocalIP returns local_ip of tunnel port
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return i.nodeConfig.NodeIPAddr.IP
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
