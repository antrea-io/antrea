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
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

// setupExternalConnectivity installs OpenFlow entries to SNAT Pod traffic using Node IP, and then Pod could communicate
// to the external IP address.
func (i *Initializer) setupExternalConnectivity() error {
	subnetCIDR := i.nodeConfig.PodCIDR
	nodeIP := i.nodeConfig.NodeIPAddr.IP
	// Install OpenFlow entries on the OVS to enable Pod traffic to communicate to external IP addresses.
	if err := i.ofClient.InstallExternalFlows(nodeIP, *subnetCIDR); err != nil {
		klog.Errorf("Failed to setup SNAT openflow entries: %v", err)
		return err
	}
	return nil
}

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
	// Create HNS network.
	return util.PrepareHNSNetwork(i.nodeConfig.PodCIDR, i.nodeConfig.NodeIPAddr, adapter)
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
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUId, config.UplinkOFPort}
	i.ifaceStore.AddInterface(uplinkInterface)

	// Move network configuration of uplink interface to OVS bridge local interface.
	// - The net configuration of uplink will be restored by OS if the attached HNS network is deleted.
	// - When ovs-switchd is down, antrea-agent will disable OVS Extension. The OVS bridge local interface will work
	//   like a normal interface on host and is responsible for forwarding host traffic.
	err = util.EnableHostInterface(brName)
	if err = util.SetAdapterMACAddress(brName, &uplinkNetConfig.MAC); err != nil {
		return err
	}
	// Remove existing IP addresses to avoid a candidate error of "Instance MSFT_NetIPAddress already exists" when
	// adding it on the adapter.
	if err = util.RemoveIPv4AddrsFromAdapter(brName); err != nil {
		return err
	}
	// TODO: Configure IPv6 Address.
	if err = util.ConfigureInterfaceAddressWithDefaultGateway(brName, uplinkNetConfig.IP, uplinkNetConfig.Gateway); err != nil {
		return err
	}
	if uplinkNetConfig.DNSServers != "" {
		if err = util.SetAdapterDNSServers(brName, uplinkNetConfig.DNSServers); err != nil {
			return err
		}
	}
	return nil
}

// initHostNetworkFlows installs Openflow flows between bridge local port and uplink port to support
// host networking. These flows are only needed on windows platform.
func (i *Initializer) initHostNetworkFlows() error {
	if err := i.ofClient.InstallBridgeUplinkFlows(config.UplinkOFPort, config.BridgeOFPort); err != nil {
		return err
	}
	return nil
}

// getTunnelLocalIP returns local_ip of tunnel port
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return i.nodeConfig.NodeIPAddr.IP
}
