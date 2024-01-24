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
	"antrea.io/antrea/pkg/agent/externalnode"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	utilip "antrea.io/antrea/pkg/util/ip"
)

var (
	// setInterfaceMTU is meant to be overridden for testing
	setInterfaceMTU = util.SetInterfaceMTU

	// setInterfaceARPAnnounce is meant to be overridden for testing.
	setInterfaceARPAnnounce = func(ifaceName string, value int) error { return nil }
)

func (i *Initializer) prepareHostNetwork() error {
	if i.nodeConfig.Type == config.K8sNode {
		return i.prepareHNSNetworkAndOVSExtension()
	}
	return i.prepareVMNetworkAndOVSExtension()
}

// prepareHNSNetworkAndOVSExtension creates HNS Network for containers, and enables OVS Extension on it.
func (i *Initializer) prepareHNSNetworkAndOVSExtension() error {
	// If the HNS Network already exists, return immediately.
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err == nil {
		// Enable OVS Extension on the HNS Network.
		if err = util.EnableHNSNetworkExtension(hnsNetwork.Id, util.OVSExtensionID); err != nil {
			return err
		}
		// Enable RSC for existing vSwitch.
		if err = util.EnableRSCOnVSwitch(util.LocalHNSNetwork); err != nil {
			return err
		}
		// Save the uplink adapter name to check if the OVS uplink port has been created in prepareOVSBridge stage.
		i.nodeConfig.UplinkNetConfig.Name = hnsNetwork.NetworkAdapterName

		// Save the uplink adapter MAC to modify Pod traffic source MAC if the packet is directly output to the uplink
		// interface in OVS pipeline.
		i.nodeConfig.UplinkNetConfig.MAC, _ = net.ParseMAC(hnsNetwork.SourceMac)
		return nil
	}
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	// Get uplink network configuration. The uplink interface is the one used for transporting Pod traffic across Nodes.
	// Use the interface specified with "transportInterface" in the configuration if configured, otherwise the interface
	// configured with NodeIP is used as uplink.
	_, _, adapter, err := i.getNodeInterfaceFromIP(&utilip.DualStackIPs{IPv4: i.nodeConfig.NodeTransportIPv4Addr.IP})
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
	i.nodeConfig.UplinkNetConfig.IPs = []*net.IPNet{i.nodeConfig.NodeTransportIPv4Addr}
	i.nodeConfig.UplinkNetConfig.Index = adapter.Index
	defaultGW, err := util.GetDefaultGatewayByInterfaceIndex(adapter.Index)
	if err != nil {
		return err
	}
	if defaultGW == "" {
		klog.InfoS("No default gateway found on interface", "interface", adapter.Name)
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

func (i *Initializer) prepareVMNetworkAndOVSExtension() error {
	klog.V(2).Info("Setting up VM network")
	// Check whether VM Switch is created
	exists, err := util.VMSwitchExists()
	if err != nil {
		return err
	}
	if exists {
		vmSwitchIFName, err := util.GetVMSwitchInterfaceName()
		if err != nil {
			return err
		}
		klog.InfoS("Got existing VM switch teaming members", "interfaceName", vmSwitchIFName)
		if i.nodeConfig.UplinkNetConfig.Name != util.GenHostInterfaceName(vmSwitchIFName) {
			return fmt.Errorf("unexpected teaming interface %s found", vmSwitchIFName)
		}
		return nil
	}

	// Get the uplink interface configuration
	uplinkIface, _, _, err := util.GetInterfaceConfig(i.nodeConfig.UplinkNetConfig.Name)
	if err != nil {
		return err
	}

	var success = false
	hostIFName := i.nodeConfig.UplinkNetConfig.Name
	uplinkIFName := util.GenerateUplinkInterfaceName(hostIFName)
	klog.InfoS("Using the interface", "hostIFName", hostIFName, "uplinkIFName", uplinkIFName)
	// Rename interfaceName to interfaceName~
	if err = util.RenameInterface(hostIFName, uplinkIFName); err != nil {
		return err
	}

	defer func() {
		if !success {
			if err = util.RenameInterface(uplinkIFName, hostIFName); err != nil {
				klog.ErrorS(err, "Failed to rename interface back")
			}
		}
	}()

	klog.V(2).InfoS("Creating VM switch", "uplinkIFName", uplinkIFName)
	if err = util.CreateVMSwitch(uplinkIFName); err != nil {
		return fmt.Errorf("failed to create VM switch for interface %s: %v", uplinkIFName, err)
	}

	defer func() {
		if !success {
			if err = util.RemoveVMSwitch(); err != nil {
				klog.ErrorS(err, "Failed to remove VMSwitch")
			}
		}
	}()

	uplinkMACStr := strings.Replace(uplinkIface.HardwareAddr.String(), ":", "", -1)
	if err = util.RenameVMNetworkAdapter(util.LocalVMSwitch, uplinkMACStr, hostIFName, true); err != nil {
		return fmt.Errorf("failed to rename VMNetworkAdapter as %s: %v", hostIFName, err)
	}

	success = true
	return nil
}

// prepareOVSBridgeForK8sNode adds local port and uplink port to OVS bridge after OVS extension is enabled on HNSNetwork.
// This function deletes OVS bridge and HNS network created by Antrea on failure.
func (i *Initializer) prepareOVSBridgeForK8sNode() error {
	return i.prepareOVSBridgeOnHNSNetwork()
}

// prepareOVSBridgeOnHNSNetwork adds local port and uplink to OVS bridge after the OVS Extension is enabled on HNSNetwork.
// This function will delete OVS bridge and HNS network created by Antrea at failures.
func (i *Initializer) prepareOVSBridgeOnHNSNetwork() error {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	defer func() {
		// prepareOVSBridge only works on Windows platform. The operation has a chance to fail on the first time agent
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
	datapathID := util.GenerateOVSDatapathID(hnsNetwork.SourceMac)
	if err = i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		klog.ErrorS(err, "Failed to set OVS bridge datapath_id", "datapathID", datapathID)
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
		if _, err = i.ovsBridgeClient.CreateInternalPort(brName, config.AutoAssignedOFPort, "", externalIDs); err != nil {
			return err
		}
	}

	// If uplink is already exists, return.
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplink := uplinkNetConfig.Name
	if ofport, err := i.ovsBridgeClient.GetOFPort(uplink, false); err == nil {
		klog.InfoS("Uplink already exists, skip the configuration", "uplink", uplink, "port", ofport)
		i.nodeConfig.UplinkNetConfig.OFPort = uint32(ofport)
		i.nodeConfig.HostInterfaceOFPort = config.BridgeOFPort
		return nil
	}
	// Create uplink port.
	freePort, err := i.ovsBridgeClient.AllocateOFPort(config.UplinkOFPort)
	if err != nil {
		klog.ErrorS(err, "Failed to find a free port on OVS")
		return err
	}
	var uplinkPortUUID string
	uplinkPortUUID, err = i.ovsBridgeClient.CreateUplinkPort(uplink, freePort, nil)
	if err != nil {
		klog.Errorf("Failed to add uplink port %s: %v", uplink, err)
		return err
	}
	uplinkOFPort, err := i.ovsBridgeClient.GetOFPort(uplink, false)
	if err != nil {
		return fmt.Errorf("failed to get uplink ofport %s: err=%w", uplink, err)
	}
	klog.InfoS("Allocated OpenFlow port for uplink interface", "port", uplink, "ofPort", uplinkOFPort)
	i.nodeConfig.UplinkNetConfig.OFPort = uint32(uplinkOFPort)
	i.nodeConfig.HostInterfaceOFPort = config.BridgeOFPort
	uplinkInterface := interfacestore.NewUplinkInterface(uplink)
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUID, uplinkOFPort} //nolint: govet
	i.ifaceStore.AddInterface(uplinkInterface)
	ovsCtlClient := ovsctl.NewClient(i.ovsBridge)

	// Enable IP forwarding on the bridge local interface. Traffic from the uplink interface will be output to the bridge
	// local interface directly. When an external client connects to a LoadBalancer type Service, and the packets of the
	// connection are routed to the selected backend Pod via the bridge interface; if we do not enable IP forwarding on
	// the bridge interface, the packet will be discarded on the bridge interface as the destination of the packet
	// is not the Node.
	if err = util.EnableIPForwarding(brName); err != nil {
		return err
	}
	// Set the uplink with "no-flood" config, so that the IP of local Pods and "antrea-gw0" will not be leaked to the
	// underlay network by the "normal" flow entry.
	if err = ovsCtlClient.SetPortNoFlood(int(uplinkOFPort)); err != nil {
		klog.Errorf("Failed to set the uplink port with no-flood config: %v", err)
		return err
	}
	return nil
}

func (i *Initializer) prepareOVSBridgeForVM() error {
	klog.InfoS("Performing OVS configuration", "hostIFName", i.nodeConfig.UplinkNetConfig.Name)
	hostIFName := i.nodeConfig.UplinkNetConfig.Name
	uplinkIFName := util.GenerateUplinkInterfaceName(hostIFName)
	ovsPorts, ovsErr := i.ovsBridgeClient.GetPortList()
	if ovsErr != nil {
		return fmt.Errorf("failed to list OVS ports: %v", ovsErr)
	}
	for _, port := range ovsPorts {
		if port.Name == hostIFName {
			klog.Info("Uplink and host interface configuration exist in OVS")
			return nil
		}
	}

	success := false
	uplinkExternalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	// TODO: Have a separate function for creation of pair ports
	// Create uplink port on OVS.
	uplinkUUID, ovsErr := i.ovsBridgeClient.CreatePort(uplinkIFName, uplinkIFName, uplinkExternalIDs)
	if ovsErr != nil {
		return fmt.Errorf("failed to create uplink port on OVS for %s: %v", uplinkIFName, ovsErr)
	}

	// Manual clean up of OVS configurations is required, when agent exits
	// abruptly or when the auto cleanup operation fails.
	defer func() {
		if !success {
			klog.InfoS("Deleting port on OVS", "uplinkUUID", uplinkUUID)
			if ovsErr := i.ovsBridgeClient.DeletePort(uplinkUUID); ovsErr != nil {
				klog.ErrorS(ovsErr, "Failed to delete port on OVS", "uplinkUUID", uplinkUUID)
			}
		}
	}()

	// Query the uplink port to check if its created
	uplinkOFPort, ovsErr := i.ovsBridgeClient.GetOFPort(uplinkIFName, false)
	if ovsErr != nil {
		return fmt.Errorf("failed to get ofport on OVS for uplink interface %s: %v", uplinkIFName, ovsErr)
	}
	klog.InfoS("Added uplink port on OVS", "ofport", uplinkOFPort)
	// ExternalEntity is not processed yet, so an empty name is set for entityName in OVSDB,
	// which will be updated by ExternalNode controller.
	attachInfo := externalnode.GetOVSAttachInfo(uplinkIFName, uplinkUUID, "", i.externalNodeNamespace, []string{""})
	// Create host port on OVS.
	hostIfUUID, ovsErr := i.ovsBridgeClient.CreateInternalPort(hostIFName, 0, "", attachInfo)
	if ovsErr != nil {
		return fmt.Errorf("failed to create host port on OVS for %s: %v", hostIFName, ovsErr)
	}

	// Manual clean up of OVS configurations is required, when agent exits abruptly.
	defer func() {
		if !success {
			klog.InfoS("Deleting port on OVS", "hostIfUUID", hostIfUUID)
			if ovsErr := i.ovsBridgeClient.DeletePort(hostIfUUID); ovsErr != nil {
				klog.ErrorS(ovsErr, "Failed to delete port on OVS", "hostIfUUID", hostIfUUID)
			}
		}
	}()

	// Query the host port to check if its created
	hostOFPort, ovsErr := i.ovsBridgeClient.GetOFPort(hostIFName, false)
	if ovsErr != nil {
		return fmt.Errorf("failed to get ofport for host interface %s: %v", hostIFName, ovsErr)
	}
	klog.InfoS("Added host port on OVS", "ofport", hostOFPort)
	success = true
	return i.setOVSDatapath()
}

// getTunnelLocalIP returns local_ip of tunnel port
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return i.nodeConfig.NodeTransportIPv4Addr.IP
}

// saveHostRoutes saves routes configured on the uplink interface before the
// interface is configured as the uplink of Antrea HNS network.
// The routes will be restored on the OVS bridge interface after the IP
// configuration is moved to the OVS bridge.
func (i *Initializer) saveHostRoutes() error {
	// IPv6 is not supported on Windows currently. Please refer to https://github.com/antrea-io/antrea/issues/5162
	// for more information.
	family := antreasyscall.AF_INET
	filter := &util.Route{
		LinkIndex:      i.nodeConfig.UplinkNetConfig.Index,
		GatewayAddress: net.ParseIP(i.nodeConfig.UplinkNetConfig.Gateway),
	}
	routes, err := util.RouteListFiltered(family, filter, util.RT_FILTER_IF|util.RT_FILTER_GW)
	if err != nil {
		return err
	}
	for _, route := range routes {
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

func getTransportIPNetDeviceByName(ifaceName string, ovsBridgeName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
	// Find transport Interface in the order: ifaceName -> br-int. Return immediately if
	// an interface using the specified name exists. Using br-int is for restart agent case.
	for _, name := range []string{ifaceName, ovsBridgeName} {
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

// ConnectUplinkToOVSBridge returns immediately on Windows. The uplink interface
// will be connected to the bridge in prepareOVSBridge().
func (i *Initializer) ConnectUplinkToOVSBridge() error { return nil }

// RestoreOVSBridge returns immediately in Windows.
// OVS is managed by system in Windows, network config can be retained after Antrea shutdown.
func (i *Initializer) RestoreOVSBridge() {}

func (i *Initializer) setInterfaceMTU(iface string, mtu int) error {
	if err := i.ovsBridgeClient.SetInterfaceMTU(iface, mtu); err != nil {
		return err
	}
	return setInterfaceMTU(iface, mtu)
}

func (i *Initializer) setVMNodeConfig(en *v1alpha1.ExternalNode, nodeName string) error {
	// TODO: Handle for multiple interfaces
	var uplinkInterface *net.Interface
	foundNetDevice := false
	for _, addr := range en.Spec.Interfaces[0].IPs {
		var ipFilter *utilip.DualStackIPs
		var err error
		epIP := net.ParseIP(addr)
		if epIP.To4() != nil {
			ipFilter = &utilip.DualStackIPs{IPv4: epIP}
		} else {
			ipFilter = &utilip.DualStackIPs{IPv6: epIP}
		}
		_, _, uplinkInterface, err = getIPNetDeviceFromIP(ipFilter, nil)
		if err != nil {
			klog.InfoS("Unable to get net device by IP", "IP", addr)
		} else {
			foundNetDevice = true
			klog.V(2).InfoS("Net device found on the ExternalNode", "interfaceName", uplinkInterface.Name)
			break
		}
	}
	if !foundNetDevice {
		return fmt.Errorf("failed to get net device for ExternalNode %s", en.Name)
	}
	i.nodeConfig = &config.NodeConfig{
		Name:      nodeName,
		Type:      config.ExternalNode,
		OVSBridge: i.ovsBridge,
		UplinkNetConfig: &config.AdapterNetConfig{
			Name: uplinkInterface.Name,
		},
	}
	return nil
}

// installVMFlows configures default flows between uplink and host port,
// so that antrea-agent can connect to antrea-controller.
func (i *Initializer) installVMInitialFlows() error {
	hostIfConfig, found := i.ifaceStore.GetInterfaceByName(i.nodeConfig.UplinkNetConfig.Name)
	if !found {
		return fmt.Errorf("not found interfaceConfig by name %s", i.nodeConfig.UplinkNetConfig.Name)
	}
	hostIFName := hostIfConfig.InterfaceName
	hostOFPort := hostIfConfig.OVSPortConfig.OFPort
	uplinkOFPort := hostIfConfig.EntityInterfaceConfig.UplinkPort.OFPort
	klog.InfoS("Installing host flows", "hostIFName", hostIFName, "hostOFPort", hostOFPort, "uplinkOFPort", uplinkOFPort)
	if err := i.ofClient.InstallVMUplinkFlows(hostIFName, hostOFPort, uplinkOFPort); err != nil {
		return fmt.Errorf("failed to install host fows for interface %s", hostIFName)
	}
	return nil
}

func (i *Initializer) prepareL7EngineInterfaces() error {
	return nil
}
