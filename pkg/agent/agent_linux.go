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

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/ethtool"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	utilip "antrea.io/antrea/pkg/util/ip"
)

var (
	// getInterfaceByName is meant to be overridden for testing.
	getInterfaceByName = net.InterfaceByName

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
	// Gateway and DNSServers are not configured at adapter in Linux
	// Limitation: dynamic DNS servers will be lost after DHCP lease expired
	uplinkNetConfig.Gateway = ""
	uplinkNetConfig.DNSServers = ""

	// Set datapathID of OVS bridge.
	// If no datapathID configured explicitly, the reconfiguration operation will change OVS bridge datapathID
	// and break the OpenFlow channel.
	datapathID := util.GenerateOVSDatapathID(uplinkNetConfig.MAC.String())

	if err = i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		return fmt.Errorf("failed to set datapath_id %s: err=%w", datapathID, err)
	}

	if hostOFPort, err := i.ovsBridgeClient.GetOFPort(uplinkNetConfig.Name, false); err == nil {
		klog.InfoS("OVS bridge local port already exists", "name", uplinkNetConfig.Name)
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
		klog.InfoS("Found uplink", "Name", adapter.Name, "Index", uplinkNetConfig.Index, "ofPort", uplinkNetConfig.OFPort)
	} else {
		klog.InfoS("Using default OpenFlow port for uplink", "ofPort", config.DefaultUplinkOFPort)
		uplinkNetConfig.OFPort = config.DefaultUplinkOFPort
		klog.InfoS("Using default OpenFlow port for host interface", "ofPort", config.DefaultHostInterfaceOFPort)
		i.nodeConfig.HostInterfaceOFPort = config.DefaultHostInterfaceOFPort
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

func (i *Initializer) ConnectUplinkToOVSBridge() error {
	// Return immediately on Linux if connectUplinkToBridge is false.
	if !i.connectUplinkToBridge {
		return nil
	}
	klog.InfoS("Bridging uplink to OVS bridge")
	var err error
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig

	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
	}
	// We request the same MTU for the bridge interface as for the uplink adapter. If we don't,
	// OVS will default to the lowest MTU among all existing bridge ports, including container
	// ports. There may be some existing workloads with a lower MTU, and using that lower value
	// may impact host connectivity.
	bridgedUplinkName, exists, err := util.PrepareHostInterfaceConnection(
		i.ovsBridgeClient,
		uplinkNetConfig.Name,
		int32(i.nodeConfig.HostInterfaceOFPort),
		externalIDs,
		i.nodeConfig.NodeTransportInterfaceMTU,
	)
	if err != nil {
		return err
	}
	if exists {
		return nil
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
	return nil
}

// RestoreOVSBridge returns immediately on Linux if connectUplinkToBridge is false.
// OVS is managed by Antrea in Linux, network config must be restored to uplink before Antrea Agent shutdown.
func (i *Initializer) RestoreOVSBridge() {
	if !i.connectUplinkToBridge {
		return
	}
	klog.InfoS("Restoring bridge config to uplink...")

	if i.nodeConfig.UplinkNetConfig.Name != "" {
		util.RestoreHostInterfaceConfiguration(i.ovsBridge, i.nodeConfig.UplinkNetConfig.Name)
		klog.InfoS("Finished restoring bridge config to uplink...")
	}
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
		portUUID, err := i.ovsBridgeClient.CreateInternalPort(portName, ovsconfig.AutoAssignedOFPort, "", trafficControlPortExternalIDs)
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

func (i *Initializer) setTXChecksumOffloadOnGateway() error {
	if i.disableTXChecksumOffload {
		if err := ethtool.EthtoolTXHWCsumOff(i.hostGateway); err != nil {
			return fmt.Errorf("error when disabling TX checksum offload on %s: %v", i.hostGateway, err)
		}
		klog.InfoS("Disabled TX checksum offload on host gateway interface", "hostGateway", i.hostGateway)
	}
	return nil
}
