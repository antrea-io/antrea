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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/plugins/pkg/ip"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"k8s.io/client-go/kubernetes"
	componentbaseconfig "k8s.io/component-base/config"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
)

const (
	OVSExtensionID = "583CC151-73EC-4A6A-8B47-578297AD7623"
)

type agentConfig struct {
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
	OVSBridge string `yaml:"ovsBridge,omitempty"`
}

type adapterNetConfig struct {
	name       string
	index      int
	mac        net.HardwareAddr
	ip         *net.IPNet
	gateway    string
	dnsServers string
}

type vSwitchExtensionPolicy struct {
	ExtensionID string `json:"Id,omitempty"`
	IsEnabled   bool
}

type ExtensionsPolicy struct {
	Extensions []vSwitchExtensionPolicy `json:"Extensions"`
}

// ensureHNSNetwork checks if the HNS Network exists. If not, create a new one.
func (p *program) ensureHNSNetwork() error {
	k8sClient, brName, err := getConfigFromFile(p.configFile)
	if err != nil {
		return err
	}
	nodeConfig, err := agent.GetNodeConfig(k8sClient, p.nodeName, false)
	if err != nil {
		return err
	}
	p.ovsBridge = brName

	_, err = hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err == nil {
		return nil
	}
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	hnsNet, adapterConfig, err := CreateHNSNetwork(util.LocalHNSNetwork, nodeConfig.PodCIDR, nodeConfig.NodeIPAddr)
	if err != nil {
		return err
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	if err = enableHNSOnOVS(hnsNet, adapterConfig, brName); err != nil {
		hnsNet.Delete()
		return err
	}
	return nil
}

func enableHNSOnOVS(hnsNet *hcsshim.HNSNetwork, adapterConfig *adapterNetConfig, ovsBrName string) error {
	// Release OS management for HNS Network if Hyper-V is enabled.
	hypervEnabled, err := util.WindowsHyperVInstalled()
	if err != nil {
		return err
	}
	if hypervEnabled {
		if err := removeManagementInterface(util.LocalHNSNetwork); err != nil {
			return err
		}
		if err := addOVSInterface(adapterConfig, ovsBrName); err != nil {
			return err
		}
	}

	// Enable the HNS Network with OVS extension.
	if err := changeHNSNetworkExtensionStaus(hnsNet.Id, OVSExtensionID, true); err != nil {
		return err
	}
	return nil
}

// removeManagementInterface removes the management interface of the HNS Network, and then the physical interface can be
// added to the OVS bridge. This function is called only if Hyper-V feature is installed on the host.
func removeManagementInterface(networkName string) error {
	var err error
	var maxRetry = 3
	var i = 0
	cmd := fmt.Sprintf("Get-VMSwitch -Name %s  | Set-VMSwitch -AllowManagementOS $false ", networkName)
	// Retry the operation here because an error is returned at the first invocation.
	for i < maxRetry {
		err = util.InvokePSCommand(cmd)
		if err == nil {
			return nil
		}
		i++
	}
	return err
}

// CreateHNSNetwork creates a new HNS Network, whose type is "Transparent". The NetworkAdapter is using the host
// interface which is configured with Node IP. HNS Network properties "ManagementIP" and "SourceMac" are used to record
// the original IP and MAC addresses on the network adapter.
func CreateHNSNetwork(hnsNetName string, subnetCIDR *net.IPNet, nodeIP *net.IPNet) (*hcsshim.HNSNetwork, *adapterNetConfig, error) {
	_, adapter, err := util.GetIPNetDeviceFromIP(nodeIP.IP)
	if err != nil {
		return nil, nil, err
	}
	adapteConfig, err := getAdapterNetConfiguration(adapter, nodeIP)
	if err != nil {
		return nil, nil, err
	}
	adapterMAC := adapteConfig.mac
	adapterName := adapteConfig.name
	gateway := ip.NextIP(subnetCIDR.IP.Mask(subnetCIDR.Mask))
	network := &hcsshim.HNSNetwork{
		Name:               hnsNetName,
		Type:               util.HNSNetworkType,
		NetworkAdapterName: adapterName,
		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  subnetCIDR.String(),
				GatewayAddress: gateway.String(),
			},
		},
		ManagementIP: nodeIP.String(),
		SourceMac:    adapterMAC.String(),
	}
	hnsNet, err := network.Create()
	if err != nil {
		return nil, nil, err
	}
	return hnsNet, adapteConfig, nil
}

func getAdapterNetConfiguration(adapter *net.Interface, ipConfig *net.IPNet) (*adapterNetConfig, error) {
	adapterIndex := adapter.Index
	defaultGW, err := getDefaultGatewayByInterface(adapterIndex)
	if err != nil {
		return nil, err
	}
	dnsServers, err := getDNServersByInterface(adapterIndex)
	if err != nil {
		return nil, err
	}
	return &adapterNetConfig{
		name:       adapter.Name,
		index:      adapterIndex,
		mac:        adapter.HardwareAddr,
		ip:         ipConfig,
		gateway:    defaultGW,
		dnsServers: dnsServers,
	}, nil
}

// changeHNSNetworkExtensionStaus changes the specified vSwitchExtension the enabling status on the target HNS Network.
// Antrea calls this function to enable or disable OVS Extension on the HNS Network.
func changeHNSNetworkExtensionStaus(hnsNetID string, vSwitchExtension string, enabled bool) error {
	extensionPolicy := vSwitchExtensionPolicy{
		ExtensionID: vSwitchExtension,
		IsEnabled:   enabled,
	}
	jsonString, _ := json.Marshal(
		ExtensionsPolicy{
			Extensions: []vSwitchExtensionPolicy{extensionPolicy},
		})

	_, err := hcsshim.HNSNetworkRequest("POST", hnsNetID, string(jsonString))
	if err != nil {
		return err
	}
	return nil
}

// getDefaultGatewayByInterface returns the default gateway configured on the speicified interface.
func getDefaultGatewayByInterface(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-NetRoute -InterfaceIndex %d -DestinationPrefix 0.0.0.0/0 ).NextHop", ifIndex)
	defaultGW, err := util.CallPSCommand(cmd)
	if err != nil {
		return "", err
	}
	defaultGW = strings.ReplaceAll(defaultGW, "\r\n", "")
	return defaultGW, nil
}

// getDNServersByInterface returns the DNS servers configured on the specified interface.
func getDNServersByInterface(ifIndex int) (string, error) {
	cmd := fmt.Sprintf("$(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses", ifIndex)
	dnsServers, err := util.CallPSCommand(cmd)
	if err != nil {
		return "", err
	}
	dnsServers = strings.ReplaceAll(dnsServers, "\r\n", ",")
	dnsServers = strings.TrimRight(dnsServers, ",")
	return dnsServers, nil
}

// addOVSInterface creates a new interface for OVS bridge. The new adapter is using the MAC and IP configuration of the
// physical network adapter which is used in the HNS Network.
func addOVSInterface(config *adapterNetConfig, ovsBridgeName string) error {
	// Create VMNetworkAdapter which is using the MAC address of the physical adapter.
	cmd := fmt.Sprintf("Add-VMNetworkAdapter -ManagementOS -Name %s -SwitchName %s -StaticMacAddress %s", ovsBridgeName, util.LocalHNSNetwork, config.mac.String())
	if err := util.InvokePSCommand(cmd); err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			cmd := fmt.Sprintf("remove-VMNetworkAdapter -ManagementOS -Name %s", ovsBridgeName)
			_ = util.InvokePSCommand(cmd)
		}
	}()
	vnicName := fmt.Sprintf("vEthernet (%s)", ovsBridgeName)
	// Add IP configuration on the new VMNetworkAdapter.
	adapterIP := config.ip.IP.String()
	adapterIPPrefix := strings.Split(config.ip.String(), "/")[1]
	// Remove the IP address if exists to avoid a candidate error of "Instance MSFT_NetIPAddress already exists" when
	// adding it on the new VMNetworkAdapter.
	cmd = fmt.Sprintf("Remove-NetIPAddress -IPAddress %s -Confirm:$false", adapterIP)
	if err := util.InvokePSCommand(cmd); err != nil {
		if !strings.Contains(err.Error(), "No MSFT_NetIPAddress objects found") {
			return err
		}
	}
	// Add IP configuration on the new VMNetworkAdapter.
	cmd = fmt.Sprintf("New-NetIPAddress -IPAddress %s -PrefixLength %s -DefaultGateway %s -InterfaceAlias '%s'", adapterIP, adapterIPPrefix, config.gateway, vnicName)
	if err := util.InvokePSCommand(cmd); err != nil {
		return err
	}
	// Config DNSServers on the new VMNetworkAdapter.
	if config.dnsServers != "" {
		cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses %s", vnicName, config.dnsServers)
		if err := util.InvokePSCommand(cmd); err != nil {
			return err
		}
	}
	success = true
	return nil
}

func getConfigFromFile(file string) (kubernetes.Interface, string, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, "", err
	}

	var c agentConfig
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return nil, "", err
	}
	k8sClient, _, err := k8s.CreateClients(c.ClientConnection)
	if err != nil {
		return nil, "", err
	}
	return k8sClient, c.OVSBridge, nil
}
