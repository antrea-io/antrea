// Copyright 2022 Antrea Authors
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

package infra

import (
	"fmt"
	"k8s.io/klog/v2"
	ovsconfig "antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/agent/openflow"
	ofconfig "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
)

const defaultSecondaryTunInterfaceName = "sectun0"

// ConfigureSecondaryNetworkInfra creates OVS bridges per SecondaryNetworkConfig needs.
func ConfigureSecondaryNetworkInfra(o *SecondaryNetworkOptions) error {
        //connect to OVS DB
        ovsdbAddr := ovsconfig.GetConnAddress(o.config.Secondary_OVSRunDir)
	klog.Info("NEW OVSDBAddress for Secondary Network is: %s and DP type: %s",ovsdbAddr, o.config.Secondary_OVSRunDir)
        ovsdbConn, err := ovsconfig.NewOVSDBConnectionUDS(ovsdbAddr)
        if err != nil {
                return fmt.Errorf("error connecting OVSDB: %v", err)
        }
        defer ovsdbConn.Close()

        ovsDatapathType := ovsconfig.OVSDatapathType(o.config.Secondary_OVSDatapathType)
        //Create br-int1 for secondary interface configuration with pods.
        ovsBridgeClient1 := ovsconfig.NewOVSBridge(o.config.Secondary_OVSBridge1, ovsDatapathType, ovsdbConn)
        if err := ovsBridgeClient1.Create(); err != nil {
                klog.Error("Failed to create Secondary Network %s OVS bridge: %v",o.config.Secondary_OVSBridge1, err)
                return err
        }
        //Initialize OpenFlow entries on secondary networking br-int1(podBridge)
        ovsBridgeMgmtAddr1 := ofconfig.GetMgmtAddress(o.config.Secondary_OVSRunDir, o.config.Secondary_OVSBridge1)
        ofClient1 := openflow.NewClient(o.config.Secondary_OVSBridge1, ovsBridgeMgmtAddr1, ovsDatapathType,false, false, false, false, false, false, false)
        if err := ofClient1.InstallDefaultFlowsForSecondaryNetworkPodBridge(); err != nil {
                klog.Error("Failed to create OpenFlow for Secondary Network PodBridge %s OVS bridge: %v",o.config.Secondary_OVSBridge1, err)
                return err
        }
        //Create br-int2 for secondary interface configuration specific node-to-node tunnel termination.
        ovsBridgeClient2 := ovsconfig.NewOVSBridge(o.config.Secondary_OVSBridge2, ovsDatapathType, ovsdbConn)
        if err := ovsBridgeClient2.Create(); err != nil {
                klog.Error("Failed to create Secondary Network tunnelBridge %s OVS bridge: %v",o.config.Secondary_OVSBridge2, err)
                return err
        }
	setupDefaultSecondaryTunInterface(ovsBridgeClient2, o)
        //Initialize OpenFlow entries on secondary networking br-int2(tunnelBridge)
        ovsBridgeMgmtAddr2 := ofconfig.GetMgmtAddress(o.config.Secondary_OVSRunDir, o.config.Secondary_OVSBridge2)
        ofClient2 := openflow.NewClient(o.config.Secondary_OVSBridge2, ovsBridgeMgmtAddr2, ovsDatapathType,false, false, false, false, false, false, false)
        if err := ofClient2.InstallDefaultFlowsForSecondaryNetworkTunnelBridge(); err != nil {
                klog.Error("Failed to create OpenFlow for Secondary Network TunnelBridge %s OVS bridge: %v",o.config.Secondary_OVSBridge2, err)
                return err
        }

        //Connect br-int1 and br-int2 with ovs patch port.
	//Create OVS patch port at podBridge and set its peer
	podPatchInterface, podPatchExist := o.interfaceStore.GetInterface(o.config.Secondary_OVSPatchPort)
        if !podPatchExist {
	        portUUID1 , err := ovsBridgeClient1.CreatePatchPort(o.config.Secondary_OVSBridge1, o.config.Secondary_OVSPatchPort, o.config.Secondary_OVSPatchPortPeer)
	        if err != nil {
                       klog.Error("Failed to create OVS patch port at Secondary Network PodBridge %s OVS bridge: %v",o.config.Secondary_OVSBridge1, err)
		       return err
	        }
		podPatchInterface = interfacestore.NewPatchInterface(o.config.Secondary_OVSPatchPort, o.config.Secondary_OVSPatchPortPeer)
		podPatchInterface.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID1, OFPort: 0}
		o.interfaceStore.AddInterface(podPatchInterface)
	}
	//Create OVS patch port at TunnelBridge and set its peer 
        tunPatchInterface, tunBridgeExist := o.interfaceStore.GetInterface(o.config.Secondary_OVSPatchPortPeer)
        if !tunBridgeExist {
                portUUID2 , err := ovsBridgeClient2.CreatePatchPort(o.config.Secondary_OVSBridge2, o.config.Secondary_OVSPatchPortPeer, o.config.Secondary_OVSPatchPort)
	        if err != nil {
                       klog.Error("Failed to create OVS patch port at Secondary Network TunnelBridge %s OVS bridge: %v",o.config.Secondary_OVSBridge2, err)
                       return err
                }
                tunPatchInterface = interfacestore.NewPatchInterface(o.config.Secondary_OVSPatchPortPeer, o.config.Secondary_OVSPatchPort)
                tunPatchInterface.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID2, OFPort: 0}
                o.interfaceStore.AddInterface(tunPatchInterface)

        }
        return nil
}

func setupDefaultSecondaryTunInterface(br *ovsconfig.OVSBridge, o *SecondaryNetworkOptions) error {
        tunnelIface, tunPortExist := o.interfaceStore.GetInterface(defaultSecondaryTunInterfaceName)

	if !tunPortExist {
                // Create the default tunnel port and interface.
                tunnelPortUUID, err := br.CreateTunnelPortExt(defaultSecondaryTunInterfaceName, o.config.Secondary_TunnelType, config.DefaultTunOFPort, false, "", "", "", nil)
                if err != nil {
                       klog.Errorf("Failed to create tunnel port %s type %s on OVS bridge: %v", defaultSecondaryTunInterfaceName, o.config.Secondary_TunnelType, err)
                       return err
                }
		klog.V(2).Infof("Secondary Tunnel port %s added to on OVS bridge %v+.", defaultSecondaryTunInterfaceName, br)
                tunnelIface = interfacestore.NewTunnelInterface(defaultSecondaryTunInterfaceName, o.config.Secondary_TunnelType, nil, false)
                tunnelIface.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: tunnelPortUUID, OFPort: config.DefaultTunOFPort}
                o.interfaceStore.AddInterface(tunnelIface)
        } else {
                klog.V(2).Infof("Secondary Tunnel port %s already exists on OVS bridge.", defaultSecondaryTunInterfaceName)
        }
        return nil
}
