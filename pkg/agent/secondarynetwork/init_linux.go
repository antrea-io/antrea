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

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/secondarynetwork/podwatch"
	"antrea.io/antrea/pkg/agent/util"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn = net.InterfaceByName
	newOVSBridgeFn    = ovsconfig.NewOVSBridge
)

// Initialize sets up OVS bridges and starts the Pod controller for secondary networks.
func Initialize(
	clientConnectionConfig componentbaseconfig.ClientConnectionConfiguration,
	kubeAPIServerOverride string,
	k8sClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	nodeName string,
	podUpdateSubscriber channel.Subscriber,
	stopCh <-chan struct{},
	secNetConfig *agentconfig.SecondaryNetworkConfig, ovsdb *ovsdb.OVSDB) error {

	ovsBridgeClient, err := createOVSBridge(secNetConfig.OVSBridges, ovsdb)
	if err != nil {
		return err
	}

	// We only support moving and restoring of interface configuration to OVS Bridge for the single physical interface case.
	if len(secNetConfig.OVSBridges) != 0 {
		phyInterfaces := make([]string, len(secNetConfig.OVSBridges[0].PhysicalInterfaces))
		copy(phyInterfaces, secNetConfig.OVSBridges[0].PhysicalInterfaces)
		if len(phyInterfaces) == 1 {

			bridgedName, _, err := util.PrepareHostInterfaceConnection(
				ovsBridgeClient,
				phyInterfaces[0],
				0,
				map[string]interface{}{
					interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
				},
			)
			if err != nil {
				return err
			}
			phyInterfaces[0] = bridgedName
		}
		if err = connectPhyInterfacesToOVSBridge(ovsBridgeClient, phyInterfaces); err != nil {
			return err
		}
	}

	// Create the NetworkAttachmentDefinition client, which handles access to secondary network object
	// definition from the API Server.
	netAttachDefClient, err := createNetworkAttachDefClient(clientConnectionConfig, kubeAPIServerOverride)
	if err != nil {
		return fmt.Errorf("NetworkAttachmentDefinition client creation failed: %v", err)
	}

	// Create podController to handle secondary network configuration for Pods with
	// k8s.v1.cni.cncf.io/networks Annotation defined.
	if podWatchController, err := podwatch.NewPodController(
		k8sClient, netAttachDefClient, podInformer,
		nodeName, podUpdateSubscriber, ovsBridgeClient); err != nil {
		return err
	} else {
		go podWatchController.Run(stopCh)
	}
	return nil
}

// RestoreHostInterfaceConfiguration restores interface configuration from secondary-bridge back to host-interface.
func RestoreHostInterfaceConfiguration(secNetConfig *agentconfig.SecondaryNetworkConfig) {
	if len(secNetConfig.OVSBridges) != 0 && len(secNetConfig.OVSBridges[0].PhysicalInterfaces) == 1 {
		util.RestoreHostInterfaceConfiguration(secNetConfig.OVSBridges[0].BridgeName, secNetConfig.OVSBridges[0].PhysicalInterfaces[0])
	}
}

func createOVSBridge(bridges []agentconfig.OVSBridgeConfig, ovsdb *ovsdb.OVSDB) (ovsconfig.OVSBridgeClient, error) {
	if len(bridges) == 0 {
		return nil, nil
	}
	// Only one OVS bridge is supported.
	bridgeConfig := bridges[0]
	ovsBridgeClient := newOVSBridgeFn(bridgeConfig.BridgeName, ovsconfig.OVSDatapathSystem, ovsdb)
	if err := ovsBridgeClient.Create(); err != nil {
		return nil, fmt.Errorf("failed to create OVS bridge %s: %v", bridgeConfig.BridgeName, err)
	}
	klog.InfoS("OVS bridge created", "bridge", bridgeConfig.BridgeName)
	return ovsBridgeClient, nil
}

func connectPhyInterfacesToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []string) error {
	for _, phyInterface := range phyInterfaces {
		if _, err := interfaceByNameFn(phyInterface); err != nil {
			return fmt.Errorf("failed to get interface %s: %v", phyInterface, err)
		}
	}

	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	for i, phyInterface := range phyInterfaces {
		if _, err := ovsBridgeClient.GetOFPort(phyInterface, false); err == nil {
			klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skip the configuration", "device", phyInterface)
			continue
		}

		if _, err := ovsBridgeClient.CreateUplinkPort(phyInterface, int32(i), externalIDs); err != nil {
			return fmt.Errorf("failed to create OVS uplink port %s: %v", phyInterface, err)
		}
		klog.InfoS("Physical interface added to secondary OVS bridge", "device", phyInterface)
	}
	return nil
}

// CreateNetworkAttachDefClient creates net-attach-def client handle from the given config.
func createNetworkAttachDefClient(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (netdefclient.K8sCniCncfIoV1Interface, error) {
	kubeConfig, err := k8s.CreateRestConfig(config, kubeAPIServerOverride)
	if err != nil {
		return nil, err
	}

	netAttachDefClient, err := netdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return netAttachDefClient, nil
}
