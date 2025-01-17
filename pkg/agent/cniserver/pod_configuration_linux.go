//go:build !windows
// +build !windows

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

package cniserver

import (
	"fmt"

	current "github.com/containernetworking/cni/pkg/types/100"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/interfacestore"
	agenttypes "antrea.io/antrea/pkg/agent/types"
)

// connectInterfaceToOVS connects an existing interface to the OVS bridge.
func (pc *podConfigurator) connectInterfaceToOVS(
	podName, podNamespace, containerID, netNS string,
	hostIface, containerIface *current.Interface,
	ips []*current.IPConfig,
	vlanID uint16,
	containerAccess *containerAccessArbitrator) (*interfacestore.InterfaceConfig, error) {
	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNamespace, containerIface, ips, vlanID)
	return containerConfig, pc.connectInterfaceToOVSCommon(ovsPortName, netNS, containerConfig)
}

func (pc *podConfigurator) connectInterfaceToOVSCommon(ovsPortName, netNS string, containerConfig *interfacestore.InterfaceConfig) error {
	// create OVS Port and add attach container configuration into external_ids
	containerID := containerConfig.ContainerID
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	ovsAttachInfo := BuildOVSPortExternalIDs(containerConfig)
	portUUID, err := pc.createOVSPort(ovsPortName, ovsAttachInfo, containerConfig.VLANID)
	if err != nil {
		return fmt.Errorf("failed to add OVS port for container %s: %v", containerID, err)
	}
	// Remove OVS port if any failure occurs in later manipulation.
	defer func() {
		if err != nil {
			_ = pc.ovsBridgeClient.DeletePort(portUUID)
		}
	}()

	var ofPort int32
	// Not needed for a secondary network interface.
	if !pc.isSecondaryNetwork {
		// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
		ofPort, err = pc.ovsBridgeClient.GetOFPort(ovsPortName, false)
		if err != nil {
			return fmt.Errorf("failed to get of_port of OVS port %s: %v", ovsPortName, err)
		}
		klog.V(2).InfoS("Setting up Openflow entries for Pod interface", "container", containerID, "port", ovsPortName)
		if err = pc.ofClient.InstallPodFlows(ovsPortName, containerConfig.IPs, containerConfig.MAC, uint32(ofPort), containerConfig.VLANID, nil); err != nil {
			return fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
		}
	}

	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)

	// Not needed for a secondary network interface.
	if !pc.isSecondaryNetwork {
		// Notify the Pod update event to required components.
		event := agenttypes.PodUpdate{
			PodName:      containerConfig.PodName,
			PodNamespace: containerConfig.PodNamespace,
			ContainerID:  containerConfig.ContainerID,
			NetNS:        netNS,
			IsAdd:        true,
		}
		pc.podUpdateNotifier.Notify(event)
	}
	return nil
}

func (pc *podConfigurator) configureInterfaces(
	podName, podNamespace, containerID, containerNetNS string,
	containerIFDev string, mtu int, sriovVFDeviceID string,
	result *ipam.IPAMResult, createOVSPort bool, containerAccess *containerAccessArbitrator) error {
	return pc.configureInterfacesCommon(podName, podNamespace, containerID, containerNetNS,
		containerIFDev, mtu, sriovVFDeviceID, result, containerAccess)
}

// reconcileMissingPods is never called on Linux, see reconcile logic.
func (pc *podConfigurator) reconcileMissingPods(ifConfigs []*interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) {
}

// isInterfaceInvalid returns true if the OVS interface's ofport is "-1" which means the host interface is disconnected.
func (pc *podConfigurator) isInterfaceInvalid(ifaceConfig *interfacestore.InterfaceConfig) bool {
	return ifaceConfig.OFPort == -1
}

func (pc *podConfigurator) initPortStatusMonitor(_ cache.SharedIndexInformer) {

}

func (pc *podConfigurator) Run(stopCh <-chan struct{}) {
	<-stopCh
}
