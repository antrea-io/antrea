// Copyright 2021 Antrea Authors
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
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

func NewSecondaryInterfaceConfigurator(ovsBridgeClient ovsconfig.OVSBridgeClient) (*podConfigurator, error) {
	return newPodConfigurator(ovsBridgeClient, nil, nil, nil, nil, ovsconfig.OVSDatapathSystem, false, false, nil, nil)
}

// ConfigureSriovSecondaryInterface configures a SR-IOV secondary interface for a Pod.
func (pc *podConfigurator) ConfigureSriovSecondaryInterface(
	podName, podNamespace string,
	containerID, containerNetNS, containerInterfaceName string,
	mtu int,
	podSriovVFDeviceID string,
	result *current.Result) error {
	if podSriovVFDeviceID == "" {
		return fmt.Errorf("error getting the Pod SR-IOV VF device ID")
	}

	err := pc.ifConfigurator.configureContainerLink(podName, podNamespace, containerID, containerNetNS, containerInterfaceName, mtu, "", podSriovVFDeviceID, result, nil)
	if err != nil {
		return err
	}
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]
	klog.InfoS("Configured SR-IOV interface", "Pod", klog.KRef(podNamespace, podName), "interface", containerInterfaceName, "hostInterface", hostIface)

	if err = pc.ifConfigurator.advertiseContainerAddr(containerNetNS, containerIface.Name, result); err != nil {
		klog.ErrorS(err, "Failed to advertise IP address for SR-IOV interface", "container ID", containerID, "interface", containerInterfaceName)
	}
	return nil
}

// ConfigureVLANSecondaryInterface configures a VLAN secondary interface on the secondary network
// OVS bridge, and returns the OVS port UUID.
func (pc *podConfigurator) ConfigureVLANSecondaryInterface(
	podName, podNamespace string,
	containerID, containerNetNS, containerInterfaceName string,
	mtu int, vlanID uint16,
	result *current.Result) (string, error) {
	// TODO: revisit the possibility of reusing configureInterfaces(), connectInterfaceToOVS()
	// removeInterfaces() code, and using InterfaceStore to store secondary interface info.
	if err := pc.ifConfigurator.configureContainerLink(podName, podNamespace, containerID, containerNetNS, containerInterfaceName, mtu, "", "", result, nil); err != nil {
		return "", err
	}
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]

	success := false
	defer func() {
		if !success {
			if err := pc.ifConfigurator.removeContainerLink(containerID, hostIface.Name); err != nil {
				klog.ErrorS(err, "failed to roll back veth creation", "container ID", containerID, "interface", containerInterfaceName)
			}
		}
	}()

	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	ovsPortUUID, err := pc.createOVSPort(ovsPortName, nil, vlanID)
	if err != nil {
		return "", fmt.Errorf("failed to add OVS port for container %s: %v", containerID, err)
	}
	klog.InfoS("Configured VLAN interface", "Pod", klog.KRef(podNamespace, podName), "interface", containerInterfaceName, "hostInterface", hostIface)

	if err := pc.ifConfigurator.advertiseContainerAddr(containerNetNS, containerIface.Name, result); err != nil {
		klog.ErrorS(err, "Failed to advertise IP address for VLAN interface", "container ID", containerID, "interface", containerInterfaceName)
	}
	success = true
	return ovsPortUUID, nil
}

// DeleteVLANSecondaryInterface deletes a VLAN secondary interface.
func (pc *podConfigurator) DeleteVLANSecondaryInterface(containerID, hostInterfaceName, ovsPortUUID string) error {
	if err := pc.ovsBridgeClient.DeletePort(ovsPortUUID); err != nil {
		return fmt.Errorf("failed to delete OVS port for container %s: %v", containerID, err)
	}
	if err := pc.ifConfigurator.removeContainerLink(containerID, hostInterfaceName); err != nil {
		return err
	}
	return nil
}
