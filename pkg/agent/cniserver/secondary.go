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
	"os"
	"path/filepath"

	current "github.com/containernetworking/cni/pkg/types/100"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

func NewSecondaryInterfaceConfigurator(ovsBridgeClient ovsconfig.OVSBridgeClient, interfaceStore interfacestore.InterfaceStore) (*podConfigurator, error) {
	pc, err := newPodConfigurator(nil, ovsBridgeClient, nil, nil, interfaceStore, nil, ovsconfig.OVSDatapathSystem, false, false, nil, nil, nil)
	if err == nil {
		pc.isSecondaryNetwork = true
	}
	return pc, err
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
	containerIface := result.Interfaces[1]
	klog.InfoS("Configured SR-IOV interface", "Pod", klog.KRef(podNamespace, podName), "interface", containerInterfaceName)

	// Use podSriovVFDeviceID as the interface name in the interface store.
	hostInterfaceName := podSriovVFDeviceID
	containerConfig := buildContainerConfig(hostInterfaceName, containerID, podName, podNamespace, containerIface, result.IPs, 0)
	pc.ifaceStore.AddInterface(containerConfig)

	if result.IPs != nil {
		if err = pc.ifConfigurator.advertiseContainerAddr(containerNetNS, containerIface.Name, result); err != nil {
			klog.ErrorS(err, "Failed to advertise IP address for SR-IOV interface",
				"container", containerID, "interface", containerInterfaceName)
		}
	}
	return nil
}

const (
	vfDriver = "ixgbevf"
)

func rebindVFToHost(pciAddr string) error {
	// echo 0000:00:04.0 > /sys/bus/pci/devices/0000:00:04.0/driver/unbind
	unbindPath := filepath.Join("/sys/bus/pci/devices", pciAddr, "driver/unbind")
	if err := os.WriteFile(unbindPath, []byte(pciAddr), 0200); err != nil {
		return fmt.Errorf("unbind driver failed: %v", err)
	}

	bindPath := filepath.Join("/sys/bus/pci/drivers", vfDriver, "bind")
	// echo 0000:00:04.0 > /sys/bus/pci/drivers/ixgbevf/bind
	if err := os.WriteFile(bindPath, []byte(pciAddr), 0200); err != nil {
		if recoverErr := recoverVFDriver(pciAddr); recoverErr != nil {
			klog.Errorf("Critical: Failed to recover VF driver: %v", recoverErr)
		}
		return fmt.Errorf("bind to driver %s failed: %v", vfDriver, err)
	}

	klog.Infof("Successfully rebound %s to %s", pciAddr, vfDriver)
	return nil
}

func recoverVFDriver(pciAddr string) error {
	bindPath := filepath.Join("/sys/bus/pci/drivers/vfio-pci/bind")
	return os.WriteFile(bindPath, []byte(pciAddr), 0200)
}

// DeleteSriovSecondaryInterface deletes a SRIOV secondary interface.
func (pc *podConfigurator) DeleteSriovSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error {
	klog.InfoS("Delete container interface link",
		"Pod", klog.KRef(interfaceConfig.PodNamespace, interfaceConfig.PodName),
		"interfaceConfig", interfaceConfig)
	if err := rebindVFToHost(interfaceConfig.InterfaceName); err != nil {
		klog.ErrorS(err, "Failed to UnbindVFFromPod",
			"Pod", klog.KRef(interfaceConfig.PodNamespace, interfaceConfig.PodName),
			"interface", interfaceConfig.InterfaceName)
	}
	pc.ifaceStore.DeleteInterface(interfaceConfig)
	klog.InfoS("Deleted SR-IOV interface", "Pod", klog.KRef(interfaceConfig.PodNamespace, interfaceConfig.PodName),
		"interface", interfaceConfig.IFDev)
	return nil
}

// ConfigureVLANSecondaryInterface configures a VLAN secondary interface on the secondary network
// OVS bridge, and returns the OVS port UUID.
func (pc *podConfigurator) ConfigureVLANSecondaryInterface(
	podName, podNamespace string,
	containerID, containerNetNS, containerInterfaceName string,
	mtu int, ipamResult *ipam.IPAMResult) error {
	return pc.configureInterfacesCommon(podName, podNamespace, containerID, containerNetNS,
		containerInterfaceName, mtu, "", ipamResult, nil)
}

// DeleteVLANSecondaryInterface deletes a VLAN secondary interface.
func (pc *podConfigurator) DeleteVLANSecondaryInterface(interfaceConfig *interfacestore.InterfaceConfig) error {
	if err := pc.disconnectInterfaceFromOVS(interfaceConfig); err != nil {
		return err
	}
	if err := pc.ifConfigurator.removeContainerLink(interfaceConfig.ContainerID, interfaceConfig.InterfaceName); err != nil {
		klog.ErrorS(err, "Failed to delete container interface link",
			"Pod", klog.KRef(interfaceConfig.PodNamespace, interfaceConfig.PodName),
			"interface", interfaceConfig.IFDev)
		// No retry for interface deletion.
	}
	return nil
}
