//go:build windows
// +build windows

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

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/util/k8s"
)

// connectInterfaceToOVSAsync waits for an interface to be created and connects it to OVS br-int asynchronously
// in another goroutine. The function is for containerd runtime. The host interface is created after
// CNI call completes.
func (pc *podConfigurator) connectInterfaceToOVSAsync(ifConfig *interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) error {
	ovsPortName := ifConfig.InterfaceName
	return pc.ifConfigurator.addPostInterfaceCreateHook(ifConfig.ContainerID, ovsPortName, containerAccess, func() error {
		if err := pc.ovsBridgeClient.SetInterfaceType(ovsPortName, "internal"); err != nil {
			return err
		}
		ofPort, err := pc.ovsBridgeClient.GetOFPort(ovsPortName, true)
		if err != nil {
			return err
		}
		containerID := ifConfig.ContainerID
		klog.V(2).Infof("Setting up Openflow entries for container %s", containerID)
		if err := pc.ofClient.InstallPodFlows(ovsPortName, ifConfig.IPs, ifConfig.MAC, uint32(ofPort), ifConfig.VLANID, nil); err != nil {
			return fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
		}
		// Update interface config with the ofPort.
		ifConfig.OVSPortConfig.OFPort = ofPort
		// Notify the Pod update event to required components.
		event := types.PodUpdate{
			PodName:      ifConfig.PodName,
			PodNamespace: ifConfig.PodNamespace,
			IsAdd:        true,
			ContainerID:  ifConfig.ContainerID,
		}
		pc.podUpdateNotifier.Notify(event)
		return nil
	})
}

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
	hostIfAlias := util.VirtualAdapterName(ovsPortName)
	// - For containerd runtime, the container interface is created after CNI replying the network setup result.
	//   So for such case we need to use asynchronous way to wait for interface to be created: we create the OVS port
	//   and set the OVS Interface type "" first, and change the OVS Interface type to "internal" to connect to the
	//   container interface after it is created. After OVS connects to the container interface, an OFPort is allocated.
	// - For Docker runtime, the container interface is created after antrea-agent attaches the HNSEndpoint to the
	//   sandbox container, so we create OVS port synchronously.
	// - Here antrea-agent determines the way of OVS port creation by checking if container interface is yet created.
	//   If one day containerd runtime changes the behavior and container interface can be created when attaching
	//   HNSEndpoint/HostComputeEndpoint, the current implementation will still work. It will choose the synchronized
	//   way to create OVS port.
	if hostInterfaceExistsFunc(hostIfAlias) {
		return containerConfig, pc.connectInterfaceToOVSCommon(ovsPortName, netNS, containerConfig)
	}
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	ovsAttachInfo := BuildOVSPortExternalIDs(containerConfig)
	portUUID, err := pc.createOVSPort(ovsPortName, ovsAttachInfo, containerConfig.VLANID)
	if err != nil {
		return nil, err
	}
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)
	return containerConfig, pc.connectInterfaceToOVSAsync(containerConfig, containerAccess)
}

func (pc *podConfigurator) configureInterfaces(
	podName, podNamespace, containerID, containerNetNS string,
	containerIFDev string, mtu int, sriovVFDeviceID string,
	result *ipam.IPAMResult, createOVSPort bool, containerAccess *containerAccessArbitrator) error {
	if !createOVSPort {
		return pc.ifConfigurator.configureContainerLink(
			podName, podNamespace, containerID, containerNetNS,
			containerIFDev, mtu, sriovVFDeviceID, "",
			&result.Result, containerAccess)
	}
	// Check if the OVS configurations for the container exists or not. If yes, return
	// immediately. This check is used on Windows, as kubelet on Windows will call CNI ADD
	// multiple times for the infrastructure container to query IP of the Pod. But there should
	// be only one OVS port created for the same Pod (identified by its sandbox container ID),
	// and if the OVS port is added more than once, OVS will return an error.
	// See: https://github.com/kubernetes/kubernetes/issues/57253#issuecomment-358897721.
	interfaceConfig, found := pc.ifaceStore.GetContainerInterface(containerID)
	if found {
		klog.V(2).Infof("Found an existing OVS port for container %s, returning", containerID)
		mac := interfaceConfig.MAC.String()
		hostIface := &current.Interface{
			Name:    interfaceConfig.InterfaceName,
			Mac:     mac,
			Sandbox: "",
		}
		containerIface := &current.Interface{
			Name:    containerIFDev,
			Mac:     mac,
			Sandbox: containerNetNS,
		}
		result.Interfaces = []*current.Interface{hostIface, containerIface}
		return nil
	}

	return pc.configureInterfacesCommon(podName, podNamespace, containerID, containerNetNS,
		containerIFDev, mtu, sriovVFDeviceID, result, containerAccess)
}

func (pc *podConfigurator) reconcileMissingPods(ifConfigs []*interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) {
	for i := range ifConfigs {
		ifaceConfig := ifConfigs[i]
		pod := k8s.NamespacedName(ifaceConfig.PodNamespace, ifaceConfig.PodName)
		if err := pc.connectInterfaceToOVSAsync(ifaceConfig, containerAccess); err != nil {
			klog.Errorf("Failed to reconcile Pod %s: %v", pod, err)
		}
	}
}
