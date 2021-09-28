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

	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
)

// connectInterfaceToOVSAsync waits for an interface to be created and connects it to OVS br-int asynchronously
// in another goroutine. The function is for Containerd runtime. The host interface is created after
// CNI call completes.
func (pc *podConfigurator) connectInterfaceToOVSAsync(ifConfig *interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) error {
	ovsPortName := ifConfig.InterfaceName
	return pc.ifConfigurator.addPostInterfaceCreateHook(ifConfig.ContainerID, ovsPortName, containerAccess, func() error {
		return pc.connectInterfaceToOVSCommon(ovsPortName, ifConfig)
	})
}

// connectInterfaceToOVS connects an existing interface to OVS br-int.
func (pc *podConfigurator) connectInterfaceToOVS(
	podName string,
	podNameSpace string,
	containerID string,
	hostIface *current.Interface,
	containerIface *current.Interface,
	ips []*current.IPConfig,
	containerAccess *containerAccessArbitrator,
) (*interfacestore.InterfaceConfig, error) {
	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNameSpace, containerIface, ips)
	hostIfAlias := fmt.Sprintf("%s (%s)", util.ContainerVNICPrefix, ovsPortName)
	// - For Containerd runtime, the container interface is created after CNI replying the network setup result.
	//   So for such case we need to use asynchronous way to wait for interface to be created.
	// - For Docker runtime, antrea-agent still creates OVS port synchronously.
	// - Here antrea-agent determines the way of OVS port creation by checking if container interface is yet created.
	//   If one day Containerd runtime changes the behavior and container interface can be created when attaching
	//   HNSEndpoint/HostComputeEndpoint, the current implementation will still work. It will choose the synchronized
	//   way to create OVS port.
	if util.HostInterfaceExists(hostIfAlias) {
		hnsMutex.Lock()
		defer hnsMutex.Unlock()

		return containerConfig, pc.connectInterfaceToOVSCommon(ovsPortName, containerConfig)
	}
	return containerConfig, pc.connectInterfaceToOVSAsync(containerConfig, containerAccess)
}

func (pc *podConfigurator) reconcileMissingPods(pods sets.String, containerAccess *containerAccessArbitrator) {
	interfacesConfig := pc.ifConfigurator.getInterfaceConfigForPods(pods)
	for pod := range pods {
		ifaceConfig, ok := interfacesConfig[pod]
		if !ok {
			klog.Errorf("Failed to reconcile Pod %s: interface config not found", pod)
			continue
		}
		if err := pc.connectInterfaceToOVSAsync(ifaceConfig, containerAccess); err != nil {
			klog.Errorf("Failed to reconcile Pod %s: %v", pod, err)
		}
	}
}
