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
	"time"

	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

// connectInterfaceToOVSAsync waits for an interface to be created and connects it to OVS br-int asynchronously
// in another goroutine. The function is for Containerd runtime. The host interface is created after
// CNI call completes.
func (pc *podConfigurator) connectInterfaceToOVSAsync(ifConfig *interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) error {
	if containerAccess == nil {
		return fmt.Errorf("container lock cannot be null")
	}
	ovsPortName := ifConfig.InterfaceName
	expectedEp, ok := pc.ifConfigurator.getEndpoint(ovsPortName)
	if !ok {
		return fmt.Errorf("failed to find HNSEndpoint %s", ovsPortName)
	}
	hostIfAlias := fmt.Sprintf("%s (%s)", util.ContainerVNICPrefix, ovsPortName)
	containerID := ifConfig.ContainerID
	go func() {
		klog.Infof("Waiting for interface %s to be created", hostIfAlias)
		err := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
			containerAccess.lockContainer(containerID)
			defer containerAccess.unlockContainer(containerID)
			curEp, ok := pc.ifConfigurator.getEndpoint(ovsPortName)
			if !ok {
				return true, fmt.Errorf("failed to find HNSEndpoint %s", ovsPortName)
			}
			if curEp.Id != expectedEp.Id {
				klog.Warningf("Detected HNSEndpoint change for port %s, exiting current goroutine", ovsPortName)
				return true, nil
			}
			if !util.HostInterfaceExists(hostIfAlias) {
				klog.Infof("Waiting for interface %s to be created", hostIfAlias)
				return false, nil
			}
			if err := pc.connectInterfaceToOVSCommon(ovsPortName, ifConfig); err != nil {
				return true, fmt.Errorf("failed to connect to OVS for container %s: %v", containerID, err)
			}
			return true, nil
		})
		if err != nil {
			klog.Errorf("Failed to create OVS port for container %s: %v", containerID, err)
		}
	}()
	return nil
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
		return containerConfig, pc.connectInterfaceToOVSCommon(ovsPortName, containerConfig)
	} else {
		return containerConfig, pc.connectInterfaceToOVSAsync(containerConfig, containerAccess)
	}
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
