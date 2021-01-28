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
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
)

// connectInterfaceToOVS connects an existing interface to ovs br-int.
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
	return containerConfig, pc.connectInterfaceToOVSCommon(ovsPortName, containerConfig)
}

func (pc *podConfigurator) reconcileMissingPods(pods sets.String, containerAccess *containerAccessArbitrator) error {
	for pod := range pods {
		// This should not happen since OVSDB is persisted on the Node.
		// TODO: is there anything else we should be doing? Assuming that the Pod's
		// interface still exists, we can repair the interface store since we can
		// retrieve the name of the host interface for the Pod by calling
		// GenerateContainerInterfaceName. One thing we would not be able to
		// retrieve is the container ID which is part of the container configuration
		// we store in the cache, but this ID is not used for anything at the
		// moment. However, if the interface does not exist, there is nothing we can
		// do since we do not have the original CNI parameters.
		klog.Warningf("Interface for Pod %s not found in the interface store", pod)
	}
	return nil
}
