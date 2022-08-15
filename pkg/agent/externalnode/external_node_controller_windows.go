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

package externalnode

import (
	"fmt"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/signals"
)

// moveIFConfigurations returns nil for single interface case, as it relies
// on Windows New-VMSwitch command to create a host network adapter and copy
// the uplink adapter configurations to host adapter.
// TODO: Implement the function to handle multiple interface case.
// It should perform the following operations:
// Enable the host interface after it is created by OVS.
// Update the host interface MAC address with uplink's.
// Copy the uplink interface's IP to the host interface.
// Copy the uplink interface's Route to the host interface.
func (c *ExternalNodeController) moveIFConfigurations(adapterConfig *config.AdapterNetConfig, src string, dst string) error {
	return nil
}

// TODO: Handle for multiple interfaces
// For multiple interfaces, should remove VMSwitch only
// when the last interface is deleted from the ExternalNode.
func (c *ExternalNodeController) removeExternalNodeConfig() error {
	if ovsErr := c.ovsBridgeClient.Delete(); ovsErr != nil {
		klog.ErrorS(ovsErr, "Failed to delete OVS bridge")
	}

	if err := util.RemoveVMSwitch(); err != nil {
		return fmt.Errorf("failed to delete VM Switch, err: %v", err)
	}
	// Antrea Agent initializer creates a VM Switch corresponding to an
	// ExternalNode. When the last ExternalNode is deleted, VM Switch is also
	// deleted. Since antrea-agent cannot resume without a restart when a new
	// ExternalNode is created, antrea-agent is terminated. Upon restart the
	// antrea-agent will wait in the initialization phase, for an ExternalNode
	// that corresponds to the VM.
	signals.GenerateStopSignal()
	return nil
}
