// +build windows

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

package agent

import (
	"k8s.io/klog"
)

// setupExternalConnectivity installs OpenFlow entries to SNAT Pod traffic using Node IP, and then Pod could communicate
// to the external IP address.
func (i *Initializer) setupExternalConnectivity() error {
	subnetCIDR := i.nodeConfig.PodCIDR
	nodeIP := i.nodeConfig.NodeIPAddr.IP
	// Install OpenFlow entries on the OVS to enable Pod traffic to communicate to external IP addresses.
	if err := i.ofClient.InstallExternalFlows(nodeIP, *subnetCIDR); err != nil {
		klog.Errorf("Failed to setup SNAT openflow entries: %v", err)
		return err
	}
	return nil
}
