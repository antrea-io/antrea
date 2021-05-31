// +build linux

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
	"net"
)

// prepareHostNetwork returns immediately on Linux.
func (i *Initializer) prepareHostNetwork() error {
	return nil
}

// prepareOVSBridge returns immediately on Linux.
func (i *Initializer) prepareOVSBridge() error {
	return nil
}

// initHostNetworkFlows returns immediately on Linux.
func (i *Initializer) initHostNetworkFlows() error {
	return nil
}

// getTunnelLocalIP returns local_ip of tunnel port.
// On linux platform, local_ip option is not needed.
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return nil
}

// registerServiceforOS returns immediately on Linux.
func (i *Initializer) registerServiceforOS() error {
	return  nil
}
