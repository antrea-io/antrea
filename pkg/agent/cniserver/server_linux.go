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

import "github.com/containernetworking/cni/pkg/types/current"

// updateResultDNSConfig updates the DNS config from CNIConfig.
func updateResultDNSConfig(result *current.Result, cniConfig *CNIConfig) {
	result.DNS = cniConfig.DNS
}

// When running in a container, the host's /proc directory is mounted under s.hostProcPathPrefix, so
// we need to prepend s.hostProcPathPrefix to the network namespace path provided by the cni. When
// running as a simple process, s.hostProcPathPrefix will be empty.
func (s *CNIServer) hostNetNsPath(netNS string) string {
	if netNS == "" {
		return ""
	}
	return s.hostProcPathPrefix + netNS
}

// isInfraContainer return if a container is infra container according to the network namespace path.
// Always return true on Linux platform, because kubelet only call CNI request for infra container.
func isInfraContainer(netNS string) bool {
	return true
}

// getInfraContainer returns the sandbox container ID of a Pod.
// On Linux, it's always the ContainerID in the request.
func (c *CNIConfig) getInfraContainer() string {
	return c.ContainerId
}
