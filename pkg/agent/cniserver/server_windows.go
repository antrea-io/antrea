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

package cniserver

import (
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/klog"
)

const infraContainerNetNS = "none"

// updateResultDNSConfig update the DNS config from CNIConfig.
// For windows platform, if runtime dns values are there use that else use cni conf supplied dns.
// See PR: https://github.com/kubernetes/kubernetes/pull/63905
// Note: For windows node, DNS Capability is needed to be set to enable DNS config can be passed to CNI.
// See PR: https://github.com/kubernetes/kubernetes/pull/67435
func updateResultDNSConfig(result *current.Result, cniConfig *CNIConfig) {
	result.DNS = cniConfig.DNS
	if len(cniConfig.RuntimeConfig.DNS.Nameservers) > 0 {
		result.DNS.Nameservers = cniConfig.RuntimeConfig.DNS.Nameservers
	}
	if len(cniConfig.RuntimeConfig.DNS.Search) > 0 {
		result.DNS.Search = cniConfig.RuntimeConfig.DNS.Search
	}
	klog.Infof("Got runtime DNS configuration: %v", result.DNS)
}

// On windows platform netNS is not used, return it directly.
func (s *CNIServer) hostNetNsPath(netNS string) string {
	return netNS
}

// isInfraContainer return if a container is infra container according to the network namespace path.
// On Windows platform, the network namespace of infra container is "none".
func isInfraContainer(netNS string) bool {
	return netNS == infraContainerNetNS
}
