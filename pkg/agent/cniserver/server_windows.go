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
	"strings"

	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/klog/v2"
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

func getInfraContainer(containerID, netNS string) string {
	if isInfraContainer(netNS) {
		return containerID
	}
	parts := strings.Split(netNS, ":")
	if len(parts) != 2 {
		klog.Errorf("Cannot get infra container ID, unexpected netNS: %v, fallback to containerID", netNS)
		return containerID
	}
	return strings.TrimSpace(parts[1])
}

// getInfraContainer returns the infra (sandbox) container ID of a Pod.
// On Windows, kubelet sends two kinds of CNI ADD requests for each Pod:
// 1. <container_id:"067e66fa59ade9c36552aeedac4f1420fe8efe0d2a4061ecdac45f67c5ef035c" netns:"none" ifname:"eth0"
// args:"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=win-webserver-6c7bdbf9fc-lswt2;K8S_POD_INFRA_CONTAINER_ID=067e66fa59ade9c36552aeedac4f1420fe8efe0d2a4061ecdac45f67c5ef035c" >
// 2. <container_id:"0cd7ab3df88aa15f6a9b7f5fc2008ef4cb5740e9ded8ede3633dca7344fd58ca" netns:"container:067e66fa59ade9c36552aeedac4f1420fe8efe0d2a4061ecdac45f67c5ef035c" ifname:"eth0"
// args:"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=win-webserver-6c7bdbf9fc-lswt2;K8S_POD_INFRA_CONTAINER_ID=0cd7ab3df88aa15f6a9b7f5fc2008ef4cb5740e9ded8ede3633dca7344fd58ca" >
//
// The first request uses infra container ID as "container_id", while subsequent requests use workload container ID as
// "container_id" and have infra container ID in "netns" in the form of "container:<INFRA CONTAINER ID>".
func (c *CNIConfig) getInfraContainer() string {
	return getInfraContainer(c.ContainerId, c.Netns)
}
