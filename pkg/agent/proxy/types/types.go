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

package types

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"

	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
)

type ServiceClient interface {
	// InstallServiceGroup installs a group for Service LB. Each endpoint
	// is a bucket of the group. For now, each bucket has the same weight.
	InstallServiceGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints []k8sproxy.Endpoint) error
	// UninstallServiceGroup removes the group and its buckets that are
	// installed by InstallServiceGroup.
	UninstallServiceGroup(groupID binding.GroupIDType) error

	// InstallEndpointFlows installs flows for accessing Endpoints.
	// If an Endpoint is on the current Node, then flows for hairpin and endpoint
	// L2 forwarding should also be installed.
	InstallEndpointFlows(protocol binding.Protocol, endpoints []k8sproxy.Endpoint, isIPv6 bool) error
	// UninstallEndpointFlows removes flows of the Endpoint installed by
	// InstallEndpointFlows.
	UninstallEndpointFlows(protocol binding.Protocol, endpoint k8sproxy.Endpoint) error

	// InstallServiceFlows installs flows for accessing Service with clusterIP.
	// It installs the flow that uses the group/bucket to do service LB. If the
	// affinityTimeout is not zero, it also installs the flow which has a learn
	// action to maintain the LB decision.
	// The group with the groupID must be installed before, otherwise the
	// installation will fail.
	InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) error
	// UninstallServiceFlows removes flows installed by InstallServiceFlows.
	UninstallServiceFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error
	// InstallLoadBalancerServiceFromOutsideFlows installs flows for LoadBalancer Service traffic from outside node.
	// The traffic is received from uplink port and will be forwarded to gateway by the installed flows. And then
	// kube-proxy will handle the traffic.
	// This function is only used for Windows platform.
	InstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error
	// UninstallLoadBalancerServiceFromOutsideFlows removes flows installed by InstallLoadBalancerServiceFromOutsideFlows.
	UninstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error
}

// ServiceInfo is the internal struct for caching service information.
type ServiceInfo struct {
	*k8sproxy.BaseServiceInfo
	// cache for performance
	OFProtocol binding.Protocol
}

// NewServiceInfo returns a new k8sproxy.ServicePort which abstracts a serviceInfo.
func NewServiceInfo(port *corev1.ServicePort, service *corev1.Service, baseInfo *k8sproxy.BaseServiceInfo) k8sproxy.ServicePort {
	info := &ServiceInfo{BaseServiceInfo: baseInfo}
	if utilnet.IsIPv6String(service.Spec.ClusterIP) {
		info.OFProtocol = binding.ProtocolTCPv6
		if port.Protocol == corev1.ProtocolUDP {
			info.OFProtocol = binding.ProtocolUDPv6
		} else if port.Protocol == corev1.ProtocolSCTP {
			info.OFProtocol = binding.ProtocolSCTPv6
		}
	} else {
		info.OFProtocol = binding.ProtocolTCP
		if port.Protocol == corev1.ProtocolUDP {
			info.OFProtocol = binding.ProtocolUDP
		} else if port.Protocol == corev1.ProtocolSCTP {
			info.OFProtocol = binding.ProtocolSCTP
		}
	}
	return info
}

// NewEndpointInfo returns a new k8sproxy.Endpoint which abstracts an endpointsInfo.
func NewEndpointInfo(baseInfo *k8sproxy.BaseEndpointInfo) k8sproxy.Endpoint {
	return baseInfo
}

type EndpointsMap map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint
