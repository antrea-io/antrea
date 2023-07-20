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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	mccommon "antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

// ServiceInfo is the internal struct for caching service information.
type ServiceInfo struct {
	*k8sproxy.BaseServiceInfo
	// cache for performance
	OFProtocol openflow.Protocol
	// IsNested means the Service's Endpoints could be another Service's ClusterIP.
	// Currently it's true for Antrea Multi-cluster Service, determined by whether
	// there is an Antrea Multi-cluster specific annotation.
	IsNested bool
	// The load balancer mode specified in annotations.
	LoadBalancerMode *config.LoadBalancerMode
}

func getLoadBalancerMode(service *corev1.Service) *config.LoadBalancerMode {
	if modeStr, exists := service.Annotations[types.ServiceLoadBalancerModeAnnotationKey]; exists {
		ok, mode := config.GetLoadBalancerModeFromStr(modeStr)
		if !ok {
			klog.ErrorS(nil, "The Service's load balancer mode annotation is invalid", "Service", klog.KObj(service), "mode", modeStr)
			return nil
		}
		return &mode
	}
	return nil
}

// NewServiceInfo returns a new k8sproxy.ServicePort which abstracts a serviceInfo.
func NewServiceInfo(port *corev1.ServicePort, service *corev1.Service, baseInfo *k8sproxy.BaseServiceInfo) k8sproxy.ServicePort {
	info := &ServiceInfo{BaseServiceInfo: baseInfo}
	info.IsNested = mccommon.IsMulticlusterService(service)
	info.LoadBalancerMode = getLoadBalancerMode(service)
	if utilnet.IsIPv6(baseInfo.ClusterIP()) {
		info.OFProtocol = openflow.ProtocolTCPv6
		if port.Protocol == corev1.ProtocolUDP {
			info.OFProtocol = openflow.ProtocolUDPv6
		} else if port.Protocol == corev1.ProtocolSCTP {
			info.OFProtocol = openflow.ProtocolSCTPv6
		}
	} else {
		info.OFProtocol = openflow.ProtocolTCP
		if port.Protocol == corev1.ProtocolUDP {
			info.OFProtocol = openflow.ProtocolUDP
		} else if port.Protocol == corev1.ProtocolSCTP {
			info.OFProtocol = openflow.ProtocolSCTP
		}
	}
	return info
}

// NewEndpointInfo returns a new k8sproxy.Endpoint which abstracts an endpointsInfo.
func NewEndpointInfo(baseInfo *k8sproxy.BaseEndpointInfo) k8sproxy.Endpoint {
	return baseInfo
}

type EndpointsMap map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint
