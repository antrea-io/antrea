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

	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/upstream"
	"github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

// ServiceInfo is the internal struct for string service information
type ServiceInfo struct {
	*upstream.BaseServiceInfo
	// cache for performance
	OFTransportProtocol openflow.Protocol
}

// NewServiceInfo returns a new upstream.ServicePort which abstracts a serviceInfo
func NewServiceInfo(port *corev1.ServicePort, service *corev1.Service, baseInfo *upstream.BaseServiceInfo) upstream.ServicePort {
	info := &ServiceInfo{BaseServiceInfo: baseInfo}
	info.OFTransportProtocol = openflow.ProtocolTCP
	if port.Protocol == corev1.ProtocolUDP {
		info.OFTransportProtocol = openflow.ProtocolUDP
	} else if port.Protocol == corev1.ProtocolSCTP {
		info.OFTransportProtocol = openflow.ProtocolSCTP
	}
	return info
}

// NewEndpointInfo returns a new upstream.Endpoint which abstracts a endpointsInfo
func NewEndpointInfo(baseInfo *upstream.BaseEndpointInfo) upstream.Endpoint {
	return baseInfo
}

type EndpointsMap map[upstream.ServicePortName]map[string]upstream.Endpoint
