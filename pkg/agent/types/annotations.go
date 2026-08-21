// Copyright 2021 Antrea Authors
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

const (
	// NodeMACAddressAnnotationKey represents the key of the Node's MAC address in the Annotations of the Node.
	NodeMACAddressAnnotationKey string = "node.antrea.io/mac-address"

	// NodeTransportAddressAnnotationKey represents the key of the interface's IP addresses on which the Node transfers Pod traffic in the Annotations of the Node.
	NodeTransportAddressAnnotationKey string = "node.antrea.io/transport-addresses"

	// NodeWireGuardPublicAnnotationKey represents the key of the Node's WireGuard public key in the Annotations of the Node.
	NodeWireGuardPublicAnnotationKey string = "node.antrea.io/wireguard-public-key"

	// NodeMaxEgressIPsAnnotationKey represents the key of maximum Egress IP number in the Annotations of the Node.
	NodeMaxEgressIPsAnnotationKey string = "node.antrea.io/max-egress-ips"

	// NodeBGPRouterIDAnnotationKey represents the key of the Node's BGP router ID in the Annotations of the Node.
	NodeBGPRouterIDAnnotationKey string = "node.antrea.io/bgp-router-id"

	// ServiceExternalIPPoolAnnotationKey is the key of the Service annotation that specifies the Service's desired external IP pool.
	ServiceExternalIPPoolAnnotationKey string = "service.antrea.io/external-ip-pool"

	// ServiceAllowSharedIPAnnotationKey is the key of the Service annotation that specifies whether the Service is allowed to use a shared LoadBalancer IP.
	ServiceAllowSharedIPAnnotationKey string = "service.antrea.io/allow-shared-load-balancer-ip"

	// ServiceLoadBalancerModeAnnotationKey is the key of the Service annotation that specifies the Service's load balancer mode.
	ServiceLoadBalancerModeAnnotationKey string = "service.antrea.io/load-balancer-mode"

	// ServiceBGPMEDAnnotationKey is the key of the Service annotation that overrides the base MULTI_EXIT_DISC (MED)
	// value used when the Service IPs are advertised with BGP. The value must be an integer in the range
	// [0, 4294967295]. It is only honored if the effective BGPPolicy enables MED for Service advertisements and does
	// not set `spec.advertisements.service.med.allowServiceOverride` to false.
	ServiceBGPMEDAnnotationKey string = "service.antrea.io/bgp-med"

	// ServiceBGPMEDModeAnnotationKey is the key of the Service annotation that overrides the MED mode used when the
	// Service IPs are advertised with BGP. The value must be one of "None", "Static" or "NodePriority". It is only
	// honored if the effective BGPPolicy enables MED for Service advertisements and does not set
	// `spec.advertisements.service.med.allowServiceOverride` to false.
	ServiceBGPMEDModeAnnotationKey string = "service.antrea.io/bgp-med-mode"
)
