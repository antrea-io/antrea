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

	// ServiceExternalIPPoolAnnotationKey is the key of the Service annotation that specifies the Service's desired external IP pool.
	ServiceExternalIPPoolAnnotationKey string = "service.antrea.io/external-ip-pool"

	// ServiceLoadBalancerModeAnnotationKey is the key of the Service annotation that specifies the Service's load balancer mode.
	ServiceLoadBalancerModeAnnotationKey string = "service.antrea.io/load-balancer-mode"

	// L7FlowExporterAnnotationKey is the key of the L7 network flow export annotation that enables L7 network flow export for annotated Pod or Namespace based on the value of annotation which is direction of traffic.
	L7FlowExporterAnnotationKey string = "visibility.antrea.io/l7-export"
)
