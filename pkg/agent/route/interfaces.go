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

package route

import (
	"net"

	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// Interface is the interface for routing container packets in host network.
type Interface interface {
	// Initialize should initialize all infrastructures required to route container packets in host network.
	// It should be idempotent and can be safely called on every startup.
	Initialize(nodeConfig *config.NodeConfig, done func()) error

	// Reconcile should remove orphaned routes and related configuration based on the desired podCIDRs. If IPv6 is enabled
	// in the cluster, Reconcile should also remove the orphaned IPv6 neighbors.
	Reconcile(podCIDRs []string) error

	// AddRoutes should add routes to the provided podCIDR.
	// It should override the routes if they already exist, without error.
	AddRoutes(podCIDR *net.IPNet, peerNodeName string, peerNodeIP, peerGwIP net.IP) error

	// DeleteRoutes should delete routes to the provided podCIDR.
	// It should do nothing if the routes don't exist, without error.
	DeleteRoutes(podCIDR *net.IPNet) error

	// MigrateRoutesToGw should move routes from device linkname to local gateway.
	MigrateRoutesToGw(linkName string) error

	// UnMigrateRoutesFromGw should move routes back from local gateway to original device linkName
	// if linkName is nil, it should remove the routes.
	UnMigrateRoutesFromGw(route *net.IPNet, linkName string) error

	// AddSNATRule should add rule to SNAT outgoing traffic with the mark, using the provided SNAT IP.
	AddSNATRule(snatIP net.IP, mark uint32) error

	// DeleteSNATRule should delete rule to SNAT outgoing traffic with the mark.
	DeleteSNATRule(mark uint32) error

	// InitService should add the basic TC configuration on Linux.
	InitService(nodePortIPMap map[int][]net.IP, isIPv6 bool) error

	// AddNodePort should add related configuration about the NodePort Service to TC on Linux.
	AddNodePort(nodePortIPMap map[int][]net.IP, port uint16, protocol binding.Protocol) error

	// DeleteNodePort should delete related configuration about the NodePort Service to TC on Linux.
	DeleteNodePort(nodePortIPMap map[int][]net.IP, port uint16, protocol binding.Protocol) error

	// AddClusterIPRoute should add route on k8s node for Service ClusterIP.
	AddClusterIPRoute(svcIP net.IP, isIPv6 bool) error

	// AddLoadBalancer should add related flows and configurations for LoadBalancer
	AddLoadBalancer(port uint16, protocol binding.Protocol, externalIPs []string, isIPv6 bool) error

	// DeleteLoadBalancer should delete related flows and configurations for LoadBalancer
	DeleteLoadBalancer(port uint16, protocol binding.Protocol, externalIPs []string, isIPv6 bool) error

	// Run starts the sync loop.
	Run(stopCh <-chan struct{})
}
