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

	// Reconcile should remove orphaned routes and related configuration based on the desired podCIDRs and Service IPs.
	// If IPv6 is enabled in the cluster, Reconcile should also remove the orphaned IPv6 neighbors.
	Reconcile(podCIDRs []string, svcIPs map[string]bool) error

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

	// AddNodePort adds configurations when a NodePort Service is created.
	AddNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error

	// DeleteNodePort deletes related configurations when a NodePort Service is deleted.
	DeleteNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error

	// AddClusterIPRoute adds route on K8s node for Service ClusterIP.
	AddClusterIPRoute(svcIP net.IP) error

	// DeleteClusterIPRoute deletes route for a Service IP when AntreaProxy is configured to handle
	// ClusterIP Service traffic from host network.
	DeleteClusterIPRoute(svcIP net.IP) error

	// AddLoadBalancer adds configurations when a LoadBalancer Service is created.
	AddLoadBalancer(externalIPs []string) error

	// DeleteLoadBalancer deletes related configurations when a LoadBalancer Service is deleted.
	DeleteLoadBalancer(externalIPs []string) error

	// Run starts the sync loop.
	Run(stopCh <-chan struct{})

	// AddLocalAntreaFlexibleIPAMPodRule is used to add IP to target ip set when an AntreaFlexibleIPAM Pod is added. An entry is added
	// for every Pod IP.
	AddLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error

	// DeleteLocalAntreaFlexibleIPAMPodRule is used to delete related IP set entries when an AntreaFlexibleIPAM Pod is deleted.
	DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error
}
