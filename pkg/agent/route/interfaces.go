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
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

var (
	// SyncInterval is exported so that sync interval can be configured for running integration test with
	// smaller values. It is meant to be used internally by Run.
	SyncInterval = 60 * time.Second
)

// Interface is the interface for routing container packets in host network.
type Interface interface {
	// Initialize should initialize all infrastructures required to route container packets in host network.
	// It should be idempotent and can be safely called on every startup.
	Initialize(nodeConfig *config.NodeConfig, done func()) error

	// Reconcile should remove orphaned routes and related configuration based on the desired podCIDRs.
	// If IPv6 is enabled in the cluster, Reconcile should also remove the orphaned IPv6 neighbors.
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

	// RestoreEgressRoutesAndRules restores the routes and rules configured on the system for Egresses to the cache.
	RestoreEgressRoutesAndRules(minTableID, maxTableID int) error

	// AddEgressRoutes creates a route table which routes Egress traffic to the provided gateway via the device.
	AddEgressRoutes(tableID uint32, dev int, gateway net.IP, prefixLength int) error

	// DeleteEgressRoutes deletes the routes installed by AddEgressRoute.
	DeleteEgressRoutes(tableID uint32) error

	// AddEgressRule creates an IP rule which makes Egress traffic with the provided mark look up the specified table.
	AddEgressRule(tableID uint32, mark uint32) error

	// DeleteEgressRule deletes the IP rule installed by AddEgressRule.
	DeleteEgressRule(tableID uint32, mark uint32) error

	// AddNodePort adds configurations when a NodePort Service is created.
	AddNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error

	// DeleteNodePort deletes related configurations when a NodePort Service is deleted.
	DeleteNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error

	// AddExternalIPRoute adds a route entry when an external IP is added.
	AddExternalIPRoute(externalIP net.IP) error

	// DeleteExternalIPRoute deletes the related route entry when an external IP is deleted.
	DeleteExternalIPRoute(externalIP net.IP) error

	// Run starts the sync loop.
	Run(stopCh <-chan struct{})

	// AddLocalAntreaFlexibleIPAMPodRule is used to add IP to target ip set when an AntreaFlexibleIPAM Pod is added. An entry is added
	// for every Pod IP.
	AddLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error

	// DeleteLocalAntreaFlexibleIPAMPodRule is used to delete related IP set entries when an AntreaFlexibleIPAM Pod is deleted.
	DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error

	// AddRouteForLink adds a route entry for a specific link in format:
	// "dstCIDR" dev "link" scope link
	AddRouteForLink(dstCIDR *net.IPNet, linkIndex int) error

	// DeleteRouteForLink deletes a route entry for a specific link.
	DeleteRouteForLink(dstCIDR *net.IPNet, linkIndex int) error

	// ClearConntrackEntryForService deletes a conntrack entry for a Service connection.
	ClearConntrackEntryForService(svcIP net.IP, svcPort uint16, endpointIP net.IP, protocol binding.Protocol) error

	// AddOrUpdateNodeNetworkPolicyIPSet adds or updates ipset created for NodeNetworkPolicy.
	AddOrUpdateNodeNetworkPolicyIPSet(ipsetName string, ipsetEntries sets.Set[string], isIPv6 bool) error

	// DeleteNodeNetworkPolicyIPSet deletes ipset created for NodeNetworkPolicy.
	DeleteNodeNetworkPolicyIPSet(ipsetName string, isIPv6 bool) error

	// AddOrUpdateNodeNetworkPolicyIPTables adds or updates iptables chains and rules within the chains for NodeNetworkPolicy.
	AddOrUpdateNodeNetworkPolicyIPTables(iptablesChains []string, iptablesRules [][]string, isIPv6 bool) error

	// DeleteNodeNetworkPolicyIPTables deletes iptables chains and rules within the chains for NodeNetworkPolicy.
	DeleteNodeNetworkPolicyIPTables(iptablesChains []string, isIPv6 bool) error
}
