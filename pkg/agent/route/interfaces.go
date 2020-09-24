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

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
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
	AddRoutes(podCIDR *net.IPNet, peerNodeIP, peerGwIP net.IP) error

	// DeleteRoutes should delete routes to the provided podCIDR.
	// It should do nothing if the routes don't exist, without error.
	DeleteRoutes(podCIDR *net.IPNet) error

	// AddRoutes should add the route to the NodePort virtual IP.
	AddNodePortRoute(isIPv6 bool) error

	// ReconcileNodePort should remove orphaned NodePort ipset entries.
	ReconcileNodePort(nodeIPs []net.IP, svcEntries []*types.ServiceInfo) error

	// AddNodePort should add entries of the NodePort Service to the ipset.
	// It should have no effect if the entry already exist, without error.
	AddNodePort(nodeIPs []net.IP, svcInfo *types.ServiceInfo, isIPv6 bool) error

	// DeleteNodePort should delete entries of the NodePort Service from ipset.
	// It should do nothing if entries of the NodePort Service don't exist, without error.
	DeleteNodePort(nodeIPs []net.IP, svcInfo *types.ServiceInfo, isIPv6 bool) error

	// MigrateRoutesToGw should move routes from device linkname to local gateway.
	MigrateRoutesToGw(linkName string) error

	// UnMigrateRoutesFromGw should move routes back from local gateway to original device linkName
	// if linkName is nil, it should remove the routes.
	UnMigrateRoutesFromGw(route *net.IPNet, linkName string) error

	// Run starts the sync loop.
	Run(stopCh <-chan struct{})
}
