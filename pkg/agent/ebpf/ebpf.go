// Copyright 2026 Antrea Authors
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

// Package ebpf forwards the traffic between the Pods of two Nodes with eBPF instead of the host network
// stack, under the EBPFHostDataPath feature gate.
//
// It replaces one thing and one only: the "remotePodCIDR via peerNodeIP" routes pkg/agent/route installs in
// noEncap mode. A packet of a local Pod bound for a remote Pod, and the packets coming back, are sent
// straight to the other interface instead of going through routing and netfilter. Nothing else moves: the
// masquerade of the traffic leaving the cluster, Egress, Service handling and the Node network policies stay
// where they are, in iptables and in the OVS pipeline.
//
// Those routes are still installed while this runs. This datapath comes before them and, whenever it cannot
// handle a packet, leaves it to them, so a Node keeps forwarding exactly what it forwards without it. That is
// what lets it fall back when a next hop is unresolved. The Agent registers managed neighbors so the kernel
// resolves and refreshes them even when packets bypass the host stack.
//
// The programs live in bpf/host_datapath.bpf.c. hack/gen-bpf-objects compiles them into objects_linux.go, so that
// the Agent binary carries the instructions and needs neither a compiler nor an eBPF library to load them.
package ebpf

import "net"

// Config is what the datapath needs to know about the Node.
type Config struct {
	// TransportName, TransportIfIndex and TransportMTU describe the interface the Node reaches its peers
	// through, where the packets coming back from remote Pods arrive. The name is how Run finds the
	// interface again when it is recreated with another index.
	TransportName    string
	TransportIfIndex int
	TransportMTU     int
	// GatewayName, GatewayIfIndex and GatewayMTU describe the Antrea gateway, where the packets of the local
	// Pods enter the host from OVS.
	GatewayName    string
	GatewayIfIndex int
	GatewayMTU     int
	// LocalPodCIDR is the IPv4 Pod CIDR. Leave it nil on IPv6-only Nodes.
	LocalPodCIDR *net.IPNet
	// GatewayIPv4 is the address of the Antrea gateway. It is inside LocalPodCIDR without belonging to a
	// Pod, and the Node sends traffic from it, so the programs exclude it from what they forward.
	GatewayIPv4 net.IP
	// NodeIPv4 is the transport address of this Node. It is only checked, as a Node whose address is
	// inside LocalPodCIDR is a configuration this datapath refuses rather than handles.
	NodeIPv4 net.IP
	// LocalPodIPv6CIDR and the corresponding addresses enable the IPv6 datapath.
	LocalPodIPv6CIDR *net.IPNet
	GatewayIPv6      net.IP
	NodeIPv6         net.IP
	// LocalPodIPs returns the current local Pod addresses. Run reconciles their managed neighbors;
	// until an address is discovered, unresolved traffic can still fall back to the host stack.
	LocalPodIPs func() []net.IP
}

// Stats counts what the programs did, per packet. A miss or a pass is a packet the host network stack handled
// instead, not a packet which was lost.
type Stats struct {
	// Forwarded and Returned count the packets sent to a peer Node and to a local Pod.
	Forwarded uint64
	Returned  uint64
	// ForwardMisses and ReturnMisses count the packets which were meant to be forwarded but were left to
	// the stack, for example because the neighbor was not resolved yet.
	ForwardMisses uint64
	ReturnMisses  uint64
	// Passed counts the packets which are not cross-Node Pod packets.
	Passed uint64
	// TTLExpired and TooBig count the packets left to the stack so that it reports them to their sender.
	TTLExpired uint64
	TooBig     uint64
}

// Interface is the eBPF host datapath as the rest of the Agent uses it. The Pod routes mirror what the route
// client installs, and are set by the Node route controller from the same events.
type Interface interface {
	// Load creates the maps, loads the programs and attaches them. Nothing is forwarded by this datapath
	// until it is called, and everything keeps working without it.
	Load(config Config) error
	// Run keeps the programs attached until stopCh is closed. It looks the two interfaces up by name
	// periodically, attaches the programs again when an interface was recreated or lost its filter, and
	// updates the MTUs and managed neighbors. It must be called after Load succeeded.
	Run(stopCh <-chan struct{})
	// AddPodRoute records that the Pods of podCIDR are on the Node reachable at nextHop, and
	// DeletePodRoute removes it. Until a CIDR is added, its traffic goes through the host stack.
	AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error
	DeletePodRoute(podCIDR *net.IPNet) error
	// Stats reports the counters of the programs.
	Stats() (Stats, error)
	// Close detaches the programs and releases the maps.
	Close() error
}
