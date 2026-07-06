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

package portcache

// NPLQuerier is a read-only view into the NPL port table, used by the flow exporter
// to resolve NPL node ports to Kubernetes Service names for IPFIX export.
// It is implemented by the NodePortLocal controller (see pkg/agent/nodeportlocal/k8s).
type NPLQuerier interface {
	// GetServiceForNPLPort returns the namespaced Service name string (e.g. "default/mysvc") for
	// the given destination IP, NPL node port, and protocol, or "" if destIP is not this Node's IP
	// for the selected family, no mapping exists, or the mapping has no associated Service.
	// Node IP check avoids matching unrelated traffic that happens to use the same port number on
	// a different destination (e.g. another Node's NPL port, or a Pod's egress connection to an
	// arbitrary server listening in the NPL port range).
	// isIPv6 selects the IPv6 Node IP/port table when true; IPv4 otherwise.
	GetServiceForNPLPort(destIP string, nodePort int, protocol string, isIPv6 bool) string
}
