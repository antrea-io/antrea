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
// to resolve NPL node ports to Kubernetes Service port names for IPFIX export.
// It is implemented by the NodePortLocal controller (see pkg/agent/nodeportlocal/k8s).
type NPLQuerier interface {
	// GetServiceForNPLPort returns the namespaced Service name string
	// (e.g. "default/mysvc") for the given NPL node port and protocol,
	// or ("", false) if no mapping exists or the mapping has no associated Service.
	GetServiceForNPLPort(nodePort int, protocol string) (string, bool)
}
