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

package endpointslice

import (
	discoveryv1 "k8s.io/api/discovery/v1"
)

// CanServe reports whether AntreaProxy would send traffic to the endpoint. It is true for a ready
// endpoint, and for an endpoint which is terminating while it is still serving, which is a Pod
// draining its connections. It mirrors the rule AntreaProxy applies when it selects the Endpoints
// of a Service, so that a Node does not advertise a Service IP its own datapath rejects. A nil
// condition is read the way the EndpointSlice API defines it.
func CanServe(ep discoveryv1.Endpoint) bool {
	ready := ep.Conditions.Ready == nil || *ep.Conditions.Ready
	serving := ep.Conditions.Serving == nil || *ep.Conditions.Serving
	terminating := ep.Conditions.Terminating != nil && *ep.Conditions.Terminating
	return ready || serving && terminating
}
