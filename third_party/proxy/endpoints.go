/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
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

Modifies:
- Remove imports: "net", "reflect", "strconv", "sync", "time", "k8s.io/api/core/v1",
  "k8s.io/api/discovery/v1beta1", "k8s.io/apimachinery/pkg/util/sets",
  "k8s.io/client-go/tools/record", "k8s.io/klog/v2", "k8s.io/utils/net"
- Remove vars: "supportedEndpointSliceAddressTypes"
- Remove functions: "newBaseEndpointInfo", "makeEndpointFunc",
  "NewEndpointChangeTracker", "detectStaleConnections"
- Remove structs: "EndpointChangeTracker", "EndpointsMap"
*/
package proxy

import (
	"net"
	"strconv"

	utilproxy "antrea.io/antrea/third_party/proxy/util"
)

// BaseEndpointInfo contains base information that defines an endpoint.
// This could be used directly by proxier while processing endpoints,
// or can be used for constructing a more specific EndpointInfo struct
// defined by the proxier if needed.
type BaseEndpointInfo struct {
	Endpoint string // TODO: should be an endpointString type
	// IsLocal indicates whether the endpoint is running in same host as kube-proxy.
	IsLocal  bool
	Topology map[string]string
}

var _ Endpoint = &BaseEndpointInfo{}

// String is part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) String() string {
	return info.Endpoint
}

// GetIsLocal is part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) GetIsLocal() bool {
	return info.IsLocal
}

// GetTopology returns the topology information of the endpoint.
func (info *BaseEndpointInfo) GetTopology() map[string]string {
	return info.Topology
}

// IP returns just the IP part of the endpoint, it's a part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) IP() string {
	return utilproxy.IPPart(info.Endpoint)
}

// Port returns just the Port part of the endpoint.
func (info *BaseEndpointInfo) Port() (int, error) {
	return utilproxy.PortPart(info.Endpoint)
}

// Equal is part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) Equal(other Endpoint) bool {
	return info.String() == other.String() && info.GetIsLocal() == other.GetIsLocal()
}

func NewBaseEndpointInfo(IP string, port int, isLocal bool, topology map[string]string) *BaseEndpointInfo {
	return &BaseEndpointInfo{
		Endpoint: net.JoinHostPort(IP, strconv.Itoa(port)),
		IsLocal:  isLocal,
		Topology: topology,
	}
}
