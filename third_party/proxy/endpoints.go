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

	"k8s.io/apimachinery/pkg/util/sets"

	utilproxy "antrea.io/antrea/third_party/proxy/util"
)

// BaseEndpointInfo contains base information that defines an endpoint.
// This could be used directly by proxier while processing endpoints,
// or can be used for constructing a more specific EndpointInfo struct
// defined by the proxier if needed.
type BaseEndpointInfo struct {
	Endpoint string // TODO: should be an endpointString type
	// IsLocal indicates whether the endpoint is running in same host as kube-proxy.
	IsLocal bool

	// ZoneHints represent the zone hints for the endpoint. This is based on
	// endpoint.hints.forZones[*].name in the EndpointSlice API.
	ZoneHints sets.Set[string]
	// Ready indicates whether this endpoint is ready and NOT terminating.
	// For pods, this is true if a pod has a ready status and a nil deletion timestamp.
	// This is only set when watching EndpointSlices. If using Endpoints, this is always
	// true since only ready endpoints are read from Endpoints.
	// TODO: Ready can be inferred from Serving and Terminating below when enabled by default.
	Ready bool
	// Serving indiciates whether this endpoint is ready regardless of its terminating state.
	// For pods this is true if it has a ready status regardless of its deletion timestamp.
	// This is only set when watching EndpointSlices. If using Endpoints, this is always
	// true since only ready endpoints are read from Endpoints.
	Serving bool
	// Terminating indicates whether this endpoint is terminating.
	// For pods this is true if it has a non-nil deletion timestamp.
	// This is only set when watching EndpointSlices. If using Endpoints, this is always
	// false since terminating endpoints are always excluded from Endpoints.
	Terminating bool

	// NodeName is the name of the node this endpoint belongs to
	NodeName string
	// Zone is the name of the zone this endpoint belongs to
	Zone string
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

// IsReady returns true if an endpoint is ready and not terminating.
func (info *BaseEndpointInfo) IsReady() bool {
	return info.Ready
}

// IsServing returns true if an endpoint is ready, regardless of if the
// endpoint is terminating.
func (info *BaseEndpointInfo) IsServing() bool {
	return info.Serving
}

// IsTerminating retruns true if an endpoint is terminating. For pods,
// that is any pod with a deletion timestamp.
func (info *BaseEndpointInfo) IsTerminating() bool {
	return info.Terminating
}

// GetZoneHints returns the zone hint for the endpoint.
func (info *BaseEndpointInfo) GetZoneHints() sets.Set[string] {
	return info.ZoneHints
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
	return info.String() == other.String() &&
		info.GetIsLocal() == other.GetIsLocal() &&
		info.IsReady() == other.IsReady()
}

// GetNodeName returns the NodeName for this endpoint.
func (info *BaseEndpointInfo) GetNodeName() string {
	return info.NodeName
}

// GetZone returns the Zone for this endpoint.
func (info *BaseEndpointInfo) GetZone() string {
	return info.Zone
}

func NewBaseEndpointInfo(IP, nodeName, zone string, port int, isLocal bool,
	ready, serving, terminating bool, zoneHints sets.Set[string]) *BaseEndpointInfo {
	return &BaseEndpointInfo{
		Endpoint:    net.JoinHostPort(IP, strconv.Itoa(port)),
		IsLocal:     isLocal,
		Ready:       ready,
		Serving:     serving,
		Terminating: terminating,
		ZoneHints:   zoneHints,
		NodeName:    nodeName,
		Zone:        zone,
	}
}
