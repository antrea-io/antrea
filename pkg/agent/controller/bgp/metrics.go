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

package bgp

import (
	"strconv"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/agent/metrics"
)

// advertisedRouteTypes lists every type of route that the controller can advertise.
var advertisedRouteTypes = []AdvertisedRouteType{EgressIP, ServiceLoadBalancerIP, ServiceExternalIP, ServiceClusterIP, NodeIPAMPodCIDR}

// initRouteMetrics creates a series of each route counter for every route type, so that the counters are exported with
// a value of 0 before the first route of a type is advertised or withdrawn.
func initRouteMetrics() {
	for _, routeType := range advertisedRouteTypes {
		metrics.BGPRouteAdvertisementCount.WithLabelValues(string(routeType))
		metrics.BGPRouteWithdrawalCount.WithLabelValues(string(routeType))
	}
}

func recordRouteAdvertised(routeType AdvertisedRouteType) {
	metrics.BGPRouteAdvertisementCount.WithLabelValues(string(routeType)).Inc()
}

func recordRouteWithdrawn(routeType AdvertisedRouteType) {
	metrics.BGPRouteWithdrawalCount.WithLabelValues(string(routeType)).Inc()
}

// sessionStateValue returns the value that the peer session state metric reports for a BGP session state.
func sessionStateValue(state bgp.SessionState) float64 {
	switch state {
	case bgp.SessionIdle:
		return 1
	case bgp.SessionConnect:
		return 2
	case bgp.SessionActive:
		return 3
	case bgp.SessionOpenSent:
		return 4
	case bgp.SessionOpenConfirm:
		return 5
	case bgp.SessionEstablished:
		return 6
	default:
		return 0
	}
}

func setPeerMetrics(peer bgp.PeerStatus) {
	asn := strconv.Itoa(int(peer.ASN))
	metrics.BGPPeerSessionState.WithLabelValues(peer.Address, asn).Set(sessionStateValue(peer.SessionState))
	up := 0.0
	if peer.SessionState == bgp.SessionEstablished {
		up = 1
	}
	metrics.BGPPeerUp.WithLabelValues(peer.Address, asn).Set(up)
}

func deletePeerMetrics(peer bgp.PeerStatus) {
	asn := strconv.Itoa(int(peer.ASN))
	metrics.BGPPeerSessionState.DeleteLabelValues(peer.Address, asn)
	metrics.BGPPeerUp.DeleteLabelValues(peer.Address, asn)
}

// updateEffectivePolicyMetric replaces the series of the effective policy metric for the previous BGPPolicy with a
// series for the current one. An empty name means that no BGPPolicy selects the Node.
func updateEffectivePolicyMetric(prePolicyName, curPolicyName string) {
	if prePolicyName != "" {
		metrics.BGPEffectivePolicy.DeleteLabelValues(prePolicyName)
	}
	if curPolicyName != "" {
		metrics.BGPEffectivePolicy.WithLabelValues(curPolicyName).Set(1)
	}
}
