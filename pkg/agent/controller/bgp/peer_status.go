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
	"context"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/bgp"
)

// peerStatusPollInterval is how often the status of the BGP peers is read from the BGP server.
const peerStatusPollInterval = 15 * time.Second

// pollPeerStatus reads the status of the BGP peers from the BGP server, updates the peer metrics, and records an Event
// when a BGP session reaches the Established state or leaves it.
func (c *Controller) pollPeerStatus(ctx context.Context) {
	var bgpServer bgp.Interface
	var policyName string
	c.bgpPolicyStateMutex.RLock()
	if c.bgpPolicyState != nil {
		bgpServer = c.bgpPolicyState.bgpServer
		policyName = c.bgpPolicyState.bgpPolicyName
	}
	c.bgpPolicyStateMutex.RUnlock()

	var peers []bgp.PeerStatus
	if bgpServer != nil {
		var err error
		if peers, err = bgpServer.GetPeers(ctx); err != nil {
			klog.ErrorS(err, "Failed to get the status of BGP peers")
			return
		}
	}

	curPeerStatuses := make(map[string]bgp.PeerStatus, len(peers))
	for _, peer := range peers {
		key := generateBGPPeerKey(peer.Address, peer.ASN)
		curPeerStatuses[key] = peer
		setPeerMetrics(peer)
		prePeer, exists := c.peerStatuses[key]
		if !exists {
			// A session is usually established before the first poll that sees its peer, for example right after the
			// BGPPolicy is applied or the Agent restarts, so that poll reports it too.
			c.recordPeerSessionEvent(policyName, nil, peer)
		} else if prePeer.SessionState != peer.SessionState {
			// goBGP already logs the sessions which go up or down at the default verbosity.
			klog.V(2).InfoS("BGP session state changed", "peer", peer.Address, "asn", peer.ASN,
				"previousState", prePeer.SessionState, "state", peer.SessionState)
			c.recordPeerSessionEvent(policyName, &prePeer, peer)
		}
	}
	for key, prePeer := range c.peerStatuses {
		if _, exists := curPeerStatuses[key]; !exists {
			deletePeerMetrics(prePeer)
		}
	}
	c.peerStatuses = curPeerStatuses
}
