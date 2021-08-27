// Copyright 2021 Antrea Authors
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

package wireguard

import (
	"net"
)

type Interface interface {
	// Init initializes the WireGuard client and sets up the WireGuard device.
	// It will generate a new private key if necessary and update the public key to the Node's annotation.
	Init() error
	// UpdatePeer updates WireGuard peer by provided public key and Node IPs.
	// It will create a new WireGuard peer if the specified Node is not present in WireGuard device.
	UpdatePeer(nodeName, publicKeyString string, peerNodeIP net.IP, podCIDRs []*net.IPNet) error
	// RemoveStalePeers reads existing WireGuard peers from the WireGuard device and deletes those which are not in currentPeerPublickeys.
	// currentPeerPublickeys is a map of Node names to public keys. It is useful to clean up stale WireGuard peers upon antrea starting.
	RemoveStalePeers(currentPeerPublickeys map[string]string) error
	// DeletePeer deletes the WireGuard peer by Node name.
	DeletePeer(nodeName string) error
}
