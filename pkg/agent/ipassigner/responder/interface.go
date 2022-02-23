// Copyright 2022 Antrea Authors
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

package responder

import "net"

// Responder is an interface to handle ARP (IPv4)/NS (IPv6) queries using raw sockets.
type Responder interface {
	// InterfaceName returns the name of the network interface which the raw sockets binds on.
	InterfaceName() string
	// AddIP assigns the IP to the responder.
	AddIP(net.IP) error
	// RemoveIP removes the IP from the responder.
	RemoveIP(net.IP) error
	// Run starts the responder.
	Run(<-chan struct{})
}
