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

package ndp

import (
	"fmt"
	"net"

	"github.com/mdlayher/ndp"
)

// GratuitousNDPOverIface sends a gratuitous NDP from 'iface' using 'srcIP' as the source IP.
func GratuitousNDPOverIface(srcIP net.IP, iface *net.Interface) error {
	if srcIP.To4() != nil {
		return fmt.Errorf("IPv4 is not supported")
	}

	conn, _, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("failed to create NDP responder for %q: %s", iface.Name, err)
	}
	defer conn.Close()

	na := &ndp.NeighborAdvertisement{
		Override:      true,
		TargetAddress: srcIP,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      iface.HardwareAddr,
			},
		},
	}
	return conn.WriteTo(na, nil, net.IPv6linklocalallnodes)
}
