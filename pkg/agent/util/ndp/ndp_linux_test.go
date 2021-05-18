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

package ndp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/util/ip"
)

func TestAdvertiserMarshalMessage(t *testing.T) {
	tests := []struct {
		name         string
		ipv6Addr     string
		hardwareAddr net.HardwareAddr
		want         []byte
	}{
		{
			name:         "NDP neighbor advertise marshalMessage",
			ipv6Addr:     "fe80::250:56ff:fea7:e29d",
			hardwareAddr: net.HardwareAddr{0x00, 0x50, 0x56, 0xa7, 0xe2, 0x9d},
			// Neighbor Advertisement Message Format
			//       0                   1                   2                   3
			//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |     Type      |     Code      |          Checksum             |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |R|S|O|                     Reserved                            |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |                                                               |
			//      +                                                               +
			//      |                                                               |
			//      +                       Target Address                          +
			//      |                                                               |
			//      +                                                               +
			//      |                                                               |
			//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//      |   Options ...
			//      +-+-+-+-+-+-+-+-+-+-+-+-
			want: []byte{
				0x88, 0x0, 0x0, 0x0,
				0x20, 0x0, 0x0, 0x0,
				0xfe, 0x80, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
				0x2, 0x50, 0x56, 0xff,
				0xfe, 0xa7, 0xe2, 0x9d,
				0x2, 0x1, 0x0, 0x50,
				0x56, 0xa7, 0xe2, 0x9d,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newNDPNeighborAdvertisementMessage(ip.MustIPv6(tt.ipv6Addr), tt.hardwareAddr)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
