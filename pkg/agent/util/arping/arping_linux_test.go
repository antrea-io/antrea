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

package arping

import (
	"net"
	"reflect"
	"testing"
)

func TestNewARPRequest(t *testing.T) {
	tests := []struct {
		name string
		sha  []byte
		spa  []byte
		tha  []byte
		tpa  []byte
		want []byte
	}{
		{
			name: "Gratuitous ARP",
			sha:  []byte{0x42, 0xaf, 0xb8, 0x14, 0xcb, 0x4e},
			spa:  net.ParseIP("192.168.10.1").To4(),
			tha:  []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			tpa:  net.ParseIP("192.168.10.1").To4(),
			want: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x42, 0xaf,
				0xb8, 0x14, 0xcb, 0x4e, 0x08, 0x06, 0x00, 0x01,
				0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x42, 0xaf,
				0xb8, 0x14, 0xcb, 0x4e, 0xc0, 0xa8, 0x0a, 0x01,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0xa8,
				0x0a, 0x01,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newARPRequest(tt.sha, tt.spa, tt.tha, tt.tpa); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newARPRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
