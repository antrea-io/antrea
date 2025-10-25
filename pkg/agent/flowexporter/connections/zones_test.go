// Copyright 2025 Antrea Authors.
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

package connections

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZoneGetter_Get(t *testing.T) {
	type fields struct {
		v4Enabled             bool
		v6Enabled             bool
		connectUplinkToBridge bool
	}
	tests := []struct {
		name   string
		fields fields
		want   []uint16
	}{
		{
			name: "nothing enabled",
			want: []uint16{},
		}, {
			name: "only uplink to bridge enabled",
			fields: fields{
				connectUplinkToBridge: true,
			},
			want: []uint16{},
		}, {
			name: "IPV4 Enabled",
			fields: fields{
				v4Enabled: true,
			},
			want: []uint16{65520},
		}, {
			name: "IPV4 Enabled with uplink to bridge",
			fields: fields{
				v4Enabled:             true,
				connectUplinkToBridge: true,
			},
			want: []uint16{4096},
		}, {
			name: "IPV6 Enabled",
			fields: fields{
				v6Enabled: true,
			},
			want: []uint16{65510},
		}, {
			name: "IPV6 Enabled with uplink to bridge",
			fields: fields{
				v6Enabled:             true,
				connectUplinkToBridge: true,
			},
			want: []uint16{12288},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := ZoneGetter{
				v4Enabled:             tt.fields.v4Enabled,
				v6Enabled:             tt.fields.v6Enabled,
				connectUplinkToBridge: tt.fields.connectUplinkToBridge,
			}
			got := z.Get()
			assert.ElementsMatch(t, got, tt.want)
		})
	}
}
