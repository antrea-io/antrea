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
