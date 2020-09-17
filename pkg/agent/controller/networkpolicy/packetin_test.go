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

package networkpolicy

import (
	"net"
	"testing"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/util"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
)

func getMockPacketIn() *ofctrl.PacketIn {
	ipPacket := protocol.IPv4{
		NWSrc:    net.IPv4(1, 1, 1, 1),
		NWDst:    net.IPv4(2, 2, 2, 2),
		Length:   1,
		Protocol: 6,
	}
	etherPacket := protocol.Ethernet{
		Ethertype: 0x0800,
		Data:      util.Message(&ipPacket),
	}
	result := ofctrl.PacketIn{
		Reason: 1,
		Data:   etherPacket,
	}
	return &result
}

func TestGetPacketInfo(t *testing.T) {
	type args struct {
		pktIn *ofctrl.PacketIn
		ob    *logInfo
	}
	mockOb := new(logInfo)
	expectedOb := logInfo{srcIP: "1.1.1.1", destIP: "2.2.2.2", pktLength: 1, protocolStr: "TCP"}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"ipv4",
			args{
				getMockPacketIn(),
				mockOb,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := getPacketInfo(tt.args.pktIn, tt.args.ob); (err != nil) != tt.wantErr {
				t.Errorf("getPacketInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, expectedOb, *mockOb, "Expect to retrieve exact packet info while differed")
		})
	}
}
