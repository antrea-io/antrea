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

package openflow

import (
	"testing"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/util"
	"github.com/stretchr/testify/assert"
)

func TestGetTCPHeaderData(t *testing.T) {
	type args struct {
		tcp              protocol.TCP
		expectTCPSrcPort uint16
		expectTCPDstPort uint16
		expectTCPSeqNum  uint32
		expectTCPAckNum  uint32
		expectTCPCode    uint8
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ipv4",
			args: args{
				tcp: protocol.TCP{
					PortSrc: 1080,
					PortDst: 80,
					SeqNum:  0,
					AckNum:  0,
					Code:    2,
				},
				expectTCPSrcPort: 1080,
				expectTCPDstPort: 80,
				expectTCPSeqNum:  0,
				expectTCPAckNum:  0,
				expectTCPCode:    2,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := tt.args.tcp
			pktIn := new(protocol.IPv4)
			bytes, _ := tcp.MarshalBinary()
			bf := new(util.Buffer)
			bf.UnmarshalBinary(bytes)
			pktIn.Data = bf

			tcpSrcPort, tcpDstPort, tcpSeqNum, tcpAckNum, tcpCode, err := GetTCPHeaderData(pktIn)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPacketInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.args.expectTCPSrcPort, tcpSrcPort, "Expect to retrieve exact TCP src port while differed")
			assert.Equal(t, tt.args.expectTCPDstPort, tcpDstPort, "Expect to retrieve exact TCP dst port while differed")
			assert.Equal(t, tt.args.expectTCPSeqNum, tcpSeqNum, "Expect to retrieve exact TCP seq num while differed")
			assert.Equal(t, tt.args.expectTCPAckNum, tcpAckNum, "Expect to retrieve exact TCP ack num while differed")
			assert.Equal(t, tt.args.expectTCPCode, tcpCode, "Expect to retrieve exact TCP code while differed")
		})
	}
}
