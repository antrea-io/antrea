// Copyright 2023 Antrea Authors
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
	"fmt"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/openflow"
)

func TestController_HandlePacketIn(t *testing.T) {
	controller, _, _ := newTestController()
	logPacketErr := fmt.Errorf("log")
	rejectRequestErr := fmt.Errorf("reject")
	storeDenyConnectionErr := fmt.Errorf("storeDenyConnection")
	controller.logPacketAction = func(in *ofctrl.PacketIn) error {
		return logPacketErr
	}
	controller.rejectRequestAction = func(in *ofctrl.PacketIn) error {
		return rejectRequestErr
	}
	controller.storeDenyConnectionAction = func(in *ofctrl.PacketIn) error {
		return storeDenyConnectionErr
	}

	logPktIn := &ofctrl.PacketIn{
		PacketIn: &openflow15.PacketIn{},
		UserData: []byte{1},
	}
	controller.HandlePacketIn(logPktIn)

	for _, tt := range []struct {
		name      string
		packetIn  *ofctrl.PacketIn
		expectErr error
	}{
		{
			name:      "EmptyPacketIn",
			packetIn:  nil,
			expectErr: fmt.Errorf("empty packetIn for Antrea Policy"),
		},
		{
			name: "MissOperationInUserdata",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP)},
			},
			expectErr: fmt.Errorf("packetIn for Antrea Policy miss the required userdata"),
		},
		{
			name: "LoggingOperation",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP), uint8(openflow.PacketInNPLoggingOperation)},
			},
			expectErr: logPacketErr,
		},
		{
			name: "RejectOperation",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP), uint8(openflow.PacketInNPRejectOperation)},
			},
			expectErr: rejectRequestErr,
		},
		{
			name: "DenyOperation",
			packetIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: []byte{uint8(openflow.PacketInCategoryNP), uint8(openflow.PacketInNPStoreDenyOperation)},
			},
			expectErr: storeDenyConnectionErr,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.HandlePacketIn(tt.packetIn)
			assert.Equal(t, err, tt.expectErr)
		})
	}
}
