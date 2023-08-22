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

package openflow

import (
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/ovs/openflow"
)

type fakeHandler struct {
	callChannel chan ofpPacketInCategory
	category    ofpPacketInCategory
}

func (fh *fakeHandler) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	fh.callChannel <- fh.category
	return nil
}

func Test_RegisterPacketInHandler(t *testing.T) {
	fc := newFakeClient(nil, true, false, config.K8sNode, config.TrafficEncapModeEncap)
	defer resetPipelines()
	fakeHandler := &fakeHandler{
		callChannel: make(chan ofpPacketInCategory),
		category:    PacketInCategoryTF,
	}
	fc.RegisterPacketInHandler(uint8(PacketInCategoryTF), fakeHandler)
	assert.Equal(t, fc.packetInHandlers, map[uint8]PacketInHandler{0: fakeHandler})
}

func Test_StartPacketInHandler(t *testing.T) {
	fc := newFakeClient(nil, true, false, config.K8sNode, config.TrafficEncapModeEncap)
	defer resetPipelines()
	callChannel := make(chan ofpPacketInCategory)
	fc.packetInHandlers[uint8(PacketInCategoryTF)] = &fakeHandler{
		callChannel: callChannel,
		category:    PacketInCategoryTF,
	}
	fc.packetInHandlers[uint8(PacketInCategoryNP)] = &fakeHandler{
		callChannel: callChannel,
		category:    PacketInCategoryNP,
	}
	fc.packetInHandlers[uint8(PacketInCategoryDNS)] = &fakeHandler{
		callChannel: callChannel,
		category:    PacketInCategoryDNS,
	}
	fc.packetInHandlers[uint8(PacketInCategoryIGMP)] = &fakeHandler{
		callChannel: callChannel,
		category:    PacketInCategoryIGMP,
	}
	fc.packetInHandlers[uint8(PacketInCategorySvcReject)] = &fakeHandler{
		callChannel: callChannel,
		category:    PacketInCategorySvcReject,
	}
	fc.StartPacketInHandler(nil)
	bridge := fc.bridge.(*openflow.OFBridge)
	for _, tt := range []struct {
		name        string
		userData    []byte
		expectValue ofpPacketInCategory
	}{
		{
			name:        "PacketInCategoryTF",
			userData:    []byte{uint8(PacketInCategoryTF)},
			expectValue: PacketInCategoryTF,
		},
		{
			name:        "PacketInCategoryNP",
			userData:    []byte{uint8(PacketInCategoryNP)},
			expectValue: PacketInCategoryNP,
		},
		{
			name:        "PacketInCategoryDNS",
			userData:    []byte{uint8(PacketInCategoryDNS)},
			expectValue: PacketInCategoryDNS,
		},
		{
			name:        "PacketInCategoryIGMP",
			userData:    []byte{uint8(PacketInCategoryIGMP)},
			expectValue: PacketInCategoryIGMP,
		},
		{
			name:        "PacketInCategorySvcReject",
			userData:    []byte{uint8(PacketInCategorySvcReject)},
			expectValue: PacketInCategorySvcReject,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packetIn := &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{},
				UserData: tt.userData,
			}
			bridge.PacketRcvd(nil, packetIn)
			select {
			case value := <-callChannel:
				assert.Equal(t, value, tt.expectValue)
			}
		})
	}
}
