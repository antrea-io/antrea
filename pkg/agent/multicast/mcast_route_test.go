//go:build linux
// +build linux

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

package multicast

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	multicasttest "antrea.io/antrea/pkg/agent/multicast/testing"
)

var (
	addrIf1    = &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	addrIf2    = &net.IPNet{IP: externalInterfaceIP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	nodeConfig = &config.NodeConfig{GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0"}, NodeIPv4Addr: addrIf1}
)

func TestParseIGMPMsg(t *testing.T) {
	mRoute := newMockMulticastRouteClient(t)
	err := mRoute.initialize(t)
	assert.Nil(t, err)

	for _, m := range []struct {
		msg                   []byte
		expectedParsedIGMPMsg *parsedIGMPMsg
		expectedErr           error
	}{
		{msg: []byte{69, 0, 0, 28, 242, 241, 64, 0, 1, 0, 0, 0, 10, 244, 0, 2, 224, 3, 3, 7, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedParsedIGMPMsg: &parsedIGMPMsg{Src: net.ParseIP("10.244.0.2"), Dst: net.ParseIP("224.3.3.7"), VIF: uint16(0)}, expectedErr: nil},
		{msg: []byte{123, 234, 112, 33, 244, 2, 64, 2, 1, 0, 1, 0, 10, 244, 0, 4, 224, 2, 4, 8, 1, 0, 0},
			expectedParsedIGMPMsg: &parsedIGMPMsg{Src: net.ParseIP("10.244.0.4"), Dst: net.ParseIP("224.2.4.8"), VIF: uint16(1)}, expectedErr: nil},
		{msg: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 11, 12, 24, 12, 34, 21, 23, 45},
			expectedErr: fmt.Errorf("failed to parse IGMPMSG: message length should be greater than 19")},
		{msg: []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 11, 11, 12, 24, 12, 34, 21, 23, 45, 22},
			expectedErr: fmt.Errorf("not a IGMPMSG_NOCACHE message: [1 2 3 4 5 6 7 8 0 0 11 11 12 24 12 34 21 23 45 22]")},
		{msg: []byte{69, 0, 0, 28, 242, 241, 64, 0, 1, 1, 0, 0, 10, 244, 0, 2, 224, 3, 3, 7, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedErr: fmt.Errorf("invalid igmpmsg message: im_mbz must be zero")},
	} {
		msg, err := mRoute.parseIGMPMsg(m.msg)
		assert.Equal(t, m.expectedErr, err)
		assert.Equal(t, m.expectedParsedIGMPMsg, msg)
	}
}

func TestProcessIGMPNocacheMsg(t *testing.T) {
	mRoute := newMockMulticastRouteClient(t)
	err := mRoute.initialize(t)
	assert.Nil(t, err)
	mRoute.multicastInterfaceConfigs = []multicastInterfaceConfig{
		{Name: "if1", IPv4Addr: addrIf1},
		{Name: "if2", IPv4Addr: addrIf2},
	}
	mRoute.externalInterfaceVIFs = []uint16{1, 2}
	mRoute.internalInterfaceVIF = uint16(0)
	status1 := &GroupMemberStatus{
		group:        net.ParseIP("224.3.3.8"),
		localMembers: map[string]time.Time{"aa": time.Now()},
	}
	mRoute.groupCache.Add(status1)
	status2 := &GroupMemberStatus{
		group:        net.ParseIP("224.3.3.9"),
		localMembers: map[string]time.Time{},
	}
	mRoute.groupCache.Add(status2)
	for _, m := range []struct {
		igmpMsg            []byte
		expectedSrc        net.IP
		expectedGroup      net.IP
		expectedIif        uint16
		expectedOifVIFs    []uint16
		expectedNumOfCalls int
	}{
		{igmpMsg: []byte{69, 0, 0, 28, 242, 241, 64, 0, 1, 0, 0, 0, 10, 244, 0, 2, 224, 3, 3, 7, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedSrc: net.ParseIP("10.244.0.2"), expectedGroup: net.ParseIP("224.3.3.7"), expectedIif: uint16(0), expectedOifVIFs: []uint16{1, 2}, expectedNumOfCalls: 1},
		{igmpMsg: []byte{69, 0, 0, 28, 242, 241, 64, 0, 1, 1, 0, 0, 10, 244, 0, 2, 224, 3, 3, 7, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedSrc: net.ParseIP("10.244.0.2"), expectedGroup: net.ParseIP("224.3.3.7"), expectedIif: uint16(0), expectedOifVIFs: []uint16{1, 2}, expectedNumOfCalls: 0},
		{igmpMsg: []byte{69, 0, 0, 28, 242, 241, 64, 2, 1, 0, 2, 0, 10, 244, 0, 3, 224, 3, 3, 8, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedSrc: net.ParseIP("10.244.0.3"), expectedGroup: net.ParseIP("224.3.3.8"), expectedIif: uint16(2), expectedOifVIFs: []uint16{0}, expectedNumOfCalls: 1},
		{igmpMsg: []byte{69, 0, 0, 28, 242, 241, 64, 2, 1, 0, 3, 0, 10, 244, 0, 3, 224, 3, 3, 8, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedSrc: net.ParseIP("10.244.0.3"), expectedGroup: net.ParseIP("224.3.3.8"), expectedIif: uint16(2), expectedOifVIFs: []uint16{0}, expectedNumOfCalls: 0},
		{igmpMsg: []byte{69, 0, 0, 28, 242, 241, 64, 2, 1, 0, 2, 0, 10, 244, 0, 3, 224, 3, 3, 9, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedSrc: net.ParseIP("10.244.0.3"), expectedGroup: net.ParseIP("224.3.3.9"), expectedIif: uint16(2), expectedOifVIFs: []uint16{0}, expectedNumOfCalls: 0},
		{igmpMsg: []byte{69, 0, 0, 28, 242, 241, 64, 2, 1, 0, 2, 0, 10, 244, 0, 3, 224, 3, 3, 10, 1, 0, 0, 0, 0, 0, 0, 0},
			expectedSrc: net.ParseIP("10.244.0.3"), expectedGroup: net.ParseIP("224.3.3.10"), expectedIif: uint16(2), expectedOifVIFs: []uint16{0}, expectedNumOfCalls: 0},
	} {
		mockMulticastSocket.EXPECT().AddMrouteEntry(m.expectedSrc, m.expectedGroup, m.expectedIif, m.expectedOifVIFs).Times(m.expectedNumOfCalls)
		mRoute.processIGMPNocacheMsg(m.igmpMsg)
	}
}

func newMockMulticastRouteClient(t *testing.T) *MRouteClient {
	controller := gomock.NewController(t)
	mockMulticastSocket = multicasttest.NewMockRouteInterface(controller)
	groupCache := cache.NewIndexer(getGroupEventKey, cache.Indexers{
		podInterfaceIndex: podInterfaceIndexFunc,
	})
	return newRouteClient(nodeConfig, groupCache, mockMulticastSocket, sets.NewString(if1.InterfaceName))
}

func (c *MRouteClient) initialize(t *testing.T) error {
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(0)).Times(1).Return([]uint16{0}, nil)
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(1)).Times(1).Return([]uint16{1, 2}, nil)
	return c.Initialize()
}
