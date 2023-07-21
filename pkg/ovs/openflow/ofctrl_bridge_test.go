// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"net"
	"sync"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

type fakeConn struct{}

func (f *fakeConn) Close() error {
	return nil
}

func (f *fakeConn) Read(b []byte) (int, error) {
	return len(b), nil
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (f *fakeConn) LocalAddr() net.Addr {
	return nil
}

func (f *fakeConn) RemoteAddr() net.Addr {
	return nil
}

func (f *fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newFakeOFSwitch(app ofctrl.AppInterface) *ofctrl.OFSwitch {
	stream := util.NewMessageStream(&fakeConn{}, nil)
	dpid, _ := net.ParseMAC("01:02:03:04:05:06:07:08")
	connCh := make(chan int)
	sw := ofctrl.NewSwitch(stream, dpid, app, connCh, 100)
	return sw
}

// TestOFBridgeIsConnected verifies it's thread-safe to call OFBridge's IsConnected method.
func TestOFBridgeIsConnected(t *testing.T) {
	b := NewOFBridge("test-br", GetMgmtAddress(ovsconfig.DefaultOVSRunDir, "test-br"))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sw := newFakeOFSwitch(b)
		b.SwitchConnected(sw)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.IsConnected()
	}()
	wg.Wait()
}

func TestDeleteGroup(t *testing.T) {
	b := NewOFBridge("test-br", GetMgmtAddress(ovsconfig.DefaultOVSRunDir, "test-br"))

	for _, m := range []struct {
		name            string
		existingGroupID GroupIDType
		deleteGroupID   GroupIDType
		err             error
	}{
		{
			name:            "delete existing group without flow",
			existingGroupID: 20,
			deleteGroupID:   20,
			err:             nil,
		},
		{
			name:            "delete non-existing group",
			existingGroupID: 20,
			deleteGroupID:   30,
			err:             nil,
		},
	} {
		t.Run(m.name, func(t *testing.T) {
			b.ofSwitch = newFakeOFSwitch(b)
			b.NewGroup(m.existingGroupID)
		})
	}
}

func TestConcurrentCreateGroups(t *testing.T) {
	b := NewOFBridge("test-br", GetMgmtAddress(ovsconfig.DefaultOVSRunDir, "test-br"))
	b.SwitchConnected(newFakeOFSwitch(b))
	// Race detector on Windows has limit of 8192 simultaneously alive goroutines.
	concurrentNum := 7000
	var wg sync.WaitGroup
	for i := 0; i < concurrentNum; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			b.NewGroup(GroupIDType(index))
		}(i)
	}
	wg.Wait()
}

func TestOFBridgePacketRcvd(t *testing.T) {
	b := NewOFBridge("test-br-pkt-rcvd", GetMgmtAddress(ovsconfig.DefaultOVSRunDir, "test-br-pkt-rcvd"))
	packetInQueueTracker := map[uint8]*PacketInQueue{}
	// Test different userdata.
	for i := 0; i < 5; i++ {
		packetInQueue := NewPacketInQueue(1, rate.Limit(10))
		b.SubscribePacketIn(uint8(i), packetInQueue)
		packetInQueueTracker[uint8(i)] = packetInQueue
		b.PacketRcvd(nil, &ofctrl.PacketIn{
			PacketIn: &openflow15.PacketIn{},
			UserData: []byte{uint8(i)},
		})
		packetIn := <-packetInQueue.packetsCh
		assert.Equal(t, packetIn.UserData, []byte{uint8(i)})
	}
	// Test empty userdata.
	b.PacketRcvd(nil, &ofctrl.PacketIn{
		PacketIn: &openflow15.PacketIn{},
		UserData: []byte{},
	})
	for _, v := range packetInQueueTracker {
		if len(v.packetsCh) > 0 {
			t.Errorf("unexpected packetIn in channel")
		}
	}
}
