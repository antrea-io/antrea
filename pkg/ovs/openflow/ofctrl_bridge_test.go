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

	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"

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
