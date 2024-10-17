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

package syscall

import (
	"net"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawSockAddrTranslation(t *testing.T) {
	for _, ipStr := range []string{
		"1.1.1.2",
		"abcd:12:03::adb3",
	} {
		ip := net.ParseIP(ipStr)
		sockAddr := NewRawSockAddrInetFromIP(ip)
		parsedIP := sockAddr.IP()
		assert.True(t, ip.Equal(parsedIP))
	}
}

func TestAddressPrefixTranslation(t *testing.T) {
	for _, ipnet := range []*net.IPNet{
		{
			IP:   net.ParseIP("1.1.1.0"),
			Mask: net.CIDRMask(28, 32),
		},
		{
			IP:   net.ParseIP("1.1.1.2"),
			Mask: net.CIDRMask(28, 32),
		},
		{
			IP:   net.ParseIP("abcd:12:03::adb3"),
			Mask: net.CIDRMask(96, 128),
		},
		{
			IP:   net.ParseIP("abcd:12:03::"),
			Mask: net.CIDRMask(96, 128),
		},
		{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		},
	} {
		sockAddr := NewAddressPrefixFromIPNet(ipnet)
		parsedIPNet := sockAddr.IPNet()
		assert.True(t, ipnet.IP.Equal(parsedIPNet.IP))
		assert.Equal(t, ipnet.String(), parsedIPNet.String())
	}
}

func TestRawSockAddrInetBasics(t *testing.T) {
	tests := []struct {
		name     string
		testInet *RawSockAddrInet
		wantIP   net.IP
	}{
		{
			name:     "IPv4",
			testInet: NewRawSockAddrInetFromIP(net.IPv4bcast),
			wantIP:   net.IPv4bcast,
		},
		{
			name:     "IPv6",
			testInet: NewRawSockAddrInetFromIP(net.IPv6zero),
			wantIP:   net.IPv6zero,
		},
		{
			name:     "Unspecified",
			testInet: &RawSockAddrInet{Family: AF_UNSPEC},
			wantIP:   net.IPv6unspecified,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantIP, tc.testInet.IP())
			assert.Equal(t, tc.wantIP.String(), tc.testInet.String())
		})
	}
}

func TestAddressPrefixBasics(t *testing.T) {
	testIPv4Net := &net.IPNet{
		IP:   net.ParseIP("1.1.1.0").To4(),
		Mask: net.CIDRMask(28, 32),
	}
	testIpv6Net := &net.IPNet{
		IP:   net.ParseIP("abcd:12:03::adb3"),
		Mask: net.CIDRMask(96, 128),
	}
	testDiffNet := &net.IPNet{
		IP:   net.ParseIP("1.1.2.0"),
		Mask: net.CIDRMask(28, 32),
	}
	tests := []struct {
		name      string
		testInet  *AddressPrefix
		wantIPNet *net.IPNet
	}{
		{
			name:      "IPv4",
			testInet:  NewAddressPrefixFromIPNet(testIPv4Net),
			wantIPNet: testIPv4Net,
		},
		{
			name:      "IPv6",
			testInet:  NewAddressPrefixFromIPNet(testIpv6Net),
			wantIPNet: testIpv6Net,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantIPNet, tc.testInet.IPNet())
			assert.Equal(t, tc.wantIPNet.String(), tc.testInet.String())
			assert.True(t, tc.testInet.EqualsTo(tc.wantIPNet))
			assert.False(t, tc.testInet.EqualsTo(testDiffNet))
		})
	}
	// Test more cases AddressPrefix EqualsTo
	testZeroNet := &net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 32),
	}
	assert.True(t, NewAddressPrefixFromIPNet(testZeroNet).EqualsTo(testZeroNet))
}

func TestIPInterfaceEntryOperations(t *testing.T) {
	tests := []struct {
		name      string
		syscallR1 uintptr
		wantErr   error
	}{
		{
			name:      "Normal",
			syscallR1: 0,
		},
		{
			name:      "Get Err",
			syscallR1: 22,
			wantErr:   syscall.Errno(22),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testNetIO := NewTestNetIO(tc.syscallR1)
			gotErr := testNetIO.GetIPInterfaceEntry(&MibIPInterfaceRow{})
			assert.Equal(t, tc.wantErr, gotErr)
			gotErr = testNetIO.SetIPInterfaceEntry(&MibIPInterfaceRow{})
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestIPForwardEntryOperations(t *testing.T) {
	tests := []struct {
		name      string
		syscallR1 uintptr
		wantErr   error
	}{
		{
			name:      "Normal",
			syscallR1: 0,
		},
		{
			name:      "Get Err",
			syscallR1: 22,
			wantErr:   syscall.Errno(22),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testNetIO := NewTestNetIO(tc.syscallR1)
			gotErr := testNetIO.CreateIPForwardEntry(&MibIPForwardRow{})
			assert.Equal(t, tc.wantErr, gotErr)
			gotErr = testNetIO.DeleteIPForwardEntry(&MibIPForwardRow{})
			assert.Equal(t, tc.wantErr, gotErr)
		})
	}
}

func TestListIPForwardRowsFailure(t *testing.T) {
	testNetIO := &netIO{
		getIPForwardTable: func(family uint16, ipForwardTable **MibIPForwardTable) (errcode error) {
			return syscall.Errno(22)
		},
		syscallN: func(trap uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
			assert.Fail(t, "freeMibTable shouldn't be called")
			return
		},
	}
	wantErr := os.NewSyscallError("iphlpapi.GetIpForwardTable", syscall.Errno(22))
	gotRows, gotErr := testNetIO.ListIPForwardRows(AF_INET)
	assert.Nil(t, gotRows)
	assert.Equal(t, wantErr, gotErr)
}

func TestListIPForwardRowsSuccess(t *testing.T) {
	row1 := MibIPForwardRow{
		Luid:  10,
		Index: 11,
		DestinationPrefix: AddressPrefix{
			Prefix: RawSockAddrInet{
				Family: AF_INET,
				data:   [26]byte{10, 10, 10, 0},
			},
			prefixLength: 24,
		},
		NextHop: RawSockAddrInet{
			Family: AF_INET,
			data:   [26]byte{11, 11, 11, 11},
		},
	}
	row2 := MibIPForwardRow{
		Luid:  20,
		Index: 21,
		DestinationPrefix: AddressPrefix{
			Prefix: RawSockAddrInet{
				Family: AF_INET,
				data:   [26]byte{20, 20, 20, 0},
			},
			prefixLength: 24,
		},
		NextHop: RawSockAddrInet{
			Family: AF_INET,
			data:   [26]byte{21, 21, 21, 21},
		},
	}
	// The table contains two rows. Its memory address will be assigned to ipForwardTable when getIPForwardTable is called.
	table := struct {
		NumEntries uint32
		Table      [2]MibIPForwardRow
	}{
		NumEntries: 2,
		Table:      [2]MibIPForwardRow{row1, row2},
	}
	freeMibTableCalled := false
	testNetIO := &netIO{
		getIPForwardTable: func(family uint16, ipForwardTable **MibIPForwardTable) (errcode error) {
			*ipForwardTable = (*MibIPForwardTable)(unsafe.Pointer(&table))
			return nil
		},
		syscallN: func(trap uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
			freeMibTableCalled = true
			// Reset the rows.
			table.Table[0] = MibIPForwardRow{}
			table.Table[1] = MibIPForwardRow{}
			return
		},
	}
	gotRows, gotErr := testNetIO.ListIPForwardRows(AF_INET)
	require.NoError(t, gotErr)
	assert.True(t, freeMibTableCalled)
	// It verifies that the returned rows are independent copies, not referencing to the original table's memory, by
	// asserting they retain the exact same content as the original table whose rows have been reset by freeMibTable.
	expectedRows := []MibIPForwardRow{row1, row2}
	assert.Equal(t, expectedRows, gotRows)
}

func NewTestNetIO(wantR1 uintptr) *netIO {
	mockSyscallN := func(trap uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
		return wantR1, 0, 0
	}
	return &netIO{syscallN: mockSyscallN}
}
