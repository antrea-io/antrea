// Copyright 2019 Antrea Authors
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

package ethtool

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	IFNAMSIZ        = 16         // defined in linux/if.h
	SIOCETHTOOL     = 0x8946     // ethtool interface, defined in linux/sockios.h
	ETHTOOL_STXCSUM = 0x00000017 // set TX hw csum enable, defined in linux/ethtool.h
)

// defined in linux/if.h (struct ifreq)
type ifReq struct {
	Name [IFNAMSIZ]byte
	Data uintptr
}

// defined in linux/ethtool.h (struct ethtool_value)
type ethtoolValue struct {
	Cmd  uint32
	Data uint32
}

// EthtoolTXHWCsumOff disables TX checksum offload on the specified interface.
func EthtoolTXHWCsumOff(name string) error {
	if len(name)+1 > IFNAMSIZ {
		return fmt.Errorf("name '%s' exceeds IFNAMSIZ (%d)", name, IFNAMSIZ)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("error when opening socket: %v", err)
	}
	defer syscall.Close(fd)

	value := ethtoolValue{
		Cmd:  ETHTOOL_STXCSUM,
		Data: 0,
	}
	request := ifReq{
		Data: uintptr(unsafe.Pointer(&value)),
	}
	copy(request.Name[:], []byte(name))

	// We perform the call unconditionally: if TX checksum offload is already disabled the call
	// will be a no-op and there will be no error.
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(SIOCETHTOOL),
		uintptr(unsafe.Pointer(&request)),
	); errno != 0 {
		return fmt.Errorf("ioctl call failed: %v", errno)
	}

	return nil
}
