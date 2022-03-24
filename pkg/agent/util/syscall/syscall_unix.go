//go:build linux && (arm || arm64 || amd64)
// +build linux
// +build arm arm64 amd64

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

package syscall

import (
	"syscall"
	"unsafe"
)

// setsockopt is modified from https://github.com/golang/sys/blob/5a964db013201115fcba5c3d31ade965d0969335/unix/zsyscall_linux_amd64.go#L520.
// Note check differences of setsockopt in zsyscall_OS_ARCH.go first if you want to add new platforms support.
// Change of build tag directly may won't work.
func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		return e1
	}
	return
}

// Please add your wrapped syscall functions below

func SetsockoptMfcctl(fd, level, opt int, mfcctl *Mfcctl) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(mfcctl), SizeofMfcctl)
}

func SetsockoptMf6cctl(fd, level, opt int, mf6cctl *Mf6cctl) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(mf6cctl), SizeofMf6cctl)
}

func SetsockoptVifctl(fd, level, opt int, vifctl *Vifctl) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(vifctl), SizeofVifctl)
}

func SetsockoptMif6ctl(fd, level, opt int, mif6ctl *Mif6ctl) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(mif6ctl), SizeofMif6ctl)
}
