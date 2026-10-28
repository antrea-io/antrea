// Copyright 2026 Antrea Authors
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

//go:build linux

package ebpf

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The bpf syscall, and the subset of its commands and arguments this datapath uses. The structures mirror
// the ones of the kernel UAPI, field for field including the padding, as the kernel reads them by offset.
// They are all part of the stable UAPI, so they only ever grow at the end: the kernel takes the size of the
// structure it is given, treats what it does not know as zero, and refuses a longer one holding a value it
// does not know.
const (
	cmdMapCreate     = 0
	cmdMapLookupElem = 1
	cmdMapUpdateElem = 2
	cmdMapDeleteElem = 3
	cmdProgLoad      = 5
	cmdLinkCreate    = 28

	progTypeSchedCLS = 3

	attachTCXIngress = 46
	attachTCXEgress  = 47

	// objNameLen is the size of the name fields, BPF_OBJ_NAME_LEN. A longer name is refused, so the
	// names are truncated to it.
	objNameLen = 16

	// verifierLogSize is the buffer the kernel writes its rejection into. The verifier stops with ENOSPC
	// when it does not fit, which loses the end of the log, where the reason is.
	verifierLogSize = 1 << 20
)

// mapDef, programDef and mapReloc are what hack/gen-bpf-objects emits into objects_linux.go.
type mapDef struct {
	name       string
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32
}

type mapReloc struct {
	// instruction is the index of a wide instruction whose immediate is replaced with the map's fd.
	instruction uint32
	mapIndex    uint32
}

type programDef struct {
	name         string
	relocs       []mapReloc
	instructions string
}

func bpf(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	ret, _, errno := unix.Syscall(unix.SYS_BPF, cmd, uintptr(attr), size)
	// The attribute structure holds pointers to Go memory which the kernel reads during the call, and
	// which nothing else refers to. Keeping it alive until here stops the collector from moving or
	// freeing it while the kernel is reading it.
	runtime.KeepAlive(attr)
	if errno != 0 {
		return 0, errno
	}
	return ret, nil
}

// objName truncates a name to what the kernel accepts, keeping the end, which is what tells two names of the
// same program apart.
func objName(name string) [objNameLen]byte {
	var out [objNameLen]byte
	if len(name) >= objNameLen {
		name = name[len(name)-objNameLen+1:]
	}
	copy(out[:], name)
	return out
}

type mapCreateAttr struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
	innerMapFD uint32
	numaNode   uint32
	mapName    [objNameLen]byte
	mapIfindex uint32
}

// createMap creates one map and returns its file descriptor, which is what the programs referring to it are
// patched with and what every access to it goes through.
func createMap(def mapDef) (int, error) {
	attr := mapCreateAttr{
		mapType:    def.mapType,
		keySize:    def.keySize,
		valueSize:  def.valueSize,
		maxEntries: def.maxEntries,
		mapFlags:   def.flags,
		mapName:    objName(def.name),
	}
	fd, err := bpf(cmdMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, fmt.Errorf("creating map %s: %w", def.name, err)
	}
	return int(fd), nil
}

type mapElemAttr struct {
	mapFD uint32
	_     uint32
	key   uint64
	value uint64
	flags uint64
}

// mapUpdate, mapLookup and mapDelete pass the key and the value by address. The kernel copies them during the
// call, so they only have to stay put until it returns.
func mapUpdate(fd int, key, value unsafe.Pointer, flags uint64) error {
	attr := mapElemAttr{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: flags,
	}
	_, err := bpf(cmdMapUpdateElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func mapLookup(fd int, key, value unsafe.Pointer) error {
	attr := mapElemAttr{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}
	_, err := bpf(cmdMapLookupElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func mapDelete(fd int, key unsafe.Pointer) error {
	attr := mapElemAttr{mapFD: uint32(fd), key: uint64(uintptr(key))}
	_, err := bpf(cmdMapDeleteElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	return err
}

type progLoadAttr struct {
	progType    uint32
	insnCnt     uint32
	insns       uint64
	license     uint64
	logLevel    uint32
	logSize     uint32
	logBuf      uint64
	kernVersion uint32
	progFlags   uint32
	progName    [objNameLen]byte
	progIfindex uint32
}

// loadProgram hands the instructions to the kernel, which verifies them and returns a file descriptor for the
// program. It is called twice when the program is rejected: the first call asks for no log, which is the
// cheap path taken every time it succeeds, and the second one asks for the log to report the rejection.
func loadProgram(name string, instructions []byte) (int, error) {
	if len(instructions) == 0 || len(instructions)%instructionSize != 0 {
		return -1, fmt.Errorf("program %s is %d bytes, not a whole number of instructions", name, len(instructions))
	}
	license := append([]byte("GPL"), 0)
	attr := progLoadAttr{
		progType: progTypeSchedCLS,
		insnCnt:  uint32(len(instructions) / instructionSize),
		insns:    uint64(uintptr(unsafe.Pointer(&instructions[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
		progName: objName(name),
	}
	fd, err := bpf(cmdProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	if err == nil {
		return int(fd), nil
	}
	return -1, fmt.Errorf("loading program %s: %w%s", name, err, verifierLog(&attr, instructions, license))
}

// verifierLog retries the load asking the kernel to explain its refusal, and returns what it said. The log
// names the instruction it stopped at, by index; the instructions are the ones of bpf/host_datapath.bpf.c compiled
// by hack/gen-bpf-objects, which is where to look them up.
func verifierLog(attr *progLoadAttr, instructions, license []byte) string {
	log := make([]byte, verifierLogSize)
	retry := *attr
	retry.logLevel = 1
	retry.logSize = uint32(len(log))
	retry.logBuf = uint64(uintptr(unsafe.Pointer(&log[0])))
	_, _ = bpf(cmdProgLoad, unsafe.Pointer(&retry), unsafe.Sizeof(retry))
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	runtime.KeepAlive(log)
	if i := indexByte(log, 0); i >= 0 {
		log = log[:i]
	}
	text := strings.TrimSpace(string(log))
	if text == "" {
		return ""
	}
	return ", the verifier said: " + text
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

type linkCreateAttr struct {
	progFD        uint32
	targetIfindex uint32
	attachType    uint32
	flags         uint32
	relativeFD    uint32
	_             uint32
	expectedRev   uint64
}

// createTCXLink attaches a program to an interface through a link, which the kernel detaches on its own once
// the returned descriptor is closed, and which orders several programs on the same hook. It needs a kernel
// 6.6 or later; attachClassic is what runs on an older one.
func createTCXLink(progFD, ifIndex int, ingress bool) (int, error) {
	attachType := uint32(attachTCXEgress)
	if ingress {
		attachType = attachTCXIngress
	}
	attr := linkCreateAttr{
		progFD:        uint32(progFD),
		targetIfindex: uint32(ifIndex),
		attachType:    attachType,
	}
	fd, err := bpf(cmdLinkCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}
