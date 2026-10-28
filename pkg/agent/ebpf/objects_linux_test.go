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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestObjectsMatchSource fails when bpf/host_datapath.bpf.c was changed without regenerating objects_linux.go. The
// instructions the Agent loads come from the generated file, so without this the two drift apart silently and
// the datapath keeps running the version of the C which happened to be compiled last.
func TestObjectsMatchSource(t *testing.T) {
	source, err := os.ReadFile("bpf/host_datapath.bpf.c")
	require.NoError(t, err)
	sum := sha256.Sum256(source)
	assert.Equal(t, bpfSourceSHA256, hex.EncodeToString(sum[:]),
		"bpf/host_datapath.bpf.c changed since objects_linux.go was generated, run \"make bpf-objects\"")
}

// TestObjectsAreLoadable checks what the loader assumes about the generated objects, so that a bad object is
// caught here rather than by the kernel on a Node.
func TestObjectsAreLoadable(t *testing.T) {
	byName := map[string]mapDef{}
	for _, m := range bpfMaps {
		assert.NotZero(t, m.mapType, "map %s has no type", m.name)
		assert.NotZero(t, m.maxEntries, "map %s has no entries", m.name)
		assert.NotZero(t, m.keySize, "map %s has no key size", m.name)
		assert.NotZero(t, m.valueSize, "map %s has no value size", m.name)
		byName[m.name] = m
	}
	// The Go structures written into the maps have to be the size the programs read.
	require.Contains(t, byName, mapPodRoutes)
	assert.EqualValues(t, len(podRouteKey{}.addr)+4, byName[mapPodRoutes].keySize,
		"podRouteKey and struct pod_route_key have drifted apart")
	assert.EqualValues(t, 4, byName[mapPodRoutes].valueSize, "a next hop is an IPv4 address")
	require.Contains(t, byName, mapNodeConfig)
	assert.EqualValues(t, 1, byName[mapNodeConfig].maxEntries)
	assert.EqualValues(t, unsafe.Sizeof(nodeConfig{}), byName[mapNodeConfig].valueSize,
		"nodeConfig and struct hostdp_config have drifted apart")
	require.Contains(t, byName, mapStats)
	assert.EqualValues(t, statCount, byName[mapStats].maxEntries,
		"stats does not hold exactly the counters Stats reads")

	programs := map[string]programDef{}
	for _, p := range bpfPrograms {
		assert.NotEmpty(t, p.instructions, "program %s is empty", p.name)
		assert.Zero(t, len(p.instructions)%instructionSize, "program %s is not a whole number of instructions", p.name)
		assert.NotEmpty(t, p.relocs, "program %s refers to no map, which cannot be", p.name)
		for _, r := range p.relocs {
			offset := int(r.instruction) * instructionSize
			require.Less(t, offset+2*instructionSize, len(p.instructions)+1,
				"program %s has a relocation past its end", p.name)
			assert.EqualValues(t, opcodeLoadImm64, p.instructions[offset],
				"program %s has a relocation on an instruction which is not a wide load", p.name)
			assert.Less(t, int(r.mapIndex), len(bpfMaps), "program %s refers to a map which does not exist", p.name)
		}
		programs[p.name] = p
	}
	assert.Contains(t, programs, programFwd)
	assert.Contains(t, programs, programReturn)
}

// TestRelocate checks that patching a program leaves the instructions alone apart from the map references,
// which the kernel would otherwise reject or, worse, accept pointing at the wrong map.
func TestRelocate(t *testing.T) {
	l := &loader{mapFDs: map[string]int{}}
	for i, m := range bpfMaps {
		l.mapFDs[m.name] = 100 + i
	}
	for _, def := range bpfPrograms {
		t.Run(def.name, func(t *testing.T) {
			patched, err := l.relocate(def)
			require.NoError(t, err)
			require.Len(t, patched, len(def.instructions))

			relocated := map[int]bool{}
			for _, r := range def.relocs {
				offset := int(r.instruction) * instructionSize
				relocated[offset] = true
				expectedFD := 100 + int(r.mapIndex)
				assert.EqualValues(t, expectedFD, binary.LittleEndian.Uint32(patched[offset+4:]),
					"the immediate at instruction %d is not the map's descriptor", r.instruction)
				assert.EqualValues(t, pseudoMapFD, patched[offset+1]>>4,
					"the source register at instruction %d does not say the immediate is a map", r.instruction)
			}
			// Everything else is byte for byte what was generated.
			for offset := 0; offset < len(patched); offset += instructionSize {
				if relocated[offset] || relocated[offset-instructionSize] {
					continue
				}
				assert.Equal(t, def.instructions[offset:offset+instructionSize],
					string(patched[offset:offset+instructionSize]),
					"instruction %d was changed and holds no map reference", offset/instructionSize)
			}
		})
	}
}

func TestRouteKeyOf(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		expectedKey podRouteKey
		expectedErr string
	}{
		{
			// The address is kept in the order it has on the wire, which is the one the trie
			// compares a prefix in. Storing it the other way round matches nothing.
			name:        "IPv4",
			cidr:        "10.10.1.0/24",
			expectedKey: podRouteKey{prefixLen: 24, addr: [4]byte{10, 10, 1, 0}},
		},
		{
			name:        "a single address",
			cidr:        "10.10.1.5/32",
			expectedKey: podRouteKey{prefixLen: 32, addr: [4]byte{10, 10, 1, 5}},
		},
		{
			name:        "IPv6 is not supported yet",
			cidr:        "2001:db8::/64",
			expectedErr: "is not IPv4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tt.cidr)
			require.NoError(t, err)
			key, err := routeKeyOf(cidr)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestNetworkOrder(t *testing.T) {
	// The programs read an address out of the packet and never swap it, so what is written into the maps
	// is the four bytes of the wire in that order.
	expected := binary.NativeEndian.Uint32([]byte{192, 168, 50, 2})
	assert.Equal(t, expected, networkOrder(net.ParseIP("192.168.50.2")))
	assert.Equal(t, expected, networkOrder(net.IPv4(192, 168, 50, 2)), "a 16 byte IPv4 address reads the same")
	assert.Zero(t, networkOrder(net.ParseIP("2001:db8::1")))
}

func TestValidate(t *testing.T) {
	_, podCIDR, err := net.ParseCIDR("10.10.0.0/24")
	require.NoError(t, err)
	valid := Config{
		TransportName:    "eth0",
		GatewayName:      "antrea-gw0",
		TransportIfIndex: 2,
		TransportMTU:     1500,
		GatewayIfIndex:   3,
		GatewayMTU:       1450,
		LocalPodCIDR:     podCIDR,
		GatewayIPv4:      net.ParseIP("10.10.0.1"),
		NodeIPv4:         net.ParseIP("192.168.50.1"),
	}
	assert.NoError(t, validate(valid))

	tests := map[string]func(*Config){
		"the transport interface name":          func(c *Config) { c.TransportName = "" },
		"the gateway interface name":            func(c *Config) { c.GatewayName = "" },
		"the transport interface index is 0":    func(c *Config) { c.TransportIfIndex = 0 },
		"the gateway interface index is 0":      func(c *Config) { c.GatewayIfIndex = 0 },
		"the transport MTU is 0":                func(c *Config) { c.TransportMTU = 0 },
		"the gateway MTU is 0":                  func(c *Config) { c.GatewayMTU = 0 },
		"the local Pod CIDR is not set":         func(c *Config) { c.LocalPodCIDR = nil },
		"the gateway address is not set":        func(c *Config) { c.GatewayIPv4 = nil },
		"the Node transport address is not set": func(c *Config) { c.NodeIPv4 = nil },
		"is not IPv4":                           func(c *Config) { c.GatewayIPv4 = net.ParseIP("2001:db8::1") },
		// A Node whose address is inside the Pod CIDR cannot be told from a Pod by the programs, which
		// know nothing but that CIDR, so it is refused rather than silently forwarded as one.
		"is inside the local Pod CIDR": func(c *Config) { c.NodeIPv4 = net.ParseIP("10.10.0.9") },
		// The gateway holds an address of that CIDR, and the exclusion of it relies on that.
		"is outside the local Pod CIDR": func(c *Config) { c.GatewayIPv4 = net.ParseIP("192.168.50.1") },
	}
	for expectedErr, break_ := range tests {
		t.Run(expectedErr, func(t *testing.T) {
			config := valid
			break_(&config)
			assert.ErrorContains(t, validate(config), expectedErr)
		})
	}
}

// TestNotLoaded checks that the datapath is inert before Load and after Close: the Node route controller
// mirrors every route into it whether it loaded or not, and it must not fail those calls.
func TestNotLoaded(t *testing.T) {
	l := NewLoader()
	_, podCIDR, err := net.ParseCIDR("10.10.1.0/24")
	require.NoError(t, err)
	assert.NoError(t, l.AddPodRoute(podCIDR, net.ParseIP("192.168.50.2")))
	assert.NoError(t, l.DeletePodRoute(podCIDR))
	stats, err := l.Stats()
	assert.NoError(t, err)
	assert.Equal(t, Stats{}, stats)
	assert.NoError(t, l.Close())
}

func TestObjName(t *testing.T) {
	assert.Equal(t, "hostdp_fwd", trim(objName("hostdp_fwd")))
	// A name the kernel would refuse is truncated, and the end is what is kept: it is what tells two
	// programs of this datapath apart.
	assert.Equal(t, "ry_long_program", trim(objName("a_very_very_long_program")))
}

func trim(name [objNameLen]byte) string {
	for i, c := range name {
		if c == 0 {
			return string(name[:i])
		}
	}
	return string(name[:])
}
