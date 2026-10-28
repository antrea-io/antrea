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
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// instructionSize is the size of an eBPF instruction. A wide one, which is what holds a map reference, takes
// two of those, and its immediate is the first four bytes after the opcode and the registers.
const instructionSize = 8

// opcodeLoadImm64 is the opcode of the wide instruction loading a 64 bit immediate, which is the only one a
// map relocation applies to. pseudoMapFD in its source register is what tells the kernel that the immediate
// is the descriptor of a map rather than a value.
const (
	opcodeLoadImm64 = 0x18
	pseudoMapFD     = 1
)

// The stats indices must match bpf/host_datapath.bpf.c.
const (
	statFwd uint32 = iota
	statFwdMiss
	statReturn
	statReturnMiss
	statPass
	statTTLExpired
	statTooBig
	statCount
)

// The names the programs are attached under, which must match the ones bpf/host_datapath.bpf.c defines.
const (
	programFwd    = "hostdp_fwd"
	programReturn = "hostdp_return"
)

const (
	mapPodRoutes  = "pod_routes"
	mapPodRoutes6 = "pod_routes6"
	mapNodeConfig = "node_config"
	mapStats      = "stats"
)

// podRouteKey is the key of the pod_routes map, which must match struct pod_route_key. The address is kept
// as bytes in network order, which is the order an LPM trie compares a prefix in.
type podRouteKey struct {
	prefixLen uint32
	addr      [4]byte
}

type podRouteKey6 struct {
	prefixLen uint32
	addr      [16]byte
}

// These layouts match the configuration structures in the BPF program.
type ipConfig4 struct {
	prefixLen uint32
	podNet    uint32
	gatewayIP uint32
}

type ipConfig6 struct {
	prefixLen uint32
	podNet    [16]byte
	gatewayIP [16]byte
}

type nodeConfig struct {
	transportMTU      uint32
	gatewayMTU        uint32
	gatewayIfIndex    uint32
	forwardingEnabled uint32
	ipv4              ipConfig4
	ipv6              ipConfig6
}

type loader struct {
	// mutex serializes the map writes, which come from the Node route controller, with Load, Run and Close.
	mutex sync.Mutex
	// mapFDs and programFDs are indexed by name, and are empty until Load succeeds.
	mapFDs     map[string]int
	programFDs map[string]int
	// attachments is indexed by the name of the program attached. An entry is nil while Run has detached a
	// program from an interface which went away and not attached it again yet.
	attachments map[string]*attachment
	// interfaces is what Run last saw of the two interfaces, indexed by the name of the program attached to
	// each of them.
	interfaces map[string]*watchedInterface
	neighbors  *neighborManager
	nextHops   map[string]net.IP
	config     nodeConfig
	loaded     bool
}

// NewLoader returns an eBPF host datapath which does nothing until Load is called.
func NewLoader() Interface {
	return &loader{
		mapFDs:      make(map[string]int),
		programFDs:  make(map[string]int),
		attachments: make(map[string]*attachment),
		interfaces:  make(map[string]*watchedInterface),
	}
}

func (l *loader) Load(config Config) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.loaded {
		return fmt.Errorf("the eBPF host datapath is already loaded")
	}
	if err := validate(config); err != nil {
		return err
	}
	var podCIDRs []*net.IPNet
	var gatewayIPs []net.IP
	var families []int
	if config.LocalPodCIDR != nil {
		podCIDRs = append(podCIDRs, config.LocalPodCIDR)
		gatewayIPs = append(gatewayIPs, config.GatewayIPv4)
		families = append(families, unix.AF_INET)
	}
	if config.LocalPodIPv6CIDR != nil {
		podCIDRs = append(podCIDRs, config.LocalPodIPv6CIDR)
		gatewayIPs = append(gatewayIPs, config.GatewayIPv6)
		families = append(families, unix.AF_INET6)
	}
	if err := probeManagedNeighbors(families); err != nil {
		return fmt.Errorf("managed neighbors are required for eBPF forwarding: %w", err)
	}
	l.neighbors = &neighborManager{
		podCIDRs:    podCIDRs,
		gatewayIPs:  gatewayIPs,
		families:    families,
		localPodIPs: config.LocalPodIPs,
		owned:       make(map[neighborKey]neighborFlags),
		paused:      true,
	}
	l.nextHops = make(map[string]net.IP)
	// A kernel older than 5.11 accounts the memory of the maps against the locked memory limit rather
	// than against the cgroup of the process, and the default limit is far below what they need.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		klog.V(2).InfoS("Could not raise the locked memory limit, which a kernel 5.11 or later ignores anyway", "err", err)
	}

	if err := l.loadLocked(config); err != nil {
		// Leave nothing half attached behind: what was done so far is undone, and the Node keeps
		// forwarding through the host stack.
		l.closeLocked()
		return err
	}
	l.loaded = true
	l.checkNeighbors()
	klog.InfoS("Loaded the eBPF host datapath", "transportIfIndex", config.TransportIfIndex,
		"gatewayIfIndex", config.GatewayIfIndex, "localPodCIDR", config.LocalPodCIDR,
		"localPodIPv6CIDR", config.LocalPodIPv6CIDR)
	return nil
}

func validate(config Config) error {
	switch {
	case config.TransportName == "":
		return fmt.Errorf("the transport interface name is not set")
	case config.GatewayName == "":
		return fmt.Errorf("the gateway interface name is not set")
	case config.TransportIfIndex <= 0:
		return fmt.Errorf("the transport interface index is %d", config.TransportIfIndex)
	case config.GatewayIfIndex <= 0:
		return fmt.Errorf("the gateway interface index is %d", config.GatewayIfIndex)
	case config.TransportMTU <= 0:
		return fmt.Errorf("the transport MTU is %d", config.TransportMTU)
	case config.GatewayMTU <= 0:
		return fmt.Errorf("the gateway MTU is %d", config.GatewayMTU)
	case config.LocalPodCIDR == nil && config.LocalPodIPv6CIDR == nil:
		return fmt.Errorf("the local Pod CIDR is not set")
	case config.LocalPodCIDR != nil && config.GatewayIPv4 == nil:
		return fmt.Errorf("the gateway address is not set")
	case config.LocalPodCIDR != nil && config.NodeIPv4 == nil:
		return fmt.Errorf("the Node transport address is not set")
	}
	if config.LocalPodIPv6CIDR != nil {
		cidr := config.LocalPodIPv6CIDR
		ones, bits := cidr.Mask.Size()
		if cidr.IP.To4() != nil || cidr.IP.To16() == nil || bits != 128 || ones == 0 {
			return fmt.Errorf("the local IPv6 Pod CIDR %s is invalid", cidr)
		}
		if config.GatewayIPv6 == nil || config.GatewayIPv6.To4() != nil || config.GatewayIPv6.To16() == nil {
			return fmt.Errorf("the IPv6 gateway address is not set or invalid")
		}
		if config.NodeIPv6 == nil || config.NodeIPv6.To4() != nil || config.NodeIPv6.To16() == nil {
			return fmt.Errorf("the IPv6 Node transport address is not set or invalid")
		}
		if cidr.Contains(config.NodeIPv6) {
			return fmt.Errorf("the Node transport address %s is inside the local Pod CIDR %s", config.NodeIPv6, cidr)
		}
		if !cidr.Contains(config.GatewayIPv6) {
			return fmt.Errorf("the gateway address %s is outside the local Pod CIDR %s", config.GatewayIPv6, cidr)
		}
	}
	if config.LocalPodCIDR == nil {
		return nil
	}
	for _, ip := range []struct {
		name  string
		value net.IP
	}{{"gateway address", config.GatewayIPv4}, {"Node transport address", config.NodeIPv4}} {
		if ip.value.To4() == nil {
			return fmt.Errorf("the %s %s is not IPv4",
				ip.name, ip.value)
		}
	}
	if config.LocalPodCIDR.IP.To4() == nil {
		return fmt.Errorf("the local Pod CIDR %s is not IPv4",
			config.LocalPodCIDR)
	}
	// The programs tell a Pod from anything else by the Pod CIDR alone, so a Node whose transport address
	// is inside it would have its own traffic forwarded as a Pod's, and the traffic of a host network Pod
	// with it. That configuration is refused rather than handled, as nothing else in the datapath could
	// tell the two apart.
	if config.LocalPodCIDR.Contains(config.NodeIPv4) {
		return fmt.Errorf("the Node transport address %s is inside the local Pod CIDR %s, which this "+
			"datapath cannot tell apart from a Pod", config.NodeIPv4, config.LocalPodCIDR)
	}
	if !config.LocalPodCIDR.Contains(config.GatewayIPv4) {
		return fmt.Errorf("the gateway address %s is outside the local Pod CIDR %s, which the datapath "+
			"assumes it is in", config.GatewayIPv4, config.LocalPodCIDR)
	}
	return nil
}

func (l *loader) loadLocked(config Config) error {
	for _, def := range bpfMaps {
		fd, err := createMap(def)
		if err != nil {
			return err
		}
		l.mapFDs[def.name] = fd
	}
	// The configuration is written before the programs are attached, so that the first packet they see
	// is matched against the real Pod CIDR rather than against an empty one.
	if err := l.writeConfig(config); err != nil {
		return err
	}
	for _, def := range bpfPrograms {
		instructions, err := l.relocate(def)
		if err != nil {
			return err
		}
		fd, err := loadProgram(def.name, instructions)
		if err != nil {
			return err
		}
		l.programFDs[def.name] = fd
	}

	// hostdp_fwd goes on the gateway ingress, where a local Pod's packet enters the host from OVS before
	// the stack routes it; hostdp_return goes on the transport ingress, where the packets coming back
	// from remote Pods arrive.
	for _, watched := range []*watchedInterface{
		{
			program: programFwd,
			name:    config.GatewayName,
			ifIndex: config.GatewayIfIndex,
			mtu:     config.GatewayMTU,
		},
		{
			program: programReturn,
			name:    config.TransportName,
			ifIndex: config.TransportIfIndex,
			mtu:     config.TransportMTU,
		},
	} {
		attached, err := attach(l.programFDs[watched.program], watched.ifIndex, true, watched.program)
		if err != nil {
			return err
		}
		l.attachments[watched.program] = attached
		l.interfaces[watched.program] = watched
	}
	return nil
}

// relocate copies the instructions of a program and replaces the immediate of each instruction referring to a
// map with the descriptor of that map.
func (l *loader) relocate(def programDef) ([]byte, error) {
	instructions := []byte(def.instructions)
	patched := make([]byte, len(instructions))
	copy(patched, instructions)
	for _, reloc := range def.relocs {
		offset := int(reloc.instruction) * instructionSize
		// A wide instruction takes two slots, so its second half has to be there as well.
		if offset < 0 || offset+2*instructionSize > len(patched) {
			return nil, fmt.Errorf("program %s has a relocation at instruction %d, which is outside "+
				"its %d instructions", def.name, reloc.instruction, len(patched)/instructionSize)
		}
		if patched[offset] != opcodeLoadImm64 {
			return nil, fmt.Errorf("program %s has a relocation at instruction %d, whose opcode is "+
				"%#02x rather than a wide load", def.name, reloc.instruction, patched[offset])
		}
		if int(reloc.mapIndex) >= len(bpfMaps) {
			return nil, fmt.Errorf("program %s refers to map %d, and there are %d",
				def.name, reloc.mapIndex, len(bpfMaps))
		}
		name := bpfMaps[reloc.mapIndex].name
		fd, ok := l.mapFDs[name]
		if !ok {
			return nil, fmt.Errorf("program %s refers to map %s, which was not created", def.name, name)
		}
		// The high nibble of the second byte is the source register, which says what the immediate is.
		patched[offset+1] = patched[offset+1]&0x0f | pseudoMapFD<<4
		binary.LittleEndian.PutUint32(patched[offset+4:], uint32(fd))
	}
	return patched, nil
}

func (l *loader) writeConfig(config Config) error {
	value := nodeConfig{
		transportMTU:   uint32(config.TransportMTU),
		gatewayMTU:     uint32(config.GatewayMTU),
		gatewayIfIndex: uint32(config.GatewayIfIndex),
	}
	if config.LocalPodCIDR != nil {
		ones, _ := config.LocalPodCIDR.Mask.Size()
		value.ipv4.prefixLen = uint32(ones)
		value.ipv4.podNet = networkOrder(config.LocalPodCIDR.IP)
		value.ipv4.gatewayIP = networkOrder(config.GatewayIPv4)
	}
	if config.LocalPodIPv6CIDR != nil {
		ones, _ := config.LocalPodIPv6CIDR.Mask.Size()
		value.ipv6.prefixLen = uint32(ones)
		copy(value.ipv6.podNet[:], config.LocalPodIPv6CIDR.IP.To16())
		copy(value.ipv6.gatewayIP[:], config.GatewayIPv6.To16())
	}
	return l.writeNodeConfig(value)
}

// writeNodeConfig updates the map and retains the last successfully written configuration.
// The loader mutex must be held.
func (l *loader) writeNodeConfig(config nodeConfig) error {
	key := uint32(0)
	if err := mapUpdate(l.mapFDs[mapNodeConfig], unsafe.Pointer(&key), unsafe.Pointer(&config), 0); err != nil {
		return fmt.Errorf("writing the Node configuration: %w", err)
	}
	l.config = config
	return nil
}

// networkOrder returns an IPv4 address as the four bytes it has on the wire, read as a native integer, which
// is the form the programs compare it in: they read it out of the packet and never swap it.
func networkOrder(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(v4)
}

func routeKeyOf(podCIDR *net.IPNet) (podRouteKey, error) {
	v4 := podCIDR.IP.To4()
	if v4 == nil {
		return podRouteKey{}, fmt.Errorf("Pod CIDR %s is not IPv4", podCIDR)
	}
	ones, bits := podCIDR.Mask.Size()
	if bits != 32 {
		return podRouteKey{}, fmt.Errorf("Pod CIDR %s does not have an IPv4 mask", podCIDR)
	}
	key := podRouteKey{prefixLen: uint32(ones)}
	copy(key.addr[:], v4)
	return key, nil
}

func routeKey6Of(podCIDR *net.IPNet) (podRouteKey6, error) {
	ones, bits := podCIDR.Mask.Size()
	if podCIDR.IP.To4() != nil || podCIDR.IP.To16() == nil || bits != 128 {
		return podRouteKey6{}, fmt.Errorf("Pod CIDR %s is not IPv6", podCIDR)
	}
	key := podRouteKey6{prefixLen: uint32(ones)}
	copy(key.addr[:], podCIDR.IP.To16())
	return key, nil
}

func (l *loader) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error {
	if podCIDR == nil || nextHop == nil {
		return fmt.Errorf("the Pod CIDR and the next hop are both required")
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if !l.loaded {
		return nil
	}
	var err error
	if podCIDR.IP.To4() != nil {
		if nextHop.To4() == nil {
			return fmt.Errorf("next hop %s is not IPv4", nextHop)
		}
		key, keyErr := routeKeyOf(podCIDR)
		if keyErr != nil {
			return keyErr
		}
		value := networkOrder(nextHop)
		err = mapUpdate(l.mapFDs[mapPodRoutes], unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
	} else {
		if nextHop.To4() != nil || nextHop.To16() == nil {
			return fmt.Errorf("next hop %s is not IPv6", nextHop)
		}
		key, keyErr := routeKey6Of(podCIDR)
		if keyErr != nil {
			return keyErr
		}
		var value [16]byte
		copy(value[:], nextHop.To16())
		err = mapUpdate(l.mapFDs[mapPodRoutes6], unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
	}
	if err != nil {
		return fmt.Errorf("adding the route to %s via %s: %w", podCIDR, nextHop, err)
	}
	if l.neighbors != nil {
		l.nextHops[podCIDR.String()] = append(net.IP(nil), nextHop...)
		l.checkNeighbors()
	}
	return nil
}

func (l *loader) DeletePodRoute(podCIDR *net.IPNet) error {
	if podCIDR == nil {
		return fmt.Errorf("the Pod CIDR is required")
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if !l.loaded {
		return nil
	}
	var err error
	if podCIDR.IP.To4() != nil {
		key, keyErr := routeKeyOf(podCIDR)
		if keyErr != nil {
			return keyErr
		}
		err = mapDelete(l.mapFDs[mapPodRoutes], unsafe.Pointer(&key))
	} else {
		key, keyErr := routeKey6Of(podCIDR)
		if keyErr != nil {
			return keyErr
		}
		err = mapDelete(l.mapFDs[mapPodRoutes6], unsafe.Pointer(&key))
	}
	// A route which was never installed is already in the wanted state.
	if err != nil && err != unix.ENOENT {
		return fmt.Errorf("deleting the route to %s: %w", podCIDR, err)
	}
	delete(l.nextHops, podCIDR.String())
	l.checkNeighbors()
	return nil
}

func (l *loader) Stats() (Stats, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var stats Stats
	if !l.loaded {
		return stats, nil
	}
	values := make([]uint64, statCount)
	for slot := range values {
		key := uint32(slot)
		if err := mapLookup(l.mapFDs[mapStats], unsafe.Pointer(&key), unsafe.Pointer(&values[slot])); err != nil {
			return Stats{}, fmt.Errorf("reading counter %d: %w", slot, err)
		}
	}
	return Stats{
		Forwarded:     values[statFwd],
		ForwardMisses: values[statFwdMiss],
		Returned:      values[statReturn],
		ReturnMisses:  values[statReturnMiss],
		Passed:        values[statPass],
		TTLExpired:    values[statTTLExpired],
		TooBig:        values[statTooBig],
	}, nil
}

func (l *loader) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.closeLocked()
}

// closeLocked undoes what Load did, in the reverse order, and reports the first thing which went wrong after
// having tried all of them: leaving a program attached because an unrelated descriptor would not close is
// worse than the error itself.
func (l *loader) closeLocked() error {
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for name, a := range l.attachments {
		if a != nil {
			record(a.detach())
		}
		delete(l.attachments, name)
	}
	if l.neighbors != nil {
		record(l.neighbors.sync(nil))
		l.neighbors = nil
	}
	clear(l.nextHops)
	clear(l.interfaces)
	for name, fd := range l.programFDs {
		record(unix.Close(fd))
		delete(l.programFDs, name)
	}
	for name, fd := range l.mapFDs {
		record(unix.Close(fd))
		delete(l.mapFDs, name)
	}
	l.loaded = false
	return firstErr
}
