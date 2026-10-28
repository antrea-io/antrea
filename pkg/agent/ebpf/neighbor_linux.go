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
	"errors"
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

type neighborKey struct {
	ifIndex int
	ip      string
}

// neighborFlags records only the flags added by this loader, so cleanup preserves existing ownership.
type neighborFlags struct {
	flags    int
	flagsExt int
}

type neighborManager struct {
	podCIDRs    []*net.IPNet
	gatewayIPs  []net.IP
	families    []int
	localPodIPs func() []net.IP
	owned       map[neighborKey]neighborFlags
	paused      bool
}

// probeManagedNeighbors verifies FlagsExt in a disposable namespace: older kernels may ignore it.
// ns.Do locks the thread and restores its original namespace after unshare.
func probeManagedNeighbors(families []int) error {
	currentNS, err := ns.GetCurrentNS()
	if err != nil {
		return err
	}
	defer currentNS.Close()
	return currentNS.Do(func(_ ns.NetNS) error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		link := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "probe0"},
			PeerName:  "probe1",
		}
		if err := netlink.LinkAdd(link); err != nil {
			return err
		}
		for _, family := range families {
			ip := net.IPv4(192, 0, 2, 1)
			if family == unix.AF_INET6 {
				ip = net.ParseIP("2001:db8::1")
			}
			if err := netlink.NeighSet(&netlink.Neigh{
				LinkIndex: link.Attrs().Index,
				Family:    family,
				IP:        ip,
				Flags:     netlink.NTF_EXT_LEARNED,
				FlagsExt:  netlink.NTF_EXT_MANAGED,
			}); err != nil {
				return err
			}
			neighbors, err := netlink.NeighList(link.Attrs().Index, family)
			if err != nil {
				return err
			}
			found := false
			for _, neighbor := range neighbors {
				if neighbor.IP.Equal(ip) && neighbor.FlagsExt&netlink.NTF_EXT_MANAGED != 0 {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("the kernel did not retain NTF_EXT_MANAGED for family %d", family)
			}
		}
		return nil
	})
}

// checkNeighbors runs with the loader mutex held. Kernel timers do the probing; this only reconciles
// registrations. If registration fails, pause redirects until a later check succeeds.
func (l *loader) checkNeighbors() {
	m := l.neighbors
	if m == nil {
		return
	}
	desired := make(map[neighborKey]struct{})
	transport := l.interfaces[programReturn]
	if transport != nil && !transport.missing {
		for _, ip := range l.nextHops {
			desired[neighborKey{ifIndex: transport.ifIndex, ip: ip.String()}] = struct{}{}
		}
	}
	gateway := l.interfaces[programFwd]
	if gateway != nil && !gateway.missing && m.localPodIPs != nil {
		for _, ip := range m.localPodIPs() {
			for i, cidr := range m.podCIDRs {
				if cidr.Contains(ip) && !ip.Equal(m.gatewayIPs[i]) {
					desired[neighborKey{ifIndex: gateway.ifIndex, ip: ip.String()}] = struct{}{}
					break
				}
			}
		}
	}
	err := m.sync(desired)
	paused := err != nil
	if paused != m.paused {
		forwardingEnabled := uint32(1)
		if paused {
			forwardingEnabled = 0
		}
		config := l.config
		config.forwardingEnabled = forwardingEnabled
		if writeErr := l.writeNodeConfig(config); writeErr != nil {
			klog.ErrorS(writeErr, "Failed to change eBPF forwarding state", "enabled", !paused)
			return
		}
		m.paused = paused
		klog.InfoS("Changed eBPF forwarding state", "enabled", !paused)
	}
	if err != nil {
		klog.ErrorS(err, "Failed to reconcile managed neighbors, using the host network stack")
	}
}

func (m *neighborManager) sync(desired map[neighborKey]struct{}) error {
	if len(desired) == 0 && len(m.owned) == 0 {
		return nil
	}
	existing := make(map[neighborKey]netlink.Neigh)
	for _, family := range m.families {
		neighbors, err := netlink.NeighList(0, family)
		if err != nil {
			return err
		}
		for _, neighbor := range neighbors {
			// Proxy entries are separate from the neighbors used for forwarding.
			if neighbor.Flags&netlink.NTF_PROXY == 0 {
				existing[neighborKey{ifIndex: neighbor.LinkIndex, ip: neighbor.IP.String()}] = neighbor
			}
		}
	}
	var errs []error
	for key := range desired {
		neighbor, found := existing[key]
		// Explicit static entries belong to their administrator.
		if neighbor.State&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) != 0 {
			delete(m.owned, key)
			continue
		}
		if !found {
			ip := net.ParseIP(key.ip)
			family := unix.AF_INET6
			if ip.To4() != nil {
				family = unix.AF_INET
			}
			neighbor = netlink.Neigh{
				LinkIndex: key.ifIndex,
				Family:    family,
				IP:        ip,
			}
		}
		added := m.owned[key]
		added.flags |= netlink.NTF_EXT_LEARNED &^ neighbor.Flags
		added.flagsExt |= netlink.NTF_EXT_MANAGED &^ neighbor.FlagsExt
		if neighbor.Flags&netlink.NTF_EXT_LEARNED == 0 || neighbor.FlagsExt&netlink.NTF_EXT_MANAGED == 0 {
			neighbor.Flags |= netlink.NTF_EXT_LEARNED
			neighbor.FlagsExt |= netlink.NTF_EXT_MANAGED
			if err := netlink.NeighSet(&neighbor); err != nil {
				errs = append(errs, fmt.Errorf("registering neighbor %s on interface %d: %w", key.ip, key.ifIndex, err))
				continue
			}
		}
		m.owned[key] = added
	}
	for key, added := range m.owned {
		if _, keep := desired[key]; keep {
			continue
		}
		neighbor, found := existing[key]
		if found && neighbor.State&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) == 0 &&
			(neighbor.Flags&added.flags != 0 || neighbor.FlagsExt&added.flagsExt != 0) {
			// Keep the current MAC and NUD state when returning an entry to ordinary kernel management.
			neighbor.Flags &^= added.flags
			neighbor.FlagsExt &^= added.flagsExt
			if err := netlink.NeighSet(&neighbor); err != nil && !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("releasing neighbor %s on interface %d: %w", key.ip, key.ifIndex, err))
				continue
			}
		}
		delete(m.owned, key)
	}
	return errors.Join(errs...)
}
