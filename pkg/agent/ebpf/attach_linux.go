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
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// A program is attached to the traffic control hook of one interface and one direction, in one of two ways.
//
// A link is the newer one, and the one to prefer: the kernel owns the attachment, detaches it when the
// descriptor is closed, and defines how several programs on the same hook are ordered. It needs a kernel 6.6.
//
// A traffic control filter is the older one, and works on every kernel this Agent supports. The kernel keeps
// it after the process which added it is gone, which is why a stale one is removed before adding ours, so
// that a program of a previous Agent, holding instructions of whatever version it was built from, does not
// keep running invisibly.
const (
	// filterPriority is the priority of the filter, and filterNamePrefix names it. Both are how a filter
	// of a previous Agent is recognized, so neither can change without leaving those behind.
	filterPriority   = 0xC000
	filterNamePrefix = "antrea_hostdp_"
)

// attachment is a program attached to one hook, and knows how to undo it.
type attachment struct {
	// linkFD is the descriptor of the link, or -1 when a filter was used instead.
	linkFD  int
	ifIndex int
	ingress bool
	name    string
}

// attach puts a program on the ingress or egress hook of an interface, through a link if the kernel has
// them and through a filter if it does not.
func attach(progFD, ifIndex int, ingress bool, name string) (*attachment, error) {
	linkFD, err := createTCXLink(progFD, ifIndex, ingress)
	if err == nil {
		return &attachment{linkFD: linkFD, ifIndex: ifIndex, ingress: ingress, name: name}, nil
	}
	if !isUnsupported(err) {
		return nil, fmt.Errorf("attaching %s to interface %d with a link: %w", name, ifIndex, err)
	}
	klog.V(2).InfoS("The kernel has no support for BPF links on traffic control, using a filter instead",
		"program", name, "ifIndex", ifIndex, "err", err)
	if err := attachFilter(progFD, ifIndex, ingress, name); err != nil {
		return nil, err
	}
	return &attachment{linkFD: -1, ifIndex: ifIndex, ingress: ingress, name: name}, nil
}

// isUnsupported reports whether the kernel refused a command because it does not know it, rather than because
// of what it was asked to do. A kernel older than 6.6 has no link for this hook, and answers with one of
// these depending on how much older it is.
func isUnsupported(err error) bool {
	return errorIs(err, unix.EINVAL) || errorIs(err, unix.ENOSYS) || errorIs(err, unix.EOPNOTSUPP)
}

func errorIs(err error, errno unix.Errno) bool {
	e, ok := err.(unix.Errno)
	return ok && e == errno
}

func (a *attachment) detach() error {
	if a.linkFD >= 0 {
		// Closing the descriptor is what detaches the program.
		return unix.Close(a.linkFD)
	}
	return removeFilters(a.ifIndex, a.ingress)
}

func parentOf(ingress bool) uint32 {
	if ingress {
		return netlink.HANDLE_MIN_INGRESS
	}
	return netlink.HANDLE_MIN_EGRESS
}

// attachFilter adds the clsact qdisc, which holds the traffic control hooks of an interface, then a filter
// running the program on the wanted one. Any filter left by a previous Agent is removed first.
func attachFilter(progFD, ifIndex int, ingress bool, name string) error {
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	// The qdisc is shared with whoever else uses these hooks, so it is added if missing and never removed.
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("adding the clsact qdisc to interface %d: %w", ifIndex, err)
	}
	if err := removeFilters(ifIndex, ingress); err != nil {
		return err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    parentOf(ingress),
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  filterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:   progFD,
		Name: filterNamePrefix + name,
		// Without this the filter's verdict is a classification, and the program's own verdict, which
		// is what says whether the packet was redirected, is ignored.
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("adding the filter for %s to interface %d: %w", name, ifIndex, err)
	}
	return nil
}

// ownedFilters returns the filters this datapath owns on one hook of an interface, whether this process added
// them or a previous one did.
func ownedFilters(ifIndex int, ingress bool) ([]*netlink.BpfFilter, error) {
	filters, err := netlink.FilterList(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Index: ifIndex}},
		parentOf(ingress))
	if err != nil {
		// The interface having no qdisc, or being gone along with its qdisc, is not an error: there is
		// then no filter.
		if errorIs(err, unix.ENOENT) || errorIs(err, unix.ENODEV) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing the filters of interface %d: %w", ifIndex, err)
	}
	var owned []*netlink.BpfFilter
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		if ok && strings.HasPrefix(bpfFilter.Name, filterNamePrefix) {
			owned = append(owned, bpfFilter)
		}
	}
	return owned, nil
}

// hasFilter reports whether the filter of a program is on one hook of an interface. Something else managing
// traffic control on the interface can remove it, and the interface does not have to be recreated for that.
func hasFilter(ifIndex int, ingress bool, name string) (bool, error) {
	filters, err := ownedFilters(ifIndex, ingress)
	if err != nil {
		return false, err
	}
	for _, f := range filters {
		if f.Name == filterNamePrefix+name {
			return true, nil
		}
	}
	return false, nil
}

// removeFilters removes the filters this datapath owns from one hook of an interface, whether this process
// added them or a previous one did.
func removeFilters(ifIndex int, ingress bool) error {
	filters, err := ownedFilters(ifIndex, ingress)
	if err != nil {
		return err
	}
	for _, bpfFilter := range filters {
		if err := netlink.FilterDel(bpfFilter); err != nil {
			return fmt.Errorf("removing filter %s from interface %d: %w", bpfFilter.Name, ifIndex, err)
		}
		klog.V(2).InfoS("Removed a traffic control filter of the eBPF host datapath", "name", bpfFilter.Name,
			"ifIndex", ifIndex)
	}
	return nil
}
