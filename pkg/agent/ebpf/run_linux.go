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
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

// checkInterval is how often Run looks the interfaces up. Until it notices a change, the packets go to the
// host network stack, which still forwards them, so a change costs performance for this long and nothing else.
const checkInterval = 30 * time.Second

// watchedInterface is what Run last saw of one of the two interfaces a program is attached to.
type watchedInterface struct {
	// program is the program attached to the interface, and name the name the interface is looked up by.
	program string
	name    string
	ifIndex int
	mtu     int
	// missing is set once the interface was found gone, so that this is logged once, and so that the
	// program is attached again when the interface comes back, even with the same index.
	missing bool
}

// observedInterface is what a check found of an interface.
type observedInterface struct {
	found   bool
	ifIndex int
	mtu     int
	// attached reports whether the program is still attached to the index which was watched. It is only
	// meaningful when the index did not change.
	attached bool
}

// interfaceChanges is what a check has to do about one interface.
type interfaceChanges struct {
	// gone is set the first time the interface is found missing.
	gone bool
	// reattach means detaching the program from the old index and attaching it to the new one.
	reattach bool
	// updateMTU means writing the new MTU into node_config.
	updateMTU bool
}

// computeInterfaceChanges compares what was last seen of an interface with what a check found. It is kept
// apart from the lookups and the syscalls so that the decisions can be tested without an interface.
func computeInterfaceChanges(watched watchedInterface, observed observedInterface) interfaceChanges {
	if !observed.found {
		return interfaceChanges{gone: !watched.missing}
	}
	return interfaceChanges{
		reattach:  watched.missing || observed.ifIndex != watched.ifIndex || !observed.attached,
		updateMTU: observed.mtu != watched.mtu,
	}
}

func (l *loader) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting the eBPF host datapath interface checks", "interval", checkInterval)
	wait.Until(l.checkInterfaces, checkInterval, stopCh)
}

func (l *loader) checkInterfaces() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if !l.loaded {
		return
	}
	for _, watched := range l.interfaces {
		if err := l.checkInterface(watched); err != nil {
			klog.ErrorS(err, "Failed to check the interface of the eBPF host datapath", "interface", watched.name,
				"program", watched.program)
		}
	}
	l.checkNeighbors()
}

// checkInterface looks one interface up and brings the attachment and node_config in line with it. What it
// records in watched is only updated once the change was made, so that a change which failed is tried again
// on the next check.
func (l *loader) checkInterface(watched *watchedInterface) error {
	observed, err := l.observeInterface(watched)
	if err != nil {
		return err
	}
	changes := computeInterfaceChanges(*watched, observed)
	if changes.gone {
		klog.V(2).InfoS("The interface of the eBPF host datapath is gone, the host network stack forwards "+
			"its traffic until it comes back", "interface", watched.name, "program", watched.program)
		watched.missing = true
	}
	if changes.reattach {
		if err := l.reattach(watched, observed.ifIndex); err != nil {
			return err
		}
	}
	if changes.updateMTU {
		config := l.config
		if watched.program == programFwd {
			config.gatewayMTU = uint32(observed.mtu)
		} else {
			config.transportMTU = uint32(observed.mtu)
		}
		if err := l.writeNodeConfig(config); err != nil {
			return err
		}
		klog.InfoS("Updated the MTU of the eBPF host datapath", "interface", watched.name,
			"oldMTU", watched.mtu, "newMTU", observed.mtu)
		watched.mtu = observed.mtu
	}
	return nil
}

func (l *loader) observeInterface(watched *watchedInterface) (observedInterface, error) {
	link, err := netlink.LinkByName(watched.name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return observedInterface{}, nil
		}
		return observedInterface{}, err
	}
	observed := observedInterface{
		found:    true,
		ifIndex:  link.Attrs().Index,
		mtu:      link.Attrs().MTU,
		attached: true,
	}
	// A link attachment lasts as long as the interface, which the index tells. A filter can also be
	// removed from an interface which stays, so it is looked for.
	attached := l.attachments[watched.program]
	if attached == nil {
		observed.attached = false
	} else if attached.linkFD < 0 && observed.ifIndex == watched.ifIndex {
		observed.attached, err = hasFilter(watched.ifIndex, attached.ingress, watched.program)
		if err != nil {
			return observedInterface{}, err
		}
	}
	return observed, nil
}

// reattach moves a program from the index it was attached to onto the new index of its interface.
func (l *loader) reattach(watched *watchedInterface, ifIndex int) error {
	if old := l.attachments[watched.program]; old != nil {
		// The old attachment is gone along with the interface most of the time, and detaching it only
		// releases what is left of it.
		if err := old.detach(); err != nil {
			return err
		}
		l.attachments[watched.program] = nil
	}
	attached, err := attach(l.programFDs[watched.program], ifIndex, true, watched.program)
	if err != nil {
		return err
	}
	l.attachments[watched.program] = attached
	if watched.program == programFwd {
		config := l.config
		config.gatewayIfIndex = uint32(ifIndex)
		if err := l.writeNodeConfig(config); err != nil {
			return err
		}
	}
	klog.InfoS("Attached the eBPF host datapath again", "interface", watched.name, "program", watched.program,
		"oldIfIndex", watched.ifIndex, "newIfIndex", ifIndex)
	watched.ifIndex = ifIndex
	watched.missing = false
	return nil
}
