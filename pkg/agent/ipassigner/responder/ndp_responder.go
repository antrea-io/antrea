// Copyright 2022 Antrea Authors
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

package responder

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

var (
	solicitedNodeMulticastAddressPrefix = netip.MustParseAddr("ff02::1:ff00:0")
)

type ndpConn interface {
	WriteTo(message ndp.Message, cm *ipv6.ControlMessage, dstIP netip.Addr) error
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	JoinGroup(netip.Addr) error
	LeaveGroup(netip.Addr) error
	Close() error
}

type ndpResponder struct {
	once            sync.Once
	linkName        string
	conn            ndpConn
	linkEventCh     chan struct{}
	assignedIPs     sets.Set[netip.Addr]
	multicastGroups map[netip.Addr]int
	mutex           sync.Mutex
}

var _ Responder = (*ndpResponder)(nil)

func parseIPv6SolicitedNodeMulticastAddress(ip netip.Addr) netip.Addr {
	target := ip.As16()
	prefix := solicitedNodeMulticastAddressPrefix.As16()
	// copy lower 24 bits
	copy(prefix[13:], target[13:])
	return netip.AddrFrom16(prefix)
}

func (r *ndpResponder) InterfaceName() string {
	return r.linkName
}

func (r *ndpResponder) handleNeighborSolicitation(conn ndpConn, link *net.Interface) error {
	pkt, _, srcIP, err := conn.ReadFrom()
	if err != nil {
		return err
	}
	ns, ok := pkt.(*ndp.NeighborSolicitation)
	if !ok {
		return nil
	}
	var nsSourceHWAddr net.HardwareAddr
	for _, o := range ns.Options {
		addr, ok := o.(*ndp.LinkLayerAddress)
		if !ok {
			continue
		}
		if addr.Direction != ndp.Source {
			continue
		}
		nsSourceHWAddr = addr.Addr
		break
	}
	if nsSourceHWAddr == nil {
		return nil
	}
	if !r.isIPAssigned(ns.TargetAddress) {
		klog.V(4).InfoS("Ignored Neighbor Solicitation", "ip", ns.TargetAddress, "interface", r.linkName)
		return nil
	}
	na := &ndp.NeighborAdvertisement{
		Solicited:     true,
		Override:      true,
		TargetAddress: ns.TargetAddress,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      link.HardwareAddr,
			},
		},
	}
	if err := conn.WriteTo(na, nil, srcIP); err != nil {
		return err
	}
	klog.V(4).InfoS("Sent Neighbor Advertisement", "ip", ns.TargetAddress.String(), "interface", r.linkName)
	return nil
}

func (r *ndpResponder) Run(stopCh <-chan struct{}) {
	// The responder instance is created by the factory and can be shared by multiple callers.
	// Using once.Do here ensures it is started only once.
	r.once.Do(func() {
		go wait.NonSlidingUntil(func() {
			r.dialAndHandleRequests(stopCh)
		}, time.Second, stopCh)
	})
	<-stopCh
}

func (r *ndpResponder) dialAndHandleRequests(stopCh <-chan struct{}) {
	transportInterface, err := net.InterfaceByName(r.linkName)
	if err != nil {
		klog.ErrorS(err, "Failed to get interface", "interface", r.linkName)
		return
	}

	// It may take time for the interface to be ready for socket binding. For example, IPv6 introduces Duplicate Address Detection,
	// which may take time to allow the address to be used for socket binding. EADDRNOTAVAIL (bind: cannot assign requested address)
	// may be returned for such cases.
	klog.InfoS("Binding NDP responder on interface", "interface", r.linkName)
	conn, _, err := ndp.Listen(transportInterface, ndp.LinkLocal)
	if err != nil {
		klog.ErrorS(err, "Failed to create NDP responder", "interface", r.linkName)
		return
	}

	r.mutex.Lock()
	r.conn = conn
	for ip := range r.assignedIPs {
		if err := r.joinMulticastGroup(ip); err != nil {
			klog.ErrorS(err, "Failed to join multicast group", "ip", ip, "interface", r.linkName)
		}
	}
	r.mutex.Unlock()

	reloadCh := make(chan struct{})

	klog.InfoS("NDP responder started", "interface", transportInterface.Name, "index", transportInterface.Index)
	defer klog.InfoS("NDP responder stopped", "interface", transportInterface.Name, "index", transportInterface.Index)

	go func() {
		defer conn.Close()
		defer close(reloadCh)

		for {
			select {
			case <-stopCh:
				return
			case <-r.linkEventCh:
				newTransportInterface, err := net.InterfaceByName(r.linkName)
				if err != nil {
					klog.ErrorS(err, "Failed to get interface by name", "name", r.linkName)
					continue
				}
				if transportInterface.Index != newTransportInterface.Index {
					klog.InfoS("Transport interface index changed, restarting NDP responder", "name", transportInterface.Name, "oldIndex", transportInterface.Index, "newIndex", newTransportInterface.Index)
					return
				}
				klog.V(4).InfoS("Transport interface not changed")
			}
		}
	}()

	for {
		select {
		case <-reloadCh:
			return
		default:
			err := r.handleNeighborSolicitation(conn, transportInterface)
			if err != nil {
				klog.ErrorS(err, "Failed to handle Neighbor Solicitation", "deviceName", r.linkName)
			}
		}
	}
}

func (r *ndpResponder) AddIP(ip net.IP) error {
	if !utilnet.IsIPv6(ip) {
		return fmt.Errorf("only IPv6 is supported")
	}

	target, _ := netip.AddrFromSlice(ip)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.assignedIPs.Has(target) {
		return nil
	}
	if err := r.joinMulticastGroup(target); err != nil {
		return err
	}
	r.assignedIPs.Insert(target)

	return nil
}

func (r *ndpResponder) joinMulticastGroup(ip netip.Addr) error {
	if r.conn == nil {
		klog.InfoS("NDP responder is not initialized")
		return nil
	}
	group := parseIPv6SolicitedNodeMulticastAddress(ip)
	if r.multicastGroups[group] > 0 {
		r.multicastGroups[group]++
		return nil
	}
	if err := r.conn.JoinGroup(group); err != nil {
		return fmt.Errorf("joining multicast group %s failed: %v", group, err)
	}
	klog.InfoS("Joined multicast group", "group", group, "interface", r.linkName)
	r.multicastGroups[group]++
	return nil
}

func (r *ndpResponder) leaveMulticastGroup(ip netip.Addr) error {
	if r.conn == nil {
		klog.InfoS("NDP responder is not initialized")
		return nil
	}
	group := parseIPv6SolicitedNodeMulticastAddress(ip)
	if r.multicastGroups[group] > 1 {
		r.multicastGroups[group]--
		return nil
	}
	if err := r.conn.LeaveGroup(group); err != nil {
		return fmt.Errorf("leaving multicast group %s failed: %v", group, err)
	}
	klog.InfoS("Left multicast group", "group", group, "interface", r.linkName)
	delete(r.multicastGroups, group)
	return nil
}

func (r *ndpResponder) RemoveIP(ip net.IP) error {
	if !utilnet.IsIPv6(ip) {
		return fmt.Errorf("only IPv6 is supported")
	}
	target, _ := netip.AddrFromSlice(ip)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.assignedIPs.Has(target) {
		return nil
	}
	if err := r.leaveMulticastGroup(target); err != nil {
		return err
	}
	r.assignedIPs.Delete(target)

	klog.InfoS("Removed IP from NDP responder", "ip", ip, "interface", r.linkName)
	return nil
}

func (r *ndpResponder) isIPAssigned(ip netip.Addr) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.assignedIPs.Has(ip)
}

func (r *ndpResponder) onLinkUpdate(linkName string) {
	klog.V(4).InfoS("Received link update event", "name", linkName)
	select {
	// if an event is already present in the channel, we can drop this new one as we only monitor one link
	case r.linkEventCh <- struct{}{}:
	default:
	}
}
