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
	"strconv"
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
	ifaceName       string
	conn            ndpConn
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
	return r.ifaceName
}

func (r *ndpResponder) handleNeighborSolicitation(conn ndpConn, intf *net.Interface) error {
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
		klog.V(4).InfoS("Ignored Neighbor Solicitation", "ip", ns.TargetAddress, "interface", r.ifaceName)
		return nil
	}
	na := &ndp.NeighborAdvertisement{
		Solicited:     true,
		Override:      true,
		TargetAddress: ns.TargetAddress,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      intf.HardwareAddr,
			},
		},
	}
	if err := conn.WriteTo(na, nil, srcIP); err != nil {
		return err
	}
	klog.V(4).InfoS("Sent Neighbor Advertisement", "ip", ns.TargetAddress.String(), "interface", r.ifaceName)
	return nil
}

func (r *ndpResponder) Run(stopCh <-chan struct{}) {
	r.once.Do(func() {
		wait.NonSlidingUntil(func() {
			r.dialAndHandleRequests(stopCh)
		}, time.Second, stopCh)
	})
	<-stopCh
}

func (r *ndpResponder) dialAndHandleRequests(endCh <-chan struct{}) {
	intf, err := net.InterfaceByName(r.ifaceName)
	if err != nil {
		klog.ErrorS(err, "Failed to get interface", "interface", r.ifaceName)
		return
	}
	addrs, err := intf.Addrs()
	if err != nil {
		klog.ErrorS(err, "Failed to get addresses for interface", "interface", r.ifaceName)
		return
	}
	var ip netip.Addr
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if utilnet.IsIPv6(ipnet.IP) && ipnet.IP.IsLinkLocalUnicast() {
				ip, _ = netip.AddrFromSlice(ipnet.IP)
				break
			}
		}
	}
	if ip.IsUnspecified() {
		klog.InfoS("Interface does not have a link-local IPv6 address yet", "interface", r.ifaceName)
		return
	}
	// Specify the zone index to bind to the correct interface.
	// The zone index is cached https://github.com/golang/go/blob/go1.23.1/src/net/interface.go#L192
	// and may result in binding on the wrong interface if using the interface name as zone in secondary network use cases.
	bindAddr := ip.WithZone(strconv.Itoa(intf.Index))

	// It may take time for the interface to be ready for socket binding. For example, IPv6 introduces Duplicate Address Detection,
	// which may take time to allow the address to be used for socket binding. EADDRNOTAVAIL (bind: cannot assign requested address)
	// may be returned for such cases.
	klog.InfoS("Binding NDP responder on address", "address", bindAddr.String(), "interface", r.ifaceName)
	conn, _, err := ndp.Listen(intf, ndp.Addr(bindAddr.String()))
	if err != nil {
		klog.ErrorS(err, "Failed to create NDP responder", "interface", r.ifaceName)
		return
	}

	r.mutex.Lock()
	r.conn = conn
	for ip := range r.assignedIPs {
		if err := r.joinMulticastGroup(ip); err != nil {
			klog.ErrorS(err, "Failed to join multicast group", "ip", ip, "interface", r.ifaceName)
		}
	}
	r.mutex.Unlock()

	klog.InfoS("NDP responder started", "interface", intf.Name, "index", intf.Index)
	for {
		select {
		case <-endCh:
			conn.Close()
			return
		default:
			err := r.handleNeighborSolicitation(conn, intf)
			if err != nil {
				klog.ErrorS(err, "Failed to handle Neighbor Solicitation", "deviceName", r.ifaceName)
			}
		}
	}
}

func (r *ndpResponder) AddIP(ip net.IP) error {
	if !utilnet.IsIPv6(ip) {
		return fmt.Errorf("only IPv6 is supported")
	}

	target, _ := netip.AddrFromSlice(ip)
	if r.isIPAssigned(target) {
		return nil
	}

	r.mutex.Lock()
	if err := r.joinMulticastGroup(target); err != nil {
		return err
	}
	r.assignedIPs.Insert(target)
	r.mutex.Unlock()

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
	klog.InfoS("Joined multicast group", "group", group, "interface", r.ifaceName)
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
	klog.InfoS("Left multicast group", "group", group, "interface", r.ifaceName)
	delete(r.multicastGroups, group)
	return nil
}

func (r *ndpResponder) RemoveIP(ip net.IP) error {
	if !utilnet.IsIPv6(ip) {
		return fmt.Errorf("only IPv6 is supported")
	}
	target, _ := netip.AddrFromSlice(ip)
	if !r.isIPAssigned(target) {
		return nil
	}

	r.mutex.Lock()
	if err := r.leaveMulticastGroup(target); err != nil {
		return err
	}
	r.assignedIPs.Delete(target)
	r.mutex.Unlock()

	klog.InfoS("Removed IP from NDP responder", "ip", ip, "interface", r.ifaceName)
	return nil
}

func (r *ndpResponder) isIPAssigned(ip netip.Addr) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.assignedIPs.Has(ip)
}
