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
	"sync"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	solicitedNodeMulticastAddressPrefix = "ff02::1:ff00:0"
)

type ndpConn interface {
	WriteTo(message ndp.Message, cm *ipv6.ControlMessage, dstIP net.IP) error
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, net.IP, error)
	JoinGroup(net.IP) error
	LeaveGroup(net.IP) error
	Close() error
}

type ndpResponder struct {
	iface           *net.Interface
	conn            ndpConn
	assignedIPs     sets.String
	multicastGroups map[int]int
	mutex           sync.Mutex
}

var _ Responder = (*ndpResponder)(nil)

func parseIPv6SolicitedNodeMulticastAddress(ip net.IP) (net.IP, int) {
	group := net.ParseIP(solicitedNodeMulticastAddressPrefix)
	// copy lower 24 bits
	copy(group[13:], ip[13:])
	key := int(group[13])<<16 | int(group[14])<<8 | int(group[15])
	return group, key
}

func NewNDPResponder(iface *net.Interface) (*ndpResponder, error) {
	conn, _, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return nil, err
	}
	return &ndpResponder{
		iface:           iface,
		conn:            conn,
		multicastGroups: make(map[int]int),
		assignedIPs:     sets.NewString(),
	}, nil
}

func (r *ndpResponder) InterfaceName() string {
	return r.iface.Name
}

// advertise sends Neighbor Advertisement for the IP.
func (r *ndpResponder) advertise(ip net.IP) error {
	na := &ndp.NeighborAdvertisement{
		Override:      true,
		TargetAddress: ip,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      r.iface.HardwareAddr,
			},
		},
	}
	return r.conn.WriteTo(na, nil, net.IPv6linklocalallnodes)
}

func (r *ndpResponder) handleNeighborSolicitation() error {
	pkt, _, srcIP, err := r.conn.ReadFrom()
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
		klog.V(4).InfoS("Ignored Neighbor Solicitation", "ip", ns.TargetAddress.String(), "interface", r.iface.Name)
		return nil
	}
	na := &ndp.NeighborAdvertisement{
		Solicited:     true,
		Override:      true,
		TargetAddress: ns.TargetAddress,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      r.iface.HardwareAddr,
			},
		},
	}
	if err := r.conn.WriteTo(na, nil, srcIP); err != nil {
		return err
	}
	klog.V(4).InfoS("Sent Neighbor Advertisement", "ip", ns.TargetAddress.String(), "interface", r.iface.Name)
	return nil
}

func (r *ndpResponder) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			r.conn.Close()
			return
		default:
			err := r.handleNeighborSolicitation()
			if err != nil {
				klog.ErrorS(err, "Failed to handle Neighbor Solicitation", "deviceName", r.iface.Name)
			}
		}
	}
}

func (r *ndpResponder) AddIP(ip net.IP) error {
	if !utilnet.IsIPv6(ip) {
		return fmt.Errorf("only IPv6 is supported")
	}
	if r.isIPAssigned(ip) {
		return nil
	}
	group, key := parseIPv6SolicitedNodeMulticastAddress(ip)
	if err := func() error {
		r.mutex.Lock()
		defer r.mutex.Unlock()
		if r.multicastGroups[key] == 0 {
			if err := r.conn.JoinGroup(group); err != nil {
				return fmt.Errorf("joining solicited-node multicast group %s for %q failed: %v", group, ip, err)
			}
			klog.InfoS("Joined solicited-node multicast group", "group", group, "interface", r.iface.Name)
		}
		klog.InfoS("Assigned IP to NDP responder", "ip", ip, "interface", r.iface.Name)
		r.multicastGroups[key]++
		r.assignedIPs.Insert(ip.String())
		return nil
	}(); err != nil {
		return err
	}
	if err := r.advertise(ip); err != nil {
		klog.ErrorS(err, "Failed to advertise", "ip", ip, "interface", r.iface.Name)
	}
	return nil
}

func (r *ndpResponder) RemoveIP(ip net.IP) error {
	if !utilnet.IsIPv6(ip) {
		return fmt.Errorf("only IPv6 is supported")
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if !r.assignedIPs.Has(ip.String()) {
		return nil
	}
	group, key := parseIPv6SolicitedNodeMulticastAddress(ip)
	if r.multicastGroups[key] == 1 {
		if err := r.conn.LeaveGroup(group); err != nil {
			return fmt.Errorf("leaving solicited-node multicast group %s for %q failed: %v", group, ip, err)
		}
		klog.InfoS("Left solicited-node multicast group", "group", group, "interface", r.iface.Name)
		delete(r.multicastGroups, key)
	} else {
		r.multicastGroups[key]--
	}
	r.assignedIPs.Delete(ip.String())
	klog.InfoS("Removed IP from NDP responder", "ip", ip, "interface", r.iface.Name)
	return nil
}

func (r *ndpResponder) isIPAssigned(ip net.IP) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.assignedIPs.Has(ip.String())
}
