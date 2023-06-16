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

	"github.com/mdlayher/arp"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

type arpResponder struct {
	iface       *net.Interface
	conn        *arp.Client
	assignedIPs sets.Set[string]
	mutex       sync.Mutex
}

var _ Responder = (*arpResponder)(nil)

func NewARPResponder(iface *net.Interface) (*arpResponder, error) {
	conn, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("creating ARP responder for %q: %s", iface.Name, err)
	}
	return &arpResponder{
		iface:       iface,
		conn:        conn,
		assignedIPs: sets.New[string](),
	}, nil
}

func (r *arpResponder) InterfaceName() string {
	return r.iface.Name
}

func (r *arpResponder) AddIP(ip net.IP) error {
	if !utilnet.IsIPv4(ip) {
		return fmt.Errorf("only IPv4 is supported")
	}
	if r.addIP(ip) {
		klog.InfoS("Assigned IP to ARP responder", "ip", ip, "interface", r.iface.Name)
	}
	return nil
}

func (r *arpResponder) RemoveIP(ip net.IP) error {
	if !utilnet.IsIPv4(ip) {
		return fmt.Errorf("only IPv4 is supported")
	}
	if r.deleteIP(ip) {
		klog.InfoS("Removed IP from ARP responder", "ip", ip, "interface", r.iface.Name)
	}
	return nil
}

func (r *arpResponder) handleARPRequest() error {
	pkt, _, err := r.conn.Read()
	if err != nil {
		return err
	}
	if pkt.Operation != arp.OperationRequest {
		return nil
	}
	if !r.isIPAssigned(pkt.TargetIP) {
		klog.V(4).InfoS("Ignored ARP request", "ip", pkt.TargetIP, "interface", r.iface.Name)
		return nil
	}
	if err := r.conn.Reply(pkt, r.iface.HardwareAddr, pkt.TargetIP); err != nil {
		return fmt.Errorf("failed to reply ARP packet for IP %s: %v", pkt.TargetIP, err)
	}
	klog.V(4).InfoS("Sent ARP response", "ip", pkt.TargetIP, "interface", r.iface.Name)
	return nil
}

func (r *arpResponder) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			r.conn.Close()
			return
		default:
			err := r.handleARPRequest()
			if err != nil {
				klog.ErrorS(err, "Failed to handle ARP request", "deviceName", r.iface.Name)
			}
		}
	}
}

func (r *arpResponder) isIPAssigned(ip net.IP) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.assignedIPs.Has(ip.String())
}

func (r *arpResponder) deleteIP(ip net.IP) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	exist := r.assignedIPs.Has(ip.String())
	if exist {
		r.assignedIPs.Delete(ip.String())
	}
	return exist
}

func (r *arpResponder) addIP(ip net.IP) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	exist := r.assignedIPs.Has(ip.String())
	if !exist {
		r.assignedIPs.Insert(ip.String())
	}
	return !exist
}
