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
	"time"

	"github.com/mdlayher/arp"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

type arpResponder struct {
	once        sync.Once
	linkName    string
	assignedIPs sets.Set[string]
	mutex       sync.Mutex
	linkEventCh chan struct{}
}

var _ Responder = (*arpResponder)(nil)

func (r *arpResponder) InterfaceName() string {
	return r.linkName
}

func (r *arpResponder) AddIP(ip net.IP) error {
	if !utilnet.IsIPv4(ip) {
		return fmt.Errorf("only IPv4 is supported")
	}
	if r.addIP(ip) {
		klog.InfoS("Assigned IP to ARP responder", "ip", ip, "interface", r.linkName)
	}
	return nil
}

func (r *arpResponder) RemoveIP(ip net.IP) error {
	if !utilnet.IsIPv4(ip) {
		return fmt.Errorf("only IPv4 is supported")
	}
	if r.deleteIP(ip) {
		klog.InfoS("Removed IP from ARP responder", "ip", ip, "interface", r.linkName)
	}
	return nil
}

func (r *arpResponder) handleARPRequest(client *arp.Client, iface *net.Interface) error {
	pkt, _, err := client.Read()
	if err != nil {
		return err
	}
	if pkt.Operation != arp.OperationRequest {
		return nil
	}
	if !r.isIPAssigned(pkt.TargetIP) {
		klog.V(4).InfoS("Ignored ARP request", "ip", pkt.TargetIP, "interface", r.linkName)
		return nil
	}
	if err := client.Reply(pkt, iface.HardwareAddr, pkt.TargetIP); err != nil {
		return fmt.Errorf("failed to reply ARP packet for IP %s: %v", pkt.TargetIP, err)
	}
	klog.V(4).InfoS("Sent ARP response", "ip", pkt.TargetIP, "interface", r.linkName)
	return nil
}

func (r *arpResponder) Run(stopCh <-chan struct{}) {
	// The responder instance is created by the factory and can be shared by multiple callers.
	// Using once.Do here ensures it is started only once.
	r.once.Do(func() {
		go wait.NonSlidingUntil(func() {
			r.dialAndHandleRequests(stopCh)
		}, time.Second, stopCh)
	})
	<-stopCh
}

func (r *arpResponder) dialAndHandleRequests(stopCh <-chan struct{}) {
	transportInterface, err := net.InterfaceByName(r.linkName)
	if err != nil {
		klog.ErrorS(err, "Failed to get interface by name", "deviceName", r.linkName)
		return
	}
	client, err := arp.Dial(transportInterface)
	if err != nil {
		klog.ErrorS(err, "Failed to dial ARP client", "deviceName", r.linkName)
		return
	}
	reloadCh := make(chan struct{})

	klog.InfoS("ARP responder started", "interface", transportInterface.Name, "index", transportInterface.Index)
	defer klog.InfoS("ARP responder stopped", "interface", transportInterface.Name, "index", transportInterface.Index)

	go func() {
		defer client.Close()
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
					klog.InfoS("Transport interface index changed, restarting ARP responder", "name", transportInterface.Name, "oldIndex", transportInterface.Index, "newIndex", newTransportInterface.Index)
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
			err := r.handleARPRequest(client, transportInterface)
			if err != nil {
				klog.ErrorS(err, "Failed to handle ARP request", "deviceName", r.linkName)
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

func (r *arpResponder) onLinkUpdate(linkName string) {
	klog.V(4).InfoS("Received link update event", "name", linkName)
	select {
	// if an event is already present in the channel, we can drop this new one as we only monitor one link
	case r.linkEventCh <- struct{}{}:
	default:
	}
}
