// Copyright 2023 Antrea Authors
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

package servicecidr

import (
	"fmt"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/util"
)

const (
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

type EventHandler func(serviceCIDRs []*net.IPNet)

type Interface interface {
	GetServiceCIDR(isIPv6 bool) (*net.IPNet, error)
	// The added handlers will be called when Service CIDR changes.
	AddEventHandler(handler EventHandler)
}

type discoverer struct {
	serviceInformer cache.SharedIndexInformer
	sync.RWMutex
	serviceIPv4CIDR *net.IPNet
	serviceIPv6CIDR *net.IPNet
	eventHandlers   []EventHandler
}

func NewServiceCIDRDiscoverer(serviceInformer coreinformers.ServiceInformer) Interface {
	d := &discoverer{
		serviceInformer: serviceInformer.Informer(),
	}
	d.serviceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.addService,
			UpdateFunc: d.updateService,
		},
		resyncPeriod,
	)
	return d
}

func (d *discoverer) GetServiceCIDR(isIPv6 bool) (*net.IPNet, error) {
	d.RLock()
	defer d.RUnlock()
	if isIPv6 {
		if d.serviceIPv6CIDR == nil {
			return nil, fmt.Errorf("Service IPv6 CIDR is not available yet")
		}
		return d.serviceIPv6CIDR, nil
	}
	if d.serviceIPv4CIDR == nil {
		return nil, fmt.Errorf("Service IPv4 CIDR is not available yet")
	}
	return d.serviceIPv4CIDR, nil
}

func (d *discoverer) AddEventHandler(handler EventHandler) {
	d.eventHandlers = append(d.eventHandlers, handler)
}

func (d *discoverer) addService(obj interface{}) {
	svc := obj.(*corev1.Service)
	d.updateServiceCIDR(svc)
}

func (d *discoverer) updateService(_, obj interface{}) {
	svc := obj.(*corev1.Service)
	d.updateServiceCIDR(svc)
}

func (d *discoverer) updateServiceCIDR(svc *corev1.Service) {
	clusterIPs := svc.Spec.ClusterIPs
	if len(clusterIPs) == 0 {
		return
	}

	var newServiceCIDRs []*net.IPNet
	klog.V(2).InfoS("Processing Service ADD or UPDATE event", "Service", klog.KObj(svc))
	func() {
		d.Lock()
		defer d.Unlock()
		for _, clusterIPStr := range clusterIPs {
			clusterIP := net.ParseIP(clusterIPStr)
			isIPv6 := utilnet.IsIPv6(clusterIP)

			curServiceCIDR := d.serviceIPv4CIDR
			mask := net.IPv4len * 8
			if isIPv6 {
				curServiceCIDR = d.serviceIPv6CIDR
				mask = net.IPv6len * 8
			}

			if curServiceCIDR != nil && curServiceCIDR.Contains(clusterIP) {
				continue
			}

			var newServiceCIDR *net.IPNet
			var err error
			if curServiceCIDR != nil {
				// If the calculated Service CIDR exists but doesn't contain the ClusterIP, calculate a new Service CIDR by
				// enlarging the current Service CIDR with the ClusterIP.
				if newServiceCIDR, err = util.ExtendCIDRWithIP(curServiceCIDR, clusterIP); err != nil {
					klog.ErrorS(err, "Error when enlarging the Service CIDR", "ServiceCIDR", curServiceCIDR, "ClusterIP", clusterIPStr)
					continue
				}
			} else {
				// If the calculated Service CIDR doesn't exist, generate a new Service CIDR with the ClusterIP.
				newServiceCIDR = &net.IPNet{IP: clusterIP, Mask: net.CIDRMask(mask, mask)}
			}

			if isIPv6 {
				d.serviceIPv6CIDR = newServiceCIDR
				klog.V(4).InfoS("Service IPv6 CIDR was updated", "ServiceCIDR", newServiceCIDR)
			} else {
				d.serviceIPv4CIDR = newServiceCIDR
				klog.V(4).InfoS("Service IPv4 CIDR was updated", "ServiceCIDR", newServiceCIDR)
			}
			newServiceCIDRs = append(newServiceCIDRs, newServiceCIDR)
		}
	}()

	for _, handler := range d.eventHandlers {
		handler(newServiceCIDRs)
	}
}
