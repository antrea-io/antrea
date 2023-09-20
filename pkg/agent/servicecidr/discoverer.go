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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/strings/slices"

	"antrea.io/antrea/pkg/agent/util"
)

const (
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

type EventHandler func(serviceCIDRs []*net.IPNet)

type Interface interface {
	GetServiceCIDRs() ([]*net.IPNet, error)
	// The added handlers will be called when Service CIDR changes.
	AddEventHandler(handler EventHandler)
}

type Discoverer struct {
	serviceInformer cache.SharedIndexInformer
	serviceLister   corelisters.ServiceLister
	sync.RWMutex
	serviceIPv4CIDR *net.IPNet
	serviceIPv6CIDR *net.IPNet
	eventHandlers   []EventHandler
	// queue maintains the Service objects that need to be synced.
	queue workqueue.Interface
	// initialized indicates whether the Discoverer has been initialized.
	initialized bool
}

func NewServiceCIDRDiscoverer(serviceInformer coreinformers.ServiceInformer) *Discoverer {
	d := &Discoverer{
		serviceInformer: serviceInformer.Informer(),
		serviceLister:   serviceInformer.Lister(),
		queue:           workqueue.New(),
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

func (d *Discoverer) Run(stopCh <-chan struct{}) {
	defer d.queue.ShutDown()

	klog.Info("Starting ServiceCIDRDiscoverer")
	defer klog.Info("Stopping ServiceCIDRDiscoverer")
	if !cache.WaitForCacheSync(stopCh, d.serviceInformer.HasSynced) {
		return
	}
	svcs, _ := d.serviceLister.List(labels.Everything())
	d.updateServiceCIDR(svcs...)

	go func() {
		for {
			obj, quit := d.queue.Get()
			if quit {
				return
			}
			nn := obj.(types.NamespacedName)

			svc, _ := d.serviceLister.Services(nn.Namespace).Get(nn.Name)
			// Ignore it if not found.
			if svc != nil {
				d.updateServiceCIDR(svc)
			}
			d.queue.Done(obj)
		}
	}()
	<-stopCh
}

func (d *Discoverer) GetServiceCIDRs() ([]*net.IPNet, error) {
	d.RLock()
	defer d.RUnlock()
	if !d.initialized {
		return nil, fmt.Errorf("Service CIDR discoverer is not initialized yet")
	}
	var serviceCIDRs []*net.IPNet
	if d.serviceIPv4CIDR != nil {
		serviceCIDRs = append(serviceCIDRs, d.serviceIPv4CIDR)
	}
	if d.serviceIPv6CIDR != nil {
		serviceCIDRs = append(serviceCIDRs, d.serviceIPv6CIDR)
	}
	return serviceCIDRs, nil
}

func (d *Discoverer) AddEventHandler(handler EventHandler) {
	d.eventHandlers = append(d.eventHandlers, handler)
}

func (d *Discoverer) addService(obj interface{}) {
	svc := obj.(*corev1.Service)
	klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(svc))
	d.queue.Add(types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name})
}

func (d *Discoverer) updateService(old, obj interface{}) {
	oldSvc := old.(*corev1.Service)
	curSvc := obj.(*corev1.Service)
	klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(curSvc))
	if !slices.Equal(oldSvc.Spec.ClusterIPs, curSvc.Spec.ClusterIPs) {
		d.queue.Add(types.NamespacedName{Namespace: curSvc.Namespace, Name: curSvc.Name})
	}
}

func (d *Discoverer) updateServiceCIDR(svcs ...*corev1.Service) {
	var newServiceCIDRs []*net.IPNet

	curServiceIPv4CIDR, curServiceIPv6CIDR := func() (*net.IPNet, *net.IPNet) {
		d.RLock()
		defer d.RUnlock()
		return d.serviceIPv4CIDR, d.serviceIPv6CIDR
	}()

	updated := false
	for _, svc := range svcs {
		for _, clusterIPStr := range svc.Spec.ClusterIPs {
			clusterIP := net.ParseIP(clusterIPStr)
			if clusterIP == nil {
				klog.V(2).InfoS("Skip invalid ClusterIP", "ClusterIP", clusterIPStr)
				continue
			}
			isIPv6 := utilnet.IsIPv6(clusterIP)

			curServiceCIDR := curServiceIPv4CIDR
			mask := net.IPv4len * 8
			if isIPv6 {
				curServiceCIDR = curServiceIPv6CIDR
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
				mask := net.CIDRMask(mask, mask)
				clusterIP := clusterIP.Mask(mask)
				// If the calculated Service CIDR doesn't exist, generate a new Service CIDR with the ClusterIP.
				newServiceCIDR = &net.IPNet{IP: clusterIP, Mask: mask}
			}

			if isIPv6 {
				curServiceIPv6CIDR = newServiceCIDR
			} else {
				curServiceIPv4CIDR = newServiceCIDR
			}
			updated = true
		}
	}

	if !updated {
		return
	}
	func() {
		d.Lock()
		defer d.Unlock()
		if d.serviceIPv4CIDR != curServiceIPv4CIDR {
			d.serviceIPv4CIDR = curServiceIPv4CIDR
			klog.InfoS("Service IPv4 CIDR was updated", "ServiceCIDR", curServiceIPv4CIDR)
			newServiceCIDRs = append(newServiceCIDRs, curServiceIPv4CIDR)
		}
		if d.serviceIPv6CIDR != curServiceIPv6CIDR {
			d.serviceIPv6CIDR = curServiceIPv6CIDR
			klog.InfoS("Service IPv6 CIDR was updated", "ServiceCIDR", curServiceIPv6CIDR)
			newServiceCIDRs = append(newServiceCIDRs, curServiceIPv6CIDR)
		}
		d.initialized = true
	}()
	for _, handler := range d.eventHandlers {
		handler(newServiceCIDRs)
	}
}
