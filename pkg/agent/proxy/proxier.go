// Copyright 2020 Antrea Authors
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

package proxy

import (
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
	"github.com/vmware-tanzu/antrea/third_party/proxy/config"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
)

// TODO: Add metrics
type proxier struct {
	once                sync.Once
	endpointSliceConfig *config.EndpointSliceConfig
	endpointsConfig     *config.EndpointsConfig
	serviceConfig       *config.ServiceConfig
	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since last syncProxyRules call. For a single object,
	// changes are accumulated. Once both endpointsChanges and serviceChanges
	// have been synced, syncProxyRules will start syncing rules to OVS.
	endpointsChanges *endpointsChangesTracker
	serviceChanges   *serviceChangesTracker
	// serviceMap stores services we expect to be installed.
	serviceMap k8sproxy.ServiceMap
	// serviceInstalledMap stores services we actually installed.
	serviceInstalledMap k8sproxy.ServiceMap
	// endpointsMap stores endpoints we expect to be installed.
	endpointsMap types.EndpointsMap
	// endpointInstalledMap stores endpoints we actually installed.
	endpointInstalledMap map[k8sproxy.ServicePortName]map[string]struct{}
	groupCounter         types.GroupCounter
	// serviceStringMap provides map from serviceString(ClusterIP:Port/Proto) to ServicePortName.
	serviceStringMap map[string]k8sproxy.ServicePortName
	// serviceStringMapMutex protects serviceStringMap object.
	serviceStringMapMutex sync.Mutex

	runner              *k8sproxy.BoundedFrequencyRunner
	stopChan            <-chan struct{}
	agentQuerier        querier.AgentQuerier
	ofClient            openflow.Client
	isIPv6              bool
	enableEndpointSlice bool
}

func (p *proxier) isInitialized() bool {
	return p.endpointsChanges.Synced() && p.serviceChanges.Synced()
}

func (p *proxier) removeStaleServices() {
	for svcPortName, svcPort := range p.serviceInstalledMap {
		if _, ok := p.serviceMap[svcPortName]; ok {
			continue
		}
		svcInfo := svcPort.(*types.ServiceInfo)
		if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		for _, ingress := range svcInfo.LoadBalancerIPStrings() {
			if ingress != "" {
				if err := p.uninstallLoadBalancerServiceFlows(net.ParseIP(ingress), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
					klog.Errorf("Error when removing Service flows: %v", err)
					continue
				}
			}
		}
		groupID, _ := p.groupCounter.Get(svcPortName)
		if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		for _, endpoint := range p.endpointsMap[svcPortName] {
			if err := p.ofClient.UninstallEndpointFlows(svcInfo.OFProtocol, endpoint); err != nil {
				klog.Errorf("Failed to remove flows of Service Endpoints %v: %v", svcPortName, err)
				continue
			}
		}
		delete(p.serviceInstalledMap, svcPortName)
		delete(p.endpointInstalledMap, svcPortName)
		p.deleteServiceByIP(svcInfo.String())
		p.groupCounter.Recycle(svcPortName)
	}
}

func getBindingProtoForIPProto(endpointIP string, protocol corev1.Protocol) binding.Protocol {
	var bindingProtocol binding.Protocol
	if utilnet.IsIPv6String(endpointIP) {
		bindingProtocol = binding.ProtocolTCPv6
		if protocol == corev1.ProtocolUDP {
			bindingProtocol = binding.ProtocolUDPv6
		} else if protocol == corev1.ProtocolSCTP {
			bindingProtocol = binding.ProtocolSCTPv6
		}
	} else {
		bindingProtocol = binding.ProtocolTCP
		if protocol == corev1.ProtocolUDP {
			bindingProtocol = binding.ProtocolUDP
		} else if protocol == corev1.ProtocolSCTP {
			bindingProtocol = binding.ProtocolSCTP
		}
	}
	return bindingProtocol
}

func (p *proxier) removeStaleEndpoints(staleEndpoints map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint) {
	for svcPortName, endpoints := range staleEndpoints {
		for _, endpoint := range endpoints {
			bindingProtocol := getBindingProtoForIPProto(endpoint.IP(), svcPortName.Protocol)
			if err := p.ofClient.UninstallEndpointFlows(bindingProtocol, endpoint); err != nil {
				klog.Errorf("Error when removing Endpoint %v for %v", endpoint, svcPortName)
				continue
			}
			if m, ok := p.endpointInstalledMap[svcPortName]; ok {
				delete(m, endpoint.String())
				if len(m) == 0 {
					delete(p.endpointInstalledMap, svcPortName)
				}
			}
		}
	}
}

func serviceIdentityChanged(svcInfo, pSvcInfo *types.ServiceInfo) bool {
	return svcInfo.ClusterIP().String() != pSvcInfo.ClusterIP().String() ||
		svcInfo.Port() != pSvcInfo.Port() ||
		svcInfo.OFProtocol != pSvcInfo.OFProtocol
}

// smallSliceDifference builds a slice which includes all the strings from s1
// which are not in s2.
func smallSliceDifference(s1, s2 []string) []string {
	var diff []string

	for _, e1 := range s1 {
		found := false
		for _, e2 := range s2 {
			if e1 == e2 {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, e1)
		}
	}

	return diff
}

// calculateServiceEndpointUpdateList calculates the Endpoints of the Service to be installed.
// If Endpoints of the Service have changed, all current Endpoints of the Service will be returned. Otherwise, it will
// return nil.
func (p *proxier) calculateServiceEndpointUpdateList(svcPortName k8sproxy.ServicePortName) ([]k8sproxy.Endpoint, bool) {
	if _, ok := p.serviceMap[svcPortName]; !ok { // The Service is not expected to be installed.
		return nil, false
	}
	var needUpdate bool
	endpointsExpected, ok := p.endpointsMap[svcPortName]
	if !ok || len(endpointsExpected) == 0 { // No endpoint for this Service.
		return nil, false
	}
	endpointInstalled, ok := p.endpointInstalledMap[svcPortName]
	if !ok {
		p.endpointInstalledMap[svcPortName] = map[string]struct{}{}
		endpointInstalled = p.endpointInstalledMap[svcPortName]
	}
	var endpointUpdateList []k8sproxy.Endpoint
	for _, endpoint := range endpointsExpected {
		_, installed := endpointInstalled[endpoint.String()]
		if !installed {
			needUpdate = true
		}
		endpointUpdateList = append(endpointUpdateList, endpoint)
	}
	if !needUpdate {
		endpointUpdateList = nil
	}
	return endpointUpdateList, needUpdate
}

func (p *proxier) installEndpoints(endpoints []k8sproxy.Endpoint, svcPortName k8sproxy.ServicePortName, svcInfo *types.ServiceInfo) error {
	groupID, _ := p.groupCounter.Get(svcPortName)
	if err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpoints, true); err != nil {
		return err
	}
	err := p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpoints)
	if err != nil {
		return err
	}
	return nil
}

func (p *proxier) installServices() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		groupID, _ := p.groupCounter.Get(svcPortName)
		endpoints, ok := p.endpointsMap[svcPortName]
		if !ok || len(endpoints) == 0 {
			continue
		}

		endpointInstalled, ok := p.endpointInstalledMap[svcPortName]
		if !ok {
			p.endpointInstalledMap[svcPortName] = map[string]struct{}{}
			endpointInstalled = p.endpointInstalledMap[svcPortName]
		}

		installedSvcPort, ok := p.serviceInstalledMap[svcPortName]
		var pSvcInfo *types.ServiceInfo
		needRemoval := false
		needUpdate := true
		if ok {
			pSvcInfo = installedSvcPort.(*types.ServiceInfo)
			needRemoval = serviceIdentityChanged(svcInfo, pSvcInfo) || (svcInfo.SessionAffinityType() != pSvcInfo.SessionAffinityType())
			needUpdate = needRemoval || (svcInfo.StickyMaxAgeSeconds() != pSvcInfo.StickyMaxAgeSeconds())
		}

		var endpointUpdateList []k8sproxy.Endpoint
		for _, endpoint := range endpoints {
			if _, ok := endpointInstalled[endpoint.String()]; !ok {
				needUpdate = true
				endpointInstalled[endpoint.String()] = struct{}{}
			}
			endpointUpdateList = append(endpointUpdateList, endpoint)
		}

		var deletedLoadBalancerIPs, addedLoadBalancerIPs []string
		if pSvcInfo != nil {
			deletedLoadBalancerIPs = smallSliceDifference(pSvcInfo.LoadBalancerIPStrings(), svcInfo.LoadBalancerIPStrings())
			addedLoadBalancerIPs = smallSliceDifference(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings())
		} else {
			deletedLoadBalancerIPs = []string{}
			addedLoadBalancerIPs = svcInfo.LoadBalancerIPStrings()
		}
		if len(deletedLoadBalancerIPs) > 0 || len(addedLoadBalancerIPs) > 0 {
			needUpdate = true
		}

		if !needUpdate {
			continue
		}

		if err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpointUpdateList, p.isIPv6); err != nil {
			klog.Errorf("Error when installing Endpoints flows: %v", err)
			continue
		}
		err := p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpointUpdateList)
		if err != nil {
			klog.Errorf("Error when installing Endpoints groups: %v", err)
			p.endpointInstalledMap[svcPortName] = nil
			continue
		}
		// Delete previous flow.
		if needRemoval {
			if err := p.ofClient.UninstallServiceFlows(pSvcInfo.ClusterIP(), uint16(pSvcInfo.Port()), pSvcInfo.OFProtocol); err != nil {
				klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			}
		}
		if err := p.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds())); err != nil {
			klog.Errorf("Error when installing Service flows: %v", err)
			continue
		}
		// Install OpenFlow entries for the ingress IPs of LoadBalancer Service.
		// The LoadBalancer Service should be accessible from Pod, Node and
		// external host.
		var toDelete, toAdd []string
		if needRemoval {
			toDelete = pSvcInfo.LoadBalancerIPStrings()
			toAdd = svcInfo.LoadBalancerIPStrings()
		} else {
			toDelete = deletedLoadBalancerIPs
			toAdd = addedLoadBalancerIPs
		}
		for _, ingress := range toDelete {
			if ingress != "" {
				// It is safe to access pSvcInfo here. If this is a new Service,
				// then toDelete will be an empty slice.
				if err := p.uninstallLoadBalancerServiceFlows(net.ParseIP(ingress), uint16(pSvcInfo.Port()), pSvcInfo.OFProtocol); err != nil {
					klog.Errorf("Error when removing LoadBalancer Service flows: %v", err)
					continue
				}
			}
		}
		for _, ingress := range toAdd {
			if ingress != "" {
				if err := p.installLoadBalancerServiceFlows(groupID, net.ParseIP(ingress), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds())); err != nil {
					klog.Errorf("Error when installing LoadBalancer Service flows: %v", err)
					continue
				}
			}
		}

		p.serviceInstalledMap[svcPortName] = svcPort
		for _, endpoint := range endpointUpdateList {
			p.endpointInstalledMap[svcPortName][endpoint.String()] = struct{}{}
		}
		p.addServiceByIP(svcInfo.String(), svcPortName)
	}
}

// syncProxyRules applies current changes in change trackers and then updates
// flows for services and endpoints. It will abort if either endpoints or services
// resources is not synced. syncProxyRules is only called through the Run method
// of the runner object, and all calls are serialized. Since this method is the
// only one accessing internal state (e.g. serviceMap), no synchronization
// mechanism, such as a mutex, is required.
func (p *proxier) syncProxyRules() {
	start := time.Now()
	defer func() {
		klog.V(4).Infof("syncProxyRules took %v", time.Since(start))
	}()
	if !p.isInitialized() {
		klog.V(4).Info("Not syncing rules until both Services and Endpoints have been synced")
		return
	}

	staleEndpoints := p.endpointsChanges.Update(p.endpointsMap)
	p.serviceChanges.Update(p.serviceMap)

	p.removeStaleServices()
	p.installServices()
	p.removeStaleEndpoints(staleEndpoints)
}

func (p *proxier) SyncLoop() {
	p.runner.Loop(p.stopChan)
}

func (p *proxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	p.OnEndpointsUpdate(nil, endpoints)
}

func (p *proxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	if p.endpointsChanges.OnEndpointUpdate(oldEndpoints, endpoints) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	p.OnEndpointsUpdate(endpoints, nil)
}

func (p *proxier) OnEndpointsSynced() {
	p.endpointsChanges.OnEndpointsSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceAdd(endpointSlice *v1beta1.EndpointSlice) {
	if p.endpointsChanges.OnEndpointSliceUpdate(endpointSlice, false) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *v1beta1.EndpointSlice) {
	if p.endpointsChanges.OnEndpointSliceUpdate(newEndpointSlice, false) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceDelete(endpointSlice *v1beta1.EndpointSlice) {
	if p.endpointsChanges.OnEndpointSliceUpdate(endpointSlice, true) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSlicesSynced() {
	p.endpointsChanges.OnEndpointsSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnServiceAdd(service *corev1.Service) {
	p.OnServiceUpdate(nil, service)
}

func (p *proxier) OnServiceUpdate(oldService, service *corev1.Service) {
	var isIPv6 bool
	if oldService != nil {
		isIPv6 = utilnet.IsIPv6String(oldService.Spec.ClusterIP)
	} else {
		isIPv6 = utilnet.IsIPv6String(service.Spec.ClusterIP)
	}
	if isIPv6 == p.isIPv6 {
		if p.serviceChanges.OnServiceUpdate(oldService, service) && p.isInitialized() {
			p.runner.Run()
		}
	}
}

func (p *proxier) OnServiceDelete(service *corev1.Service) {
	p.OnServiceUpdate(service, nil)
}

func (p *proxier) OnServiceSynced() {
	p.serviceChanges.OnServiceSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool) {
	p.serviceStringMapMutex.Lock()
	defer p.serviceStringMapMutex.Unlock()

	serviceInfo, exists := p.serviceStringMap[serviceStr]
	return serviceInfo, exists
}

func (p *proxier) addServiceByIP(serviceStr string, servicePortName k8sproxy.ServicePortName) {
	p.serviceStringMapMutex.Lock()
	defer p.serviceStringMapMutex.Unlock()

	p.serviceStringMap[serviceStr] = servicePortName
}

func (p *proxier) deleteServiceByIP(serviceStr string) {
	p.serviceStringMapMutex.Lock()
	defer p.serviceStringMapMutex.Unlock()

	delete(p.serviceStringMap, serviceStr)
}

func (p *proxier) Run(stopCh <-chan struct{}) {
	p.once.Do(func() {
		go p.serviceConfig.Run(stopCh)
		if p.enableEndpointSlice {
			go p.endpointSliceConfig.Run(stopCh)
		} else {
			go p.endpointsConfig.Run(stopCh)
		}
		p.stopChan = stopCh
		p.SyncLoop()
	})
}

func NewProxier(
	hostname string,
	informerFactory informers.SharedInformerFactory,
	ofClient openflow.Client,
	enableEndpointSlice bool,
	isIPv6 bool) *proxier {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)

	klog.Infof("Creating proxier with IPv6 enabled=%t", isIPv6)
	p := &proxier{
		enableEndpointSlice:  enableEndpointSlice,
		serviceConfig:        config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		serviceChanges:       newServiceChangesTracker(recorder, isIPv6),
		endpointsChanges:     newEndpointsChangesTracker(hostname, enableEndpointSlice),
		serviceMap:           k8sproxy.ServiceMap{},
		serviceInstalledMap:  k8sproxy.ServiceMap{},
		endpointInstalledMap: map[k8sproxy.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		serviceStringMap:     map[string]k8sproxy.ServicePortName{},
		groupCounter:         types.NewGroupCounter(),
		ofClient:             ofClient,
		isIPv6:               isIPv6,
	}
	p.serviceConfig.RegisterEventHandler(p)
	if enableEndpointSlice {
		p.endpointSliceConfig = config.NewEndpointSliceConfig(informerFactory.Discovery().V1beta1().EndpointSlices(), resyncPeriod)
		p.endpointSliceConfig.RegisterEventHandler(p)
	} else {
		p.endpointsConfig = config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod)
		p.endpointsConfig.RegisterEventHandler(p)
	}
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, 0, 30*time.Second, -1)
	return p
}

func NewDualStackProxier(
	hostname string, informerFactory informers.SharedInformerFactory, ofClient openflow.Client) k8sproxy.Provider {

	// Create an ipv4 instance of the single-stack proxier
	ipv4Proxier := NewProxier(hostname, informerFactory, ofClient, true, false)

	// Create an ipv6 instance of the single-stack proxier
	ipv6Proxier := NewProxier(hostname, informerFactory, ofClient, true, true)

	// Return a meta-proxier that dispatch calls between the two
	// single-stack proxier instances
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)
	return metaProxier
}
