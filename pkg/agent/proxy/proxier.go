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
	"fmt"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/metrics"
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

type proxier struct {
	once            sync.Once
	endpointsConfig *config.EndpointsConfig
	serviceConfig   *config.ServiceConfig
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
	// endpointReferenceCounter stores the number of times an Endpoint is referenced by Services.
	endpointReferenceCounter map[string]uint
	// groupCounter is used to allocate groupID.
	groupCounter types.GroupCounter
	// serviceStringMap provides map from serviceString(ClusterIP:Port/Proto) to ServicePortName.
	serviceStringMap map[string]k8sproxy.ServicePortName
	// serviceStringMapMutex protects serviceStringMap object.
	serviceStringMapMutex sync.Mutex

	runner       *k8sproxy.BoundedFrequencyRunner
	stopChan     <-chan struct{}
	agentQuerier querier.AgentQuerier
	ofClient     openflow.Client
	isIPv6       bool
}

func endpointKey(endpoint k8sproxy.Endpoint, protocol binding.Protocol) string {
	return fmt.Sprintf("%s/%s", endpoint.String(), protocol)
}

func (p *proxier) isInitialized() bool {
	return p.endpointsChanges.Synced() && p.serviceChanges.Synced()
}

// removeStaleServices removes all expired Services. Once a Service was deleted, all
// its Endpoints will be expired, and removeStaleEndpoints take response for cleaning up,
// thus we don't need to do removeEndpoint in this function.
func (p *proxier) removeStaleServices() {
	for svcPortName, svcPort := range p.serviceInstalledMap {
		if _, ok := p.serviceMap[svcPortName]; ok {
			continue
		}
		svcInfo := svcPort.(*types.ServiceInfo)
		klog.V(2).Infof("Removing stale Service: %s %s", svcPortName.Name, svcInfo.String())
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
		// We don't need to uninstall Endpoint flows,
		delete(p.serviceInstalledMap, svcPortName)
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

// removeEndpoint removes flows for the given Endpoint from the data path if these flows are no longer
// needed by any Service. Endpoints from different Services can have the same characteristics and thus
// can share the same flows. removeEndpoint must be called whenever an Endpoint is no longer used by a
// given Service. If the Endpoint is still be referenced by any other Services, there will be no
// operation on the data path. The method only returns an error if a data path operation fails. If the
// flows are successfully removed from the data path, the method return true. Otherwise, if the flows
// are still needed for other Services, it returns false.
func (p *proxier) removeEndpoint(endpoint k8sproxy.Endpoint, protocol binding.Protocol) (bool, error) {
	key := endpointKey(endpoint, protocol)
	count := p.endpointReferenceCounter[key]
	if count == 1 {
		if err := p.ofClient.UninstallEndpointFlows(protocol, endpoint); err != nil {
			return false, err
		}
		delete(p.endpointReferenceCounter, key)
	} else if count > 1 {
		p.endpointReferenceCounter[key] = p.endpointReferenceCounter[key] - 1
		return false, nil
	}
	return true, nil
}

func (p *proxier) removeStaleEndpoints(staleEndpoints map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint) {
	for svcPortName, endpoints := range staleEndpoints {
		for _, endpoint := range endpoints {
			klog.V(2).Infof("Removing stale Endpoint %s of Service %s", endpoint.String(), svcPortName.String())
			removed, err := p.removeEndpoint(endpoint, getBindingProtoForIPProto(endpoint.IP(), svcPortName.Protocol))
			if err != nil {
				klog.Errorf("Error when removing Endpoint %v for %v", endpoint, svcPortName)
				continue
			}
			if removed {
				m := p.endpointInstalledMap[svcPortName]
				delete(m, endpoint.String())
				if len(m) == 0 {
					delete(p.endpointInstalledMap, svcPortName)
				}
				klog.V(2).Infof("Endpoint %s/%s removed", endpoint.String(), svcPortName.Protocol)
			} else {
				klog.V(2).Infof("Stale Endpoint %s/%s of Service %s is still referenced by other Services, removing 1 reference", endpoint.String(), svcPortName.Protocol, svcPortName)
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

func (p *proxier) installServices() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		groupID, _ := p.groupCounter.Get(svcPortName)
		endpointsInstalled, ok := p.endpointInstalledMap[svcPortName]
		if !ok {
			p.endpointInstalledMap[svcPortName] = map[string]struct{}{}
			endpointsInstalled = p.endpointInstalledMap[svcPortName]
		}
		endpoints := p.endpointsMap[svcPortName]
		// If both expected Endpoints number and installed Endpoints number are 0, we don't need to take care of this Service.
		if len(endpoints) == 0 && len(endpointsInstalled) == 0 {
			continue
		}

		installedSvcPort, ok := p.serviceInstalledMap[svcPortName]
		var pSvcInfo *types.ServiceInfo
		var needRemoval, needUpdateService, needUpdateEndpoints bool
		if ok { // Need to update.
			pSvcInfo = installedSvcPort.(*types.ServiceInfo)
			needRemoval = serviceIdentityChanged(svcInfo, pSvcInfo) || (svcInfo.SessionAffinityType() != pSvcInfo.SessionAffinityType())
			needUpdateService = needRemoval || (svcInfo.StickyMaxAgeSeconds() != pSvcInfo.StickyMaxAgeSeconds())
			needUpdateEndpoints = pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType()
		} else { // Need to install.
			needUpdateService = true
		}

		var endpointUpdateList []k8sproxy.Endpoint
		for _, endpoint := range endpoints { // Check if there is any installed Endpoint which is not expected anymore.
			if _, ok := endpointsInstalled[endpoint.String()]; !ok { // There is an expected Endpoint which is not installed.
				needUpdateEndpoints = true
			}
			endpointUpdateList = append(endpointUpdateList, endpoint)
		}
		if len(endpoints) < len(endpointsInstalled) { // There are Endpoints which expired.
			klog.V(2).Infof("Some Endpoints of Service %s removed, updating Endpoints", svcInfo.String())
			needUpdateEndpoints = true
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
			needUpdateService = true
		}

		// If neither the Service nor Endpoints of the Service need to be updated, we skip.
		if !needUpdateService && !needUpdateEndpoints {
			continue
		}

		op := "Installing"
		if pSvcInfo != nil {
			op = "Updating"
		}
		klog.V(2).Infof("%s Service %s %s", op, svcPortName.Name, svcInfo.String())

		if needUpdateEndpoints {
			err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpointUpdateList, p.isIPv6)
			if err != nil {
				klog.Errorf("Error when installing Endpoints flows: %v", err)
				continue
			}
			err = p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpointUpdateList)
			if err != nil {
				klog.Errorf("Error when installing Endpoints groups: %v", err)
				p.endpointInstalledMap[svcPortName] = nil
				continue
			}
			newEndpointsInstalled := map[string]struct{}{}
			for _, e := range endpointUpdateList {
				// If the Endpoint is newly installed, add a reference.
				if _, ok := endpointsInstalled[e.String()]; !ok {
					key := endpointKey(e, svcInfo.OFProtocol)
					p.endpointReferenceCounter[key] = p.endpointReferenceCounter[key] + 1
				}
				newEndpointsInstalled[e.String()] = struct{}{}
			}
			p.endpointInstalledMap[svcPortName] = newEndpointsInstalled
		}

		if needUpdateService {
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
		}

		p.serviceInstalledMap[svcPortName] = svcPort
		p.addServiceByIP(svcInfo.String(), svcPortName)
	}
}

// syncProxyRules applies current changes in change trackers and then updates
// flows for services and endpoints. It will return immediately if either
// endpoints or services resources are not synced. syncProxyRules is only called
// through the Run method of the runner object, and all calls are
// serialized. Since this method is the only one accessing internal state
// (e.g. serviceMap), no synchronization mechanism, such as a mutex, is
// required.
func (p *proxier) syncProxyRules() {
	start := time.Now()
	defer func() {
		delta := time.Since(start)
		if p.isIPv6 {
			metrics.SyncProxyDurationV6.Observe(delta.Seconds())
		} else {
			metrics.SyncProxyDuration.Observe(delta.Seconds())
		}
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

	counter := 0
	for _, endpoints := range p.endpointsMap {
		counter += len(endpoints)
	}
	if p.isIPv6 {
		metrics.ServicesInstalledTotalV6.Set(float64(len(p.serviceMap)))
		metrics.EndpointsInstalledTotalV6.Set(float64(counter))
	} else {
		metrics.ServicesInstalledTotal.Set(float64(len(p.serviceMap)))
		metrics.EndpointsInstalledTotal.Set(float64(counter))
	}
}

func (p *proxier) SyncLoop() {
	p.runner.Loop(p.stopChan)
}

func (p *proxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	p.OnEndpointsUpdate(nil, endpoints)
}

func (p *proxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	if p.isIPv6 {
		metrics.EndpointsUpdatesTotalV6.Inc()
	} else {
		metrics.EndpointsUpdatesTotal.Inc()
	}
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

func (p *proxier) OnServiceAdd(service *corev1.Service) {
	p.OnServiceUpdate(nil, service)
}

func (p *proxier) OnServiceUpdate(oldService, service *corev1.Service) {
	if p.isIPv6 {
		metrics.ServicesUpdatesTotalV6.Inc()
	} else {
		metrics.ServicesUpdatesTotal.Inc()
	}
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
		go p.endpointsConfig.Run(stopCh)
		p.stopChan = stopCh
		p.SyncLoop()
	})
}

func NewProxier(
	hostname string,
	informerFactory informers.SharedInformerFactory,
	ofClient openflow.Client,
	isIPv6 bool) *proxier {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	metrics.Register()
	klog.V(2).Infof("Creating proxier with IPv6 enabled=%t", isIPv6)
	p := &proxier{
		endpointsConfig:          config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
		serviceConfig:            config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:         newEndpointsChangesTracker(hostname),
		serviceChanges:           newServiceChangesTracker(recorder, isIPv6),
		serviceMap:               k8sproxy.ServiceMap{},
		serviceInstalledMap:      k8sproxy.ServiceMap{},
		endpointInstalledMap:     map[k8sproxy.ServicePortName]map[string]struct{}{},
		endpointsMap:             types.EndpointsMap{},
		endpointReferenceCounter: map[string]uint{},
		serviceStringMap:         map[string]k8sproxy.ServicePortName{},
		groupCounter:             types.NewGroupCounter(),
		ofClient:                 ofClient,
		isIPv6:                   isIPv6,
	}
	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, 0, 30*time.Second, -1)
	return p
}

func NewDualStackProxier(
	hostname string, informerFactory informers.SharedInformerFactory, ofClient openflow.Client) k8sproxy.Provider {

	// Create an ipv4 instance of the single-stack proxier
	ipv4Proxier := NewProxier(hostname, informerFactory, ofClient, false)

	// Create an ipv6 instance of the single-stack proxier
	ipv6Proxier := NewProxier(hostname, informerFactory, ofClient, true)

	// Return a meta-proxier that dispatch calls between the two
	// single-stack proxier instances
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)
	return metaProxier
}
