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
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	"github.com/vmware-tanzu/antrea/pkg/features"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
	"github.com/vmware-tanzu/antrea/third_party/proxy/config"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
)

// Proxier wraps proxy.Provider and adds extra methods. It is introduced for
// extending the proxy.Provider implementations with extra methods, without
// modifying the proxy.Provider interface.
type Proxier interface {
	// GetProxyProvider returns the real proxy Provider.
	GetProxyProvider() k8sproxy.Provider
	// GetServiceFlowKeys returns the keys (match strings) of the cached OVS
	// flows and the OVS group IDs for a Service. False is returned if the
	// Service is not found.
	GetServiceFlowKeys(serviceName, namespace string) ([]string, []binding.GroupIDType, bool)
	// GetServiceByIP returns the ServicePortName struct for the given serviceString(ClusterIP:Port/Proto).
	// False is returned if the serviceString is not found in serviceStringMap.
	GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool)
}

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
	// endpointsInstalledMap stores endpoints we actually installed.
	endpointsInstalledMap types.EndpointsMap
	// serviceEndpointsMapsMutex protects serviceMap, serviceInstalledMap,
	// endpointsMap, and endpointsInstalledMap, which can be read by
	// GetServiceFlowKeys() called by the "/ovsflows" API handler.
	serviceEndpointsMapsMutex sync.Mutex
	// endpointReferenceCounter stores the number of times an Endpoint is referenced by Services.
	endpointReferenceCounter map[string]int
	// groupCounter is used to allocate groupID.
	groupCounter types.GroupCounter
	// serviceStringMap provides map from serviceString(ClusterIP:Port/Proto) to ServicePortName.
	serviceStringMap map[string]k8sproxy.ServicePortName
	// serviceStringMapMutex protects serviceStringMap object.
	serviceStringMapMutex sync.Mutex

	runner              *k8sproxy.BoundedFrequencyRunner
	stopChan            <-chan struct{}
	ofClient            openflow.Client
	isIPv6              bool
	enableEndpointSlice bool
}

func endpointKey(endpoint k8sproxy.Endpoint, protocol binding.Protocol) string {
	return fmt.Sprintf("%s/%s", endpoint.String(), protocol)
}

func (p *proxier) isInitialized() bool {
	return p.endpointsChanges.Synced() && p.serviceChanges.Synced()
}

// removeStaleServices removes all expired Services. Once a Service is deleted, all
// its Endpoints will be expired, and the removeStaleEndpoints method takes
// responsibility for cleaning up, thus we don't need to call removeEndpoint in this
// function.
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
// given Service. If the Endpoint is still referenced by any other Services, no flow will be removed.
// The method only returns an error if a data path operation fails. If the flows are successfully
// removed from the data path, the method returns true. Otherwise, if the flows are still needed for
// other Services, it returns false.
func (p *proxier) removeEndpoint(endpoint k8sproxy.Endpoint, protocol binding.Protocol) (bool, error) {
	key := endpointKey(endpoint, protocol)
	count := p.endpointReferenceCounter[key]
	if count == 1 {
		if err := p.ofClient.UninstallEndpointFlows(protocol, endpoint); err != nil {
			return false, err
		}
		delete(p.endpointReferenceCounter, key)
		klog.V(2).Infof("Endpoint %s/%s removed", endpoint.String(), protocol)
	} else if count > 1 {
		p.endpointReferenceCounter[key] = count - 1
		klog.V(2).Infof("Stale Endpoint %s/%s is still referenced by other Services, decrementing reference count by 1", endpoint.String(), protocol)
		return false, nil
	}
	return true, nil
}

// removeStaleEndpoints compares Endpoints we installed with Endpoints we expected. All installed but unexpected Endpoints
// will be deleted by using removeEndpoint.
func (p *proxier) removeStaleEndpoints() {
	for svcPortName, installedEps := range p.endpointsInstalledMap {
		for installedEpName, installedEp := range installedEps {
			if _, ok := p.endpointsMap[svcPortName][installedEpName]; !ok {
				if _, err := p.removeEndpoint(installedEp, getBindingProtoForIPProto(installedEp.IP(), svcPortName.Protocol)); err != nil {
					klog.Errorf("Error when removing Endpoint %v for %v", installedEp, svcPortName)
					continue
				}
				delete(installedEps, installedEpName)
			}
		}
		if len(installedEps) == 0 {
			delete(p.endpointsInstalledMap, svcPortName)
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
		endpointsInstalled, ok := p.endpointsInstalledMap[svcPortName]
		if !ok {
			endpointsInstalled = map[string]k8sproxy.Endpoint{}
			p.endpointsInstalledMap[svcPortName] = endpointsInstalled
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

		if pSvcInfo != nil {
			klog.V(2).Infof("Updating Service %s %s", svcPortName.Name, svcInfo.String())
		} else {
			klog.V(2).Infof("Installing Service %s %s", svcPortName.Name, svcInfo.String())
		}

		if needUpdateEndpoints {
			err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpointUpdateList)
			if err != nil {
				klog.Errorf("Error when installing Endpoints flows: %v", err)
				continue
			}
			err = p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpointUpdateList)
			if err != nil {
				klog.Errorf("Error when installing Endpoints groups: %v", err)
				continue
			}
			for _, e := range endpointUpdateList {
				// If the Endpoint is newly installed, add a reference.
				if _, ok := endpointsInstalled[e.String()]; !ok {
					key := endpointKey(e, svcInfo.OFProtocol)
					p.endpointReferenceCounter[key] = p.endpointReferenceCounter[key] + 1
					endpointsInstalled[e.String()] = e
				}
			}
		}

		if needUpdateService {
			// Delete previous flow.
			if needRemoval {
				if err := p.ofClient.UninstallServiceFlows(pSvcInfo.ClusterIP(), uint16(pSvcInfo.Port()), pSvcInfo.OFProtocol); err != nil {
					klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
					continue
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
// through the Run method of the runner object, and all calls are serialized.
// This method is the only one that changes internal state, but
// GetServiceFlowKeys(), which is called by the the "/ovsflows" API handler,
// also reads service and endpoints maps, so serviceEndpointsMapsMutex is used
// to protect these two maps.
func (p *proxier) syncProxyRules() {
	if !p.isInitialized() {
		klog.V(4).Info("Not syncing rules until both Services and Endpoints have been synced")
		return
	}

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

	// Protect Service and endpoints maps, which can be read by
	// GetServiceFlowKeys().
	p.serviceEndpointsMapsMutex.Lock()
	defer p.serviceEndpointsMapsMutex.Unlock()
	p.endpointsChanges.Update(p.endpointsMap)
	p.serviceChanges.Update(p.serviceMap)

	p.removeStaleServices()
	p.installServices()
	p.removeStaleEndpoints()

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
		if p.enableEndpointSlice {
			go p.endpointSliceConfig.Run(stopCh)
		} else {
			go p.endpointsConfig.Run(stopCh)
		}
		p.stopChan = stopCh
		p.SyncLoop()
	})
}

func (p *proxier) GetProxyProvider() k8sproxy.Provider {
	// Return myself.
	return p
}

func (p *proxier) GetServiceFlowKeys(serviceName, namespace string) ([]string, []binding.GroupIDType, bool) {
	namespacedName := k8sapitypes.NamespacedName{Namespace: namespace, Name: serviceName}
	p.serviceEndpointsMapsMutex.Lock()
	defer p.serviceEndpointsMapsMutex.Unlock()

	var flows []string
	var groups []binding.GroupIDType
	found := false
	for svcPortName := range p.serviceMap {
		if namespacedName != svcPortName.NamespacedName {
			continue
		}
		found = true

		installedSvcPort, ok := p.serviceInstalledMap[svcPortName]
		if !ok {
			// Service flows not installed.
			continue
		}
		svcInfo := installedSvcPort.(*types.ServiceInfo)

		var epList []k8sproxy.Endpoint
		endpoints, ok := p.endpointsMap[svcPortName]
		if ok && len(endpoints) > 0 {
			epList = make([]k8sproxy.Endpoint, 0, len(endpoints))
			for _, ep := range endpoints {
				epList = append(epList, ep)
			}
		}

		svcFlows := p.ofClient.GetServiceFlowKeys(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol, epList)
		flows = append(flows, svcFlows...)

		groupID, _ := p.groupCounter.Get(svcPortName)
		groups = append(groups, groupID)
	}

	return flows, groups, found
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

	enableEndpointSlice := features.DefaultFeatureGate.Enabled(features.EndpointSlice)

	p := &proxier{
		enableEndpointSlice:      enableEndpointSlice,
		endpointsConfig:          config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
		serviceConfig:            config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:         newEndpointsChangesTracker(hostname, enableEndpointSlice, isIPv6),
		serviceChanges:           newServiceChangesTracker(recorder, isIPv6),
		serviceMap:               k8sproxy.ServiceMap{},
		serviceInstalledMap:      k8sproxy.ServiceMap{},
		endpointsInstalledMap:    types.EndpointsMap{},
		endpointsMap:             types.EndpointsMap{},
		endpointReferenceCounter: map[string]int{},
		serviceStringMap:         map[string]k8sproxy.ServicePortName{},
		groupCounter:             types.NewGroupCounter(),
		ofClient:                 ofClient,
		isIPv6:                   isIPv6,
	}
	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, 2)
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

// metaProxierWrapper wraps metaProxier, and implements the extra methods added
// in interface Proxier.
type metaProxierWrapper struct {
	ipv4Proxier *proxier
	ipv6Proxier *proxier
	metaProxier k8sproxy.Provider
}

func (p *metaProxierWrapper) GetProxyProvider() k8sproxy.Provider {
	return p.metaProxier
}

func (p *metaProxierWrapper) GetServiceFlowKeys(serviceName, namespace string) ([]string, []binding.GroupIDType, bool) {
	v4Flows, v4Groups, v4Found := p.ipv4Proxier.GetServiceFlowKeys(serviceName, namespace)
	v6Flows, v6Groups, v6Found := p.ipv6Proxier.GetServiceFlowKeys(serviceName, namespace)

	// Return the unions of IPv4 and IPv6 flows and groups.
	return append(v4Flows, v6Flows...), append(v4Groups, v6Groups...), v4Found || v6Found
}

func (p *metaProxierWrapper) GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool) {
	// Format of serviceStr is <clusterIP>:<svcPort>/<protocol>.
	lastColonIndex := strings.LastIndex(serviceStr, ":")
	if utilnet.IsIPv6String(serviceStr[:lastColonIndex]) {
		return p.ipv6Proxier.GetServiceByIP(serviceStr)
	} else {
		return p.ipv4Proxier.GetServiceByIP(serviceStr)
	}
}

func NewDualStackProxier(
	hostname string, informerFactory informers.SharedInformerFactory, ofClient openflow.Client) *metaProxierWrapper {

	// Create an ipv4 instance of the single-stack proxier
	ipv4Proxier := NewProxier(hostname, informerFactory, ofClient, false)

	// Create an ipv6 instance of the single-stack proxier
	ipv6Proxier := NewProxier(hostname, informerFactory, ofClient, true)

	// Create a meta-proxier that dispatch calls between the two
	// single-stack proxier instances.
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)

	return &metaProxierWrapper{ipv4Proxier, ipv6Proxier, metaProxier}
}
