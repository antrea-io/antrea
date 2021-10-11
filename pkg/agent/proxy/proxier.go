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
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	agentconfig "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy/metrics"
	"antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/features"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
	"antrea.io/antrea/third_party/proxy/config"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
	// Due to the maximum message size in Openflow 1.3 and the implementation of Services in Antrea, the maximum number
	// of Endpoints that Antrea can support at the moment is 800. If the number of Endpoints for a given Service exceeds
	// 800, extra Endpoints will be dropped.
	maxEndpoints = 800
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
	// oversizeServiceSet records the Services that have more than 800 Endpoints.
	oversizeServiceSet sets.String

	// syncedOnce returns true if the proxier has synced rules at least once.
	syncedOnce      bool
	syncedOnceMutex sync.RWMutex

	runner               *k8sproxy.BoundedFrequencyRunner
	stopChan             <-chan struct{}
	ofClient             openflow.Client
	routeClient          route.Interface
	nodePortAddresses    []net.IP
	hostGateWay          string
	isIPv6               bool
	proxyAll             bool
	endpointSliceEnabled bool
}

func (p *proxier) SyncedOnce() bool {
	p.syncedOnceMutex.RLock()
	defer p.syncedOnceMutex.RUnlock()
	return p.syncedOnce
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
		if p.oversizeServiceSet.Has(svcPortName.String()) {
			p.oversizeServiceSet.Delete(svcPortName.String())
		}
		if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
			klog.ErrorS(err, "Failed to remove flows of Service", "Service", svcPortName)
			continue
		}

		if p.proxyAll {
			// Remove NodePort flows and configurations.
			if svcInfo.NodePort() > 0 {
				if err := p.uninstallNodePortService(uint16(svcInfo.NodePort()), svcInfo.OFProtocol); err != nil {
					klog.ErrorS(err, "Failed to remove flows and configurations of Service", "Service", svcPortName)
					continue
				}
			}
		}
		// Remove LoadBalancer flows and configurations.
		if len(svcInfo.LoadBalancerIPStrings()) > 0 {
			if err := p.uninstallLoadBalancerService(svcInfo.LoadBalancerIPStrings(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
				klog.ErrorS(err, "Failed to remove flows and configurations of Service", "Service", svcPortName)
				continue
			}
		}
		// Remove Service group whose Endpoints are local.
		if svcInfo.NodeLocalExternal() {
			groupIDLocal, _ := p.groupCounter.Get(svcPortName, true)
			if err := p.ofClient.UninstallServiceGroup(groupIDLocal); err != nil {
				klog.ErrorS(err, "Failed to remove flows of Service", "Service", svcPortName)
				continue
			}
			p.groupCounter.Recycle(svcPortName, true)
		}
		// Remove Service group which has all Endpoints.
		groupID, _ := p.groupCounter.Get(svcPortName, false)
		if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
			klog.ErrorS(err, "Failed to remove flows of Service", "Service", svcPortName)
			continue
		}

		delete(p.serviceInstalledMap, svcPortName)
		p.deleteServiceByIP(svcInfo.String())
		p.groupCounter.Recycle(svcPortName, false)
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
		svcInfo.OFProtocol != pSvcInfo.OFProtocol ||
		svcInfo.NodePort() != pSvcInfo.NodePort() ||
		svcInfo.NodeLocalExternal() != pSvcInfo.NodeLocalExternal()
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

func (p *proxier) installNodePortService(groupID binding.GroupIDType, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool) error {
	svcIP := agentconfig.VirtualServiceIPv4
	if p.isIPv6 {
		svcIP = agentconfig.VirtualServiceIPv6
	}
	if err := p.ofClient.InstallServiceFlows(groupID, svcIP, svcPort, protocol, affinityTimeout, nodeLocalExternal, corev1.ServiceTypeNodePort); err != nil {
		return fmt.Errorf("failed to install Service NodePort load balancing flows: %w", err)
	}
	if err := p.routeClient.AddNodePort(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to install Service NodePort traffic redirecting flows: %w", err)
	}
	return nil
}

func (p *proxier) uninstallNodePortService(svcPort uint16, protocol binding.Protocol) error {
	svcIP := agentconfig.VirtualServiceIPv4
	if p.isIPv6 {
		svcIP = agentconfig.VirtualServiceIPv6
	}
	if err := p.ofClient.UninstallServiceFlows(svcIP, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to remove Service NodePort NodePort load balancing flows: %w", err)
	}
	if err := p.routeClient.DeleteNodePort(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to remove Service NodePort traffic redirecting flows: %w", err)
	}
	return nil
}

func (p *proxier) installLoadBalancerService(groupID binding.GroupIDType, loadBalancerIPStrings []string, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			if err := p.ofClient.InstallServiceFlows(groupID, net.ParseIP(ingress), svcPort, protocol, affinityTimeout, nodeLocalExternal, corev1.ServiceTypeLoadBalancer); err != nil {
				return fmt.Errorf("failed to install Service LoadBalancer load balancing flows: %w", err)
			}
			if err := p.ofClient.InstallLoadBalancerServiceFromOutsideFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to install Service LoadBalancer flows: %w", err)
			}
		}
	}
	if p.proxyAll {
		if err := p.routeClient.AddLoadBalancer(loadBalancerIPStrings); err != nil {
			return fmt.Errorf("failed to install Service LoadBalancer traffic redirecting flows: %w", err)
		}
	}

	return nil
}

func (p *proxier) uninstallLoadBalancerService(loadBalancerIPStrings []string, svcPort uint16, protocol binding.Protocol) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			if err := p.ofClient.UninstallServiceFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove Service LoadBalancer load balancing flows: %w", err)
			}
			if err := p.ofClient.UninstallLoadBalancerServiceFromOutsideFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove Service LoadBalancer flows: %w", err)
			}
		}
	}
	if p.proxyAll {
		if err := p.routeClient.DeleteLoadBalancer(loadBalancerIPStrings); err != nil {
			return fmt.Errorf("failed to remove Service LoadBalancer traffic redirecting flows: %w", err)
		}
	}

	return nil
}

func (p *proxier) installServices() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		groupID, _ := p.groupCounter.Get(svcPortName, false)
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
		if len(endpoints) > maxEndpoints {
			if !p.oversizeServiceSet.Has(svcPortName.String()) {
				klog.Warningf("Since Endpoints of Service %s exceeds %d, extra Endpoints will be dropped", svcPortName.String(), maxEndpoints)
				p.oversizeServiceSet.Insert(svcPortName.String())
			}
			// If the length of endpoints > maxEndpoints, endpoints should be cut. However, endpoints is a map. Therefore,
			// iterate the map and append every Endpoint to a slice endpointList. Since the iteration order of map in
			// Golang is random, if cut directly without any sorting, some Endpoints may not be installed. So cutting
			// slice endpointList after sorting can avoid this situation in some degree.
			var endpointList []k8sproxy.Endpoint
			for _, endpoint := range endpoints {
				endpointList = append(endpointList, endpoint)
			}
			sort.Sort(byEndpoint(endpointList))
			endpointList = endpointList[:maxEndpoints]

			for _, endpoint := range endpointList { // Check if there is any installed Endpoint which is not expected anymore.
				if _, ok := endpointsInstalled[endpoint.String()]; !ok { // There is an expected Endpoint which is not installed.
					needUpdateEndpoints = true
				}
				endpointUpdateList = append(endpointUpdateList, endpoint)
			}
		} else {
			if p.oversizeServiceSet.Has(svcPortName.String()) {
				p.oversizeServiceSet.Delete(svcPortName.String())
			}
			for _, endpoint := range endpoints { // Check if there is any installed Endpoint which is not expected anymore.
				if _, ok := endpointsInstalled[endpoint.String()]; !ok { // There is an expected Endpoint which is not installed.
					needUpdateEndpoints = true
				}
				endpointUpdateList = append(endpointUpdateList, endpoint)
			}
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
				klog.ErrorS(err, "Error when installing Endpoints flows")
				continue
			}
			err = p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpointUpdateList)
			if err != nil {
				klog.ErrorS(err, "Error when installing Endpoints groups")
				continue
			}

			// Install another group when Service externalTrafficPolicy is Local.
			if p.proxyAll && svcInfo.NodeLocalExternal() {
				groupIDLocal, _ := p.groupCounter.Get(svcPortName, true)
				var localEndpointList []k8sproxy.Endpoint
				for _, ed := range endpointUpdateList {
					if !ed.GetIsLocal() {
						continue
					}
					localEndpointList = append(localEndpointList, ed)
				}
				if err = p.ofClient.InstallServiceGroup(groupIDLocal, svcInfo.StickyMaxAgeSeconds() != 0, localEndpointList); err != nil {
					klog.ErrorS(err, "Error when installing Group for Service whose externalTrafficPolicy is Local")
					continue
				}
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
				// If previous Service should be removed, remove ClusterIP flows of previous Service.
				if err := p.ofClient.UninstallServiceFlows(pSvcInfo.ClusterIP(), uint16(pSvcInfo.Port()), pSvcInfo.OFProtocol); err != nil {
					klog.ErrorS(err, "Failed to remove flows of Service", "Service", svcPortName)
					continue
				}

				if p.proxyAll {
					// If previous Service which has NodePort should be removed, remove NodePort flows and configurations of previous Service.
					if pSvcInfo.NodePort() > 0 {
						if err := p.uninstallNodePortService(uint16(pSvcInfo.NodePort()), pSvcInfo.OFProtocol); err != nil {
							klog.ErrorS(err, "Failed to remove flows and configurations of Service", "Service", svcPortName)
							continue
						}
					}
				}
			}

			// Install ClusterIP flows of current Service.
			if err := p.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds()), false, corev1.ServiceTypeClusterIP); err != nil {
				klog.Errorf("Error when installing Service flows: %v", err)
				continue
			}

			// If externalTrafficPolicy of the Service is Local, Service NodePort or LoadBalancer should use the Service
			// group whose Endpoints are local.
			nGroupID := groupID
			if svcInfo.NodeLocalExternal() {
				nGroupID, _ = p.groupCounter.Get(svcPortName, true)
			}

			if p.proxyAll {
				// Install ClusterIP route on Node so that ClusterIP can be accessed on Node. Every time a new ClusterIP
				// is created, the routing target IP block will be recalculated for expansion to be able to route the new
				// created ClusterIP. Deleting a ClusterIP will not shrink the target routing IP block. The Service CIDR
				// can be finally calculated after creating enough ClusterIPs.
				if err := p.routeClient.AddClusterIPRoute(svcInfo.ClusterIP()); err != nil {
					klog.ErrorS(err, "Failed to install ClusterIP route of Service", "Service", svcPortName)
					continue
				}

				// If previous Service is nil or NodePort flows and configurations of previous Service have been removed,
				// install NodePort flows and configurations for current Service.
				if svcInfo.NodePort() > 0 && (pSvcInfo == nil || needRemoval) {
					if err := p.installNodePortService(nGroupID, uint16(svcInfo.NodePort()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds()), svcInfo.NodeLocalExternal()); err != nil {
						klog.ErrorS(err, "Failed to install NodePort flows and configurations of Service", "Service", svcPortName)
						continue
					}
				}
			}

			// Service LoadBalancer flows can be partially updated.
			var toDelete, toAdd []string
			if needRemoval {
				toDelete = pSvcInfo.LoadBalancerIPStrings()
				toAdd = svcInfo.LoadBalancerIPStrings()
			} else {
				toDelete = deletedLoadBalancerIPs
				toAdd = addedLoadBalancerIPs
			}
			// Remove LoadBalancer flows and configurations.
			if len(toDelete) > 0 {
				if err := p.uninstallLoadBalancerService(toDelete, uint16(pSvcInfo.Port()), pSvcInfo.OFProtocol); err != nil {
					klog.ErrorS(err, "Failed to remove flows and configurations of Service", "Service", svcPortName)
					continue
				}
			}
			// Install LoadBalancer flows and configurations.
			if len(toAdd) > 0 {
				if err := p.installLoadBalancerService(nGroupID, toAdd, uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds()), svcInfo.NodeLocalExternal()); err != nil {
					klog.ErrorS(err, "Failed to install LoadBalancer flows and configurations of Service", "Service", svcPortName)
					continue
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

	p.syncedOnceMutex.Lock()
	defer p.syncedOnceMutex.Unlock()
	p.syncedOnce = true
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
	if p.serviceChanges.OnServiceUpdate(oldService, service) {
		if p.isInitialized() {
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
		if p.endpointSliceEnabled {
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

		// TODO: This causes antctl command output incomplete groups, fix it latter.
		groupID, _ := p.groupCounter.Get(svcPortName, false)
		groups = append(groups, groupID)
	}

	return flows, groups, found
}

func NewProxier(
	hostname string,
	informerFactory informers.SharedInformerFactory,
	ofClient openflow.Client,
	isIPv6 bool,
	routeClient route.Interface,
	nodePortAddresses []net.IP,
	proxyAllEnabled bool,
	skipServices []string) *proxier {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	metrics.Register()
	klog.V(2).Infof("Creating proxier with IPv6 enabled=%t", isIPv6)

	endpointSliceEnabled := features.DefaultFeatureGate.Enabled(features.EndpointSlice)
	ipFamily := corev1.IPv4Protocol
	if isIPv6 {
		ipFamily = corev1.IPv6Protocol
	}

	p := &proxier{
		endpointsConfig:          config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
		serviceConfig:            config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:         newEndpointsChangesTracker(hostname, endpointSliceEnabled, isIPv6),
		serviceChanges:           newServiceChangesTracker(recorder, ipFamily, skipServices),
		serviceMap:               k8sproxy.ServiceMap{},
		serviceInstalledMap:      k8sproxy.ServiceMap{},
		endpointsInstalledMap:    types.EndpointsMap{},
		endpointsMap:             types.EndpointsMap{},
		endpointReferenceCounter: map[string]int{},
		serviceStringMap:         map[string]k8sproxy.ServicePortName{},
		oversizeServiceSet:       sets.NewString(),
		groupCounter:             types.NewGroupCounter(isIPv6),
		ofClient:                 ofClient,
		routeClient:              routeClient,
		nodePortAddresses:        nodePortAddresses,
		isIPv6:                   isIPv6,
		proxyAll:                 proxyAllEnabled,
		endpointSliceEnabled:     endpointSliceEnabled,
	}

	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, 2)
	if endpointSliceEnabled {
		p.endpointSliceConfig = config.NewEndpointSliceConfig(informerFactory.Discovery().V1beta1().EndpointSlices(), resyncPeriod)
		p.endpointSliceConfig.RegisterEventHandler(p)
	} else {
		p.endpointsConfig = config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod)
		p.endpointsConfig.RegisterEventHandler(p)
	}
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
	}
	return p.ipv4Proxier.GetServiceByIP(serviceStr)
}

func NewDualStackProxier(
	hostname string,
	informerFactory informers.SharedInformerFactory,
	ofClient openflow.Client,
	routeClient route.Interface,
	nodePortAddressesIPv4 []net.IP,
	nodePortAddressesIPv6 []net.IP,
	proxyAllEnabled bool,
	skipServices []string) *metaProxierWrapper {

	// Create an IPv4 instance of the single-stack proxier.
	ipv4Proxier := NewProxier(hostname, informerFactory, ofClient, false, routeClient, nodePortAddressesIPv4, proxyAllEnabled, skipServices)

	// Create an IPv6 instance of the single-stack proxier.
	ipv6Proxier := NewProxier(hostname, informerFactory, ofClient, true, routeClient, nodePortAddressesIPv6, proxyAllEnabled, skipServices)

	// Create a meta-proxier that dispatch calls between the two
	// single-stack proxier instances.
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)

	return &metaProxierWrapper{ipv4Proxier, ipv6Proxier, metaProxier}
}
