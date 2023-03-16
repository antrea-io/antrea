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
	"math"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
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
	"antrea.io/antrea/third_party/proxy/healthcheck"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
	// SessionAffinity timeout is implemented using a hard_timeout in OVS. hard_timeout is
	// represented by a uint16 in the OpenFlow protocol.
	maxSupportedAffinityTimeout = math.MaxUint16
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
	nodeConfig          *config.NodeConfig
	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since last syncProxyRules call. For a single object,
	// changes are accumulated. Once both endpointsChanges and serviceChanges
	// have been synced, syncProxyRules will start syncing rules to OVS.
	endpointsChanges *endpointsChangesTracker
	serviceChanges   *serviceChangesTracker
	nodeLabels       map[string]string
	// serviceMap stores services we expect to be installed.
	serviceMap k8sproxy.ServiceMap
	// serviceInstalledMap stores services we actually installed.
	serviceInstalledMap k8sproxy.ServiceMap
	// endpointsMap stores endpoints we expect to be installed.
	endpointsMap types.EndpointsMap
	// endpointsInstalledMap stores endpoints we actually installed.
	endpointsInstalledMap types.EndpointsMap
	// serviceEndpointsMapsMutex protects serviceMap, serviceInstalledMap,
	// endpointsMap, nodeLabels, and endpointsInstalledMap, which can be read by
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

	serviceHealthServer healthcheck.ServiceHealthServer
	numLocalEndpoints   map[apimachinerytypes.NamespacedName]int

	// syncedOnce returns true if the proxier has synced rules at least once.
	syncedOnce      bool
	syncedOnceMutex sync.RWMutex

	runner                    *k8sproxy.BoundedFrequencyRunner
	stopChan                  <-chan struct{}
	ofClient                  openflow.Client
	routeClient               route.Interface
	nodePortAddresses         []net.IP
	hostname                  string
	isIPv6                    bool
	proxyAll                  bool
	endpointSliceEnabled      bool
	proxyLoadBalancerIPs      bool
	topologyAwareHintsEnabled bool
	supportNestedService      bool
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

// removeStaleServices removes all the configurations of expired Services and their associated Endpoints.
func (p *proxier) removeStaleServices() {
	for svcPortName, svcPort := range p.serviceInstalledMap {
		if _, ok := p.serviceMap[svcPortName]; ok {
			continue
		}
		svcInfo := svcPort.(*types.ServiceInfo)
		svcInfoStr := svcInfo.String()
		klog.V(2).InfoS("Removing stale Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
		if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
			klog.ErrorS(err, "Error when uninstalling ClusterIP flows for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
			continue
		}
		// Remove associated Endpoints flows.
		if endpoints, ok := p.endpointsInstalledMap[svcPortName]; ok {
			if err := p.removeStaleEndpoints(endpoints, svcInfo.Protocol()); err != nil {
				klog.ErrorS(err, "Error when removing Endpoints flows for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
				continue
			}
			delete(p.endpointsInstalledMap, svcPortName)
		}
		// Remove NodePort flows and configurations.
		if p.proxyAll && svcInfo.NodePort() > 0 {
			if err := p.uninstallNodePortService(uint16(svcInfo.NodePort()), svcInfo.OFProtocol); err != nil {
				klog.ErrorS(err, "Error when uninstalling NodePort flows and configurations for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
				continue
			}
		}
		// Remove LoadBalancer flows and configurations.
		if p.proxyLoadBalancerIPs && len(svcInfo.LoadBalancerIPStrings()) > 0 {
			if err := p.uninstallLoadBalancerService(svcInfo.LoadBalancerIPStrings(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
				klog.ErrorS(err, "Error when uninstalling LoadBalancer flows and configurations for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
				continue
			}
		}
		// Remove Service group which has only local Endpoints.
		if groupID, exist := p.groupCounter.Get(svcPortName, true); exist {
			if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
				klog.ErrorS(err, "Error when uninstalling group of local Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
				continue
			}
			p.groupCounter.Recycle(svcPortName, true)
		}
		// Remove Service group which has all Endpoints.
		if groupID, exist := p.groupCounter.Get(svcPortName, false); exist {
			if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
				klog.ErrorS(err, "Error when uninstalling group of all Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
				continue
			}
			p.groupCounter.Recycle(svcPortName, false)
		}

		delete(p.serviceInstalledMap, svcPortName)
		p.deleteServiceByIP(svcInfoStr)
	}
}

func getBindingProtoForIPProto(isIPv6 bool, protocol corev1.Protocol) binding.Protocol {
	var bindingProtocol binding.Protocol
	if isIPv6 {
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

// removeStaleEndpoints removes flows for the given Endpoints from the data path if these flows are no longer
// needed by any Service. Endpoints from different Services can have the same characteristics and thus
// can share the same flows. removeStaleEndpoints must be called whenever Endpoints are no longer used by a
// given Service. If the Endpoints are still referenced by any other Services, no flow will be removed.
// The method only returns an error if a data path operation fails. If the flows are successfully
// removed from the data path, the method returns nil.
func (p *proxier) removeStaleEndpoints(staleEndpoints map[string]k8sproxy.Endpoint, ipProtocol corev1.Protocol) error {
	var endpointsToRemove []k8sproxy.Endpoint
	bindingProtocol := getBindingProtoForIPProto(p.isIPv6, ipProtocol)

	// Get all Endpoints whose reference counter is 1, and these Endpoints should be removed.
	for _, endpoint := range staleEndpoints {
		key := endpointKey(endpoint, bindingProtocol)
		count := p.endpointReferenceCounter[key]
		if count == 1 {
			endpointsToRemove = append(endpointsToRemove, endpoint)
			klog.V(2).InfoS("Endpoint will be removed", "Endpoint", endpoint.String(), "Protocol", bindingProtocol)
		}
	}

	// Remove flows for these Endpoints.
	if len(endpointsToRemove) != 0 {
		if err := p.ofClient.UninstallEndpointFlows(bindingProtocol, endpointsToRemove); err != nil {
			return err
		}
	}

	// Update the reference counter of Endpoints.
	for _, endpoint := range staleEndpoints {
		key := endpointKey(endpoint, bindingProtocol)
		count := p.endpointReferenceCounter[key]
		if count == 1 {
			delete(p.endpointReferenceCounter, key)
			klog.V(2).InfoS("Endpoint was removed", "Endpoint", endpoint.String(), "Protocol", bindingProtocol)
		} else {
			p.endpointReferenceCounter[key] = count - 1
			klog.V(2).InfoS("Stale Endpoint is still referenced by other Services, decrementing reference count by 1", "Endpoint", endpoint.String(), "Protocol", bindingProtocol)
		}
	}

	return nil
}

func serviceIdentityChanged(svcInfo, pSvcInfo *types.ServiceInfo) bool {
	return svcInfo.ClusterIP().String() != pSvcInfo.ClusterIP().String() ||
		svcInfo.Port() != pSvcInfo.Port() ||
		svcInfo.OFProtocol != pSvcInfo.OFProtocol ||
		svcInfo.NodePort() != pSvcInfo.NodePort() ||
		svcInfo.ExternalPolicyLocal() != pSvcInfo.ExternalPolicyLocal()
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
	svcIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6 {
		svcIP = agentconfig.VirtualNodePortDNATIPv6
	}
	if err := p.ofClient.InstallServiceFlows(groupID, svcIP, svcPort, protocol, affinityTimeout, nodeLocalExternal, corev1.ServiceTypeNodePort, false); err != nil {
		return fmt.Errorf("failed to install NodePort load balancing flows: %w", err)
	}
	if err := p.routeClient.AddNodePort(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to install NodePort traffic redirecting rules: %w", err)
	}
	return nil
}

func (p *proxier) uninstallNodePortService(svcPort uint16, protocol binding.Protocol) error {
	svcIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6 {
		svcIP = agentconfig.VirtualNodePortDNATIPv6
	}
	if err := p.ofClient.UninstallServiceFlows(svcIP, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to remove NodePort load balancing flows: %w", err)
	}
	if err := p.routeClient.DeleteNodePort(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to remove NodePort traffic redirecting rules: %w", err)
	}
	return nil
}

func (p *proxier) installLoadBalancerService(groupID binding.GroupIDType, loadBalancerIPStrings []string, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			if err := p.ofClient.InstallServiceFlows(groupID, net.ParseIP(ingress), svcPort, protocol, affinityTimeout, nodeLocalExternal, corev1.ServiceTypeLoadBalancer, false); err != nil {
				return fmt.Errorf("failed to install LoadBalancer load balancing flows: %w", err)
			}
		}
	}
	if p.proxyAll {
		if err := p.routeClient.AddLoadBalancer(loadBalancerIPStrings); err != nil {
			return fmt.Errorf("failed to install LoadBalancer traffic redirecting routes: %w", err)
		}
	}

	return nil
}

func (p *proxier) uninstallLoadBalancerService(loadBalancerIPStrings []string, svcPort uint16, protocol binding.Protocol) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			if err := p.ofClient.UninstallServiceFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove LoadBalancer load balancing flows: %w", err)
			}
		}
	}
	if p.proxyAll {
		if err := p.routeClient.DeleteLoadBalancer(loadBalancerIPStrings); err != nil {
			return fmt.Errorf("failed to remove LoadBalancer traffic redirecting routes: %w", err)
		}
	}

	return nil
}

func (p *proxier) installServices() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		svcInfoStr := svcInfo.String()
		endpointsInstalled, ok := p.endpointsInstalledMap[svcPortName]
		if !ok {
			endpointsInstalled = map[string]k8sproxy.Endpoint{}
			p.endpointsInstalledMap[svcPortName] = endpointsInstalled
		}
		endpointsToInstall := p.endpointsMap[svcPortName]
		// If both expected Endpoints number and installed Endpoints number are 0, we don't need to take care of this Service.
		if len(endpointsToInstall) == 0 && len(endpointsInstalled) == 0 {
			continue
		}

		installedSvcPort, ok := p.serviceInstalledMap[svcPortName]
		var pSvcInfo *types.ServiceInfo
		var needRemoval, needUpdateService, needUpdateEndpoints bool
		if ok { // Need to update.
			pSvcInfo = installedSvcPort.(*types.ServiceInfo)
			needRemoval = serviceIdentityChanged(svcInfo, pSvcInfo) || (svcInfo.SessionAffinityType() != pSvcInfo.SessionAffinityType())
			needUpdateService = needRemoval || (svcInfo.StickyMaxAgeSeconds() != pSvcInfo.StickyMaxAgeSeconds())
			needUpdateEndpoints = pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType() ||
				pSvcInfo.ExternalPolicyLocal() != svcInfo.ExternalPolicyLocal() ||
				pSvcInfo.InternalPolicyLocal() != svcInfo.InternalPolicyLocal()
		} else { // Need to install.
			needUpdateService = true
			// We need to ensure a group is created for a new Service even if there is no available Endpoints,
			// otherwise it would fail to install Service flows because the group doesn't exist.
			needUpdateEndpoints = true
		}

		affinityTimeout := svcInfo.StickyMaxAgeSeconds()
		if svcInfo.StickyMaxAgeSeconds() > maxSupportedAffinityTimeout {
			// SessionAffinity timeout is implemented using a hard_timeout in
			// OVS. hard_timeout is represented by a uint16 in the OpenFlow protocol,
			// hence we cannot support timeouts greater than 65535 seconds. However, the
			// K8s Service spec allows timeout values up to 86400 seconds
			// (https://godoc.org/k8s.io/api/core/v1#ClientIPConfig). For values greater
			// than 65535 seconds, we need to set the hard_timeout to 65535 rather than
			// let the timeout value wrap around.
			affinityTimeout = maxSupportedAffinityTimeout
			if !ok || (svcInfo.StickyMaxAgeSeconds() != pSvcInfo.StickyMaxAgeSeconds()) {
				// We only log a warning when the Service hasn't been installed
				// yet, or when the timeout has changed.
				klog.InfoS(
					"The timeout configured for ClientIP-based session affinity exceeds the max supported value",
					"service", svcPortName.String(),
					"timeout", svcInfo.StickyMaxAgeSeconds(),
					"maxTimeout", maxSupportedAffinityTimeout,
				)
			}
		}

		var internalPolicyLocal, externalPolicyLocal bool
		if svcInfo.InternalPolicyLocal() {
			internalPolicyLocal = true
		}
		if p.proxyAll && svcInfo.ExternalPolicyLocal() {
			externalPolicyLocal = true
		}

		clusterEndpoints, localEndpoints, allReachableEndpoints := p.categorizeEndpoints(endpointsToInstall, svcInfo)
		// If there are new Endpoints, Endpoints installed should be updated.
		for _, endpoint := range allReachableEndpoints {
			if _, ok := endpointsInstalled[endpoint.String()]; !ok { // There is an expected Endpoint which is not installed.
				needUpdateEndpoints = true
				klog.V(2).InfoS("At least one Endpoint of Service is not installed, updating Endpoints", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
				break
			}
		}
		// If there are expired Endpoints, Endpoints installed should be updated.
		if len(allReachableEndpoints) < len(endpointsInstalled) {
			klog.V(2).InfoS("Some Endpoints of Service was removed, updating Endpoints", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
			needUpdateEndpoints = true
		}

		var deletedLoadBalancerIPs, addedLoadBalancerIPs []string
		if p.proxyLoadBalancerIPs {
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
		}

		// If neither the Service nor Endpoints of the Service need to be updated, we skip.
		if !needUpdateService && !needUpdateEndpoints {
			continue
		}

		if pSvcInfo != nil {
			klog.V(2).InfoS("Updating Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
		} else {
			klog.V(2).InfoS("Installing Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
		}

		var err error
		if needUpdateEndpoints {
			// Install Endpoints.
			if len(allReachableEndpoints) > 0 {
				err = p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, allReachableEndpoints)
				if err != nil {
					klog.ErrorS(err, "Error when installing Endpoints flows for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
					continue
				}
			}
			if internalPolicyLocal != externalPolicyLocal {
				if svcInfo.ExternallyAccessible() {
					// If the type of the Service is NodePort or LoadBalancer, when internalTrafficPolicy and externalTrafficPolicy
					// of the Service are different, install two groups. One group has cluster Endpoints, the other has
					// local Endpoints.
					groupID := p.groupCounter.AllocateIfNotExist(svcPortName, true)
					if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, localEndpoints); err != nil {
						klog.ErrorS(err, "Error when installing group of local Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
						continue
					}
					groupID = p.groupCounter.AllocateIfNotExist(svcPortName, false)
					if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, clusterEndpoints); err != nil {
						klog.ErrorS(err, "Error when installing group of all Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
						continue
					}
				} else {
					// If the type of the Service is ClusterIP, install a group according to internalTrafficPolicy.
					groupID := p.groupCounter.AllocateIfNotExist(svcPortName, internalPolicyLocal)
					if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, allReachableEndpoints); err != nil {
						klog.ErrorS(err, "Error when installing group of Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
						continue
					}
				}
			} else {
				// Regardless of the type of the Service, when internalTrafficPolicy and externalTrafficPolicy of the Service
				// are the same, only install one group and unconditionally uninstall another group. If both internalTrafficPolicy
				// and externalTrafficPolicy are Local, install the group that has only local Endpoints and unconditionally
				// uninstall the group which has all Endpoints; if both internalTrafficPolicy and externalTrafficPolicy are
				// Cluster, install the group which has all Endpoints and unconditionally uninstall the group which has
				// only local Endpoints. Note that, if a group doesn't exist on OVS, then the return value will be nil.
				// Note that, since internalTrafficPolicy and externalTrafficPolicy are the same, bothPolicyLocal just equals
				// internalPolicyLocal.
				bothPolicyLocal := internalPolicyLocal
				groupID := p.groupCounter.AllocateIfNotExist(svcPortName, bothPolicyLocal)
				if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, allReachableEndpoints); err != nil {
					klog.ErrorS(err, "Error when installing group of Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr, "BothTrafficPolicies", bothPolicyLocal)
					continue
				}
				if groupID, exist := p.groupCounter.Get(svcPortName, !bothPolicyLocal); exist {
					if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
						klog.ErrorS(err, "Error when uninstalling group of Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr, "BothTrafficPolicies", !bothPolicyLocal)
						continue
					}
					p.groupCounter.Recycle(svcPortName, !bothPolicyLocal)
				}
			}

			// Map endpointsInstalled stores the Endpoints actually installed in last syncProxyRules call. Slice
			// allReachableEndpoints stores the Endpoints actually installed in this syncProxyRules call. We call compareEndpoints
			// to get:
			// - Map updatedEndpointsInstalled, stores the Endpoints actually installed in this syncProxyRules call, and
			//   it is used to replace the old cache endpointsInstalled.
			// - Map staleEndpoints, stores the Endpoints that should be removed in this syncProxyRules call.
			// - Slice newEndpoints, stores the Endpoints newly installed in this syncProxyRules call.
			updatedEndpointsInstalled, staleEndpoints, newEndpoints := compareEndpoints(endpointsInstalled, allReachableEndpoints)
			// Remove stale Endpoints.
			if len(staleEndpoints) != 0 {
				if err = p.removeStaleEndpoints(staleEndpoints, svcPortName.Protocol); err != nil {
					klog.ErrorS(err, "Error when removing flows of stale Endpoints for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
					continue
				}
			}
			// Cache the Endpoints actually installed this time.
			p.endpointsInstalledMap[svcPortName] = updatedEndpointsInstalled
			// Update reference counter of Endpoints newly install.
			for _, endpoint := range newEndpoints {
				key := endpointKey(endpoint, svcInfo.OFProtocol)
				p.endpointReferenceCounter[key] = p.endpointReferenceCounter[key] + 1
			}
		}

		if needUpdateService {
			// Delete previous flow.
			if needRemoval {
				// If previous Service should be removed, remove ClusterIP flows of previous Service.
				if err := p.ofClient.UninstallServiceFlows(pSvcInfo.ClusterIP(), uint16(pSvcInfo.Port()), pSvcInfo.OFProtocol); err != nil {
					klog.ErrorS(err, "Error when uninstalling ClusterIP flows for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
					continue
				}

				if p.proxyAll {
					// If previous Service which has NodePort should be removed, remove NodePort flows and configurations of previous Service.
					if pSvcInfo.NodePort() > 0 {
						if err := p.uninstallNodePortService(uint16(pSvcInfo.NodePort()), pSvcInfo.OFProtocol); err != nil {
							klog.ErrorS(err, "Error when uninstalling NodePort flows and configurations for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
							continue
						}
					}
					// If previous Service which has ClusterIP should be removed, remove ClusterIP routes.
					if svcInfo.ClusterIP() != nil {
						if err := p.routeClient.DeleteClusterIPRoute(pSvcInfo.ClusterIP()); err != nil {
							klog.ErrorS(err, "Error when uninstalling ClusterIP route for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
							continue
						}
					}
				}
			}

			var isNestedService bool
			if p.supportNestedService {
				// Check the `IsNested` field only when Proxy is enabled with `supportNestedService`.
				// It is true only when the Service is an Antrea Multi-cluster Service for now.
				isNestedService = svcInfo.IsNested
			}

			// Install ClusterIP flows for the Service.
			groupID, exists := p.groupCounter.Get(svcPortName, internalPolicyLocal)
			if !exists {
				klog.ErrorS(nil, "Group for Service internalTrafficPolicy was not installed", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr, "internalTrafficPolicy", internalPolicyLocal)
				continue
			}
			if err := p.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(affinityTimeout), externalPolicyLocal, corev1.ServiceTypeClusterIP, isNestedService); err != nil {
				klog.Errorf("Error when installing Service flows: %v", err)
				continue
			}

			if p.proxyAll {
				// Install ClusterIP route on Node so that ClusterIP can be accessed on Node. Every time a new ClusterIP
				// is created, the routing target IP block will be recalculated for expansion to be able to route the new
				// created ClusterIP. Deleting a ClusterIP will not shrink the target routing IP block. The Service CIDR
				// can be finally calculated after creating enough ClusterIPs.
				if err := p.routeClient.AddClusterIPRoute(svcInfo.ClusterIP()); err != nil {
					klog.ErrorS(err, "Error when installing ClusterIP route for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
					continue
				}

				// If previous Service is nil or NodePort flows and configurations of previous Service have been removed,
				// install NodePort flows and configurations for current Service.
				if svcInfo.NodePort() > 0 && (pSvcInfo == nil || needRemoval) {
					groupID, exists = p.groupCounter.Get(svcPortName, externalPolicyLocal)
					if !exists {
						klog.ErrorS(nil, "Group for Service externalTrafficPolicy was not installed", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr, "externalTrafficPolicy", externalPolicyLocal)
						continue
					}
					if err := p.installNodePortService(groupID, uint16(svcInfo.NodePort()), svcInfo.OFProtocol, uint16(affinityTimeout), svcInfo.ExternalPolicyLocal()); err != nil {
						klog.ErrorS(err, "Error when installing NodePort flows and configurations of Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
						continue
					}
				}
			}

			if p.proxyLoadBalancerIPs {
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
						klog.ErrorS(err, "Error when uninstalling LoadBalancer flows and configurations for Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
						continue
					}
				}
				// Install LoadBalancer flows and configurations.
				if len(toAdd) > 0 {
					groupID, exists = p.groupCounter.Get(svcPortName, externalPolicyLocal)
					if !exists {
						klog.ErrorS(nil, "Group for Service externalTrafficPolicy was not installed", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr, "externalTrafficPolicy", externalPolicyLocal)
						continue
					}
					if err := p.installLoadBalancerService(groupID, toAdd, uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(affinityTimeout), svcInfo.ExternalPolicyLocal()); err != nil {
						klog.ErrorS(err, "Error when installing LoadBalancer flows and configurations for Service", "Service", "ServicePortName", svcPortName, "ServiceInfo", svcInfoStr)
						continue
					}
				}
			}
		}

		p.serviceInstalledMap[svcPortName] = svcPort
		p.addServiceByIP(svcInfoStr, svcPortName)
	}
}

func compareEndpoints(endpointsCached map[string]k8sproxy.Endpoint, endpointsInstalled []k8sproxy.Endpoint) (map[string]k8sproxy.Endpoint, map[string]k8sproxy.Endpoint, []k8sproxy.Endpoint) {
	// Map endpointsToCache is used to store the Endpoints actually installed.
	endpointsToCache := map[string]k8sproxy.Endpoint{}
	// Map endpointsToRemove is used to store the Endpoints that should be removed.
	endpointsToRemove := map[string]k8sproxy.Endpoint{}
	// Slice newEndpoints is used to store the Endpoints that are newly installed.
	var newEndpoints []k8sproxy.Endpoint

	// Copy every Endpoint in endpointsCached to endpointsToRemove. After removing all actually installed Endpoints,
	// only stale Endpoints are left.
	for endpointString, endpoint := range endpointsCached {
		endpointsToRemove[endpointString] = endpoint
	}

	for _, endpoint := range endpointsInstalled {
		// Add the Endpoint to map endpointsToCache since Endpoints in endpointsInstalled are actually installed Endpoints.
		endpointsToCache[endpoint.String()] = endpoint
		// If the Endpoint is in the map endpointsCached, then it is not newly installed, remove it from map endpointsToRemove;
		// otherwise, add it to slice newEndpoints.
		if _, exists := endpointsCached[endpoint.String()]; exists {
			delete(endpointsToRemove, endpoint.String())
		} else {
			newEndpoints = append(newEndpoints, endpoint)
		}
	}
	return endpointsToCache, endpointsToRemove, newEndpoints
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
	p.endpointsChanges.Update(p.endpointsMap, p.numLocalEndpoints)
	serviceUpdateResult := p.serviceChanges.Update(p.serviceMap)

	p.removeStaleServices()
	p.installServices()

	if p.serviceHealthServer != nil {
		if err := p.serviceHealthServer.SyncServices(serviceUpdateResult.HCServiceNodePorts); err != nil {
			klog.ErrorS(err, "Error syncing healthcheck Services")
		}
		if err := p.serviceHealthServer.SyncEndpoints(p.numLocalEndpoints); err != nil {
			klog.ErrorS(err, "Error syncing healthcheck Endpoints")
		}
	}

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

func (p *proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	if p.endpointsChanges.OnEndpointSliceUpdate(endpointSlice, false) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) {
	if p.endpointsChanges.OnEndpointSliceUpdate(newEndpointSlice, false) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
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

// OnNodeAdd is called whenever creation of new node object
// is observed.
func (p *proxier) OnNodeAdd(node *corev1.Node) {
	if node.Name != p.hostname {
		return
	}

	if reflect.DeepEqual(p.nodeLabels, node.Labels) {
		return
	}

	p.serviceEndpointsMapsMutex.Lock()
	p.nodeLabels = map[string]string{}
	for k, v := range node.Labels {
		p.nodeLabels[k] = v
	}
	p.serviceEndpointsMapsMutex.Unlock()
	klog.V(4).InfoS("Updated proxier Node labels", "labels", node.Labels)

	p.syncProxyRules()
}

// OnNodeUpdate is called whenever modification of an existing
// node object is observed.
func (p *proxier) OnNodeUpdate(oldNode, node *corev1.Node) {
	if node.Name != p.hostname {
		return
	}

	if reflect.DeepEqual(p.nodeLabels, node.Labels) {
		return
	}

	p.serviceEndpointsMapsMutex.Lock()
	p.nodeLabels = map[string]string{}
	for k, v := range node.Labels {
		p.nodeLabels[k] = v
	}
	p.serviceEndpointsMapsMutex.Unlock()
	klog.V(4).InfoS("Updated proxier Node labels", "labels", node.Labels)

	p.syncProxyRules()
}

// OnNodeDelete is called whenever deletion of an existing node
// object is observed.
func (p *proxier) OnNodeDelete(node *corev1.Node) {
	if node.Name != p.hostname {
		return
	}
	p.serviceEndpointsMapsMutex.Lock()
	p.nodeLabels = nil
	p.serviceEndpointsMapsMutex.Unlock()

	p.syncProxyRules()
}

// OnNodeSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (p *proxier) OnNodeSynced() {
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
			if p.topologyAwareHintsEnabled {
				go p.nodeConfig.Run(stopCh)
			}
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
	namespacedName := apimachinerytypes.NamespacedName{Namespace: namespace, Name: serviceName}
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

		if groupID, ok := p.groupCounter.Get(svcPortName, false); ok {
			groups = append(groups, groupID)
		}
		if groupID, ok := p.groupCounter.Get(svcPortName, true); ok {
			groups = append(groups, groupID)
		}
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
	skipServices []string,
	proxyLoadBalancerIPs bool,
	groupCounter types.GroupCounter,
	supportNestedService bool) *proxier {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	metrics.Register()
	klog.V(2).Infof("Creating proxier with IPv6 enabled=%t", isIPv6)

	endpointSliceEnabled := features.DefaultFeatureGate.Enabled(features.EndpointSlice)
	topologyAwareHintsEnabled := endpointSliceEnabled && features.DefaultFeatureGate.Enabled(features.TopologyAwareHints)
	ipFamily := corev1.IPv4Protocol
	if isIPv6 {
		ipFamily = corev1.IPv6Protocol
	}

	var serviceHealthServer healthcheck.ServiceHealthServer
	if proxyAllEnabled {
		nodePortAddressesString := make([]string, len(nodePortAddresses))
		for i, address := range nodePortAddresses {
			nodePortAddressesString[i] = address.String()
		}
		serviceHealthServer = healthcheck.NewServiceHealthServer(hostname, nil, nodePortAddressesString)
	}

	p := &proxier{
		serviceConfig:             config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:          newEndpointsChangesTracker(hostname, endpointSliceEnabled, isIPv6),
		serviceChanges:            newServiceChangesTracker(recorder, ipFamily, skipServices),
		serviceMap:                k8sproxy.ServiceMap{},
		serviceInstalledMap:       k8sproxy.ServiceMap{},
		endpointsInstalledMap:     types.EndpointsMap{},
		endpointsMap:              types.EndpointsMap{},
		endpointReferenceCounter:  map[string]int{},
		nodeLabels:                map[string]string{},
		serviceStringMap:          map[string]k8sproxy.ServicePortName{},
		groupCounter:              groupCounter,
		ofClient:                  ofClient,
		routeClient:               routeClient,
		nodePortAddresses:         nodePortAddresses,
		isIPv6:                    isIPv6,
		proxyAll:                  proxyAllEnabled,
		endpointSliceEnabled:      endpointSliceEnabled,
		topologyAwareHintsEnabled: topologyAwareHintsEnabled,
		proxyLoadBalancerIPs:      proxyLoadBalancerIPs,
		hostname:                  hostname,
		serviceHealthServer:       serviceHealthServer,
		numLocalEndpoints:         map[apimachinerytypes.NamespacedName]int{},
		supportNestedService:      supportNestedService,
	}

	p.serviceConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, 2)
	if endpointSliceEnabled {
		p.endpointSliceConfig = config.NewEndpointSliceConfig(informerFactory.Discovery().V1().EndpointSlices(), resyncPeriod)
		p.endpointSliceConfig.RegisterEventHandler(p)
		if p.topologyAwareHintsEnabled {
			p.nodeConfig = config.NewNodeConfig(informerFactory.Core().V1().Nodes(), resyncPeriod)
			p.nodeConfig.RegisterEventHandler(p)
		}
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
	skipServices []string,
	proxyLoadBalancerIPs bool,
	v4groupCounter types.GroupCounter,
	v6groupCounter types.GroupCounter,
	nestedServiceSupport bool) *metaProxierWrapper {

	// Create an IPv4 instance of the single-stack proxier.
	ipv4Proxier := NewProxier(hostname, informerFactory, ofClient, false, routeClient, nodePortAddressesIPv4, proxyAllEnabled, skipServices, proxyLoadBalancerIPs, v4groupCounter, nestedServiceSupport)

	// Create an IPv6 instance of the single-stack proxier.
	ipv6Proxier := NewProxier(hostname, informerFactory, ofClient, true, routeClient, nodePortAddressesIPv6, proxyAllEnabled, skipServices, proxyLoadBalancerIPs, v6groupCounter, nestedServiceSupport)

	// Create a meta-proxier that dispatch calls between the two
	// single-stack proxier instances.
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)

	return &metaProxierWrapper{ipv4Proxier, ipv6Proxier, metaProxier}
}
