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
	// represented by an uint16 in the OpenFlow protocol,
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
	hostGateWay               string
	hostname                  string
	isIPv6                    bool
	proxyAll                  bool
	endpointSliceEnabled      bool
	proxyLoadBalancerIPs      bool
	topologyAwareHintsEnabled bool
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
		klog.V(2).InfoS("Removing stale Service", "Service", svcPortName, "ServiceInfo", svcInfo)

		// Remove ClusterIP flows.
		if err := p.removeClusterIPFlows(svcInfo); err != nil {
			klog.ErrorS(err, "Failed to remove ClusterIP flows", "Service", svcPortName, "ServiceInfo", svcInfo)
			continue
		}
		klog.V(2).InfoS("ClusterIP flows have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)

		// Remove NodePort flows and ipsets.
		if p.proxyAll && svcInfo.NodePort() > 0 {
			if err := p.uninstallNodePortService(svcInfo); err != nil {
				klog.ErrorS(err, "Failed to remove NodePort flows and ipsets", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			klog.V(2).InfoS("NodePort flows and ipsets have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
		}
		// Remove LoadBalancer flows and routes.
		if p.proxyLoadBalancerIPs && len(svcInfo.LoadBalancerIPStrings()) > 0 {
			if err := p.uninstallLoadBalancerService(svcInfo); err != nil {
				klog.ErrorS(err, "Failed to remove LoadBalancer flows and routes", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			klog.V(2).InfoS("LoadBalancer flows and routes have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
		}
		// Remove Service group which has only local Endpoints if existing.
		if groupID, exist := p.groupCounter.Get(svcPortName, true); exist {
			if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
				klog.ErrorS(err, "Failed to remove group which has only local Endpoints", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			p.groupCounter.Recycle(svcPortName, true)
			klog.V(2).InfoS("Group that has only local Endpoints has been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
		}
		// Remove Service group which has all Endpoints if existing.
		if groupID, exist := p.groupCounter.Get(svcPortName, false); exist {
			if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
				klog.ErrorS(err, "Failed to remove group which has all Endpoints", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			p.groupCounter.Recycle(svcPortName, false)
			klog.V(2).InfoS("Group that has all Endpoints has been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
		}

		delete(p.serviceInstalledMap, svcPortName)
		p.deleteServiceByIP(svcInfo.String())
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

func (p *proxier) uninstallNodePortService(svcInfo *types.ServiceInfo) error {
	svcIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6 {
		svcIP = agentconfig.VirtualNodePortDNATIPv6
	}
	if err := p.removeNodePortFlows(svcIP, svcInfo); err != nil {
		return err
	}
	if err := p.removeNodePortIPSets(svcInfo); err != nil {
		return err
	}
	return nil
}

func (p *proxier) uninstallLoadBalancerService(svcInfo *types.ServiceInfo) error {
	loadBalancerIPStrings := svcInfo.LoadBalancerIPStrings()
	if err := p.removeLoadBalancerFlows(loadBalancerIPStrings, svcInfo); err != nil {
		return err
	}
	if p.proxyAll && len(loadBalancerIPStrings) > 0 {
		if err := p.removeLoadBalancerRoutes(loadBalancerIPStrings); err != nil {
			return err
		}
	}

	return nil
}

// updateEndpoints updates Endpoint OVS flows and groups for a Service.
func (p *proxier) updateEndpoints(pSvcInfo,
	svcInfo *types.ServiceInfo,
	svcPortName k8sproxy.ServicePortName,
	allEndpointUpdateList,
	localEndpointUpdateList []k8sproxy.Endpoint,
	endpointsInstalled map[string]k8sproxy.Endpoint) error {
	internalNodeLocal := svcInfo.NodeLocalInternal()
	externalNodeLocal := svcInfo.NodeLocalExternal()
	affinityTimeout := getAffinityTimeout(pSvcInfo, svcInfo, svcPortName)
	var endpointUpdateList []k8sproxy.Endpoint
	// If the type of the Service is NodePort or LoadBalancer and both internalTrafficPolicy and externalTrafficPolicy
	// are Local, or the type of the Service is ClusterIP and internalTrafficPolicy is Local, then only local
	// Endpoints should be installed, otherwise all Endpoints should be installed.
	if internalNodeLocal && (externalNodeLocal || svcInfo.NodePort() == 0) {
		endpointUpdateList = localEndpointUpdateList
	} else {
		endpointUpdateList = allEndpointUpdateList
	}
	// Install Endpoint flows.
	err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpointUpdateList)
	if err != nil {
		return fmt.Errorf("error when installing Endpoint flows: %w", err)
	}
	if internalNodeLocal != externalNodeLocal {
		if svcInfo.NodePort() > 0 {
			// If the type of the Service is NodePort or LoadBalancer, when internalTrafficPolicy and externalTrafficPolicy
			// of the Service are different, install two groups. One group has all Endpoints, the other has only
			// local Endpoints.
			groupID := p.groupCounter.AllocateIfNotExist(svcPortName, true)
			if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, localEndpointUpdateList); err != nil {
				return fmt.Errorf("error when installing group which only has local Endpoints: %w", err)
			}
			groupID = p.groupCounter.AllocateIfNotExist(svcPortName, false)
			if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, allEndpointUpdateList); err != nil {
				return fmt.Errorf("error when installing group which has all Endpoints: %w", err)
			}
		} else {
			// If the type of the Service is ClusterIP, install a group according to internalTrafficPolicy.
			groupID := p.groupCounter.AllocateIfNotExist(svcPortName, internalNodeLocal)
			if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, endpointUpdateList); err != nil {
				return fmt.Errorf("error when installing group: %w", err)
			}
			// Regardless of the value of internalTrafficPolicy, unconditionally uninstall the another group which is
			// got by the opposite value of internalTrafficPolicy if it exists.
			if groupID, exist := p.groupCounter.Get(svcPortName, !internalNodeLocal); exist {
				if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
					return fmt.Errorf("error when uninstalling stale group: %w", err)
				}
				p.groupCounter.Recycle(svcPortName, !internalNodeLocal)
			}
		}
	} else {
		// Regardless of the type of the Service, when internalTrafficPolicy and externalTrafficPolicy of the Service
		// are the same, only install one group and unconditionally uninstall another group. If both internalTrafficPolicy
		// and externalTrafficPolicy are Local, install the group that has only local Endpoints and unconditionally
		// uninstall the group which has all Endpoints; if both internalTrafficPolicy and externalTrafficPolicy are
		// Cluster, install the group which has all Endpoints and unconditionally uninstall the group which has
		// only local Endpoints. Note that, if a group doesn't exist on OVS, then the return value will be nil.
		nodeLocalVal := internalNodeLocal && externalNodeLocal
		groupID := p.groupCounter.AllocateIfNotExist(svcPortName, nodeLocalVal)
		if err = p.ofClient.InstallServiceGroup(groupID, affinityTimeout != 0, endpointUpdateList); err != nil {
			return fmt.Errorf("error when installing group: %w", err)
		}
		if groupID, exist := p.groupCounter.Get(svcPortName, !nodeLocalVal); exist {
			if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
				return fmt.Errorf("error when uninstalling stale group: %w", err)
			}
			p.groupCounter.Recycle(svcPortName, !nodeLocalVal)
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
	return nil
}

// removeClusterIPFlows removes ClusterIP OVS flows for a Service.
func (p *proxier) removeClusterIPFlows(svcInfo *types.ServiceInfo) error {
	if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
		return fmt.Errorf("error when uninstalling ClusterIP flows: %w", err)
	}
	return nil
}

// updateClusterIPFlows updates ClusterIP OVS flows for a Service. The flows are used to do service LB in OVS.
func (p *proxier) updateClusterIPFlows(pSvcInfo, svcInfo *types.ServiceInfo, svcPortName k8sproxy.ServicePortName) error {
	if pSvcInfo != nil {
		if err := p.removeClusterIPFlows(pSvcInfo); err != nil {
			return err
		}
	}
	groupID := p.groupCounter.AllocateIfNotExist(svcPortName, svcInfo.NodeLocalInternal())
	if err := p.ofClient.InstallServiceFlows(groupID,
		svcInfo.ClusterIP(),
		uint16(svcInfo.Port()),
		svcInfo.OFProtocol,
		getAffinityTimeout(pSvcInfo, svcInfo, svcPortName),
		svcInfo.NodeLocalExternal(),
		corev1.ServiceTypeClusterIP); err != nil {
		return fmt.Errorf("error when installing ClusterIP flows : %w", err)
	}
	return nil
}

// updateClusterIPRoutes updates ClusterIP routes for a Service. The routes are used to forward ClusterIP traffic to
// OVS via Antrea gateway.
func (p *proxier) updateClusterIPRoutes(pSvcInfo, svcInfo *types.ServiceInfo) error {
	if err := p.routeClient.AddClusterIPRoute(svcInfo.ClusterIP()); err != nil {
		return fmt.Errorf("error when installing CluterIP route: %w", err)
	}
	if pSvcInfo != nil {
		if err := p.routeClient.DeleteClusterIPRoute(pSvcInfo.ClusterIP()); err != nil {
			return fmt.Errorf("error when uninstalling stale CluterIP route: %w", err)
		}
	}
	return nil
}

// removeNodePortFlows removes NodePort OVS flows for a Service.
func (p *proxier) removeNodePortFlows(svcIP net.IP, svcInfo *types.ServiceInfo) error {
	if err := p.ofClient.UninstallServiceFlows(svcIP, uint16(svcInfo.NodePort()), svcInfo.OFProtocol); err != nil {
		return fmt.Errorf("error when uninstalling NodePort flows: %w", err)
	}
	return nil
}

// updateNodePortFlows updates NodePort OVS flows for a Service. The flows are used to do service LB in OVS.
func (p *proxier) updateNodePortFlows(pSvcInfo, svcInfo *types.ServiceInfo, svcPortName k8sproxy.ServicePortName) error {
	svcIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6 {
		svcIP = agentconfig.VirtualNodePortDNATIPv6
	}
	if pSvcInfo != nil {
		if err := p.removeNodePortFlows(svcIP, pSvcInfo); err != nil {
			return err
		}
	}
	groupID := p.groupCounter.AllocateIfNotExist(svcPortName, svcInfo.NodeLocalExternal())
	if err := p.ofClient.InstallServiceFlows(groupID,
		svcIP,
		uint16(svcInfo.NodePort()),
		svcInfo.OFProtocol,
		getAffinityTimeout(pSvcInfo, svcInfo, svcPortName),
		svcInfo.NodeLocalExternal(),
		corev1.ServiceTypeNodePort); err != nil {
		return fmt.Errorf("error when installing NodePort flows: %w", err)
	}
	return nil
}

// removeNodePortIPSets removes ClusterIP ipsets for a Service.
func (p *proxier) removeNodePortIPSets(svcInfo *types.ServiceInfo) error {
	if err := p.routeClient.DeleteNodePort(p.nodePortAddresses, uint16(svcInfo.NodePort()), svcInfo.OFProtocol); err != nil {
		return fmt.Errorf("error when uninstalling stale NodePort ipsets: %w", err)
	}
	return nil
}

// updateNodePortIPSets updates ClusterIP ipsets for a Service. The ipsets are used to match NodePort traffic, and they
// are used in iptables to forward matched traffic to OVS via Antrea gateway.
func (p *proxier) updateNodePortIPSets(pSvcInfo, svcInfo *types.ServiceInfo) error {
	if err := p.routeClient.AddNodePort(p.nodePortAddresses, uint16(svcInfo.NodePort()), svcInfo.OFProtocol); err != nil {
		return fmt.Errorf("error when installing NodePort ipsets: %w", err)
	}
	if pSvcInfo != nil {
		if err := p.removeNodePortIPSets(pSvcInfo); err != nil {
			return err
		}
	}
	return nil
}

// removeLoadBalancerFlows removes LoadBalancer OVS flows for a Service.
func (p *proxier) removeLoadBalancerFlows(toDeleteLoadBalancerIPs []string, svcInfo *types.ServiceInfo) error {
	for _, ingress := range toDeleteLoadBalancerIPs {
		if err := p.ofClient.UninstallServiceFlows(net.ParseIP(ingress), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
			return fmt.Errorf("error when uninstalling stale LoadBalancer flows: %w", err)
		}
	}
	return nil
}

// updateLoadBalancerFlows updates LoadBalancer OVS flows for a Service. The flows are used to do service LB in OVS.
func (p *proxier) updateLoadBalancerFlows(pSvcInfo, svcInfo *types.ServiceInfo, svcPortName k8sproxy.ServicePortName, needUpdateAllFlows bool) error {
	var toAddLoadBalancerIPs, toDeleteLoadBalancerIPs []string
	if pSvcInfo != nil {
		if needUpdateAllFlows {
			// When all flows should be updated, all stale flows should be uninstalled before installing new flows.
			toDeleteLoadBalancerIPs = pSvcInfo.LoadBalancerIPStrings()
			toAddLoadBalancerIPs = svcInfo.LoadBalancerIPStrings()
		} else {
			// When not all flows should be updated, only process the changes of LoadBalancer IPs.
			toDeleteLoadBalancerIPs = smallSliceDifference(pSvcInfo.LoadBalancerIPStrings(), svcInfo.LoadBalancerIPStrings())
			toAddLoadBalancerIPs = smallSliceDifference(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings())
		}
	} else {
		toDeleteLoadBalancerIPs = []string{}
		toAddLoadBalancerIPs = svcInfo.LoadBalancerIPStrings()
	}
	if err := p.removeLoadBalancerFlows(toDeleteLoadBalancerIPs, pSvcInfo); err != nil {
		return err
	}
	groupID := p.groupCounter.AllocateIfNotExist(svcPortName, svcInfo.NodeLocalExternal())
	for _, ingress := range toAddLoadBalancerIPs {
		if err := p.ofClient.InstallServiceFlows(groupID,
			net.ParseIP(ingress),
			uint16(svcInfo.Port()),
			svcInfo.OFProtocol,
			getAffinityTimeout(pSvcInfo, svcInfo, svcPortName),
			svcInfo.NodeLocalExternal(),
			corev1.ServiceTypeLoadBalancer); err != nil {
			return fmt.Errorf("error when installing LoadBalancer flows: %w", err)
		}
	}

	return nil
}

// removeLoadBalancerRoutes removes LoadBalancer routes for a Service.
func (p *proxier) removeLoadBalancerRoutes(toDeleteLoadBalancerIPs []string) error {
	if err := p.routeClient.DeleteLoadBalancer(toDeleteLoadBalancerIPs); err != nil {
		return fmt.Errorf("error when uninstalling stale LoadBalancer routes: %w", err)
	}
	return nil
}

// updateLoadBalancerRoutes updates LoadBalancer routes for a Service. The routes are used to forward LoadBalancer traffic
// to OVS via Antrea gateway.
func (p *proxier) updateLoadBalancerRoutes(pSvcInfo, svcInfo *types.ServiceInfo) error {
	var toAddLoadBalancerIPs, toDeleteLoadBalancerIPs []string
	if pSvcInfo != nil {
		toDeleteLoadBalancerIPs = smallSliceDifference(pSvcInfo.LoadBalancerIPStrings(), svcInfo.LoadBalancerIPStrings())
		toAddLoadBalancerIPs = smallSliceDifference(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings())
	} else {
		toDeleteLoadBalancerIPs = []string{}
		toAddLoadBalancerIPs = svcInfo.LoadBalancerIPStrings()
	}
	if err := p.routeClient.AddLoadBalancer(toAddLoadBalancerIPs); err != nil {
		return fmt.Errorf("error when installing LoadBalancer routes: %w", err)
	}
	if len(toDeleteLoadBalancerIPs) > 0 {
		if err := p.removeLoadBalancerRoutes(toDeleteLoadBalancerIPs); err != nil {
			return err
		}
	}
	return nil
}

// ifNeedUpdateClusterIPFlows returns that if ClusterIP OVS flows should be updated.
func (p *proxier) ifNeedUpdateClusterIPFlows(pSvcInfo, svcInfo *types.ServiceInfo) bool {
	// For a new ClusterIP, ClusterIP flows should be installed.
	if pSvcInfo == nil {
		return true
	}
	// When one or more ClusterIP related attributes listed below are updated, corresponding ClusterIP flows should be
	// also updated.
	// - ClusterIP:           update corresponding OVS flow matching condition "nw_dst" or "ipv6_dst".
	// - Port:                update corresponding OVS flow matching condition "tp_dst".
	// - SessionAffinityType: changes in the number of corresponding OVS flows.
	// - NodeLocalInternal:   update corresponding OVS flow action "group".
	// - StickyMaxAgeSeconds: update corresponding OVS flow action "learn" (field "hard_timeout").
	return pSvcInfo.ClusterIP().String() != svcInfo.ClusterIP().String() ||
		pSvcInfo.Port() != svcInfo.Port() ||
		pSvcInfo.NodeLocalInternal() != svcInfo.NodeLocalInternal() ||
		pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType() ||
		pSvcInfo.StickyMaxAgeSeconds() != svcInfo.StickyMaxAgeSeconds()
}

// ifNeedUpdateClusterIPRoutes returns that if ClusterIP routes should be updated. The update is only triggered by updating
// attribute ClusterIP of Service
//
//	ClusterIP.
func (p *proxier) ifNeedUpdateClusterIPRoutes(pSvcInfo, svcInfo *types.ServiceInfo) bool {
	// Without enabling proxyAll, ClusterIP routes should not be installed.
	if !p.proxyAll {
		return false
	}
	// For a new ClusterIP, ClusterIP routes should be installed.
	if pSvcInfo == nil {
		return true
	}
	return pSvcInfo.ClusterIP().String() != svcInfo.ClusterIP().String()
}

// ifNeedUpdateNodePortFlows returns that if NodePort OVS flows should be updated.
func (p *proxier) ifNeedUpdateNodePortFlows(pSvcInfo, svcInfo *types.ServiceInfo) bool {
	// Without enabling proxyAll, NodePort flows should not be installed.
	if !p.proxyAll {
		return false
	}
	// Without attribute NodePort, NodePort flows should not be installed.
	if svcInfo.NodePort() == 0 {
		return false
	}
	// For a new NodePort, NodePort flows should be installed.
	if pSvcInfo == nil {
		return true
	}
	// When one or more NodePort related attributes listed below are updated, corresponding NodePort flows should be
	// also updated.
	// - NodePort:            update corresponding OVS flow matching condition "tp_dst".
	// - SessionAffinityType: changes in the number of corresponding OVS flows.
	// - NodeLocalExternal:   update corresponding OVS flow action "group".
	// - StickyMaxAgeSeconds: update corresponding OVS flow action "learn" (field "hard_timeout").
	return pSvcInfo.NodePort() != svcInfo.NodePort() ||
		pSvcInfo.NodeLocalExternal() != svcInfo.NodeLocalExternal() ||
		pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType() ||
		pSvcInfo.StickyMaxAgeSeconds() != svcInfo.StickyMaxAgeSeconds()
}

// ifNeedUpdateNodePortIPSets returns that if NodePort ipsets should be updated. The update is only triggered by updating
// attribute NodePort of Service NodePort.
func (p *proxier) ifNeedUpdateNodePortIPSets(pSvcInfo, svcInfo *types.ServiceInfo) bool {
	// Without enabling proxyAll, NodePort ipsets should not be installed.
	if !p.proxyAll {
		return false
	}
	// Without attribute NodePort, NodePort ipsets should not be installed.
	if svcInfo.NodePort() == 0 {
		return false
	}
	// For a new NodePort, NodePort ipsets should be installed.
	if pSvcInfo == nil {
		return true
	}
	return pSvcInfo.NodePort() != svcInfo.NodePort()
}

// ifNeedUpdateLoadBalancerFlows returns that if LoadBalancer OVS flows should be updated.
func (p *proxier) ifNeedUpdateLoadBalancerFlows(pSvcInfo, svcInfo *types.ServiceInfo) (bool, bool) {
	// Without enabling proxyLoadBalancerIPs, LoadBalancer OVS flows should not be installed.
	if !p.proxyLoadBalancerIPs {
		return false, false
	}
	// Without a LoadBalancer IP, LoadBalancer OVS flows should not be installed.
	if len(svcInfo.LoadBalancerIPStrings()) == 0 {
		return false, false
	}
	// For a new LoadBalancer, only with LoadBalancer IPs, LoadBalancer OVS flows should be installed, otherwise no flow
	// should be installed.
	if pSvcInfo == nil {
		if len(svcInfo.LoadBalancerIPStrings()) > 0 {
			return true, false
		}
		return false, false
	}
	// When one or more LoadBalancer related attributes listed below are updated, corresponding LoadBalancer flows should
	// be also updated.
	// - Port:                  update corresponding OVS flow matching condition "tp_dst".
	// - SessionAffinityType:   changes in the number of corresponding OVS flows.
	// - NodeLocalExternal:     update corresponding OVS flow action "group".
	// - StickyMaxAgeSeconds:   update corresponding OVS flow action "learn" (field "hard_timeout").
	// - LoadBalancerIPStrings: changes in the number of corresponding OVS flows.

	// When one or more LoadBalancer related attributes listed below are updated, OVS flows of every LoadBalancer ingress
	// IP should be updated. Note that, every LoadBalancer ingress IP has its own corresponding OVS flows by calling
	// InstallServiceFlows.
	// - Port:                  update corresponding OVS flow matching condition "tp_dst".
	// - SessionAffinityType:   changes in the number of corresponding OVS flows.
	// - NodeLocalExternal:     update corresponding OVS flow action "group".
	// - StickyMaxAgeSeconds:   update corresponding OVS flow action "learn" (field "hard_timeout").
	deletedLoadBalancerIPs := smallSliceDifference(pSvcInfo.LoadBalancerIPStrings(), svcInfo.LoadBalancerIPStrings())
	addedLoadBalancerIPs := smallSliceDifference(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings())
	return pSvcInfo.Port() != svcInfo.Port() ||
			pSvcInfo.NodeLocalExternal() != svcInfo.NodeLocalExternal() ||
			pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType() ||
			pSvcInfo.StickyMaxAgeSeconds() != svcInfo.StickyMaxAgeSeconds() ||
			len(deletedLoadBalancerIPs) > 0 ||
			len(addedLoadBalancerIPs) > 0,
		pSvcInfo.Port() != svcInfo.Port() ||
			pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType() ||
			pSvcInfo.NodeLocalExternal() != svcInfo.NodeLocalExternal() ||
			pSvcInfo.StickyMaxAgeSeconds() != svcInfo.StickyMaxAgeSeconds()
}

// ifNeedUpdateLoadBalancerRoutes returns that if LoadBalancer routes should be updated. The update is only triggered by
// changes of LoadBalancer IPs.
func (p *proxier) ifNeedUpdateLoadBalancerRoutes(pSvcInfo, svcInfo *types.ServiceInfo) bool {
	// Without enabling proxyAll and proxyLoadBalancerIPs, LoadBalancer routes should not be installed.
	if !(p.proxyAll && p.proxyLoadBalancerIPs) {
		return false
	}
	// Without a LoadBalancer IP, LoadBalancer OVS routes should not be installed.
	if len(svcInfo.LoadBalancerIPStrings()) == 0 {
		return false
	}
	// For a new LoadBalancer, only with LoadBalancer IPs, LoadBalancer routes should be installed, otherwise no routes
	// should be installed.
	if pSvcInfo == nil {
		if len(svcInfo.LoadBalancerIPStrings()) > 0 {
			return true
		}
		return false
	}
	deletedLoadBalancerIPs := smallSliceDifference(pSvcInfo.LoadBalancerIPStrings(), svcInfo.LoadBalancerIPStrings())
	addedLoadBalancerIPs := smallSliceDifference(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings())
	return len(deletedLoadBalancerIPs) > 0 || len(addedLoadBalancerIPs) > 0
}

func (p *proxier) ifNeedUpdateEndpoints(pSvcInfo, svcInfo *types.ServiceInfo) bool {
	if pSvcInfo == nil {
		return false
	}
	return pSvcInfo.NodeLocalExternal() != svcInfo.NodeLocalExternal() ||
		pSvcInfo.NodeLocalInternal() != svcInfo.NodeLocalInternal()
}

func getAffinityTimeout(pSvcInfo, svcInfo *types.ServiceInfo, svcPortName k8sproxy.ServicePortName) uint16 {
	affinityTimeout := svcInfo.StickyMaxAgeSeconds()
	if svcInfo.StickyMaxAgeSeconds() > maxSupportedAffinityTimeout {
		// SessionAffinity timeout is implemented using a hard_timeout in OVS. hard_timeout is represented by an uint16
		// in the OpenFlow protocol, hence we cannot support timeouts greater than 65535 seconds. However, the K8s
		// Service spec allows timeout values up to 86400 seconds (https://godoc.org/k8s.io/api/core/v1#ClientIPConfig).
		// For values greater than 65535 seconds, we need to set the hard_timeout to 65535 rather than let the timeout
		// value wrap around.
		affinityTimeout = maxSupportedAffinityTimeout
		if pSvcInfo == nil || (svcInfo.StickyMaxAgeSeconds() != pSvcInfo.StickyMaxAgeSeconds()) {
			// We only log a warning when the Service hasn't been installed yet, or when the timeout has changed.
			klog.InfoS("The timeout configured for ClientIP-based session affinity exceeds the max supported value",
				"Service", svcPortName.String(),
				"timeout", svcInfo.StickyMaxAgeSeconds(),
				"maxTimeout", maxSupportedAffinityTimeout,
			)
		}
	}
	return uint16(affinityTimeout)
}

func (p *proxier) installServices() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		endpointsInstalled, ok := p.endpointsInstalledMap[svcPortName]
		if !ok {
			endpointsInstalled = map[string]k8sproxy.Endpoint{}
			p.endpointsInstalledMap[svcPortName] = endpointsInstalled
		}
		endpoints := p.endpointsMap[svcPortName]
		// Filter Endpoints with hints if feature TopologyAwareHints is enabled.
		if p.topologyAwareHintsEnabled {
			endpoints = filterEndpoints(endpoints, svcInfo, p.nodeLabels)
		}
		// If both expected Endpoints number and installed Endpoints number are 0, we don't need to take care of this Service.
		if len(endpoints) == 0 && len(endpointsInstalled) == 0 {
			continue
		}

		var pSvcInfo *types.ServiceInfo
		installedSvcPort, ok := p.serviceInstalledMap[svcPortName]
		if ok {
			pSvcInfo = installedSvcPort.(*types.ServiceInfo)
		}
		needUpdateEndpoints := p.ifNeedUpdateEndpoints(pSvcInfo, svcInfo)
		needUpdateClusterIPFlows := p.ifNeedUpdateClusterIPFlows(pSvcInfo, svcInfo)
		needUpdateClusterIPRoutes := p.ifNeedUpdateClusterIPRoutes(pSvcInfo, svcInfo)
		needUpdateNodePortFlows := p.ifNeedUpdateNodePortFlows(pSvcInfo, svcInfo)
		needUpdateNodePortIPSets := p.ifNeedUpdateNodePortIPSets(pSvcInfo, svcInfo)
		needUpdateLoadBalancerFlows, needUpdateAllLoadBalancerFlows := p.ifNeedUpdateLoadBalancerFlows(pSvcInfo, svcInfo)
		needUpdateLoadBalancerRoutes := p.ifNeedUpdateLoadBalancerRoutes(pSvcInfo, svcInfo)

		var internalNodeLocal, externalNodeLocal bool
		if svcInfo.NodeLocalInternal() {
			internalNodeLocal = true
		}
		if p.proxyAll && svcInfo.NodeLocalExternal() {
			externalNodeLocal = true
		}

		var allEndpointUpdateList, localEndpointUpdateList []k8sproxy.Endpoint
		// Check if there is any installed Endpoint which is not expected anymore. If internalTrafficPolicy and externalTrafficPolicy
		// are both Local, only local Endpoints should be installed and checked; if internalTrafficPolicy or externalTrafficPolicy
		// is Cluster, all Endpoints should be installed and checked.
		for _, endpoint := range endpoints {
			if internalNodeLocal && externalNodeLocal && endpoint.GetIsLocal() || !internalNodeLocal || !externalNodeLocal {
				if _, ok := endpointsInstalled[endpoint.String()]; !ok { // There is an expected Endpoint which is not installed.
					needUpdateEndpoints = true
				}
			}
			allEndpointUpdateList = append(allEndpointUpdateList, endpoint)
			if endpoint.GetIsLocal() {
				localEndpointUpdateList = append(localEndpointUpdateList, endpoint)
			}
		}

		// If there are expired Endpoints, Endpoints installed should be updated.
		if internalNodeLocal && externalNodeLocal && len(localEndpointUpdateList) < len(endpointsInstalled) ||
			!(internalNodeLocal && externalNodeLocal) && len(allEndpointUpdateList) < len(endpointsInstalled) {
			klog.V(2).InfoS("Some Endpoints of the Service are remove, Endpoints flows will be updated", "Service", svcPortName, "ServiceInfo", svcInfo)
			needUpdateEndpoints = true
		}

		// If neither the Service nor Endpoints of the Service need to be updated, we skip.
		if !needUpdateEndpoints &&
			!needUpdateClusterIPFlows &&
			!needUpdateClusterIPRoutes &&
			!needUpdateNodePortFlows &&
			!needUpdateNodePortIPSets &&
			!needUpdateLoadBalancerFlows &&
			!needUpdateLoadBalancerRoutes {
			continue
		}

		if pSvcInfo != nil {
			klog.V(2).InfoS("Updating Service", "Service", svcPortName, "ServiceInfo", svcInfo)
		} else {
			klog.V(2).InfoS("Installing Service", "Service", svcPortName, "ServiceInfo", svcInfo)
		}

		if needUpdateEndpoints {
			err := p.updateEndpoints(pSvcInfo,
				svcInfo,
				svcPortName,
				allEndpointUpdateList,
				localEndpointUpdateList,
				endpointsInstalled)
			if err != nil {
				klog.ErrorS(err, "Failed to update Endpoint flows and groups", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("Endpoint flows and groups have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("Endpoint flows and groups have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			}
		}

		if needUpdateClusterIPFlows {
			err := p.updateClusterIPFlows(pSvcInfo, svcInfo, svcPortName)
			if err != nil {
				klog.ErrorS(err, "Failed to update ClusterIP flows", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("ClusterIP flows have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("ClusterIP flows have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			}
		}

		if needUpdateClusterIPRoutes {
			err := p.updateClusterIPRoutes(pSvcInfo, svcInfo)
			if err != nil {
				klog.ErrorS(err, "Failed to update ClusterIP routes", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("ClusterIP routes have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("ClusterIP routes have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			}
		}

		if needUpdateNodePortFlows {
			err := p.updateNodePortFlows(pSvcInfo, svcInfo, svcPortName)
			if err != nil {
				klog.ErrorS(err, "Failed to update NodePort flows", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("NodePort flows have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("NodePort flows have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			}
		}

		if needUpdateNodePortIPSets {
			err := p.updateNodePortIPSets(pSvcInfo, svcInfo)
			if err != nil {
				klog.ErrorS(err, "Failed to update NodePort ipsets", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("NodePort ipsets have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("NodePort ipsets have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			}
		}

		if needUpdateLoadBalancerFlows {
			err := p.updateLoadBalancerFlows(pSvcInfo, svcInfo, svcPortName, needUpdateAllLoadBalancerFlows)
			if err != nil {
				klog.ErrorS(err, "Failed to update LoadBalancer flows", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("LoadBalancer flows have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("LoadBalancer flows have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			}
		}

		if needUpdateLoadBalancerRoutes {
			err := p.updateLoadBalancerRoutes(pSvcInfo, svcInfo)
			if err != nil {
				klog.ErrorS(err, "Failed to update LoadBalancer routes", "Service", svcPortName, "ServiceInfo", svcInfo)
				continue
			}
			if pSvcInfo != nil {
				klog.V(2).InfoS("LoadBalancer routes have been updated successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
			} else {
				klog.V(2).InfoS("LoadBalancer routes have been installed successfully", "Service", svcPortName, "ServiceInfo", svcInfo)
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
// GetServiceFlowKeys(), which is called by the "/ovsflows" API handler,
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

	// Protect Service and endpoints maps, which can be read by GetServiceFlowKeys().
	p.serviceEndpointsMapsMutex.Lock()
	defer p.serviceEndpointsMapsMutex.Unlock()
	p.endpointsChanges.Update(p.endpointsMap, p.numLocalEndpoints)
	serviceUpdateResult := p.serviceChanges.Update(p.serviceMap)

	p.removeStaleServices()
	p.installServices()
	p.removeStaleEndpoints()

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
	groupCounter types.GroupCounter) *proxier {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	metrics.Register()
	klog.V(2).Infof("Creating proxier with IPv6 enabled=%t", isIPv6)

	endpointSliceEnabled := features.DefaultFeatureGate.Enabled(features.EndpointSlice)
	topologyAwareHintsEnabled := features.DefaultFeatureGate.Enabled(features.TopologyAwareHints)
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
		endpointsConfig:           config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
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
	}

	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
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
	v6groupCounter types.GroupCounter) *metaProxierWrapper {

	// Create an IPv4 instance of the single-stack proxier.
	ipv4Proxier := NewProxier(hostname, informerFactory, ofClient, false, routeClient, nodePortAddressesIPv4, proxyAllEnabled, skipServices, proxyLoadBalancerIPs, v4groupCounter)

	// Create an IPv6 instance of the single-stack proxier.
	ipv6Proxier := NewProxier(hostname, informerFactory, ofClient, true, routeClient, nodePortAddressesIPv6, proxyAllEnabled, skipServices, proxyLoadBalancerIPs, v6groupCounter)

	// Create a meta-proxier that dispatch calls between the two
	// single-stack proxier instances.
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)

	return &metaProxierWrapper{ipv4Proxier, ipv6Proxier, metaProxier}
}
