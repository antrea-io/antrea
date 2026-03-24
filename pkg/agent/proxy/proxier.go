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
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	agentconfig "antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/nodeip"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	"antrea.io/antrea/v2/pkg/agent/proxy/metrics"
	"antrea.io/antrea/v2/pkg/agent/proxy/types"
	"antrea.io/antrea/v2/pkg/agent/route"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	antreaconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/features"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/v2/third_party/proxy"
	"antrea.io/antrea/v2/third_party/proxy/config"
	"antrea.io/antrea/v2/third_party/proxy/healthcheck"
	"antrea.io/antrea/v2/third_party/proxy/metaproxier"
	"antrea.io/antrea/v2/third_party/proxy/runner"
	utilproxy "antrea.io/antrea/v2/third_party/proxy/util"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
	// SessionAffinity timeout is implemented using a hard_timeout in OVS. hard_timeout is
	// represented by a uint16 in the OpenFlow protocol.
	maxSupportedAffinityTimeout = math.MaxUint16
	// labelServiceProxyName is the well-known label for service proxy name defined in
	// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/2447-Make-kube-proxy-service-abstraction-optional
	labelServiceProxyName = "service.kubernetes.io/service-proxy-name"
)

// Proxier extends the standard k8sproxy.Provider interface with additional query capabilities defined in interface
// ProxyQuerier. It serves as an enhanced proxy provider implementation without modifying the original k8sproxy.Provider
// interface.
type Proxier interface {
	k8sproxy.Provider
	ProxyQuerier
}

// ProxyQuerier is the query interface for retrieving information from the Proxy.
type ProxyQuerier interface {
	// GetServiceFlowKeys returns the keys (match strings) of the cached OVS
	// flows and the OVS group IDs for a Service. False is returned if the
	// Service is not found.
	GetServiceFlowKeys(serviceName, namespace string) ([]string, []binding.GroupIDType, bool)
	// GetServiceByIP returns the ServicePortName struct for the given serviceString(ClusterIP:Port/Proto).
	// False is returned if the serviceString is not found in serviceStringMap.
	GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool)
}

type ProxyServer struct {
	endpointSliceConfig *config.EndpointSliceConfig
	serviceConfig       *config.ServiceConfig
	nodeConfig          *config.NodeConfig

	nodeManager   *k8sproxy.NodeManager
	healthzServer *healthcheck.ProxyHealthServer
	ofClient      openflow.Client
	proxier       Proxier
}

type proxier struct {
	// mu protects the fields below, which can be read by GetServiceFlowKeys() called by the "/ovsflows" API handler.
	mu sync.Mutex
	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since last syncProxyRules call. For a single object,
	// changes are accumulated. Once both endpointsChanges and serviceChanges
	// have been synced, syncProxyRules will start syncing rules to OVS.
	endpointsChanges *endpointsChangesTracker
	serviceChanges   *serviceChangesTracker
	topologyLabels   map[string]string
	nodeIPChecker    nodeip.Checker
	// serviceMap stores services we expect to be installed.
	serviceMap k8sproxy.ServicePortMap
	// serviceInstalledMap stores services we actually installed.
	serviceInstalledMap k8sproxy.ServicePortMap
	// endpointsMap stores endpoints we expect to be installed.
	endpointsMap k8sproxy.EndpointsMap
	// endpointsInstalledMap stores endpoints we actually installed.
	endpointsInstalledMap k8sproxy.EndpointsMap
	// endpointReferenceCounter stores the number of times an Endpoint is referenced by Services.
	endpointReferenceCounter map[string]int
	// groupCounter is used to allocate groupID.
	groupCounter types.GroupCounter

	ipToServiceMap      *ipToServiceMap
	serviceHealthServer healthcheck.ServiceHealthServer
	healthzServer       *healthcheck.ProxyHealthServer

	// syncedOnce returns true if the proxier has synced rules at least once.
	syncedOnce      bool
	syncedOnceMutex sync.RWMutex

	runner                               *runner.BoundedFrequencyRunner
	stopChan                             <-chan struct{}
	ofClient                             openflow.Client
	routeClient                          route.Interface
	nodePortAddresses                    []net.IP
	hostname                             string
	ipFamily                             corev1.IPFamily
	proxyAll                             bool
	proxyLoadBalancerIPs                 bool
	preferSameTrafficDistributionEnabled bool
	supportNestedService                 bool
	cleanupStaleUDPSvcConntrack          bool

	// When a Service's LoadBalancerMode is DSR, the following changes will be applied to the OpenFlow flows and groups:
	// 1. ClusterGroup will be used by traffic working in DSR mode on ingress Node.
	//   * If a local Endpoint is selected, it will just be handled normally as DSR is not applicable in this case.
	//   * If a remote Endpoint is selected, it will be sent to the backend Node that hosts the Endpoint without being
	//     NAT'd, the eventual Endpoint will be determined on the backend Node and may be different from the one
	//     selected here.
	// 2. LocalGroup will be used by traffic working in DSR mode on backend Node. In this way, each Endpoint has the
	//    same chance to be selected eventually.
	// 3. Traffic working in DSR mode on ingress Node will be marked and treated specially, e.g. bypassing SNAT.
	// 4. Learned flow will be created for each connection to ensure consistent load balance decision for a connection of DSR mode.
	//
	// Learned flow is necessary because connections of DSR mode will remain invalid on ingress Node as it can only see
	// requests and not responses. And OVS doesn't provide ct_state and ct_label for invalid connections. Thus, we can't
	// store the load balance decision of the connection to ct_state or ct_label. To ensure consistent load balancing
	// decision for packets of a connection, we use "learn" action to generate a learned flow when processing the first
	// packet of a connection, and rely on the learned flow to process subsequent packets of the same connection.
	defaultLoadBalancerMode agentconfig.LoadBalancerMode
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
	// When LoadBalancerModeDSR is enabled, we wait for NodeIPChecker to be initialized before processing any Service, to
	// ensure we get correct result when checking if an Endpoint is running in host network.
	if features.DefaultFeatureGate.Enabled(features.LoadBalancerModeDSR) {
		if !p.nodeIPChecker.HasSynced() {
			return false
		}
	}
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
		if !p.removeServiceFlows(svcInfo) {
			continue
		}
		// Remove Service group which has only local Endpoints.
		if !p.removeServiceGroup(svcPortName, true) {
			continue
		}
		// Remove Service group which has all Endpoints.
		if !p.removeServiceGroup(svcPortName, false) {
			continue
		}
		// Remove associated Endpoints flows.
		if endpoints, ok := p.endpointsInstalledMap[svcPortName]; ok {
			if !p.removeStaleEndpoints(svcPortName, svcInfo.OFProtocol, endpoints) {
				continue
			}
			delete(p.endpointsInstalledMap, svcPortName)
		}
		if p.cleanupStaleUDPSvcConntrack && needClearConntrackEntries(svcInfo.OFProtocol) {
			if !p.removeStaleServiceConntrackEntries(svcPortName, svcInfo) {
				continue
			}
		}

		delete(p.serviceInstalledMap, svcPortName)
		p.ipToServiceMap.delete(svcInfo)
	}
}

func (p *proxier) removeServiceFlows(svcInfo *types.ServiceInfo) bool {
	svcInfoStr := svcInfo.String()
	svcPort := uint16(svcInfo.Port())
	svcProto := svcInfo.OFProtocol
	// Remove ClusterIP flows.
	if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), svcPort, svcProto); err != nil {
		klog.ErrorS(err, "Error when uninstalling ClusterIP flows for Service", "ServiceInfo", svcInfoStr)
		return false
	}

	if p.proxyAll {
		// Remove NodePort flows and configurations.
		if err := p.uninstallNodePortService(uint16(svcInfo.NodePort()), svcProto); err != nil {
			klog.ErrorS(err, "Error when uninstalling NodePort flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
		// Remove ExternalIP flows and configurations.
		if err := p.uninstallExternalIPService(svcInfoStr, svcInfo.ExternalIPs(), svcPort, svcProto); err != nil {
			klog.ErrorS(err, "Error when uninstalling ExternalIP flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	// Remove LoadBalancer flows and configurations.
	if p.proxyLoadBalancerIPs {
		if err := p.uninstallLoadBalancerService(svcInfoStr, svcInfo.LoadBalancerVIPs(), svcPort, svcProto); err != nil {
			klog.ErrorS(err, "Error when uninstalling LoadBalancer flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	return true
}

func (p *proxier) installServiceGroup(svcPortName k8sproxy.ServicePortName, needUpdate, local, withSessionAffinity bool, endpoints []k8sproxy.Endpoint) (binding.GroupIDType, bool) {
	groupID, exists := p.groupCounter.Get(svcPortName, local)
	if exists && !needUpdate {
		return groupID, true
	}
	success := false
	if !exists {
		groupID = p.groupCounter.AllocateIfNotExist(svcPortName, local)
		// If the installation of the group fails, recycle it.
		defer func() {
			if !success {
				p.groupCounter.Recycle(svcPortName, local)
			}
		}()
	}
	if err := p.ofClient.InstallServiceGroup(groupID, withSessionAffinity, endpoints); err != nil {
		klog.ErrorS(err, "Error when installing group of Endpoints for Service", "ServicePortName", svcPortName, "local", local)
		return 0, false
	}
	success = true
	return groupID, true
}

func (p *proxier) removeServiceGroup(svcPortName k8sproxy.ServicePortName, local bool) bool {
	if groupID, exist := p.groupCounter.Get(svcPortName, local); exist {
		if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
			klog.ErrorS(err, "Error when uninstalling group of Endpoints for Service", "ServicePortName", svcPortName, "local", local)
			return false
		}
		p.groupCounter.Recycle(svcPortName, local)
	}
	return true
}

// removeStaleEndpoints removes flows for the given Endpoints from the data path if these flows are no longer
// needed by any Service. Endpoints from different Services can have the same characteristics and thus
// can share the same flows. removeStaleEndpoints must be called whenever Endpoints are no longer used by a
// given Service. If the Endpoints are still referenced by any other Services, no flow will be removed.
// The method only returns an error if a data path operation fails. If the flows are successfully
// removed from the data path, the method returns nil.
func (p *proxier) removeStaleEndpoints(svcPortName k8sproxy.ServicePortName, protocol binding.Protocol, staleEndpoints map[string]k8sproxy.Endpoint) bool {
	var endpointsToRemove []k8sproxy.Endpoint

	// Get all Endpoints whose reference counter is 1, and these Endpoints should be removed.
	for _, endpoint := range staleEndpoints {
		key := endpointKey(endpoint, protocol)
		count := p.endpointReferenceCounter[key]
		if count == 1 {
			endpointsToRemove = append(endpointsToRemove, endpoint)
			klog.V(2).InfoS("Endpoint will be removed", "Endpoint", endpoint.String(), "Protocol", protocol)
		}
	}

	// Remove flows for these Endpoints.
	if len(endpointsToRemove) != 0 {
		if err := p.ofClient.UninstallEndpointFlows(protocol, endpointsToRemove); err != nil {
			klog.ErrorS(err, "Error when removing flows of stale Endpoints for Service", "ServicePortName", svcPortName)
			return false
		}
	}

	// Update the reference counter of Endpoints and remove them from the installed Endpoints of the ServicePortName.
	for _, endpoint := range staleEndpoints {
		key := endpointKey(endpoint, protocol)
		count := p.endpointReferenceCounter[key]
		if count == 1 {
			delete(p.endpointReferenceCounter, key)
			klog.V(2).InfoS("Endpoint was removed", "Endpoint", endpoint.String(), "Protocol", protocol)
		} else {
			p.endpointReferenceCounter[key] = count - 1
			klog.V(2).InfoS("Stale Endpoint is still referenced by other Services, decrementing reference count by 1", "Endpoint", endpoint.String(), "Protocol", protocol)
		}
		delete(p.endpointsInstalledMap[svcPortName], endpoint.String())
	}

	return true
}

func (p *proxier) removeStaleServiceConntrackEntries(svcPortName k8sproxy.ServicePortName, svcInfo *types.ServiceInfo) bool {
	svcPort := uint16(svcInfo.Port())
	nodePort := uint16(svcInfo.NodePort())
	svcProto := svcInfo.OFProtocol
	virtualNodePortDNATIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6() {
		virtualNodePortDNATIP = agentconfig.VirtualNodePortDNATIPv6
	}

	svcIPToPort := make(map[string]uint16)
	svcIPToPort[svcInfo.ClusterIP().String()] = svcPort
	for _, ip := range svcInfo.ExternalIPs() {
		svcIPToPort[ip.String()] = svcPort
	}
	for _, ip := range svcInfo.LoadBalancerVIPs() {
		svcIPToPort[ip.String()] = svcPort
	}
	if nodePort > 0 {
		for _, nodeIP := range p.nodePortAddresses {
			svcIPToPort[nodeIP.String()] = nodePort
		}
		svcIPToPort[virtualNodePortDNATIP.String()] = nodePort
	}

	// Clean up the UDP conntrack entries matching the stale Service IPs and ports. For a UDP Service without Endpoint,
	// no UDP conntrack entry will have been generated, but there is no harm in calling this function.
	for svcIPStr, port := range svcIPToPort {
		svcIP := net.ParseIP(svcIPStr)
		if err := p.routeClient.ClearConntrackEntryForService(svcIP, port, nil, svcProto); err != nil {
			klog.ErrorS(err, "Error when removing conntrack for Service", "ServicePortName", svcPortName, "ServiceIP", svcIP, "ServicePort", port)
			return false
		}
	}

	return true
}

func (p *proxier) removeStaleConntrackEntries(svcPortName k8sproxy.ServicePortName, pSvcInfo, svcInfo *types.ServiceInfo, staleEndpoints map[string]k8sproxy.Endpoint) bool {
	pSvcPort := uint16(pSvcInfo.Port())
	svcPort := uint16(svcInfo.Port())
	pNodePort := uint16(pSvcInfo.NodePort())
	nodePort := uint16(svcInfo.NodePort())
	pClusterIP := pSvcInfo.ClusterIP().String()
	clusterIP := svcInfo.ClusterIP().String()
	pExternalIPs := pSvcInfo.ExternalIPs()
	externalIPs := svcInfo.ExternalIPs()
	pLoadBalancerIPs := pSvcInfo.LoadBalancerVIPs()
	loadBalancerIPs := svcInfo.LoadBalancerVIPs()
	virtualNodePortDNATIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6() {
		virtualNodePortDNATIP = agentconfig.VirtualNodePortDNATIPv6
	}
	var svcPortChanged, svcNodePortChanged bool

	staleSvcIPToPort := make(map[string]uint16)
	// If the port of the Service is changed, delete all conntrack entries related to the previous Service IPs and the
	// previous Service port. These previous Service IPs includes external IPs, loadBalancer IPs and the ClusterIP.
	if pSvcPort != svcPort {
		staleSvcIPToPort[pClusterIP] = pSvcPort
		for _, ip := range pExternalIPs {
			staleSvcIPToPort[ip.String()] = pSvcPort
		}
		for _, ip := range pLoadBalancerIPs {
			staleSvcIPToPort[ip.String()] = pSvcPort
		}
		svcPortChanged = true
	} else {
		// If the port of the Service is not changed, delete the conntrack entries related to the stale Service IPs and
		// the Service port. These stale Service IPs could be clusterIP, externalIPs or loadBalancerIPs.
		if pClusterIP != clusterIP {
			staleSvcIPToPort[pClusterIP] = pSvcPort
		}
		deletedExternalIPs := smallSliceDifference(pExternalIPs, externalIPs)
		deletedLoadBalancerIPs := smallSliceDifference(pLoadBalancerIPs, loadBalancerIPs)
		for _, ip := range deletedExternalIPs {
			staleSvcIPToPort[ip.String()] = pSvcPort
		}
		for _, ip := range deletedLoadBalancerIPs {
			staleSvcIPToPort[ip.String()] = pSvcPort
		}
	}
	// If the NodePort of the Service is changed, delete the conntrack entries related to each of the Node IPs / the
	// virtual IP to which NodePort traffic from external will be DNATed and the Service nodePort.
	if pNodePort != nodePort {
		for _, nodeIP := range p.nodePortAddresses {
			staleSvcIPToPort[nodeIP.String()] = pNodePort
		}
		staleSvcIPToPort[virtualNodePortDNATIP.String()] = pNodePort
		svcNodePortChanged = true
	}
	// Clean up the UDP conntrack entries matching the stale Service IPs and ports.
	for svcIPStr, port := range staleSvcIPToPort {
		svcIP := net.ParseIP(svcIPStr)
		if err := p.routeClient.ClearConntrackEntryForService(svcIP, port, nil, pSvcInfo.OFProtocol); err != nil {
			klog.ErrorS(err, "Error when removing conntrack for Service", "ServicePortName", svcPortName, "ServiceIP", svcIP, "ServicePort", port)
			return false
		}
	}

	remainingSvcIPToPort := make(map[string]uint16)
	if !svcPortChanged {
		// Get all remaining Service IPs.
		remainingSvcIPToPort[clusterIP] = svcPort
		for _, ip := range smallSliceSame(pExternalIPs, externalIPs) {
			remainingSvcIPToPort[ip.String()] = svcPort
		}
		for _, ip := range smallSliceSame(pLoadBalancerIPs, loadBalancerIPs) {
			remainingSvcIPToPort[ip.String()] = svcPort
		}
	}
	if !svcNodePortChanged && nodePort > 0 {
		// Get all Node IPs.
		for _, nodeIP := range p.nodePortAddresses {
			remainingSvcIPToPort[nodeIP.String()] = nodePort
		}
	}
	// Clean up the UDP conntrack entries matching the remaining Service IPs and ports, and the stale Endpoint IPs.
	for svcIPStr, port := range remainingSvcIPToPort {
		for _, endpoint := range staleEndpoints {
			svcIP := net.ParseIP(svcIPStr)
			endpointIP := net.ParseIP(endpoint.IP())
			if err := p.routeClient.ClearConntrackEntryForService(svcIP, port, endpointIP, svcInfo.OFProtocol); err != nil {
				klog.ErrorS(err, "Error when removing conntrack for Service", "ServicePortName", svcPortName, "ServiceIP", svcIP, "ServicePort", port, "EndpointIP", endpointIP)
				return false
			}
		}
	}

	return true
}

func (p *proxier) addNewEndpoints(svcPortName k8sproxy.ServicePortName, protocol binding.Protocol, newEndpoints map[string]k8sproxy.Endpoint) bool {
	var endpointsToAdd []k8sproxy.Endpoint

	// Get all Endpoints whose reference counter is 0, and these Endpoints should be added.
	for _, endpoint := range newEndpoints {
		key := endpointKey(endpoint, protocol)
		count := p.endpointReferenceCounter[key]
		if count == 0 {
			endpointsToAdd = append(endpointsToAdd, endpoint)
			klog.V(2).InfoS("Endpoint will be added", "Endpoint", endpoint.String(), "Protocol", protocol)
		}
	}

	// Add flows for these Endpoints.
	if len(endpointsToAdd) != 0 {
		if err := p.ofClient.InstallEndpointFlows(protocol, endpointsToAdd); err != nil {
			klog.ErrorS(err, "Error when installing Endpoints flows for Service", "ServicePortName", svcPortName)
			return false
		}
	}

	// Update the reference counter of Endpoints.
	for _, endpoint := range newEndpoints {
		p.endpointsInstalledMap[svcPortName][endpoint.String()] = endpoint
		key := endpointKey(endpoint, protocol)
		p.endpointReferenceCounter[key] = p.endpointReferenceCounter[key] + 1
	}
	return true
}

func serviceIdentityChanged(svcInfo, pSvcInfo *types.ServiceInfo) bool {
	return svcInfo.ClusterIP().String() != pSvcInfo.ClusterIP().String() ||
		svcInfo.Port() != pSvcInfo.Port() ||
		svcInfo.OFProtocol != pSvcInfo.OFProtocol
}

func serviceExternalAddressesChanged(svcInfo, pSvcInfo *types.ServiceInfo) bool {
	return svcInfo.NodePort() != pSvcInfo.NodePort() ||
		len(smallSliceDifference(svcInfo.LoadBalancerVIPs(), pSvcInfo.LoadBalancerVIPs())) > 0 ||
		len(smallSliceDifference(svcInfo.ExternalIPs(), pSvcInfo.ExternalIPs())) > 0
}

// smallSliceDifference builds a slice which includes all the IPs from s1
// which are not in s2.
func smallSliceDifference(s1, s2 []net.IP) []net.IP {
	var diff []net.IP

	for _, e1 := range s1 {
		found := false
		for _, e2 := range s2 {
			if e1.Equal(e2) {
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

// smallSliceSame builds a slice which includes all the IPs are both in s1 and s2.
func smallSliceSame(s1, s2 []net.IP) []net.IP {
	var same []net.IP

	for _, e1 := range s1 {
		for _, e2 := range s2 {
			if e1.Equal(e2) {
				same = append(same, e1)
				break
			}
		}
	}

	return same
}

func (p *proxier) installNodePortService(localGroupID, clusterGroupID binding.GroupIDType, svcPort uint16, protocol binding.Protocol, trafficPolicyLocal bool, affinityTimeout uint16) error {
	if svcPort == 0 {
		return nil
	}
	svcIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6() {
		svcIP = agentconfig.VirtualNodePortDNATIPv6
	}
	if err := p.ofClient.InstallServiceFlows(&agenttypes.ServiceConfig{
		ServiceIP:          svcIP,
		ServicePort:        svcPort,
		Protocol:           protocol,
		TrafficPolicyLocal: trafficPolicyLocal,
		LocalGroupID:       localGroupID,
		ClusterGroupID:     clusterGroupID,
		AffinityTimeout:    affinityTimeout,
		IsExternal:         true,
		IsNodePort:         true,
		IsNested:           false, // Unsupported for NodePort
		IsDSR:              false, // Unsupported because external traffic has been DNAT'd in host network before it's forwarded to OVS.
	}); err != nil {
		return fmt.Errorf("failed to install NodePort load balancing OVS flows: %w", err)
	}
	if err := p.routeClient.AddNodePortConfigs(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to install NodePort traffic redirecting routing configurations: %w", err)
	}
	return nil
}

func (p *proxier) uninstallNodePortService(svcPort uint16, protocol binding.Protocol) error {
	if svcPort == 0 {
		return nil
	}
	svcIP := agentconfig.VirtualNodePortDNATIPv4
	if p.isIPv6() {
		svcIP = agentconfig.VirtualNodePortDNATIPv6
	}
	if err := p.ofClient.UninstallServiceFlows(svcIP, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to remove NodePort load balancing flows: %w", err)
	}
	if err := p.routeClient.DeleteNodePortConfigs(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to remove NodePort traffic redirecting routing configurations: %w", err)
	}
	return nil
}

func (p *proxier) installExternalIPService(svcInfoStr string,
	localGroupID,
	clusterGroupID binding.GroupIDType,
	externalIPs []net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	trafficPolicyLocal bool,
	affinityTimeout uint16,
	loadBalancerMode agentconfig.LoadBalancerMode) error {
	for _, ip := range externalIPs {
		if err := p.ofClient.InstallServiceFlows(&agenttypes.ServiceConfig{
			ServiceIP:          ip,
			ServicePort:        svcPort,
			Protocol:           protocol,
			TrafficPolicyLocal: trafficPolicyLocal,
			LocalGroupID:       localGroupID,
			ClusterGroupID:     clusterGroupID,
			AffinityTimeout:    affinityTimeout,
			IsExternal:         true,
			IsNodePort:         false,
			IsNested:           false, // Unsupported for ExternalIP
			IsDSR:              features.DefaultFeatureGate.Enabled(features.LoadBalancerModeDSR) && loadBalancerMode == agentconfig.LoadBalancerModeDSR,
		}); err != nil {
			return fmt.Errorf("failed to install ExternalIP load balancing OVS flows: %w", err)
		}
		if err := p.routeClient.AddExternalIPConfigs(svcInfoStr, ip); err != nil {
			return fmt.Errorf("failed to install ExternalIP load balancing routing configurations: %w", err)
		}
	}
	return nil
}

func (p *proxier) uninstallExternalIPService(svcInfoStr string, externalIPs []net.IP, svcPort uint16, protocol binding.Protocol) error {
	for _, ip := range externalIPs {
		if err := p.ofClient.UninstallServiceFlows(ip, svcPort, protocol); err != nil {
			return fmt.Errorf("failed to remove ExternalIP load balancing OVS flows: %w", err)
		}
		if err := p.routeClient.DeleteExternalIPConfigs(svcInfoStr, ip); err != nil {
			return fmt.Errorf("failed to remove ExternalIP traffic redirecting routing configurations: %w", err)
		}
	}
	return nil
}

func (p *proxier) installLoadBalancerService(svcInfoStr string,
	localGroupID,
	clusterGroupID binding.GroupIDType,
	loadBalancerIPs []net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	trafficPolicyLocal bool,
	affinityTimeout uint16,
	loadBalancerMode agentconfig.LoadBalancerMode) error {
	for _, ip := range loadBalancerIPs {
		if err := p.ofClient.InstallServiceFlows(&agenttypes.ServiceConfig{
			ServiceIP:          ip,
			ServicePort:        svcPort,
			Protocol:           protocol,
			TrafficPolicyLocal: trafficPolicyLocal,
			LocalGroupID:       localGroupID,
			ClusterGroupID:     clusterGroupID,
			AffinityTimeout:    affinityTimeout,
			IsExternal:         true,
			IsNodePort:         false,
			IsNested:           false, // Unsupported for LoadBalancerIP
			IsDSR:              features.DefaultFeatureGate.Enabled(features.LoadBalancerModeDSR) && loadBalancerMode == agentconfig.LoadBalancerModeDSR,
		}); err != nil {
			return fmt.Errorf("failed to install LoadBalancerIP load balancing OVS flows: %w", err)
		}
		if p.proxyAll {
			if err := p.routeClient.AddExternalIPConfigs(svcInfoStr, ip); err != nil {
				return fmt.Errorf("failed to install LoadBalancerIP traffic redirecting routing configurations: %w", err)
			}
		}
	}
	return nil
}

func (p *proxier) uninstallLoadBalancerService(svcInfoStr string, loadBalancerIPs []net.IP, svcPort uint16, protocol binding.Protocol) error {
	for _, ip := range loadBalancerIPs {
		if err := p.ofClient.UninstallServiceFlows(ip, svcPort, protocol); err != nil {
			return fmt.Errorf("failed to remove LoadBalancerIP load balancing OVS flows: %w", err)
		}
		if p.proxyAll {
			if err := p.routeClient.DeleteExternalIPConfigs(svcInfoStr, ip); err != nil {
				return fmt.Errorf("failed to remove LoadBalancerIP traffic redirecting routing configurations: %w", err)
			}
		}
	}
	return nil
}

func (p *proxier) installServices() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		p.ipToServiceMap.add(svcInfo, svcPortName)
		endpointsInstalled, ok := p.endpointsInstalledMap[svcPortName]
		if !ok {
			endpointsInstalled = map[string]k8sproxy.Endpoint{}
			p.endpointsInstalledMap[svcPortName] = endpointsInstalled
		}
		endpointsToInstall := p.endpointsMap[svcPortName]

		installedSvcPort, ok := p.serviceInstalledMap[svcPortName]
		var pSvcInfo *types.ServiceInfo
		var needUpdateServiceExternalAddresses, needUpdateService, needUpdateEndpoints bool
		var needCleanupStaleUDPServiceConntrack bool
		if ok { // Need to update.
			pSvcInfo = installedSvcPort.(*types.ServiceInfo)
			// The changes to serviceIdentity, session affinity config, and traffic policies affect all Service
			// flows while the changes to external addresses (NodePort and LoadBalancerIPs) affect external Service
			// flows only.
			needUpdateService = serviceIdentityChanged(svcInfo, pSvcInfo) ||
				svcInfo.SessionAffinityType() != pSvcInfo.SessionAffinityType() || // All Service flows use it.
				svcInfo.StickyMaxAgeSeconds() != pSvcInfo.StickyMaxAgeSeconds() || // All Service flows use it.
				svcInfo.ExternalPolicyLocal() != pSvcInfo.ExternalPolicyLocal() || // It affects the group ID used by external Service flows.
				svcInfo.InternalPolicyLocal() != pSvcInfo.InternalPolicyLocal() || // It affects the group ID used by internal Service flows.
				svcInfo.LoadBalancerMode != pSvcInfo.LoadBalancerMode
			needUpdateServiceExternalAddresses = serviceExternalAddressesChanged(svcInfo, pSvcInfo)
			needUpdateEndpoints = pSvcInfo.SessionAffinityType() != svcInfo.SessionAffinityType() ||
				pSvcInfo.ExternalPolicyLocal() != svcInfo.ExternalPolicyLocal() ||
				pSvcInfo.InternalPolicyLocal() != svcInfo.InternalPolicyLocal()
			if p.cleanupStaleUDPSvcConntrack && needClearConntrackEntries(pSvcInfo.OFProtocol) {
				// We clean the UDP conntrack entries for the following Service update cases:
				// - Service port changed, clean the conntrack entries matched by each of the current clusterIP / externalIPs
				//   / loadBalancerIPs and the stale Service port.
				// - ClusterIP changed, clean the conntrack entries matched by the clusterIP and the Service port.
				// - Some externalIPs / loadBalancerIPs are removed, clean the conntrack entries matched by each of the
				//   removed Service IPs and the current Service port.
				// - Service nodePort changed, clean the conntrack entries matched by each of the Node IPs / the virtual
				//   NodePort DNAT IP and the stale Service nodePort.
				// However, we DO NOT clean the UDP conntrack entries related to remote Endpoints that are still
				// referenced by the Service but are no longer selectable Endpoints for the corresponding Service IPs
				// (for externalTrafficPolicy, these IPs are loadBalancerIPs, externalIPs and NodeIPs; for
				// internalTrafficPolicy, these IPs clusterIPs) when externalTrafficPolicy or internalTrafficPolicy is
				// changed from Cluster to Local. Consequently, the connections, which are supposed to select local
				// Endpoints, will continue to send packets to remote Endpoints due to the existing UDP conntrack entries
				// until timeout.
				needCleanupStaleUDPServiceConntrack = svcInfo.Port() != pSvcInfo.Port() ||
					svcInfo.ClusterIP().String() != pSvcInfo.ClusterIP().String() ||
					needUpdateServiceExternalAddresses
			}
		} else { // Need to install.
			needUpdateService = true
			// We need to ensure a group is created for a new Service even if there is no available Endpoints,
			// otherwise it would fail to install Service flows because the group doesn't exist.
			needUpdateEndpoints = true
		}

		clusterEndpoints, localEndpoints, allReachableEndpoints := p.categorizeEndpoints(endpointsToInstall, svcInfo, p.hostname, p.topologyLabels)
		// Get the stale Endpoints and new Endpoints based on the diff of endpointsInstalled and allReachableEndpoints.
		staleEndpoints, newEndpoints := compareEndpoints(endpointsInstalled, allReachableEndpoints)
		if len(staleEndpoints) > 0 || len(newEndpoints) > 0 {
			needUpdateEndpoints = true
		}
		// We also clean the conntrack entries related to the stale Endpoints for a UDP Service. Conntrack entries
		// matched by each of stale Endpoint IPs and each of the remaining Service IPs and ports will be deleted.
		if len(staleEndpoints) > 0 && needClearConntrackEntries(svcInfo.OFProtocol) {
			needCleanupStaleUDPServiceConntrack = true
		}

		if needUpdateEndpoints {
			if !p.addNewEndpoints(svcPortName, svcInfo.OFProtocol, newEndpoints) {
				continue
			}
			if !p.removeStaleEndpoints(svcPortName, svcInfo.OFProtocol, staleEndpoints) {
				continue
			}
		}

		withSessionAffinity := svcInfo.SessionAffinityType() == corev1.ServiceAffinityClientIP
		var localGroupID, clusterGroupID binding.GroupIDType
		// categorizeEndpoints has checked if localGroup and clusterGroup should exist. We just create the group if its
		// Endpoints is not nil.
		// Note that nil represents the group should not exist and empty represents the group should exist but there is
		// no available Endpoints.
		if localEndpoints != nil {
			if localGroupID, ok = p.installServiceGroup(svcPortName, needUpdateEndpoints, true, withSessionAffinity, localEndpoints); !ok {
				continue
			}
		} else {
			if !p.removeServiceGroup(svcPortName, true) {
				continue
			}
		}
		if clusterEndpoints != nil {
			if clusterGroupID, ok = p.installServiceGroup(svcPortName, needUpdateEndpoints, false, withSessionAffinity, clusterEndpoints); !ok {
				continue
			}
		} else {
			if !p.removeServiceGroup(svcPortName, false) {
				continue
			}
		}

		if needUpdateService {
			// Delete previous flows.
			if pSvcInfo != nil {
				if !p.removeServiceFlows(pSvcInfo) {
					continue
				}
			}
			if !p.installServiceFlows(svcInfo, localGroupID, clusterGroupID) {
				continue
			}
		} else if needUpdateServiceExternalAddresses {
			if !p.updateServiceExternalAddresses(pSvcInfo, svcInfo, localGroupID, clusterGroupID) {
				continue
			}
		}
		if needCleanupStaleUDPServiceConntrack {
			if !p.removeStaleConntrackEntries(svcPortName, pSvcInfo, svcInfo, staleEndpoints) {
				continue
			}
		}

		p.serviceInstalledMap[svcPortName] = svcPort
	}
}

// getLoadBalancerMode returns the default load balancer mode if the Service doesn't have the annotation overriding it.
// Otherwise, it returns the mode specified in the annotation.
func (p *proxier) getLoadBalancerMode(svcInfo *types.ServiceInfo) agentconfig.LoadBalancerMode {
	if svcInfo.LoadBalancerMode == nil {
		return p.defaultLoadBalancerMode
	}
	if *svcInfo.LoadBalancerMode == agentconfig.LoadBalancerModeDSR && !features.DefaultFeatureGate.Enabled(features.LoadBalancerModeDSR) {
		klog.InfoS("The Service's load balancer mode is set to DSR but won't take effect as feature gate LoadBalancerModeDSR is not enabled", "ServiceInfo", svcInfo.String())
		return p.defaultLoadBalancerMode
	}
	return *svcInfo.LoadBalancerMode
}

func getAffinityTimeout(svcInfo *types.ServiceInfo) uint16 {
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
		klog.InfoS(
			"The timeout configured for ClientIP-based session affinity exceeds the max supported value",
			"ServiceInfo", svcInfo.String(),
			"timeout", svcInfo.StickyMaxAgeSeconds(),
			"maxTimeout", maxSupportedAffinityTimeout,
		)
	}
	return uint16(affinityTimeout)
}

func (p *proxier) installServiceFlows(svcInfo *types.ServiceInfo, localGroupID, clusterGroupID binding.GroupIDType) bool {
	svcInfoStr := svcInfo.String()
	svcPort := uint16(svcInfo.Port())
	svcProto := svcInfo.OFProtocol
	affinityTimeout := getAffinityTimeout(svcInfo)

	var isNestedService bool
	if p.supportNestedService {
		// Check the `IsNested` field only when Proxy is enabled with `supportNestedService`.
		// It is true only when the Service is an Antrea Multi-cluster Service for now.
		isNestedService = svcInfo.IsNested
	}
	loadBalancerMode := p.getLoadBalancerMode(svcInfo)

	// Install ClusterIP flows.
	if err := p.ofClient.InstallServiceFlows(&agenttypes.ServiceConfig{
		ServiceIP:          svcInfo.ClusterIP(),
		ServicePort:        svcPort,
		Protocol:           svcProto,
		TrafficPolicyLocal: svcInfo.InternalPolicyLocal(),
		LocalGroupID:       localGroupID,
		ClusterGroupID:     clusterGroupID,
		AffinityTimeout:    affinityTimeout,
		IsExternal:         false,
		IsNodePort:         false,
		IsNested:           isNestedService,
		IsDSR:              false, // not applicable for ClusterIP
	}); err != nil {
		klog.ErrorS(err, "Error when installing ClusterIP flows for Service", "ServiceInfo", svcInfoStr)
		return false
	}
	if p.proxyAll {
		// Install NodePort flows and configurations.
		if err := p.installNodePortService(localGroupID, clusterGroupID, uint16(svcInfo.NodePort()), svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout); err != nil {
			klog.ErrorS(err, "Error when installing NodePort flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
		// Install ExternalIP flows and configurations.
		if err := p.installExternalIPService(svcInfoStr, localGroupID, clusterGroupID, svcInfo.ExternalIPs(), svcPort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout, loadBalancerMode); err != nil {
			klog.ErrorS(err, "Error when installing ExternalIP flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	// Install LoadBalancer flows and configurations.
	if p.proxyLoadBalancerIPs {
		if err := p.installLoadBalancerService(svcInfoStr, localGroupID, clusterGroupID, svcInfo.LoadBalancerVIPs(), svcPort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout, loadBalancerMode); err != nil {
			klog.ErrorS(err, "Error when installing LoadBalancer flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	return true
}

func (p *proxier) updateServiceExternalAddresses(pSvcInfo, svcInfo *types.ServiceInfo, localGroupID, clusterGroupID binding.GroupIDType) bool {
	pSvcInfoStr := pSvcInfo.String()
	svcInfoStr := svcInfo.String()
	pSvcPort := uint16(pSvcInfo.Port())
	svcPort := uint16(svcInfo.Port())
	pSvcNodePort := uint16(pSvcInfo.NodePort())
	svcNodePort := uint16(svcInfo.NodePort())
	pSvcProto := pSvcInfo.OFProtocol
	svcProto := svcInfo.OFProtocol
	affinityTimeout := getAffinityTimeout(svcInfo)
	loadBalancerMode := p.getLoadBalancerMode(svcInfo)
	if p.proxyAll {
		if pSvcNodePort != svcNodePort {
			if err := p.uninstallNodePortService(pSvcNodePort, pSvcProto); err != nil {
				klog.ErrorS(err, "Error when uninstalling NodePort flows and configurations for Service", "ServiceInfo", pSvcInfoStr)
				return false
			}
			if err := p.installNodePortService(localGroupID, clusterGroupID, svcNodePort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout); err != nil {
				klog.ErrorS(err, "Error when installing NodePort flows and configurations for Service", "ServiceInfo", svcInfoStr)
				return false
			}
		}
		deletedExternalIPs := smallSliceDifference(pSvcInfo.ExternalIPs(), svcInfo.ExternalIPs())
		addedExternalIPs := smallSliceDifference(svcInfo.ExternalIPs(), pSvcInfo.ExternalIPs())
		// The deleted ExternalIPs need to be removed from the map explicitly while the added ExternalIPs (they are always included in the current ExternalIPs) will be added at the end of installServices.
		p.ipToServiceMap.deleteServiceIPs(generateServiceInfoStrings(pSvcInfo.Protocol(), pSvcInfo.Port(), deletedExternalIPs))
		if err := p.uninstallExternalIPService(pSvcInfoStr, deletedExternalIPs, pSvcPort, pSvcProto); err != nil {
			klog.ErrorS(err, "Error when uninstalling ExternalIP flows and configurations for Service", "ServiceInfo", pSvcInfoStr)
			return false
		}
		if err := p.installExternalIPService(svcInfoStr, localGroupID, clusterGroupID, addedExternalIPs, svcPort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout, loadBalancerMode); err != nil {
			klog.ErrorS(err, "Error when installing ExternalIP flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	if p.proxyLoadBalancerIPs {
		deletedLoadBalancerIPs := smallSliceDifference(pSvcInfo.LoadBalancerVIPs(), svcInfo.LoadBalancerVIPs())
		addedLoadBalancerIPs := smallSliceDifference(svcInfo.LoadBalancerVIPs(), pSvcInfo.LoadBalancerVIPs())

		// The deleted LoadBalancerIPs need to be removed from the map explicitly while the added LoadBalancerIPs (they are always included in the current LoadBalancerIPs) will be added at the end of installServices.
		p.ipToServiceMap.deleteServiceIPs(generateServiceInfoStrings(pSvcInfo.Protocol(), pSvcInfo.Port(), deletedLoadBalancerIPs))

		if err := p.uninstallLoadBalancerService(pSvcInfoStr, deletedLoadBalancerIPs, pSvcPort, pSvcProto); err != nil {
			klog.ErrorS(err, "Error when uninstalling LoadBalancer flows and configurations for Service", "ServiceInfo", pSvcInfoStr)
			return false
		}
		if err := p.installLoadBalancerService(svcInfoStr, localGroupID, clusterGroupID, addedLoadBalancerIPs, svcPort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout, loadBalancerMode); err != nil {
			klog.ErrorS(err, "Error when installing LoadBalancer flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	return true
}

func compareEndpoints(endpointsCached map[string]k8sproxy.Endpoint, endpointsInstalled []k8sproxy.Endpoint) (map[string]k8sproxy.Endpoint, map[string]k8sproxy.Endpoint) {
	// Map endpointsToRemove is used to store the Endpoints that should be removed.
	endpointsToRemove := map[string]k8sproxy.Endpoint{}
	// Map endpointsToAdd is used to store the Endpoints that are newly added.
	endpointsToAdd := map[string]k8sproxy.Endpoint{}

	// Copy every Endpoint in endpointsCached to endpointsToRemove. After removing all actually installed Endpoints,
	// only stale Endpoints are left.
	for endpointString, endpoint := range endpointsCached {
		endpointsToRemove[endpointString] = endpoint
	}

	for _, endpoint := range endpointsInstalled {
		// If the Endpoint is in the map endpointsCached, then it is not newly installed, remove it from map endpointsToRemove;
		// otherwise, add it to map endpointsToAdd.
		if _, exists := endpointsCached[endpoint.String()]; exists {
			delete(endpointsToRemove, endpoint.String())
		} else {
			endpointsToAdd[endpoint.String()] = endpoint
		}
	}
	return endpointsToRemove, endpointsToAdd
}

// syncProxyRules applies current changes in change trackers and then updates
// flows for services and endpoints. It will return immediately if either
// endpoints or services resources are not synced. syncProxyRules is only called
// through the Run method of the runner object, and all calls are serialized.
// This method is the only one that changes internal state, but
// GetServiceFlowKeys(), which is called by the "/ovsflows" API handler,
// also reads service and endpoints maps, so mu is used to protect these two maps.
func (p *proxier) syncProxyRules() error {
	if !p.isInitialized() {
		klog.V(4).Info("Not syncing rules until both Services and Endpoints have been synced")
		return nil
	}

	start := time.Now()
	defer func() {
		delta := time.Since(start)
		if p.isIPv6() {
			metrics.SyncProxyDurationV6.Observe(delta.Seconds())
		} else {
			metrics.SyncProxyDuration.Observe(delta.Seconds())
		}
		klog.V(4).Infof("syncProxyRules took %v", time.Since(start))
	}()

	// Protect Service and endpoints maps, which can be read by
	// GetServiceFlowKeys().
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpointsChanges.Update(p.endpointsMap)
	p.serviceChanges.Update(p.serviceMap)

	p.removeStaleServices()
	p.installServices()

	if p.healthzServer != nil {
		p.healthzServer.Updated(p.ipFamily)
	}
	if p.serviceHealthServer != nil {
		if err := p.serviceHealthServer.SyncServices(p.serviceMap.HealthCheckNodePorts()); err != nil {
			klog.ErrorS(err, "Error syncing healthcheck Services")
		}
		if err := p.serviceHealthServer.SyncEndpoints(p.endpointsMap.LocalReadyEndpoints()); err != nil {
			klog.ErrorS(err, "Error syncing healthcheck Endpoints")
		}
	}

	counter := 0
	for _, endpoints := range p.endpointsMap {
		counter += len(endpoints)
	}
	if p.isIPv6() {
		metrics.ServicesInstalledTotalV6.Set(float64(len(p.serviceMap)))
		metrics.EndpointsInstalledTotalV6.Set(float64(counter))
	} else {
		metrics.ServicesInstalledTotal.Set(float64(len(p.serviceMap)))
		metrics.EndpointsInstalledTotal.Set(float64(counter))
	}

	p.syncedOnceMutex.Lock()
	defer p.syncedOnceMutex.Unlock()
	p.syncedOnce = true

	return nil
}

func (p *proxier) SyncLoop() {
	if p.healthzServer != nil {
		p.healthzServer.Updated(p.ipFamily)
	}
	p.runner.Loop(p.stopChan)
}

// Sync is called to synchronize the proxier as soon as possible.
func (p *proxier) Sync() {
	if p.healthzServer != nil {
		p.healthzServer.QueuedUpdate(p.ipFamily)
	}
	p.runner.Run()
}

func (p *proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	if !p.matchAddressFamily(endpointSlice) {
		return
	}
	klog.V(2).InfoS("Processing EndpointSlice ADD event", "EndpointSlice", klog.KObj(endpointSlice))
	p.OnEndpointSliceUpdate(nil, endpointSlice)
}

func (p *proxier) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) {
	if !p.matchAddressFamily(newEndpointSlice) {
		return
	}
	if oldEndpointSlice != nil && newEndpointSlice != nil {
		klog.V(2).InfoS("Processing EndpointSlice UPDATE event", "EndpointSlice", klog.KObj(newEndpointSlice))
	}
	if p.isIPv6() {
		metrics.EndpointsUpdatesTotalV6.Inc()
	} else {
		metrics.EndpointsUpdatesTotal.Inc()
	}
	if p.endpointsChanges.OnEndpointSliceUpdate(newEndpointSlice, false) && p.isInitialized() {
		p.Sync()
	}
}

func (p *proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	if !p.matchAddressFamily(endpointSlice) {
		return
	}
	klog.V(2).InfoS("Processing EndpointSlice DELETE event", "EndpointSlice", klog.KObj(endpointSlice))
	if p.endpointsChanges.OnEndpointSliceUpdate(endpointSlice, true) && p.isInitialized() {
		p.Sync()
	}
}

func (p *proxier) OnEndpointSlicesSynced() {
	p.endpointsChanges.OnEndpointsSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) matchAddressFamily(eps *discovery.EndpointSlice) bool {
	switch eps.AddressType {
	case discovery.AddressTypeIPv4:
		return !p.isIPv6()
	case discovery.AddressTypeIPv6:
		return p.isIPv6()
	default:
		return false
	}
}

func (p *proxier) OnServiceAdd(service *corev1.Service) {
	klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(service))
	p.OnServiceUpdate(nil, service)
}

func (p *proxier) serviceSupportsIPFamily(preSvc, curSvc *corev1.Service) bool {
	// Prefer current Service if available.
	svc := curSvc
	if svc == nil {
		svc = preSvc
	}
	if svc == nil {
		return false
	}
	var ipFamily corev1.IPFamily
	if p.isIPv6() {
		ipFamily = corev1.IPv6Protocol
	} else {
		ipFamily = corev1.IPv4Protocol
	}
	if utilproxy.GetClusterIPByFamily(ipFamily, svc) != "" {
		return true
	}
	return false
}

func (p *proxier) OnServiceUpdate(oldService, service *corev1.Service) {
	if oldService != nil && service != nil {
		klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(service))
	}

	if p.serviceSupportsIPFamily(oldService, service) {
		if p.isIPv6() {
			metrics.ServicesUpdatesTotalV6.Inc()
		} else {
			metrics.ServicesUpdatesTotal.Inc()
		}
	}

	if p.serviceChanges.OnServiceUpdate(oldService, service) && p.isInitialized() {
		p.Sync()
	}
}

func (p *proxier) OnServiceDelete(service *corev1.Service) {
	klog.V(2).InfoS("Processing Service DELETE event", "Service", klog.KObj(service))
	p.OnServiceUpdate(service, nil)
}

func (p *proxier) OnServiceSynced() {
	p.serviceChanges.OnServiceSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

// OnTopologyChange is called whenever this node's proxy relevant topology-related labels change.
func (p *proxier) OnTopologyChange(topologyLabels map[string]string) {
	p.mu.Lock()
	p.topologyLabels = topologyLabels
	p.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node topology labels", "labels", topologyLabels)
	p.Sync()
}

// OnServiceCIDRsChanged is called whenever a change is observed
// in any of the ServiceCIDRs, and provides complete list of service cidrs.
func (p *proxier) OnServiceCIDRsChanged(_ []string) {}

func (p *proxier) GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool) {
	return p.ipToServiceMap.get(serviceStr)
}

func (p *proxier) Run(stopCh <-chan struct{}) {
	p.stopChan = stopCh
	p.SyncLoop()
}

func (p *ProxyServer) Run(ctx context.Context) {
	p.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategorySvcReject), p)
	serveHealthz(ctx, p.healthzServer)
	go p.serviceConfig.Run(ctx.Done())
	go p.endpointSliceConfig.Run(ctx.Done())
	go p.nodeConfig.Run(ctx.Done())
	p.proxier.Run(ctx.Done())
}

func (p *proxier) GetServiceFlowKeys(serviceName, namespace string) ([]string, []binding.GroupIDType, bool) {
	namespacedName := apimachinerytypes.NamespacedName{Namespace: namespace, Name: serviceName}
	p.mu.Lock()
	defer p.mu.Unlock()

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

func (p *ProxyServer) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if pktIn == nil {
		return fmt.Errorf("empty packetin for Antrea Proxy")
	}
	matches := pktIn.GetMatches()

	// Get Ethernet data.
	ethernetPkt, err := openflow.GetEthernetPacket(pktIn)
	if err != nil {
		return err
	}
	srcMAC := ethernetPkt.HWDst.String()
	dstMAC := ethernetPkt.HWSrc.String()

	var (
		srcIP, dstIP string
		proto        uint8
		isIPv6       bool
	)
	switch ipPkt := ethernetPkt.Data.(type) {
	case *protocol.IPv4:
		srcIP = ipPkt.NWDst.String()
		dstIP = ipPkt.NWSrc.String()
		proto = ipPkt.Protocol
		isIPv6 = false
	case *protocol.IPv6:
		srcIP = ipPkt.NWDst.String()
		dstIP = ipPkt.NWSrc.String()
		proto = ipPkt.NextHeader
		isIPv6 = true
	}

	inPortField := matches.GetMatchByName(binding.OxmFieldInPort)
	if inPortField == nil {
		return fmt.Errorf("error when getting match field inPort")
	}
	outPort := inPortField.GetValue().(uint32)
	// It cannot use CONTROLLER (the default value when inPort is 0) as the inPort due to a bug in Windows ovsext
	// driver, otherwise the Windows OS would crash. See https://github.com/openvswitch/ovs-issues/issues/280.
	inPort := uint32(openflow15.P_LOCAL)
	return openflow.SendRejectPacketOut(p.ofClient,
		srcMAC,
		dstMAC,
		srcIP,
		dstIP,
		inPort,
		outPort,
		isIPv6,
		ethernetPkt,
		proto,
		nil)
}

// newProxier returns a new single-stack proxier.
func newProxier(
	hostname string,
	ofClient openflow.Client,
	ipFamily corev1.IPFamily,
	routeClient route.Interface,
	nodeIPChecker nodeip.Checker,
	nodePortAddresses []net.IP,
	proxyAllEnabled bool,
	skipServices []string,
	proxyLoadBalancerIPs bool,
	defaultLoadBalancerMode agentconfig.LoadBalancerMode,
	groupCounter types.GroupCounter,
	supportNestedService bool,
	serviceHealthServerDisabled bool,
	preferSameTrafficDistributionEnabled bool,
	serviceLabelSelector labels.Selector,
	healthzServer *healthcheck.ProxyHealthServer,
) (*proxier, error) {
	klog.V(2).Infof("Creating proxier with IPv6 enabled=%t", ipFamily == corev1.IPv6Protocol)

	var serviceHealthServer healthcheck.ServiceHealthServer
	if proxyAllEnabled {
		if serviceHealthServerDisabled {
			klog.V(2).InfoS("Service health check server will not be run")
		} else {
			nodePortAddressesString := make([]string, len(nodePortAddresses))
			for i, address := range nodePortAddresses {
				nodePortAddressesString[i] = address.String()
			}
			serviceHealthServer = healthcheck.NewServiceHealthServer(hostname, nil, nodePortAddressesString, healthzServer)
		}
	}

	p := &proxier{
		nodeIPChecker:                        nodeIPChecker,
		endpointsChanges:                     newEndpointsChangesTracker(hostname, ipFamily),
		serviceChanges:                       newServiceChangesTracker(ipFamily, serviceLabelSelector, skipServices),
		serviceMap:                           k8sproxy.ServicePortMap{},
		serviceInstalledMap:                  k8sproxy.ServicePortMap{},
		endpointsInstalledMap:                k8sproxy.EndpointsMap{},
		endpointsMap:                         k8sproxy.EndpointsMap{},
		endpointReferenceCounter:             map[string]int{},
		topologyLabels:                       map[string]string{},
		ipToServiceMap:                       newIPToServiceMap(),
		groupCounter:                         groupCounter,
		ofClient:                             ofClient,
		routeClient:                          routeClient,
		nodePortAddresses:                    nodePortAddresses,
		ipFamily:                             ipFamily,
		proxyAll:                             proxyAllEnabled,
		preferSameTrafficDistributionEnabled: preferSameTrafficDistributionEnabled,
		cleanupStaleUDPSvcConntrack:          features.DefaultFeatureGate.Enabled(features.CleanupStaleUDPSvcConntrack),
		proxyLoadBalancerIPs:                 proxyLoadBalancerIPs,
		hostname:                             hostname,
		serviceHealthServer:                  serviceHealthServer,
		healthzServer:                        healthzServer,
		supportNestedService:                 supportNestedService,
		defaultLoadBalancerMode:              defaultLoadBalancerMode,
	}
	p.runner = runner.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, time.Hour)
	return p, nil
}

// metaProxierWrapper wraps metaProxier, and implements the extra methods added
// in interface ProxyQuerier.
type metaProxierWrapper struct {
	k8sproxy.Provider
	ipv4Proxier *proxier
	ipv6Proxier *proxier
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

func newDualStackProxier(
	hostname string,
	ofClient openflow.Client,
	routeClient route.Interface,
	nodeIPChecker nodeip.Checker,
	nodePortAddressesIPv4 []net.IP,
	nodePortAddressesIPv6 []net.IP,
	proxyAllEnabled bool,
	skipServices []string,
	proxyLoadBalancerIPs bool,
	defaultLoadBalancerMode agentconfig.LoadBalancerMode,
	v4groupCounter types.GroupCounter,
	v6groupCounter types.GroupCounter,
	nestedServiceSupport bool,
	serviceHealthServerDisabled bool,
	preferSameTrafficDistributionEnabled bool,
	serviceLabelSelector labels.Selector,
	healthzServer *healthcheck.ProxyHealthServer,
) (Proxier, error) {
	// Create an IPv4 instance of the single-stack proxier.
	ipv4Proxier, err := newProxier(hostname,
		ofClient,
		corev1.IPv4Protocol,
		routeClient,
		nodeIPChecker,
		nodePortAddressesIPv4,
		proxyAllEnabled,
		skipServices,
		proxyLoadBalancerIPs,
		defaultLoadBalancerMode,
		v4groupCounter,
		nestedServiceSupport,
		serviceHealthServerDisabled,
		preferSameTrafficDistributionEnabled,
		serviceLabelSelector,
		healthzServer,
	)
	if err != nil {
		return nil, fmt.Errorf("error when creating IPv4 proxier: %v", err)
	}
	// Create an IPv6 instance of the single-stack proxier.
	ipv6Proxier, err := newProxier(hostname,
		ofClient,
		corev1.IPv6Protocol,
		routeClient,
		nodeIPChecker,
		nodePortAddressesIPv6,
		proxyAllEnabled,
		skipServices,
		proxyLoadBalancerIPs,
		defaultLoadBalancerMode,
		v6groupCounter,
		nestedServiceSupport,
		serviceHealthServerDisabled,
		preferSameTrafficDistributionEnabled,
		serviceLabelSelector,
		healthzServer,
	)
	if err != nil {
		return nil, fmt.Errorf("error when creating IPv6 proxier: %v", err)
	}
	// Create a meta-proxier that dispatch calls between the two
	// single-stack proxier instances.
	metaProxier := &metaProxierWrapper{
		ipv4Proxier: ipv4Proxier,
		ipv6Proxier: ipv6Proxier,
		Provider:    metaproxier.NewMetaProxier(ipv4Proxier, ipv6Proxier),
	}

	return metaProxier, nil
}

func generateServiceLabelSelector(serviceProxyName string) labels.Selector {
	// TODO: The label selector nonHeadlessServiceSelector was added to pass the Kubernetes e2e test
	//  'Services should implement service.kubernetes.io/headless'. You can find the test case at:
	//  https://github.com/kubernetes/kubernetes/blob/027ac5a426a261ba6b66a40e79e123e75e9baf5b/test/e2e/network/service.go#L2281
	//  However, in AntreaProxy, headless Services are skipped by checking the ClusterIP.
	nonHeadlessServiceSelector, _ := labels.NewRequirement(corev1.IsHeadlessService, selection.DoesNotExist, nil)
	var serviceProxyNameSelector *labels.Requirement
	if serviceProxyName == "" {
		serviceProxyNameSelector, _ = labels.NewRequirement(labelServiceProxyName, selection.DoesNotExist, nil)
	} else {
		serviceProxyNameSelector, _ = labels.NewRequirement(labelServiceProxyName, selection.DoubleEquals, []string{serviceProxyName})
	}
	serviceLabelSelector := labels.NewSelector()
	serviceLabelSelector = serviceLabelSelector.Add(*serviceProxyNameSelector, *nonHeadlessServiceSelector)
	return serviceLabelSelector
}

func NewProxyServer(hostname string,
	nodeManager *k8sproxy.NodeManager,
	ofClient openflow.Client,
	routeClient route.Interface,
	nodeIPChecker nodeip.Checker,
	v4Enabled bool,
	v6Enabled bool,
	nodePortAddressesIPv4 []net.IP,
	nodePortAddressesIPv6 []net.IP,
	proxyConfig antreaconfig.AntreaProxyConfig,
	defaultLoadBalancerMode agentconfig.LoadBalancerMode,
	v4GroupCounter types.GroupCounter,
	v6GroupCounter types.GroupCounter,
	nestedServiceSupport bool) (*ProxyServer, error) {
	metrics.Register()

	proxyAllEnabled := proxyConfig.ProxyAll
	skipServices := proxyConfig.SkipServices
	proxyLoadBalancerIPs := *proxyConfig.ProxyLoadBalancerIPs
	serviceProxyName := proxyConfig.ServiceProxyName
	serviceHealthServerDisabled := proxyConfig.DisableServiceHealthCheckServer
	serviceHealthCheckServerBindAddress := proxyConfig.ServiceHealthCheckServerBindAddress

	var healthzServer *healthcheck.ProxyHealthServer
	if proxyAllEnabled && !serviceHealthServerDisabled {
		healthzServer = healthcheck.NewProxyHealthServer(serviceHealthCheckServerBindAddress, 2*resyncPeriod, nodeManager)
	}
	serviceLabelSelector := generateServiceLabelSelector(serviceProxyName)
	preferSameTrafficDistributionEnabled := features.DefaultFeatureGate.Enabled(features.PreferSameTrafficDistribution)

	var proxier Proxier
	var err error
	switch {
	case v4Enabled && v6Enabled:
		proxier, err = newDualStackProxier(hostname,
			ofClient,
			routeClient,
			nodeIPChecker,
			nodePortAddressesIPv4,
			nodePortAddressesIPv6,
			proxyAllEnabled,
			skipServices,
			proxyLoadBalancerIPs,
			defaultLoadBalancerMode,
			v4GroupCounter,
			v6GroupCounter,
			nestedServiceSupport,
			serviceHealthServerDisabled,
			preferSameTrafficDistributionEnabled,
			serviceLabelSelector,
			healthzServer,
		)
		if err != nil {
			return nil, fmt.Errorf("error when creating dual-stack proxier: %v", err)
		}
	case v4Enabled:
		proxier, err = newProxier(hostname,
			ofClient,
			corev1.IPv4Protocol,
			routeClient,
			nodeIPChecker,
			nodePortAddressesIPv4,
			proxyAllEnabled,
			skipServices,
			proxyLoadBalancerIPs,
			defaultLoadBalancerMode,
			v4GroupCounter,
			nestedServiceSupport,
			serviceHealthServerDisabled,
			preferSameTrafficDistributionEnabled,
			serviceLabelSelector,
			healthzServer,
		)
		if err != nil {
			return nil, fmt.Errorf("error when creating IPv4 proxier: %v", err)
		}
	case v6Enabled:
		proxier, err = newProxier(hostname,
			ofClient,
			corev1.IPv6Protocol,
			routeClient,
			nodeIPChecker,
			nodePortAddressesIPv6,
			proxyAllEnabled,
			skipServices,
			proxyLoadBalancerIPs,
			defaultLoadBalancerMode,
			v6GroupCounter,
			nestedServiceSupport,
			serviceHealthServerDisabled,
			preferSameTrafficDistributionEnabled,
			serviceLabelSelector,
			healthzServer,
		)
		if err != nil {
			return nil, fmt.Errorf("error when creating IPv6 proxier: %v", err)
		}
	default:
		return nil, fmt.Errorf("either IPv4 or IPv6 proxier, or both proxiers should be created")
	}

	proxyServer := &ProxyServer{
		healthzServer: healthzServer,
		nodeManager:   nodeManager,
		ofClient:      ofClient,
		proxier:       proxier,
	}

	return proxyServer, nil
}

func (p *ProxyServer) Initialize(ctx context.Context,
	serviceInformer coreinformers.ServiceInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer) {
	serviceConfig := config.NewServiceConfig(ctx, serviceInformer, resyncPeriod)
	serviceConfig.RegisterEventHandler(p.proxier)
	p.serviceConfig = serviceConfig

	endpointSliceConfig := config.NewEndpointSliceConfig(ctx, endpointSliceInformer, resyncPeriod)
	endpointSliceConfig.RegisterEventHandler(p.proxier)
	p.endpointSliceConfig = endpointSliceConfig

	nodeConfig := config.NewNodeConfig(ctx, p.nodeManager.NodeInformer(), resyncPeriod)
	if p.healthzServer != nil {
		nodeConfig.RegisterEventHandler(p.nodeManager)
	}
	p.nodeConfig = nodeConfig

	nodeTopologyConfig := config.NewNodeTopologyConfig(ctx, p.nodeManager.NodeInformer(), resyncPeriod)
	nodeTopologyConfig.RegisterEventHandler(p.proxier)
}

func needClearConntrackEntries(protocol binding.Protocol) bool {
	return protocol == binding.ProtocolUDP || protocol == binding.ProtocolUDPv6
}

func (p *proxier) isIPv6() bool {
	return p.ipFamily == corev1.IPv6Protocol
}

func serveHealthz(ctx context.Context, hz *healthcheck.ProxyHealthServer) {
	if hz == nil {
		return
	}

	fn := func(ctx context.Context) {
		err := hz.Run(ctx)
		if err != nil {
			klog.ErrorS(err, "Healthz server failed")
		} else {
			klog.Info("Healthz server returned without error")
		}
	}
	go wait.UntilWithContext(ctx, fn, 5*time.Second)
}

func (p *ProxyServer) GetProxyQuerier() ProxyQuerier {
	return p.proxier
}

func (p *ProxyServer) GetProxyProvider() Proxier {
	return p.proxier
}

func newIPToServiceMap() *ipToServiceMap {
	return &ipToServiceMap{
		serviceStringMap: map[string]k8sproxy.ServicePortName{},
	}
}

// ipToServiceMap is a thread-safe store for Service lookup, providing
// access to Service names based IPs such as external IPs, loadBalancer IPs
// and the ClusterIP.
type ipToServiceMap struct {
	// serviceStringMapMutex protects serviceStringMap object.
	serviceStringMapMutex sync.RWMutex
	// serviceStringMap provides map from serviceString(IP:Port/Protocol) to ServicePortName.
	serviceStringMap map[string]k8sproxy.ServicePortName
}

// add registers a new Service to the map.
func (m *ipToServiceMap) add(serviceInfo *types.ServiceInfo, servicePortName k8sproxy.ServicePortName) {
	m.serviceStringMapMutex.Lock()
	defer m.serviceStringMapMutex.Unlock()

	for _, serviceStr := range getServiceIPStrings(serviceInfo) {
		m.serviceStringMap[serviceStr] = servicePortName
	}
}

// delete removes the Service from the map with thread safety.
func (m *ipToServiceMap) delete(serviceInfo *types.ServiceInfo) {
	m.deleteServiceIPs(getServiceIPStrings(serviceInfo))
}

// deleteServiceIPs removes the associated keys from the map for the given set
// of Service IPs.
//
// Deleting a key that does not exist is safely ignored.
func (m *ipToServiceMap) deleteServiceIPs(serviceStrings []string) {
	m.serviceStringMapMutex.Lock()
	defer m.serviceStringMapMutex.Unlock()

	for _, serviceStr := range serviceStrings {
		delete(m.serviceStringMap, serviceStr)
	}
}

// get retrieves the associated Service given it's serviceStr of the format
// (IP:Port/Protocol) where IP can be ExternalIPs, LoadBalancerIPs and ClusterIP.
func (m *ipToServiceMap) get(serviceStr string) (k8sproxy.ServicePortName, bool) {
	m.serviceStringMapMutex.RLock()
	defer m.serviceStringMapMutex.RUnlock()

	servicePortName, exists := m.serviceStringMap[serviceStr]
	return servicePortName, exists
}

// getServiceIPStrings returns a slice of serviceStrings with the format
// "IP:Port/Protocol" for all Service IPs.
func getServiceIPStrings(s *types.ServiceInfo) []string {
	lbIPs := s.LoadBalancerVIPs()
	externalIPs := s.ExternalIPs()

	port := s.Port()
	proto := s.Protocol()

	svcInfos := make([]string, 0, len(lbIPs)+len(externalIPs)+1) // +1 for ClusterIP
	addSvcInfoFromIPs := func(ips []net.IP) {
		for _, ip := range ips {
			svcInfos = append(svcInfos, fmt.Sprintf("%s:%d/%s", ip, port, proto))
		}
	}
	addSvcInfoFromIPs(lbIPs)
	addSvcInfoFromIPs(externalIPs)
	svcInfos = append(svcInfos, s.String())

	return svcInfos
}

// GenerateServiceStrings generates service strings for the given IPs in the format
// "IP:Port/Protocol".
func generateServiceInfoStrings(protocol corev1.Protocol, port int, ips []net.IP) []string {
	serviceStrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		serviceStr := fmt.Sprintf("%s:%d/%s", ip, port, protocol)
		serviceStrs = append(serviceStrs, serviceStr)
	}
	return serviceStrs
}
