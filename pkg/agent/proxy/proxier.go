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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/strings/slices"

	agentconfig "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/nodeip"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy/metrics"
	"antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/route"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	antreaconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
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
	// labelServiceProxyName is the well-known label for service proxy name defined in
	// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/2447-Make-kube-proxy-service-abstraction-optional
	labelServiceProxyName = "service.kubernetes.io/service-proxy-name"
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
	nodeIPChecker    nodeip.Checker
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

	// serviceIPRouteReferences tracks the references of Service IP routes. The key is the Service IP and the value is
	// the set of ServiceInfo strings. Because a Service could have multiple ports and each port will generate a
	// ServicePort (which is the unit of the processing), a Service IP route may be required by several ServicePorts.
	// With the references, we install a route exactly once as long as it's used by any ServicePorts and uninstall it
	// exactly once when it's no longer used by any ServicePorts.
	// It applies to ClusterIP and LoadBalancerIP.
	serviceIPRouteReferences map[string]sets.Set[string]
	// syncedOnce returns true if the proxier has synced rules at least once.
	syncedOnce      bool
	syncedOnceMutex sync.RWMutex

	runner                      *k8sproxy.BoundedFrequencyRunner
	stopChan                    <-chan struct{}
	ofClient                    openflow.Client
	routeClient                 route.Interface
	nodePortAddresses           []net.IP
	hostname                    string
	isIPv6                      bool
	proxyAll                    bool
	endpointSliceEnabled        bool
	proxyLoadBalancerIPs        bool
	topologyAwareHintsEnabled   bool
	supportNestedService        bool
	cleanupStaleUDPSvcConntrack bool

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
		// Cleanup all UDP conntrack connections related to the Service.
		if p.cleanupStaleUDPSvcConntrack && needClearConntrackEntries(svcInfo.OFProtocol) {
			if !p.removeStaleServiceConntrackEntries(svcPortName, svcInfo) {
				continue
			}
		}

		delete(p.serviceInstalledMap, svcPortName)
		p.deleteServiceByIP(svcInfoStr)
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
		if err := p.uninstallExternalIPService(svcInfoStr, svcInfo.ExternalIPStrings(), svcPort, svcProto); err != nil {
			klog.ErrorS(err, "Error when uninstalling ExternalIP flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	// Remove LoadBalancer flows and configurations.
	if p.proxyLoadBalancerIPs {
		if err := p.uninstallLoadBalancerService(svcInfoStr, svcInfo.LoadBalancerIPStrings(), svcPort, svcProto); err != nil {
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

	svcIPToPort := make(map[string]uint16)
	svcIPToPort[svcInfo.ClusterIP().String()] = svcPort
	for _, ip := range svcInfo.ExternalIPStrings() {
		svcIPToPort[ip] = svcPort
	}
	for _, ip := range svcInfo.LoadBalancerIPStrings() {
		if ip != "" {
			svcIPToPort[ip] = svcPort
		}
	}
	if nodePort > 0 {
		for _, nodeIP := range p.nodePortAddresses {
			svcIPToPort[nodeIP.String()] = nodePort
		}
	}

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
	pExternalIPStrings := pSvcInfo.ExternalIPStrings()
	externalIPStrings := svcInfo.ExternalIPStrings()
	pLoadBalancerIPStrings := pSvcInfo.LoadBalancerIPStrings()
	loadBalancerIPStrings := svcInfo.LoadBalancerIPStrings()
	var svcPortChanged, svcNodePortChanged bool

	staleSvcIPToPort := make(map[string]uint16)
	// If the port of the Service is changed, delete all conntrack entries related to the previous Service IPs and the
	// previous Service port. These previous Service IPs includes external IPs, loadBalancer IPs and the ClusterIP.
	if pSvcPort != svcPort {
		staleSvcIPToPort[pSvcInfo.ClusterIP().String()] = pSvcPort
		for _, ip := range pExternalIPStrings {
			staleSvcIPToPort[ip] = pSvcPort
		}
		for _, ip := range pLoadBalancerIPStrings {
			if ip != "" {
				staleSvcIPToPort[ip] = pSvcPort
			}
		}
		svcPortChanged = true
	} else {
		// If the port of the Service is not changed, delete the conntrack entries related to the stale Service IPs and
		// the Service port. These stale Service IPs could be from external IPs and loadBalancer IPs.
		deletedExternalIPs := smallSliceDifference(pExternalIPStrings, externalIPStrings)
		deletedLoadBalancerIPs := smallSliceDifference(pLoadBalancerIPStrings, loadBalancerIPStrings)
		for _, ip := range deletedExternalIPs {
			staleSvcIPToPort[ip] = pSvcPort
		}
		for _, ip := range deletedLoadBalancerIPs {
			staleSvcIPToPort[ip] = pSvcPort
		}
	}
	// If the NodePort of the Service is changed, delete the contrack entries related to the Node IPs and the Service nodePort.
	if pNodePort != nodePort {
		for _, nodeIP := range p.nodePortAddresses {
			staleSvcIPToPort[nodeIP.String()] = pNodePort
		}
		svcNodePortChanged = true
	}
	// Delete the conntrack entries due to the change of the Service.
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
		remainingSvcIPToPort[svcInfo.ClusterIP().String()] = svcPort
		for _, ip := range smallSliceSame(pExternalIPStrings, externalIPStrings) {
			remainingSvcIPToPort[ip] = svcPort
		}
		for _, ip := range smallSliceSame(pLoadBalancerIPStrings, loadBalancerIPStrings) {
			remainingSvcIPToPort[ip] = svcPort
		}
	}
	if !svcNodePortChanged && nodePort > 0 {
		// Get all Node IPs.
		for _, nodeIP := range p.nodePortAddresses {
			remainingSvcIPToPort[nodeIP.String()] = nodePort
		}
	}
	// Delete the conntrack entries related to the remaining Service IPs, Service port, nodePort and stale Endpoint IPs.
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
		!slices.Equal(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings()) ||
		!slices.Equal(svcInfo.ExternalIPStrings(), pSvcInfo.ExternalIPStrings())
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

// smallSliceSame builds a slice which includes all the strings are both in s1 and s2.
func smallSliceSame(s1, s2 []string) []string {
	var same []string

	for _, e1 := range s1 {
		for _, e2 := range s2 {
			if e1 == e2 {
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
	if p.isIPv6 {
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
		return fmt.Errorf("failed to install NodePort load balancing flows: %w", err)
	}
	if err := p.routeClient.AddNodePort(p.nodePortAddresses, svcPort, protocol); err != nil {
		return fmt.Errorf("failed to install NodePort traffic redirecting rules: %w", err)
	}
	return nil
}

func (p *proxier) uninstallNodePortService(svcPort uint16, protocol binding.Protocol) error {
	if svcPort == 0 {
		return nil
	}
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

func (p *proxier) installExternalIPService(svcInfoStr string,
	localGroupID,
	clusterGroupID binding.GroupIDType,
	externalIPStrings []string,
	svcPort uint16,
	protocol binding.Protocol,
	trafficPolicyLocal bool,
	affinityTimeout uint16,
	loadBalancerMode agentconfig.LoadBalancerMode) error {
	for _, externalIP := range externalIPStrings {
		ip := net.ParseIP(externalIP)
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
			return fmt.Errorf("failed to install ExternalIP load balancing flows: %w", err)
		}
		if err := p.addRouteForServiceIP(svcInfoStr, ip, p.routeClient.AddExternalIPRoute); err != nil {
			return fmt.Errorf("failed to install ExternalIP traffic redirecting routes: %w", err)
		}
	}
	return nil
}

func (p *proxier) uninstallExternalIPService(svcInfoStr string, externalIPStrings []string, svcPort uint16, protocol binding.Protocol) error {
	for _, externalIP := range externalIPStrings {
		ip := net.ParseIP(externalIP)
		if err := p.ofClient.UninstallServiceFlows(ip, svcPort, protocol); err != nil {
			return fmt.Errorf("failed to remove ExternalIP load balancing flows: %w", err)
		}
		if err := p.deleteRouteForServiceIP(svcInfoStr, ip, p.routeClient.DeleteExternalIPRoute); err != nil {
			return fmt.Errorf("failed to remove ExternalIP traffic redirecting routes: %w", err)
		}
	}
	return nil
}

func (p *proxier) installLoadBalancerService(svcInfoStr string,
	localGroupID,
	clusterGroupID binding.GroupIDType,
	loadBalancerIPStrings []string,
	svcPort uint16,
	protocol binding.Protocol,
	trafficPolicyLocal bool,
	affinityTimeout uint16,
	loadBalancerMode agentconfig.LoadBalancerMode) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			ip := net.ParseIP(ingress)
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
				return fmt.Errorf("failed to install LoadBalancer load balancing flows: %w", err)
			}
			if p.proxyAll {
				if err := p.addRouteForServiceIP(svcInfoStr, ip, p.routeClient.AddExternalIPRoute); err != nil {
					return fmt.Errorf("failed to install LoadBalancer traffic redirecting routes: %w", err)
				}
			}
		}
	}
	return nil
}

func (p *proxier) addRouteForServiceIP(svcInfoStr string, ip net.IP, addRouteFn func(net.IP) error) error {
	ipStr := ip.String()
	references, exists := p.serviceIPRouteReferences[ipStr]
	// If the IP was not referenced by any Service port, install a route for it.
	// Otherwise, just reference it.
	if !exists {
		if err := addRouteFn(ip); err != nil {
			return err
		}
		references = sets.New[string](svcInfoStr)
		p.serviceIPRouteReferences[ipStr] = references
	} else {
		references.Insert(svcInfoStr)
	}
	return nil
}

func (p *proxier) uninstallLoadBalancerService(svcInfoStr string, loadBalancerIPStrings []string, svcPort uint16, protocol binding.Protocol) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			ip := net.ParseIP(ingress)
			if err := p.ofClient.UninstallServiceFlows(ip, svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove LoadBalancer load balancing flows: %w", err)
			}
			if p.proxyAll {
				if err := p.deleteRouteForServiceIP(svcInfoStr, ip, p.routeClient.DeleteExternalIPRoute); err != nil {
					return fmt.Errorf("failed to remove LoadBalancer traffic redirecting routes: %w", err)
				}
			}
		}
	}
	return nil
}

func (p *proxier) deleteRouteForServiceIP(svcInfoStr string, ip net.IP, deleteRouteFn func(net.IP) error) error {
	ipStr := ip.String()
	references, exists := p.serviceIPRouteReferences[ipStr]
	// If the IP was not referenced by this Service port, skip it.
	if exists && references.Has(svcInfoStr) {
		// Delete the IP only if this Service port is the last one referencing it.
		// Otherwise, just dereference it.
		if references.Len() == 1 {
			if err := deleteRouteFn(ip); err != nil {
				return err
			}
			delete(p.serviceIPRouteReferences, ipStr)
		} else {
			references.Delete(svcInfoStr)
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

		clusterEndpoints, localEndpoints, allReachableEndpoints := p.categorizeEndpoints(endpointsToInstall, svcInfo)
		// Get the stale Endpoints and new Endpoints based on the diff of endpointsInstalled and allReachableEndpoints.
		staleEndpoints, newEndpoints := compareEndpoints(endpointsInstalled, allReachableEndpoints)
		if len(staleEndpoints) > 0 || len(newEndpoints) > 0 {
			needUpdateEndpoints = true
		}
		// If there are stale Endpoints for a UDP Service, conntrack connections of these stale Endpoints should be deleted.
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
		p.addServiceByIP(svcInfoStr, svcPortName)
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
		if err := p.installExternalIPService(svcInfoStr, localGroupID, clusterGroupID, svcInfo.ExternalIPStrings(), svcPort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout, loadBalancerMode); err != nil {
			klog.ErrorS(err, "Error when installing ExternalIP flows and configurations for Service", "ServiceInfo", svcInfoStr)
			return false
		}
	}
	// Install LoadBalancer flows and configurations.
	if p.proxyLoadBalancerIPs {
		if err := p.installLoadBalancerService(svcInfoStr, localGroupID, clusterGroupID, svcInfo.LoadBalancerIPStrings(), svcPort, svcProto, svcInfo.ExternalPolicyLocal(), affinityTimeout, loadBalancerMode); err != nil {
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
		deletedExternalIPs := smallSliceDifference(pSvcInfo.ExternalIPStrings(), svcInfo.ExternalIPStrings())
		addedExternalIPs := smallSliceDifference(svcInfo.ExternalIPStrings(), pSvcInfo.ExternalIPStrings())
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
		deletedLoadBalancerIPs := smallSliceDifference(pSvcInfo.LoadBalancerIPStrings(), svcInfo.LoadBalancerIPStrings())
		addedLoadBalancerIPs := smallSliceDifference(svcInfo.LoadBalancerIPStrings(), pSvcInfo.LoadBalancerIPStrings())
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
	klog.V(2).InfoS("Processing Endpoints ADD event", "Endpoints", klog.KObj(endpoints))
	p.OnEndpointsUpdate(nil, endpoints)
}

func (p *proxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	if oldEndpoints != nil && endpoints != nil {
		klog.V(2).InfoS("Processing Endpoints UPDATE event", "Endpoints", klog.KObj(endpoints))
	}
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
	klog.V(2).InfoS("Processing Endpoints DELETE event", "Endpoints", klog.KObj(endpoints))
	p.OnEndpointsUpdate(endpoints, nil)
}

func (p *proxier) OnEndpointsSynced() {
	p.endpointsChanges.OnEndpointsSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	klog.V(2).InfoS("Processing EndpointSlice ADD event", "EndpointSlice", klog.KObj(endpointSlice))
	if p.endpointsChanges.OnEndpointSliceUpdate(endpointSlice, false) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice) {
	klog.V(2).InfoS("Processing EndpointSlice UPDATE event", "EndpointSlice", klog.KObj(newEndpointSlice))
	if p.endpointsChanges.OnEndpointSliceUpdate(newEndpointSlice, false) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	klog.V(2).InfoS("Processing EndpointSlice DELETE event", "EndpointSlice", klog.KObj(endpointSlice))
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
	klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(service))
	p.OnServiceUpdate(nil, service)
}

func (p *proxier) OnServiceUpdate(oldService, service *corev1.Service) {
	if oldService != nil && service != nil {
		klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(service))
	}
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
	klog.V(2).InfoS("Processing Service DELETE event", "Service", klog.KObj(service))
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
		p.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategorySvcReject), p)
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

func (p *proxier) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
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

func newProxier(
	hostname string,
	serviceProxyName string,
	k8sClient clientset.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointsInformer coreinformers.EndpointsInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	nodeInformer coreinformers.NodeInformer,
	ofClient openflow.Client,
	isIPv6 bool,
	routeClient route.Interface,
	nodeIPChecker nodeip.Checker,
	nodePortAddresses []net.IP,
	proxyAllEnabled bool,
	skipServices []string,
	proxyLoadBalancerIPs bool,
	defaultLoadBalancerMode agentconfig.LoadBalancerMode,
	groupCounter types.GroupCounter,
	supportNestedService bool) (*proxier, error) {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	metrics.Register()
	klog.V(2).Infof("Creating proxier with IPv6 enabled=%t", isIPv6)

	endpointSliceEnabled := features.DefaultFeatureGate.Enabled(features.EndpointSlice)
	if endpointSliceEnabled {
		apiAvailable, err := k8sutil.EndpointSliceAPIAvailable(k8sClient)
		if err != nil {
			return nil, fmt.Errorf("error checking if EndpointSlice v1 API is available")
		}
		if !apiAvailable {
			klog.InfoS("The EndpointSlice feature gate is enabled, but the EndpointSlice v1 API is not available, falling back to the Endpoints API")
			endpointSliceEnabled = false
		}
	}
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

	p := &proxier{
		nodeIPChecker:               nodeIPChecker,
		serviceConfig:               config.NewServiceConfig(serviceInformer, resyncPeriod),
		endpointsChanges:            newEndpointsChangesTracker(hostname, endpointSliceEnabled, isIPv6),
		serviceChanges:              newServiceChangesTracker(recorder, ipFamily, serviceLabelSelector, skipServices),
		serviceMap:                  k8sproxy.ServiceMap{},
		serviceInstalledMap:         k8sproxy.ServiceMap{},
		endpointsInstalledMap:       types.EndpointsMap{},
		endpointsMap:                types.EndpointsMap{},
		endpointReferenceCounter:    map[string]int{},
		serviceIPRouteReferences:    map[string]sets.Set[string]{},
		nodeLabels:                  map[string]string{},
		serviceStringMap:            map[string]k8sproxy.ServicePortName{},
		groupCounter:                groupCounter,
		ofClient:                    ofClient,
		routeClient:                 routeClient,
		nodePortAddresses:           nodePortAddresses,
		isIPv6:                      isIPv6,
		proxyAll:                    proxyAllEnabled,
		endpointSliceEnabled:        endpointSliceEnabled,
		topologyAwareHintsEnabled:   topologyAwareHintsEnabled,
		cleanupStaleUDPSvcConntrack: features.DefaultFeatureGate.Enabled(features.CleanupStaleUDPSvcConntrack),
		proxyLoadBalancerIPs:        proxyLoadBalancerIPs,
		hostname:                    hostname,
		serviceHealthServer:         serviceHealthServer,
		numLocalEndpoints:           map[apimachinerytypes.NamespacedName]int{},
		supportNestedService:        supportNestedService,
		defaultLoadBalancerMode:     defaultLoadBalancerMode,
	}

	p.serviceConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, time.Second, 30*time.Second, 2)
	if endpointSliceEnabled {
		p.endpointSliceConfig = config.NewEndpointSliceConfig(endpointSliceInformer, resyncPeriod)
		p.endpointSliceConfig.RegisterEventHandler(p)
		if p.topologyAwareHintsEnabled {
			p.nodeConfig = config.NewNodeConfig(nodeInformer, resyncPeriod)
			p.nodeConfig.RegisterEventHandler(p)
		}
	} else {
		p.endpointsConfig = config.NewEndpointsConfig(endpointsInformer, resyncPeriod)
		p.endpointsConfig.RegisterEventHandler(p)
	}
	return p, nil
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

func newDualStackProxier(
	hostname string,
	serviceProxyName string,
	k8sClient clientset.Interface,
	servicesInformer coreinformers.ServiceInformer,
	endpointInformer coreinformers.EndpointsInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	nodeInformer coreinformers.NodeInformer,
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
	nestedServiceSupport bool) (*metaProxierWrapper, error) {

	// Create an IPv4 instance of the single-stack proxier.
	ipv4Proxier, err := newProxier(hostname,
		serviceProxyName,
		k8sClient,
		servicesInformer,
		endpointInformer,
		endpointSliceInformer,
		nodeInformer,
		ofClient,
		false,
		routeClient,
		nodeIPChecker,
		nodePortAddressesIPv4,
		proxyAllEnabled,
		skipServices,
		proxyLoadBalancerIPs,
		defaultLoadBalancerMode,
		v4groupCounter,
		nestedServiceSupport)
	if err != nil {
		return nil, fmt.Errorf("error when creating IPv4 proxier: %v", err)
	}
	// Create an IPv6 instance of the single-stack proxier.
	ipv6Proxier, err := newProxier(hostname,
		serviceProxyName,
		k8sClient,
		servicesInformer,
		endpointInformer,
		endpointSliceInformer,
		nodeInformer,
		ofClient,
		true,
		routeClient,
		nodeIPChecker,
		nodePortAddressesIPv6,
		proxyAllEnabled,
		skipServices,
		proxyLoadBalancerIPs,
		defaultLoadBalancerMode,
		v6groupCounter,
		nestedServiceSupport)
	if err != nil {
		return nil, fmt.Errorf("error when creating IPv6 proxier: %v", err)
	}
	// Create a meta-proxier that dispatch calls between the two
	// single-stack proxier instances.
	metaProxier := k8sproxy.NewMetaProxier(ipv4Proxier, ipv6Proxier)

	return &metaProxierWrapper{ipv4Proxier, ipv6Proxier, metaProxier}, nil
}

func NewProxier(hostname string,
	k8sClient clientset.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointsInformer coreinformers.EndpointsInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	nodeInformer coreinformers.NodeInformer,
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
	nestedServiceSupport bool) (Proxier, error) {
	proxyAllEnabled := proxyConfig.ProxyAll
	skipServices := proxyConfig.SkipServices
	proxyLoadBalancerIPs := *proxyConfig.ProxyLoadBalancerIPs
	serviceProxyName := proxyConfig.ServiceProxyName

	var proxier Proxier
	var err error
	switch {
	case v4Enabled && v6Enabled:
		proxier, err = newDualStackProxier(hostname,
			serviceProxyName,
			k8sClient,
			serviceInformer,
			endpointsInformer,
			endpointSliceInformer,
			nodeInformer,
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
			nestedServiceSupport)
		if err != nil {
			return nil, fmt.Errorf("error when creating dual-stack proxier: %v", err)
		}
	case v4Enabled:
		proxier, err = newProxier(hostname,
			serviceProxyName,
			k8sClient,
			serviceInformer,
			endpointsInformer,
			endpointSliceInformer,
			nodeInformer,
			ofClient,
			false,
			routeClient,
			nodeIPChecker,
			nodePortAddressesIPv4,
			proxyAllEnabled,
			skipServices,
			proxyLoadBalancerIPs,
			defaultLoadBalancerMode,
			v4GroupCounter,
			nestedServiceSupport)
		if err != nil {
			return nil, fmt.Errorf("error when creating IPv4 proxier: %v", err)
		}
	case v6Enabled:
		proxier, err = newProxier(hostname,
			serviceProxyName,
			k8sClient,
			serviceInformer,
			endpointsInformer,
			endpointSliceInformer,
			nodeInformer,
			ofClient,
			true,
			routeClient,
			nodeIPChecker,
			nodePortAddressesIPv6,
			proxyAllEnabled,
			skipServices,
			proxyLoadBalancerIPs,
			defaultLoadBalancerMode,
			v6GroupCounter,
			nestedServiceSupport)
		if err != nil {
			return nil, fmt.Errorf("error when creating IPv6 proxier: %v", err)
		}
	default:
		return nil, fmt.Errorf("either IPv4 or IPv6 proxier, or both proxiers should be created")
	}

	return proxier, nil
}

func needClearConntrackEntries(protocol binding.Protocol) bool {
	return protocol == binding.ProtocolUDP || protocol == binding.ProtocolUDPv6
}
