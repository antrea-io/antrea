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

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
	"github.com/vmware-tanzu/antrea/third_party/proxy/config"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
)

var _ Proxier = new(proxier)

type Proxier interface {
	Run(stopCh <-chan struct{})
	GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool)
}

// TODO: Add metrics
type proxier struct {
	onceRun                  sync.Once
	onceInitializedReconcile sync.Once
	endpointsConfig          *config.EndpointsConfig
	serviceConfig            *config.ServiceConfig
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

	runner            *k8sproxy.BoundedFrequencyRunner
	stopChan          <-chan struct{}
	agentQuerier      querier.AgentQuerier
	ofClient          openflow.Client
	routeClient       route.Interface
	nodeIPs           []net.IP
	virtualNodePortIP net.IP
}

func (p *proxier) isInitialized() bool {
	return p.endpointsChanges.Synced() && p.serviceChanges.Synced()
}

func (p *proxier) removeStaleServices() {
	for svcPortName, svcPort := range p.serviceInstalledMap {
		installed := svcPort.(*types.ServiceInfo)
		expected := p.serviceMap[svcPortName]
		if expected != nil && expected.(*types.ServiceInfo).Equal(installed) {
			continue
		}
		if err := p.ofClient.UninstallServiceFlows(installed.ClusterIP(), uint16(installed.Port()), installed.OFProtocol); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		for _, ingress := range installed.LoadBalancerIPStrings() {
			if ingress != "" {
				if err := p.ofClient.UninstallServiceFlows(net.ParseIP(ingress), uint16(installed.Port()), installed.OFProtocol); err != nil {
					klog.Errorf("Error when installing Service flows: %v", err)
					continue
				}
			}
		}
		if installed.NodePort() > 0 {
			if err := p.ofClient.UninstallServiceFlows(p.virtualNodePortIP, uint16(installed.NodePort()), installed.OFProtocol); err != nil {
				klog.Errorf("Failed to remove NodePort flow of Service %v: %v", svcPortName, err)
				continue
			}
			if err := p.routeClient.DeleteNodePort(p.nodeIPs, installed); err != nil {
				klog.Errorf("Error when removing NodePort rules of Service %v, %v", installed.String(), err)
			}
		}
		groupID, _ := p.groupCounter.Get(svcPortName)
		if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		for _, endpoint := range p.endpointsMap[svcPortName] {
			if err := p.ofClient.UninstallEndpointFlows(installed.OFProtocol, endpoint); err != nil {
				klog.Errorf("Failed to remove flows of Service Endpoints %v: %v", svcPortName, err)
				continue
			}
		}
		delete(p.serviceInstalledMap, svcPortName)
		delete(p.endpointInstalledMap, svcPortName)
		p.deleteServiceByIP(installed.String())
		p.groupCounter.Recycle(svcPortName)
	}
}

func (p *proxier) removeStaleEndpoints(staleEndpoints map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint) {
	for svcPortName, endpoints := range staleEndpoints {
		bindingProtocol := binding.ProtocolTCP
		if svcPortName.Protocol == corev1.ProtocolUDP {
			bindingProtocol = binding.ProtocolUDP
		} else if svcPortName.Protocol == corev1.ProtocolSCTP {
			bindingProtocol = binding.ProtocolSCTP
		}
		var m map[string]struct{}
		if m = p.endpointInstalledMap[svcPortName]; len(m) == 0 {
			continue
		}
		for _, endpoint := range endpoints {
			if _, ok := p.endpointInstalledMap[svcPortName][endpoint.String()]; !ok {
				continue
			}
			if err := p.ofClient.UninstallEndpointFlows(bindingProtocol, endpoint); err != nil {
				klog.Errorf("Error when removing Endpoint %v for %v", endpoint, svcPortName)
				continue
			}
			delete(m, endpoint.String())
		}
		if len(m) == 0 {
			delete(p.endpointInstalledMap, svcPortName)
		}
	}
}

// calculateServiceEndpointUpdateList calculates the Endpoints of the Service to be installed.
// If Endpoints of the Service have changed, all current Endpoints of the Service will be returned. Otherwise, it will
// return nil.
func (p *proxier) calculateServiceEndpointUpdateList(svcPortName k8sproxy.ServicePortName, local bool) ([]k8sproxy.Endpoint, bool) {
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
		shouldInstall := !local || endpoint.GetIsLocal()
		if installed != shouldInstall {
			needUpdate = true
		}
		if shouldInstall {
			endpointUpdateList = append(endpointUpdateList, endpoint)
		}
	}
	if !needUpdate {
		endpointUpdateList = nil
	}
	return endpointUpdateList, needUpdate
}

func (p *proxier) installEndpoints(endpoints []k8sproxy.Endpoint, svcPortName k8sproxy.ServicePortName, svcInfo *types.ServiceInfo, isNodeLocalNodePort bool) error {
	groupID, _ := p.groupCounter.Get(svcPortName)
	if err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpoints); err != nil {
		return err
	}
	err := p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpoints)
	if err != nil {
		return err
	}
	return nil
}

func (p *proxier) installService(svcPortName k8sproxy.ServicePortName, svcInfo *types.ServiceInfo) error {
	groupID, _ := p.groupCounter.Get(svcPortName)
	if err := p.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds())); err != nil {
		return err
	}
	// Install OpenFlow entries for the ingress IPs of LoadBalancer Service.
	// The LoadBalancer Service should can be accessed from Pod, Node and
	// external host.
	for _, ingress := range svcInfo.LoadBalancerIPStrings() {
		if ingress != "" {
			if err := p.installLoadBalancerServiceFlows(groupID, net.ParseIP(ingress), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds())); err != nil {
				klog.Errorf("Error when installing LoadBalancer Service flows: %v", err)
				continue
			}
		}
	}
	if svcInfo.NodePort() > 0 {
		if err := p.ofClient.InstallServiceFlows(groupID, p.virtualNodePortIP, uint16(svcInfo.NodePort()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds())); err != nil {
			return fmt.Errorf("error when installing Service NodePort flow: %w", err)
		}
		if err := p.routeClient.AddNodePort(p.nodeIPs, svcInfo); err != nil {
			return fmt.Errorf("error when installing Service NodePort rules: %w", err)
		}
	}
	return nil
}

func (p *proxier) install() {
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		endpointUpdateList, needUpdateEndpoints := p.calculateServiceEndpointUpdateList(svcPortName, svcInfo.OnlyNodeLocalEndpoints())
		if needUpdateEndpoints {
			if err := p.installEndpoints(endpointUpdateList, svcPortName, svcInfo, svcInfo.OnlyNodeLocalEndpoints()); err != nil {
				klog.Errorf("Error when installing Endpoints flows for Service %v: %v", svcPortName.String(), err)
				continue
			}
		}
		installedSvcPort := p.serviceInstalledMap[svcPortName]
		if installedSvcPort == nil && !needUpdateEndpoints && len(p.endpointInstalledMap[svcPortName]) == 0 {
			continue
		}
		if installedSvcPort == nil {
			klog.Infof("Installing Service %s %s", svcInfo.String(), svcInfo.ResourceVersion)
			if err := p.installService(svcPortName, svcInfo); err != nil {
				klog.Errorf("Error when installing the Service %v flow: %v", svcPortName.String(), err)
				continue
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
	// When the first time both Services and Endpoints are synced, we do a reconciliation.
	p.onceInitializedReconcile.Do(func() {
		start := time.Now()
		defer func() {
			klog.Infof("Finish reconciliation for NodePort IPSet: %s", time.Since(start).String())
		}()
		var svcInfos []*types.ServiceInfo
		for _, svcPort := range p.serviceMap {
			svcInfos = append(svcInfos, svcPort.(*types.ServiceInfo))
		}
		if err := p.routeClient.ReconcileNodePort(p.nodeIPs, svcInfos); err != nil {
			klog.Errorf("Error when reconciling NodePort route: %v", err)
		} else {
			klog.V(4).Infoln("NodePort iptables rules and routes reconciled.")
		}
	})

	staleEndpoints := p.endpointsChanges.Update(p.endpointsMap)
	p.serviceChanges.Update(p.serviceMap)

	p.removeStaleServices()
	p.removeStaleEndpoints(staleEndpoints)
	p.install()
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

func (p *proxier) OnServiceAdd(service *corev1.Service) {
	p.OnServiceUpdate(nil, service)
}

func (p *proxier) OnServiceUpdate(oldService, service *corev1.Service) {
	if p.serviceChanges.OnServiceUpdate(oldService, service) && p.isInitialized() {
		p.runner.Run()
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
	p.onceRun.Do(func() {
		if err := p.routeClient.AddNodePortRoute(); err != nil {
			panic(err)
		}
		go p.serviceConfig.Run(stopCh)
		go p.endpointsConfig.Run(stopCh)
		p.stopChan = stopCh
		p.SyncLoop()
	})
}

// getLocalAddrs returns a list of all network addresses on the local system.
func getLocalAddrs() ([]net.IP, error) {
	var localAddrs []net.IP

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, err
		}
		localAddrs = append(localAddrs, ip)
	}

	return localAddrs, nil
}

func filterIPFamily(isV6 bool, ips ...net.IP) []net.IP {
	var result []net.IP
	for _, ip := range ips {
		if !isV6 && ip.To4() != nil {
			result = append(result, ip)
		} else if isV6 && ip.To4() != nil && ip.To16() != nil {
			result = append(result, ip)
		}
	}
	return result
}

func getAvailableAddresses(nodePortAddresses []*net.IPNet, podCIDR *net.IPNet) ([]net.IP, error) {
	localAddresses, err := getLocalAddrs()
	if err != nil {
		return nil, err
	}
	var nodeIPs []net.IP
	for _, nodeIP := range filterIPFamily(false, localAddresses...) {
		if podCIDR.Contains(nodeIP) {
			continue
		}
		var contains bool
		for _, nodePortAddress := range nodePortAddresses {
			if nodePortAddress.Contains(nodeIP) {
				contains = true
				break
			}
		}
		if len(nodePortAddresses) == 0 || contains {
			nodeIPs = append(nodeIPs, nodeIP)
		}
	}
	if len(nodeIPs) == 0 {
		klog.Warningln("No qualified node IP found.")
	}
	return nodeIPs, nil
}

func New(virtualNodePortIP net.IP, nodePortAddresses []*net.IPNet, hostname string, podCIDR *net.IPNet, informerFactory informers.SharedInformerFactory, ofClient openflow.Client, routeClient route.Interface) (*proxier, error) {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	nodeIPs, err := getAvailableAddresses(nodePortAddresses, podCIDR)
	if err != nil {
		return nil, err
	}
	klog.Infof("Proxy NodePort Services on addresses: %v", nodeIPs)
	p := &proxier{
		endpointsConfig:      config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
		serviceConfig:        config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:     newEndpointsChangesTracker(hostname),
		serviceChanges:       newServiceChangesTracker(recorder),
		serviceMap:           k8sproxy.ServiceMap{},
		serviceInstalledMap:  k8sproxy.ServiceMap{},
		endpointInstalledMap: map[k8sproxy.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		serviceStringMap:     map[string]k8sproxy.ServicePortName{},
		groupCounter:         types.NewGroupCounter(),
		ofClient:             ofClient,
		routeClient:          routeClient,
		virtualNodePortIP:    virtualNodePortIP,
		nodeIPs:              nodeIPs,
	}
	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, 0, 30*time.Second, -1)
	return p, nil
}
