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
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/upstream"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

// TODO: Add metrics
type proxier struct {
	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since last syncProxyRules call. For a single object,
	// changes are accumulated, i.e. previous is state from before all of them,
	// current is state after applying all of those.
	endpointsChanges *endpointsChangesTracker
	serviceChanges   *serviceChangesTracker
	// syncProxyRulesMutex protects internal caches and states
	syncProxyRulesMutex sync.Mutex
	// serviceMap stores services we expected to be installed.
	serviceMap upstream.ServiceMap
	// serviceInstalledMap stores services we actually installed.
	serviceInstalledMap upstream.ServiceMap
	// endpointsMap stores endpoints we expected to be installed.
	endpointsMap types.EndpointsMap
	// endpointInstalledMap stores endpoints we actually installed.
	endpointInstalledMap map[upstream.ServicePortName]map[string]struct{}
	groupCounter         types.GroupCounter

	runner       *upstream.BoundedFrequencyRunner
	stopChan     <-chan struct{}
	agentQuerier querier.AgentQuerier
	ofClient     openflow.Client
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
		if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFTransportProtocol); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		endpoints := p.endpointsMap[svcPortName]
		var endpointsList []upstream.Endpoint
		for _, endpoint := range endpoints {
			endpointsList = append(endpointsList, endpoint)
		}
		if err := p.ofClient.UninstallServiceEndpointsFlows(svcInfo.OFTransportProtocol, endpointsList...); err != nil {
			klog.Errorf("Failed to remove flows of Service Endpoints %v: %v", svcPortName, err)
			continue
		}
		groupID, _ := p.groupCounter.Get(svcPortName)
		if err := p.ofClient.UninstallServiceEndpointsGroup(groupID); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		delete(p.serviceInstalledMap, svcPortName)
	}
}

func (p *proxier) removeStaleEndpoints(staleEndpoints map[upstream.ServicePortName]map[string]upstream.Endpoint) {
	for svcPortName, endpoints := range staleEndpoints {
		bindingProtocol := binding.ProtocolTCP
		if svcPortName.Protocol == corev1.ProtocolUDP {
			bindingProtocol = binding.ProtocolUDP
		} else if svcPortName.Protocol == corev1.ProtocolSCTP {
			bindingProtocol = binding.ProtocolSCTP
		}
		for _, endpoint := range endpoints {
			if err := p.ofClient.UninstallServiceEndpointsFlows(bindingProtocol, endpoint); err != nil {
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

func (p *proxier) localPodsL3L2Mapping() map[string]net.HardwareAddr {
	mapping := map[string]net.HardwareAddr{}
	for _, ifCfg := range p.agentQuerier.GetInterfaceStore().GetInterfacesByType(interfacestore.ContainerInterface) {
		mapping[ifCfg.IP.String()] = ifCfg.MAC
	}
	return mapping
}

func getAffinityTimeoutSeconds(svcInfo *types.ServiceInfo) uint16 {
	var affinityTimeoutSeconds uint16
	if svcInfo.SessionAffinityType() == corev1.ServiceAffinityClientIP {
		affinityTimeoutSeconds = uint16(svcInfo.StickyMaxAgeSeconds())
		if affinityTimeoutSeconds == 0 {
			affinityTimeoutSeconds = uint16(corev1.DefaultClientIPServiceAffinitySeconds)
		}
	}
	return affinityTimeoutSeconds
}

func (p *proxier) installServices() {
	ipMACMapping := p.localPodsL3L2Mapping()
	for svcPortName, svcPort := range p.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		affinityTimeoutSeconds := getAffinityTimeoutSeconds(svcInfo)
		groupID, _ := p.groupCounter.Get(svcPortName)

		endpoints, ok := p.endpointsMap[svcPortName]
		if !ok || len(endpoints) == 0 {
			continue
		}
		if _, ok := p.endpointInstalledMap[svcPortName]; !ok {
			p.endpointInstalledMap[svcPortName] = map[string]struct{}{}
		}

		var endpointsUpdated bool
		var endpointsList []upstream.Endpoint

		for _, endpoint := range endpoints {
			if _, ok := p.endpointInstalledMap[svcPortName][endpoint.String()]; ok {
				continue
			}
			if err := p.ofClient.InstallServiceEndpointsFlows(svcInfo.OFTransportProtocol, ipMACMapping[endpoint.IP()], endpoint); err != nil {
				klog.Errorf("Error when installing Endpoints flows: %v", err)
				continue
			}
			endpointsList = append(endpointsList, endpoint)
			p.endpointInstalledMap[svcPortName][endpoint.String()] = struct{}{}
			endpointsUpdated = true
		}

		if endpointsUpdated {
			err := p.ofClient.InstallServiceEndpointsGroup(groupID, affinityTimeoutSeconds != 0, endpointsList...)
			if err != nil {
				klog.Errorf("Error when installing Endpoints groups: %v", err)
				p.endpointInstalledMap[svcPortName] = nil
				continue
			}
		}

		if _, ok := p.serviceInstalledMap[svcPortName]; !ok {
			if err := p.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFTransportProtocol, affinityTimeoutSeconds); err != nil {
				klog.Errorf("Error when installing Service flows: %v", err)
				continue
			}
		}
		p.serviceInstalledMap[svcPortName] = svcPort
	}
}

// syncProxyRulesMutex applies current changes in change trackers and then updates
// flows for services and endpoints. It will abort if either endpoints or services
// resources is not synced.
func (p *proxier) syncProxyRules() {
	p.syncProxyRulesMutex.Lock()
	defer p.syncProxyRulesMutex.Unlock()

	start := time.Now()
	defer func() {
		klog.Infof("syncProxyRules took %v", time.Since(start))
	}()
	if !p.isInitialized() {
		klog.Info("Not syncing rules until both Services and Endpoints have been received")
		return
	}

	staleEndpoints := p.endpointsChanges.Update(p.endpointsMap)
	p.serviceChanges.Update(p.serviceMap)

	p.removeStaleEndpoints(staleEndpoints)
	p.removeStaleServices()
	p.installServices()
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

func newProxier(hostname string, recorder record.EventRecorder) *proxier {
	p := &proxier{
		endpointsChanges:     newEndpointsChangesTracker(hostname),
		serviceChanges:       newServiceChangesTracker(recorder),
		serviceMap:           upstream.ServiceMap{},
		serviceInstalledMap:  upstream.ServiceMap{},
		endpointInstalledMap: map[upstream.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		groupCounter:         types.NewGroupCounter(),
	}
	p.runner = upstream.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, 0, 30*time.Second, -1)
	return p
}
