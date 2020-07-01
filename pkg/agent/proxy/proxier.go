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
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
	"github.com/vmware-tanzu/antrea/third_party/proxy/config"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
)

// TODO: Add metrics
type Proxier struct {
	once            sync.Once
	endpointsConfig *config.EndpointsConfig
	serviceConfig   *config.ServiceConfig
	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since last syncProxyRules call. For a single object,
	// changes are accumulated. Once both endpointsChanges and serviceChanges
	// have been synced, syncProxyRules will start syncing rules to OVS.
	endpointsChanges *endpointsChangesTracker
	serviceChanges   *serviceChangesTracker
	// syncProxyRulesMutex protects internal caches and states.
	syncProxyRulesMutex sync.Mutex
	// serviceMap stores services we expect to be installed.
	serviceMap k8sproxy.ServiceMap
	// serviceInstalledMap stores services we actually installed.
	serviceInstalledMap k8sproxy.ServiceMap
	// endpointsMap stores endpoints we expect to be installed.
	endpointsMap types.EndpointsMap
	// endpointInstalledMap stores endpoints we actually installed.
	endpointInstalledMap map[k8sproxy.ServicePortName]map[string]struct{}
	groupCounter         types.GroupCounter

	runner       *k8sproxy.BoundedFrequencyRunner
	stopChan     <-chan struct{}
	agentQuerier querier.AgentQuerier
	ofClient     openflow.Client
}

func (p *Proxier) isInitialized() bool {
	return p.endpointsChanges.Synced() && p.serviceChanges.Synced()
}

func (p *Proxier) removeStaleServices() {
	for svcPortName, svcPort := range p.serviceInstalledMap {
		if _, ok := p.serviceMap[svcPortName]; ok {
			continue
		}
		svcInfo := svcPort.(*types.ServiceInfo)
		if err := p.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		for _, endpoint := range p.endpointsMap[svcPortName] {
			if err := p.ofClient.UninstallEndpointFlows(svcInfo.OFProtocol, endpoint); err != nil {
				klog.Errorf("Failed to remove flows of Service Endpoints %v: %v", svcPortName, err)
				continue
			}
		}
		groupID, _ := p.groupCounter.Get(svcPortName)
		if err := p.ofClient.UninstallServiceGroup(groupID); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		delete(p.serviceInstalledMap, svcPortName)
		p.groupCounter.Recycle(svcPortName)
	}
}

func (p *Proxier) removeStaleEndpoints(staleEndpoints map[k8sproxy.ServicePortName]map[string]k8sproxy.Endpoint) {
	for svcPortName, endpoints := range staleEndpoints {
		bindingProtocol := binding.ProtocolTCP
		if svcPortName.Protocol == corev1.ProtocolUDP {
			bindingProtocol = binding.ProtocolUDP
		} else if svcPortName.Protocol == corev1.ProtocolSCTP {
			bindingProtocol = binding.ProtocolSCTP
		}
		for _, endpoint := range endpoints {
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

func (p *Proxier) installServices() {
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
		needUpdate := !ok || !installedSvcPort.(*types.ServiceInfo).Equal(svcInfo)

		var endpointUpdateList []k8sproxy.Endpoint
		for _, endpoint := range endpoints {
			if _, ok := endpointInstalled[endpoint.String()]; !ok {
				needUpdate = true
				endpointInstalled[endpoint.String()] = struct{}{}
			}
			endpointUpdateList = append(endpointUpdateList, endpoint)
		}

		if !needUpdate {
			continue
		}

		if err := p.ofClient.InstallEndpointFlows(svcInfo.OFProtocol, endpointUpdateList); err != nil {
			klog.Errorf("Error when installing Endpoints flows: %v", err)
			continue
		}
		err := p.ofClient.InstallServiceGroup(groupID, svcInfo.StickyMaxAgeSeconds() != 0, endpointUpdateList)
		if err != nil {
			klog.Errorf("Error when installing Endpoints groups: %v", err)
			p.endpointInstalledMap[svcPortName] = nil
			continue
		}
		if err := p.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFProtocol, uint16(svcInfo.StickyMaxAgeSeconds())); err != nil {
			klog.Errorf("Error when installing Service flows: %v", err)
			continue
		}
		p.serviceInstalledMap[svcPortName] = svcPort
	}
}

// syncProxyRulesMutex applies current changes in change trackers and then updates
// flows for services and endpoints. It will abort if either endpoints or services
// resources is not synced.
func (p *Proxier) syncProxyRules() {
	p.syncProxyRulesMutex.Lock()
	defer p.syncProxyRulesMutex.Unlock()

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

	p.removeStaleEndpoints(staleEndpoints)
	p.removeStaleServices()
	p.installServices()
}

func (p *Proxier) SyncLoop() {
	p.runner.Loop(p.stopChan)
}

func (p *Proxier) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	p.OnEndpointsUpdate(nil, endpoints)
}

func (p *Proxier) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	if p.endpointsChanges.OnEndpointUpdate(oldEndpoints, endpoints) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *Proxier) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	p.OnEndpointsUpdate(endpoints, nil)
}

func (p *Proxier) OnEndpointsSynced() {
	p.endpointsChanges.OnEndpointsSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *Proxier) OnServiceAdd(service *corev1.Service) {
	p.OnServiceUpdate(nil, service)
}

func (p *Proxier) OnServiceUpdate(oldService, service *corev1.Service) {
	if p.serviceChanges.OnServiceUpdate(oldService, service) && p.isInitialized() {
		p.runner.Run()
	}
}

func (p *Proxier) OnServiceDelete(service *corev1.Service) {
	p.OnServiceUpdate(service, nil)
}

func (p *Proxier) OnServiceSynced() {
	p.serviceChanges.OnServiceSynced()
	if p.isInitialized() {
		p.runner.Run()
	}
}

func (p *Proxier) Run(stopCh <-chan struct{}) {
	p.once.Do(func() {
		go p.serviceConfig.Run(stopCh)
		go p.endpointsConfig.Run(stopCh)
		p.stopChan = stopCh
		p.SyncLoop()
	})
}

func New(hostname string, informerFactory informers.SharedInformerFactory, ofClient openflow.Client) *Proxier {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	p := &Proxier{
		endpointsConfig:      config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
		serviceConfig:        config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:     newEndpointsChangesTracker(hostname),
		serviceChanges:       newServiceChangesTracker(recorder),
		serviceMap:           k8sproxy.ServiceMap{},
		serviceInstalledMap:  k8sproxy.ServiceMap{},
		endpointInstalledMap: map[k8sproxy.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		groupCounter:         types.NewGroupCounter(),
		ofClient:             ofClient,
	}
	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
	p.runner = k8sproxy.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, 0, 30*time.Second, -1)
	return p
}
