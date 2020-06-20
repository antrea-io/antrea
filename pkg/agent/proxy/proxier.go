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
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/upstream"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/upstream/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
)

// TODO: Add metrics
type Instance struct {
	once            sync.Once
	endpointsConfig *config.EndpointsConfig
	serviceConfig   *config.ServiceConfig
	// endpointsChanges and serviceChanges contains all changes to endpoints and
	// services that happened since last syncProxyRules call. For a single object,
	// changes are accumulated, i.e. previous is state from before all of them,
	// current is state after applying all of those.
	endpointsChanges *endpointsChangesTracker
	serviceChanges   *serviceChangesTracker
	// syncProxyRulesMutex protects internal caches and states.
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

func (i *Instance) isInitialized() bool {
	return i.endpointsChanges.Synced() && i.serviceChanges.Synced()
}

func (i *Instance) removeStaleServices() {
	for svcPortName, svcPort := range i.serviceInstalledMap {
		if _, ok := i.serviceMap[svcPortName]; ok {
			continue
		}
		svcInfo := svcPort.(*types.ServiceInfo)
		if err := i.ofClient.UninstallServiceFlows(svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFTransportProtocol); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		for _, endpoint := range i.endpointsMap[svcPortName] {
			if err := i.ofClient.UninstallEndpointFlows(svcInfo.OFTransportProtocol, endpoint); err != nil {
				klog.Errorf("Failed to remove flows of Service Endpoints %v: %v", svcPortName, err)
				continue
			}
		}
		groupID, _ := i.groupCounter.Get(svcPortName)
		if err := i.ofClient.UninstallServiceGroup(groupID); err != nil {
			klog.Errorf("Failed to remove flows of Service %v: %v", svcPortName, err)
			continue
		}
		delete(i.serviceInstalledMap, svcPortName)
	}
}

func (i *Instance) removeStaleEndpoints(staleEndpoints map[upstream.ServicePortName]map[string]upstream.Endpoint) {
	for svcPortName, endpoints := range staleEndpoints {
		bindingProtocol := binding.ProtocolTCP
		if svcPortName.Protocol == corev1.ProtocolUDP {
			bindingProtocol = binding.ProtocolUDP
		} else if svcPortName.Protocol == corev1.ProtocolSCTP {
			bindingProtocol = binding.ProtocolSCTP
		}
		for _, endpoint := range endpoints {
			if err := i.ofClient.UninstallEndpointFlows(bindingProtocol, endpoint); err != nil {
				klog.Errorf("Error when removing Endpoint %v for %v", endpoint, svcPortName)
				continue
			}
			if m, ok := i.endpointInstalledMap[svcPortName]; ok {
				delete(m, endpoint.String())
				if len(m) == 0 {
					delete(i.endpointInstalledMap, svcPortName)
				}
			}
		}
	}
}

func (i *Instance) installServices() {
	for svcPortName, svcPort := range i.serviceMap {
		svcInfo := svcPort.(*types.ServiceInfo)
		groupID, _ := i.groupCounter.Get(svcPortName)
		endpoints, ok := i.endpointsMap[svcPortName]
		if !ok || len(endpoints) == 0 {
			continue
		}

		endpointInstalled, ok := i.endpointInstalledMap[svcPortName]
		if !ok {
			i.endpointInstalledMap[svcPortName] = map[string]struct{}{}
			endpointInstalled = i.endpointInstalledMap[svcPortName]
		}

		installedSvcPort, ok := i.serviceInstalledMap[svcPortName]
		needUpdate := !ok || !installedSvcPort.(*types.ServiceInfo).Equal(svcInfo)

		var endpointUpdateList []upstream.Endpoint
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

		if err := i.ofClient.InstallEndpointFlows(svcInfo.OFTransportProtocol, endpointUpdateList); err != nil {
			klog.Errorf("Error when installing Endpoints flows: %v", err)
			continue
		}
		err := i.ofClient.InstallServiceGroup(groupID, svcInfo.AffinityTimeoutSeconds != 0, endpointUpdateList)
		if err != nil {
			klog.Errorf("Error when installing Endpoints groups: %v", err)
			i.endpointInstalledMap[svcPortName] = nil
			continue
		}
		if err := i.ofClient.InstallServiceFlows(groupID, svcInfo.ClusterIP(), uint16(svcInfo.Port()), svcInfo.OFTransportProtocol, svcInfo.AffinityTimeoutSeconds); err != nil {
			klog.Errorf("Error when installing Service flows: %v", err)
			continue
		}
		i.serviceInstalledMap[svcPortName] = svcPort
	}
}

// syncProxyRulesMutex applies current changes in change trackers and then updates
// flows for services and endpoints. It will abort if either endpoints or services
// resources is not synced.
func (i *Instance) syncProxyRules() {
	i.syncProxyRulesMutex.Lock()
	defer i.syncProxyRulesMutex.Unlock()

	start := time.Now()
	defer func() {
		klog.Infof("syncProxyRules took %v", time.Since(start))
	}()
	if !i.isInitialized() {
		klog.Info("Not syncing rules until both Services and Endpoints have been received")
		return
	}

	staleEndpoints := i.endpointsChanges.Update(i.endpointsMap)
	i.serviceChanges.Update(i.serviceMap)

	i.removeStaleEndpoints(staleEndpoints)
	i.removeStaleServices()
	i.installServices()
}

func (i *Instance) SyncLoop() {
	i.runner.Loop(i.stopChan)
}

func (i *Instance) OnEndpointsAdd(endpoints *corev1.Endpoints) {
	i.OnEndpointsUpdate(nil, endpoints)
}

func (i *Instance) OnEndpointsUpdate(oldEndpoints, endpoints *corev1.Endpoints) {
	if i.endpointsChanges.OnEndpointUpdate(oldEndpoints, endpoints) && i.isInitialized() {
		i.runner.Run()
	}
}

func (i *Instance) OnEndpointsDelete(endpoints *corev1.Endpoints) {
	i.OnEndpointsUpdate(endpoints, nil)
}

func (i *Instance) OnEndpointsSynced() {
	i.endpointsChanges.OnEndpointsSynced()
	if i.isInitialized() {
		i.runner.Run()
	}
}

func (i *Instance) OnServiceAdd(service *corev1.Service) {
	i.OnServiceUpdate(nil, service)
}

func (i *Instance) OnServiceUpdate(oldService, service *corev1.Service) {
	if i.serviceChanges.OnServiceUpdate(oldService, service) && i.isInitialized() {
		i.runner.Run()
	}
}

func (i *Instance) OnServiceDelete(service *corev1.Service) {
	i.OnServiceUpdate(service, nil)
}

func (i *Instance) OnServiceSynced() {
	i.serviceChanges.OnServiceSynced()
	if i.isInitialized() {
		i.runner.Run()
	}
}

func (i *Instance) Run(stopCh <-chan struct{}) {
	i.once.Do(func() {
		go i.serviceConfig.Run(stopCh)
		go i.endpointsConfig.Run(stopCh)
		i.stopChan = stopCh
		i.SyncLoop()
	})
}

func New(hostname string, informerFactory informers.SharedInformerFactory, ofClient openflow.Client) *Instance {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	p := &Instance{
		endpointsConfig:      config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod),
		serviceConfig:        config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod),
		endpointsChanges:     newEndpointsChangesTracker(hostname),
		serviceChanges:       newServiceChangesTracker(recorder),
		serviceMap:           upstream.ServiceMap{},
		serviceInstalledMap:  upstream.ServiceMap{},
		endpointInstalledMap: map[upstream.ServicePortName]map[string]struct{}{},
		endpointsMap:         types.EndpointsMap{},
		groupCounter:         types.NewGroupCounter(),
		ofClient:             ofClient,
	}
	p.serviceConfig.RegisterEventHandler(p)
	p.endpointsConfig.RegisterEventHandler(p)
	p.runner = upstream.NewBoundedFrequencyRunner(componentName, p.syncProxyRules, 0, 30*time.Second, -1)
	return p
}
