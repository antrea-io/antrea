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

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/upstream/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
)

const (
	resyncPeriod  = time.Minute
	componentName = "antrea-agent-proxy"
)

type instance struct {
	serviceConfig   *config.ServiceConfig
	endpointsConfig *config.EndpointsConfig
	proxier         *proxier

	once sync.Once
}

// Instance defines the interface to run the antrea agent proxy.
type Instance interface {
	// Run starts the antrea agent proxy, this method should return once it
	// receives from the stopCh.
	Run(agentQuerier querier.AgentQuerier, ofClient openflow.Client, stopCh <-chan struct{})
}

func (i *instance) Run(agentQuerier querier.AgentQuerier, ofClient openflow.Client, stopCh <-chan struct{}) {
	i.once.Do(func() {
		i.proxier.agentQuerier = agentQuerier
		i.proxier.ofClient = ofClient

		go i.serviceConfig.Run(stopCh)
		go i.endpointsConfig.Run(stopCh)

		i.proxier.stopChan = stopCh
		i.proxier.SyncLoop()
	})
}

func New(hostname string, informerFactory informers.SharedInformerFactory) (Instance, error) {
	recorder := record.NewBroadcaster().NewRecorder(
		runtime.NewScheme(),
		corev1.EventSource{Component: componentName, Host: hostname},
	)
	p := newProxier(hostname, recorder)

	serviceConfig := config.NewServiceConfig(informerFactory.Core().V1().Services(), resyncPeriod)
	serviceConfig.RegisterEventHandler(p)
	endpointsConfig := config.NewEndpointsConfig(informerFactory.Core().V1().Endpoints(), resyncPeriod)
	endpointsConfig.RegisterEventHandler(p)

	return &instance{
		endpointsConfig: endpointsConfig,
		serviceConfig:   serviceConfig,
		proxier:         p,
	}, nil
}
