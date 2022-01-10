//go:build !windows
// +build !windows

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

package nodeportlocal

import (
	"fmt"
	"time"

	nplk8s "antrea.io/antrea/pkg/agent/nodeportlocal/k8s"
	"antrea.io/antrea/pkg/agent/nodeportlocal/portcache"

	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Set resyncPeriod to 0 to disable resyncing.
// UpdateFunc event handler will be called only when the object is actually updated.
const resyncPeriod = 0 * time.Minute

// InitializeNPLAgent initializes the NodePortLocal agent.
// It sets up event handlers to handle Pod add, update and delete events.
// When a Pod gets created, a free Node port is obtained from the port table cache and a DNAT rule is added to NAT traffic to the Pod's ip:port.
func InitializeNPLAgent(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	startPort int,
	endPort int,
	nodeName string,
	podInformer cache.SharedIndexInformer,
) (*nplk8s.NPLController, error) {
	portTable, err := portcache.NewPortTable(startPort, endPort)
	if err != nil {
		return nil, fmt.Errorf("error when initializing NodePortLocal port table: %v", err)
	}

	return InitController(kubeClient, informerFactory, portTable, nodeName, podInformer)
}

// InitController initializes the NPLController with appropriate Pod and Service Informers.
// This function can be used independently while unit testing without using InitializeNPLAgent function.
func InitController(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portTable *portcache.PortTable, nodeName string, podInformer cache.SharedIndexInformer) (*nplk8s.NPLController, error) {
	svcInformer := informerFactory.Core().V1().Services().Informer()

	c := nplk8s.NewNPLController(kubeClient,
		podInformer,
		svcInformer,
		resyncPeriod,
		portTable,
		nodeName)

	return c, nil
}
