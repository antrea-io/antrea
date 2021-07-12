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
	"errors"
	"fmt"
	"time"

	nplk8s "antrea.io/antrea/pkg/agent/nodeportlocal/k8s"
	"antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	"antrea.io/antrea/pkg/agent/nodeportlocal/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Set resyncPeriod to 0 to disable resyncing.
// UpdateFunc event handler will be called only when the object is actually updated.
const resyncPeriod = 0 * time.Minute

// InitializeNPLAgent initializes the NodePortLocal agent.
// It sets up event handlers to handle Pod add, update and delete events.
// When a Pod gets created, a free Node port is obtained from the port table cache and a DNAT rule is added to NAT traffic to the Pod's ip:port.
func InitializeNPLAgent(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portRange, nodeName string) (*nplk8s.NPLController, error) {
	start, end, err := util.ParsePortsRange(portRange)
	if err != nil {
		return nil, fmt.Errorf("error while fetching port range: %v", err)
	}
	var ok bool
	portTable, ok := portcache.NewPortTable(start, end)
	if !ok {
		return nil, errors.New("error when initializing NodePortLocal port table")
	}

	err = portTable.PodPortRules.Init()
	if err != nil {
		return nil, fmt.Errorf("NPL rules for pod ports could not be initialized, error: %v", err)
	}

	return InitController(kubeClient, informerFactory, portTable, nodeName)
}

// InitController initializes the NPLController with appropriate Pod and Service Informers.
// This function can be used independently while unit testing without using InitializeNPLAgent function.
func InitController(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portTable *portcache.PortTable, nodeName string) (*nplk8s.NPLController, error) {
	// Watch only the Pods which belong to the Node where the agent is running.
	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	}
	podInformer := coreinformers.NewFilteredPodInformer(
		kubeClient,
		metav1.NamespaceAll,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
		listOptions,
	)

	svcInformer := informerFactory.Core().V1().Services().Informer()

	c := nplk8s.NewNPLController(kubeClient,
		podInformer,
		svcInformer,
		resyncPeriod,
		portTable,
		nodeName)

	return c, nil
}
