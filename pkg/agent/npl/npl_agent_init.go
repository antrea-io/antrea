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

package npl

import (
	"errors"
	"fmt"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent/npl/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/npl/portcache"
	"github.com/vmware-tanzu/antrea/pkg/agent/npl/util"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

const resyncPeriod = 60 * time.Minute

// InitializeNPLAgent starts NodePortLocal (NPL) agent.
// It initializes port table cache to keep a track of Node ports available for use of NPL,
// sets up event handlers to handle Pod add, update and delete events.
// When a Pod gets created, a free Node port is obtained from the port table cache and a DNAT rule is added to send traffic to the Pod ip:port.
func InitializeNPLAgent(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portRange string, stop <-chan struct{}) error {
	nodeName, err := env.GetNodeName()
	if err != nil {
		return fmt.Errorf("Could not get node name while initializing NPL: %v", err)
	}
	start, end, err := util.ParsePortsRange(portRange)
	if err != nil {
		return fmt.Errorf("something went wrong while fetching port range: %v", err)
	}
	var ok bool
	portTable, ok := portcache.NewPortTable(start, end)
	if !ok {
		return errors.New("NPL port table could not be initialized")
	}
	ok = portTable.PodPortRules.Init()
	if !ok {
		return errors.New("NPL rules for pod ports could not be initialized")
	}
	c := k8s.NewNPLController(kubeClient, portTable)
	c.RemoveNPLAnnotationFromPods()

	// Watch only the Pods which belong to the node where the agent is running
	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName)
	lw := cache.NewListWatchFromClient(kubeClient.CoreV1().RESTClient(), "pods", metav1.NamespaceAll, fieldSelector)
	_, controller := cache.NewInformer(lw, &corev1.Pod{}, resyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.HandleAddPod,
			DeleteFunc: c.HandleDeletePod,
			UpdateFunc: c.HandleUpdatePod,
		},
	)

	go controller.Run(stop)
	return nil
}
