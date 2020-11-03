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

package nplagent

import (
	"errors"
	"fmt"

	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/portcache"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
)

// InitializeNPLAgent : start NodePortLocal (NPL) agent
// Initialize port table cache to keep a track of node ports available for use of NPL
// SetupEventHandlers to handle pod add, update and delete events
// When a Pod gets created, a free node port is obtained from the port table cache and a DNAT rule is added to send traffic to the pod ip:port
func InitializeNPLAgent(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portRange string) error {
	c := k8s.NewNPLController(kubeClient)
	start, end, err := lib.ParsePortsRange(portRange)
	if err != nil {
		return fmt.Errorf("something went wrong while fetching port range: %v", err)
	}
	var ok bool
	c.PortTable, ok = portcache.NewPortTable(start, end)
	if !ok {
		return errors.New("NPL port table could not be initialized")
	}
	ok = c.PortTable.PodPortRules.Init()
	if !ok {
		return errors.New("NPL rules for pod ports could not be initialized")
	}
	c.RemoveNPLAnnotationFromPods()
	c.SetupEventHandlers(informerFactory)
	return nil
}
