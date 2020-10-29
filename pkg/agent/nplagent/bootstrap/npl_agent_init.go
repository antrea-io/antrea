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

package bootstrap

import (
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/k8s"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/portcache"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

// InitializeNPLAgent : start NodePortLocal (NPL) agent
// Initialize port table cache to keep a track of node ports available for use of NPL
// SetupEventHandlers to handle pod add, update and delete events
// When a Pod gets created, a free node port is obtained from the port table cache and a DNAT rule is added to send traffic to the pod ip:port
func InitializeNPLAgent(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory) error {
	c := k8s.NewNPLController(kubeClient)
	start, end, err := lib.GetPortsRange()
	if err != nil {
		klog.Errorf("Something went wrong while fetching port range: %s", err.Error())
		return err
	}
	c.PortTable = portcache.NewPortTable(start, end)
	c.RemoveNPLAnnotationFromPods()
	c.SetupEventHandlers(informerFactory)
	return nil
}
