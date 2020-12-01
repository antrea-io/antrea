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

package k8s

import (
	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Controller struct {
	portTable  *portcache.PortTable
	kubeClient clientset.Interface
	Ctrl       cache.Controller
}

func NewNPLController(kubeClient clientset.Interface, pt *portcache.PortTable) *Controller {
	return &Controller{kubeClient: kubeClient, portTable: pt}
}

// Run starts watching and processing Pod updates for the node where Antrea Agent is running
func (c *Controller) Run(stop <-chan struct{}) {
	go c.Ctrl.Run(stop)
}
