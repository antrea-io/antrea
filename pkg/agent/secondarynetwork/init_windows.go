//go:build windows
// +build windows

// Copyright 2024 Antrea Authors
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

package secondarynetwork

import (
	"github.com/ovn-kubernetes/libovsdb/client"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/util/channel"
)

func NewController(
	clientConnectionConfig componentbaseconfig.ClientConnectionConfiguration,
	kubeAPIServerOverride string,
	k8sClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	podUpdateSubscriber channel.Subscriber,
	primaryInterfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
	secNetConfig *agentconfig.SecondaryNetworkConfig,
	ovsdbClient client.Client,
	ipPoolLister crdlisters.IPPoolLister,
	ancUpdateSubscriber channel.Subscriber,
) (*Controller, error) {
	klog.V(2).InfoS("Secondary network controller is not supported on Windows")
	return nil, nil
}

func (c *Controller) Initialize(stopCh <-chan struct{}) error {
	return nil
}

func (c *Controller) Restore() {
	// Not supported on Windows.
}

func (c *Controller) Run(stopCh <-chan struct{}) {}
