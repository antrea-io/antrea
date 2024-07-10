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
	"fmt"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/secondarynetwork/podwatch"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	newOVSBridgeFn = ovsconfig.NewOVSBridge
)

type Controller struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	secNetConfig    *agentconfig.SecondaryNetworkConfig
	podController   *podwatch.PodController
}

func NewController(
	clientConnectionConfig componentbaseconfig.ClientConnectionConfiguration,
	kubeAPIServerOverride string,
	k8sClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	podUpdateSubscriber channel.Subscriber,
	secNetConfig *agentconfig.SecondaryNetworkConfig, ovsdb *ovsdb.OVSDB,
) (*Controller, error) {
	ovsBridgeClient, err := createOVSBridge(secNetConfig.OVSBridges, ovsdb)
	if err != nil {
		return nil, err
	}

	// Create the NetworkAttachmentDefinition client, which handles access to secondary network object
	// definition from the API Server.
	netAttachDefClient, err := createNetworkAttachDefClient(clientConnectionConfig, kubeAPIServerOverride)
	if err != nil {
		return nil, fmt.Errorf("NetworkAttachmentDefinition client creation failed: %v", err)
	}

	// Create podController to handle secondary network configuration for Pods with
	// k8s.v1.cni.cncf.io/networks Annotation defined.
	podWatchController, err := podwatch.NewPodController(
		k8sClient, netAttachDefClient, podInformer,
		podUpdateSubscriber, ovsBridgeClient)
	if err != nil {
		return nil, err
	}
	return &Controller{
		ovsBridgeClient: ovsBridgeClient,
		secNetConfig:    secNetConfig,
		podController:   podWatchController}, nil
}

// Run starts the Pod controller for secondary networks.
func (c *Controller) Run(stopCh <-chan struct{}) {
	c.podController.Run(stopCh)
}

// CreateNetworkAttachDefClient creates net-attach-def client handle from the given config.
func createNetworkAttachDefClient(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (netdefclient.K8sCniCncfIoV1Interface, error) {
	kubeConfig, err := k8s.CreateRestConfig(config, kubeAPIServerOverride)
	if err != nil {
		return nil, err
	}

	netAttachDefClient, err := netdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return netAttachDefClient, nil
}

func createOVSBridge(bridges []agentconfig.OVSBridgeConfig, ovsdb *ovsdb.OVSDB) (ovsconfig.OVSBridgeClient, error) {
	if len(bridges) == 0 {
		return nil, nil
	}
	// Only one OVS bridge is supported.
	bridgeConfig := bridges[0]
	ovsBridgeClient := newOVSBridgeFn(bridgeConfig.BridgeName, ovsconfig.OVSDatapathSystem, ovsdb)
	if err := ovsBridgeClient.Create(); err != nil {
		return nil, fmt.Errorf("failed to create OVS bridge %s: %v", bridgeConfig.BridgeName, err)
	}
	klog.InfoS("OVS bridge created", "bridge", bridgeConfig.BridgeName)
	return ovsBridgeClient, nil
}
