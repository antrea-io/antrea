// Copyright 2019 Antrea Authors
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

package main

import (
	"fmt"
	"net"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/agent/cniserver"
	_ "github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/monitor"
	ofconfig "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/signals"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

// informerDefaultResync is the default resync period if a handler doesn't specify one.
// Use the same default value as kube-controller-manager:
// https://github.com/kubernetes/kubernetes/blob/release-1.17/pkg/controller/apis/config/v1alpha1/defaults.go#L120
const informerDefaultResync = 12 * time.Hour

// run starts Antrea agent with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea agent (version %s)", version.GetFullVersion())
	// Create K8s Clientset, CRD Clientset and SharedInformerFactory for the given config.
	k8sClient, crdClient, err := k8s.CreateClients(o.config.ClientConnection)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}
	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)

	// Create Antrea Clientset for the given config.
	antreaClient, err := agent.CreateAntreaClient(o.config.AntreaClientConnection)
	if err != nil {
		return fmt.Errorf("error creating Antrea client: %v", err)
	}

	// Create ovsdb and openflow clients.
	ovsdbAddress := ovsconfig.GetConnAddress(o.config.OVSRunDir)
	ovsdbConnection, err := ovsconfig.NewOVSDBConnectionUDS(ovsdbAddress)
	if err != nil {
		// TODO: ovsconfig.NewOVSDBConnectionUDS might return timeout in the future, need to add retry
		return fmt.Errorf("error connecting OVSDB: %v", err)
	}
	defer ovsdbConnection.Close()

	ovsBridgeClient := ovsconfig.NewOVSBridge(o.config.OVSBridge, o.config.OVSDatapathType, ovsdbConnection)
	ovsBridgeMgmtAddr := ofconfig.GetMgmtAddress(o.config.OVSRunDir, o.config.OVSBridge)
	ofClient := openflow.NewClient(o.config.OVSBridge, ovsBridgeMgmtAddr)

	_, serviceCIDRNet, _ := net.ParseCIDR(o.config.ServiceCIDR)
	_, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	networkConfig := &config.NetworkConfig{
		TunnelType:        ovsconfig.TunnelType(o.config.TunnelType),
		TrafficEncapMode:  encapMode,
		EnableIPSecTunnel: o.config.EnableIPSecTunnel}

	routeClient, err := route.NewClient(o.config.HostGateway, serviceCIDRNet, encapMode)

	// Create an ifaceStore that caches network interfaces managed by this node.
	ifaceStore := interfacestore.NewInterfaceStore()

	// Initialize agent and node network.
	agentInitializer := agent.NewInitializer(
		k8sClient,
		ovsBridgeClient,
		ofClient,
		routeClient,
		ifaceStore,
		o.config.HostGateway,
		o.config.DefaultMTU,
		serviceCIDRNet,
		networkConfig)
	err = agentInitializer.Initialize()
	if err != nil {
		return fmt.Errorf("error initializing agent: %v", err)
	}
	nodeConfig := agentInitializer.GetNodeConfig()

	nodeRouteController := noderoute.NewNodeRouteController(
		k8sClient,
		informerFactory,
		ofClient,
		ovsBridgeClient,
		routeClient,
		ifaceStore,
		networkConfig,
		nodeConfig)

	// podUpdates is a channel for receiving Pod updates from CNIServer and
	// notifying NetworkPolicyController to reconcile rules related to the
	// updated Pods.
	podUpdates := make(chan v1beta1.PodReference, 100)
	networkPolicyController := networkpolicy.NewNetworkPolicyController(antreaClient, ofClient, ifaceStore, nodeConfig.Name, podUpdates)
	isChaining := false
	if networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		isChaining = true
	}
	cniServer := cniserver.New(
		o.config.CNISocket,
		o.config.HostProcPathPrefix,
		o.config.DefaultMTU,
		nodeConfig,
		k8sClient,
		podUpdates,
		isChaining,
		routeClient)
	err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, o.config.OVSDatapathType)
	if err != nil {
		return fmt.Errorf("error initializing CNI server: %v", err)
	}

	// set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	go cniServer.Run(stopCh)

	informerFactory.Start(stopCh)

	go nodeRouteController.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	agentMonitor := monitor.NewAgentMonitor(
		crdClient,
		o.config.OVSBridge,
		nodeConfig.Name,
		fmt.Sprintf("%s", nodeConfig.PodCIDR),
		ifaceStore,
		ofClient,
		ovsBridgeClient,
		networkPolicyController)

	go agentMonitor.Run(stopCh)

	apiServer, err := apiserver.New(agentMonitor, networkPolicyController)
	if err != nil {
		return fmt.Errorf("error when creating agent API server: %v", err)
	}
	go apiServer.Run(stopCh)

	<-stopCh
	klog.Info("Stopping Antrea agent")
	return nil
}
