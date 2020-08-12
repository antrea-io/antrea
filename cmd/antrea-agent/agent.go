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

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/agent/cniserver"
	_ "github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/traceflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/exporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/log"
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
	k8sClient, _, crdClient, err := k8s.CreateClients(o.config.ClientConnection)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}
	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	traceflowInformer := crdInformerFactory.Ops().V1alpha1().Traceflows()

	// Create Antrea Clientset for the given config.
	antreaClientProvider := agent.NewAntreaClientProvider(o.config.AntreaClientConnection, k8sClient)
	if err != nil {
		return fmt.Errorf("error creating Antrea client: %v", err)
	}

	// Register Antrea Agent metrics if EnablePrometheusMetrics is set
	if o.config.EnablePrometheusMetrics {
		metrics.InitializePrometheusMetrics()
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
	ofClient := openflow.NewClient(o.config.OVSBridge, ovsBridgeMgmtAddr,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		features.DefaultFeatureGate.Enabled(features.ClusterNetworkPolicy))

	_, serviceCIDRNet, _ := net.ParseCIDR(o.config.ServiceCIDR)
	_, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	networkConfig := &config.NetworkConfig{
		TunnelType:        ovsconfig.TunnelType(o.config.TunnelType),
		TrafficEncapMode:  encapMode,
		EnableIPSecTunnel: o.config.EnableIPSecTunnel}

	routeClient, err := route.NewClient(serviceCIDRNet, encapMode)
	if err != nil {
		return fmt.Errorf("error creating route client: %v", err)
	}

	// Create an ifaceStore that caches network interfaces managed by this node.
	ifaceStore := interfacestore.NewInterfaceStore()

	// Initialize agent and node network.
	agentInitializer := agent.NewInitializer(
		k8sClient,
		ovsBridgeClient,
		ofClient,
		routeClient,
		ifaceStore,
		o.config.OVSBridge,
		o.config.HostGateway,
		o.config.DefaultMTU,
		serviceCIDRNet,
		networkConfig,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy))
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

	var traceflowController *traceflow.Controller
	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		traceflowController = traceflow.NewTraceflowController(
			k8sClient,
			informerFactory,
			crdClient,
			traceflowInformer,
			ofClient,
			ovsBridgeClient,
			ifaceStore,
			networkConfig,
			nodeConfig)
	}

	// podUpdates is a channel for receiving Pod updates from CNIServer and
	// notifying NetworkPolicyController to reconcile rules related to the
	// updated Pods.
	podUpdates := make(chan v1beta1.PodReference, 100)
	networkPolicyController := networkpolicy.NewNetworkPolicyController(antreaClientProvider, ofClient, ifaceStore, nodeConfig.Name, podUpdates)
	isChaining := false
	if networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		isChaining = true
	}
	var proxier *proxy.Proxier
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		proxier = proxy.New(nodeConfig.Name, informerFactory, ofClient)
	}
	cniServer := cniserver.New(
		o.config.CNISocket,
		o.config.HostProcPathPrefix,
		nodeConfig,
		k8sClient,
		podUpdates,
		isChaining,
		routeClient)
	err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, o.config.OVSDatapathType)
	if err != nil {
		return fmt.Errorf("error initializing CNI server: %v", err)
	}

	// TODO: we should call this after installing flows for initial node routes
	//  and initial NetworkPolicies so that no packets will be mishandled.
	if err := agentInitializer.FlowRestoreComplete(); err != nil {
		return err
	}

	if err := antreaClientProvider.RunOnce(); err != nil {
		return err
	}
	// set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	log.StartLogFileNumberMonitor(stopCh)

	go cniServer.Run(stopCh)

	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go antreaClientProvider.Run(stopCh)

	go nodeRouteController.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		go traceflowController.Run(stopCh)
	}

	agentQuerier := querier.NewAgentQuerier(
		nodeConfig,
		ifaceStore,
		k8sClient,
		ofClient,
		ovsBridgeClient,
		networkPolicyController,
		o.config.APIPort)

	agentMonitor := monitor.NewAgentMonitor(crdClient, agentQuerier)

	go agentMonitor.Run(stopCh)

	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		go proxier.Run(stopCh)
	}

	apiServer, err := apiserver.New(
		agentQuerier,
		networkPolicyController,
		o.config.APIPort,
		o.config.EnablePrometheusMetrics,
		o.config.ClientConnection.Kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating agent API server: %v", err)
	}
	go apiServer.Run(stopCh)

	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		go ofClient.StartPacketInHandler(stopCh)
	}

	// Initialize flow exporter to start go routines to poll conntrack flows and export IPFIX flow records
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		connStore := connections.NewConnectionStore(
			connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, agentQuerier.GetOVSCtlClient(), o.config.OVSDatapathType),
			ifaceStore,
			o.pollInterval)
		pollDone := make(chan struct{})
		go connStore.Run(stopCh, pollDone)

		flowExporter := exporter.NewFlowExporter(
			flowrecords.NewFlowRecords(connStore),
			o.config.FlowExportFrequency)
		go wait.Until(func() { flowExporter.Export(o.flowCollector, stopCh, pollDone) }, 0, stopCh)
	}

	<-stopCh
	klog.Info("Stopping Antrea agent")
	return nil
}
