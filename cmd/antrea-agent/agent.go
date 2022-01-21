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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/apiserver"
	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/egress"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/controller/traceflow"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/ipassigner"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/multicast"
	npl "antrea.io/antrea/pkg/agent/nodeportlocal"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	"antrea.io/antrea/pkg/agent/secondarynetwork/podwatch"
	"antrea.io/antrea/pkg/agent/stats"
	"antrea.io/antrea/pkg/agent/types"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/monitor"
	ofconfig "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/cipher"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/version"
)

// informerDefaultResync is the default resync period if a handler doesn't specify one.
// Use the same default value as kube-controller-manager:
// https://github.com/kubernetes/kubernetes/blob/release-1.17/pkg/controller/apis/config/v1alpha1/defaults.go#L120
const informerDefaultResync = 12 * time.Hour

// resyncPeriodDisabled is 0 to disable resyncing.
// UpdateFunc event handler will be called only when the object is actually updated.
const resyncPeriodDisabled = 0 * time.Minute

// The devices that should be excluded from NodePort.
var excludeNodePortDevices = []string{"antrea-egress0", "kube-ipvs0"}

// run starts Antrea agent with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea agent (version %s)", version.GetFullVersion())
	// Create K8s Clientset, CRD Clientset and SharedInformerFactory for the given config.
	k8sClient, _, crdClient, _, err := k8s.CreateClients(o.config.ClientConnection, o.config.KubeAPIServerOverride)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}
	legacyCRDClient, err := k8s.CreateLegacyCRDClient(o.config.ClientConnection, o.config.KubeAPIServerOverride)
	if err != nil {
		return fmt.Errorf("error creating legacy CRD client: %v", err)
	}

	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	traceflowInformer := crdInformerFactory.Crd().V1alpha1().Traceflows()
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	nodeInformer := informerFactory.Core().V1().Nodes()
	externalIPPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

	// Create Antrea Clientset for the given config.
	antreaClientProvider := agent.NewAntreaClientProvider(o.config.AntreaClientConnection, k8sClient)

	// Register Antrea Agent metrics if EnablePrometheusMetrics is set
	if *o.config.EnablePrometheusMetrics {
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

	// Enable AntreaIPAM will set connectUplinkToBridge to True. Currently only Linux+IPv4 is supported.
	// AntreaIPAM works with system OVSDatapathType and noEncap, noSNAT mode. Egress feature is not supported.
	// AntreaIPAM is only verified with other FeatureGates at default state.
	connectUplinkToBridge := features.DefaultFeatureGate.Enabled(features.AntreaIPAM)

	ovsDatapathType := ovsconfig.OVSDatapathType(o.config.OVSDatapathType)
	ovsBridgeClient := ovsconfig.NewOVSBridge(o.config.OVSBridge, ovsDatapathType, ovsdbConnection)
	ovsBridgeMgmtAddr := ofconfig.GetMgmtAddress(o.config.OVSRunDir, o.config.OVSBridge)
	ofClient := openflow.NewClient(o.config.OVSBridge, ovsBridgeMgmtAddr, ovsDatapathType,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		features.DefaultFeatureGate.Enabled(features.AntreaPolicy),
		features.DefaultFeatureGate.Enabled(features.Egress),
		features.DefaultFeatureGate.Enabled(features.FlowExporter),
		o.config.AntreaProxy.ProxyAll,
		connectUplinkToBridge,
		features.DefaultFeatureGate.Enabled(features.Multicast))

	_, serviceCIDRNet, _ := net.ParseCIDR(o.config.ServiceCIDR)
	var serviceCIDRNetv6 *net.IPNet
	// Todo: use FeatureGate to check if IPv6 is enabled and then read configuration item "ServiceCIDRv6".
	if o.config.ServiceCIDRv6 != "" {
		_, serviceCIDRNetv6, _ = net.ParseCIDR(o.config.ServiceCIDRv6)
	}

	_, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	_, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.config.TrafficEncryptionMode)
	if o.config.EnableIPSecTunnel {
		klog.InfoS("enableIPSecTunnel is deprecated, use trafficEncryptionMode instead.")
		encryptionMode = config.TrafficEncryptionModeIPSec
	}
	networkConfig := &config.NetworkConfig{
		TunnelType:            ovsconfig.TunnelType(o.config.TunnelType),
		TrafficEncapMode:      encapMode,
		TrafficEncryptionMode: encryptionMode,
		TransportIface:        o.config.TransportInterface,
		TransportIfaceCIDRs:   o.config.TransportInterfaceCIDRs,
	}

	wireguardConfig := &config.WireGuardConfig{
		Port: o.config.WireGuard.Port,
	}
	exceptCIDRs := []net.IPNet{}
	for _, cidr := range o.config.Egress.ExceptCIDRs {
		_, exceptCIDR, _ := net.ParseCIDR(cidr)
		exceptCIDRs = append(exceptCIDRs, *exceptCIDR)
	}
	egressConfig := &config.EgressConfig{
		ExceptCIDRs: exceptCIDRs,
	}
	routeClient, err := route.NewClient(networkConfig, o.config.NoSNAT, o.config.AntreaProxy.ProxyAll, connectUplinkToBridge, features.DefaultFeatureGate.Enabled(features.Multicast))
	if err != nil {
		return fmt.Errorf("error creating route client: %v", err)
	}

	// Create an ifaceStore that caches network interfaces managed by this node.
	ifaceStore := interfacestore.NewInterfaceStore()

	// networkReadyCh is used to notify that the Node's network is ready.
	// Functions that rely on the Node's network should wait for the channel to close.
	networkReadyCh := make(chan struct{})
	// set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	// Get all available NodePort addresses.
	var nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP
	if o.config.AntreaProxy.ProxyAll {
		nodePortAddressesIPv4, nodePortAddressesIPv6, err = getAvailableNodePortAddresses(o.config.AntreaProxy.NodePortAddresses, append(excludeNodePortDevices, o.config.HostGateway))
		if err != nil {
			return fmt.Errorf("getting available NodePort IP addresses failed: %v", err)
		}
	}

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
		serviceCIDRNetv6,
		networkConfig,
		wireguardConfig,
		egressConfig,
		networkReadyCh,
		stopCh,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		o.config.AntreaProxy.ProxyAll,
		nodePortAddressesIPv4,
		nodePortAddressesIPv6,
		connectUplinkToBridge)
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
		nodeConfig,
		agentInitializer.GetWireGuardClient(),
		o.config.AntreaProxy.ProxyAll)

	var groupCounters []proxytypes.GroupCounter
	groupIDUpdates := make(chan string, 100)
	v4GroupCounter := proxytypes.NewGroupCounter(false, groupIDUpdates)
	v6GroupCounter := proxytypes.NewGroupCounter(true, groupIDUpdates)

	v4Enabled := config.IsIPv4Enabled(nodeConfig, networkConfig.TrafficEncapMode)
	v6Enabled := config.IsIPv6Enabled(nodeConfig, networkConfig.TrafficEncapMode)
	var proxier proxy.Proxier
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		proxyAll := o.config.AntreaProxy.ProxyAll
		skipServices := o.config.AntreaProxy.SkipServices
		proxyLoadBalancerIPs := *o.config.AntreaProxy.ProxyLoadBalancerIPs

		switch {
		case v4Enabled && v6Enabled:
			proxier = proxy.NewDualStackProxier(nodeConfig.Name, informerFactory, ofClient, routeClient, nodePortAddressesIPv4, nodePortAddressesIPv6, proxyAll, skipServices, proxyLoadBalancerIPs, v4GroupCounter, v6GroupCounter)
			groupCounters = append(groupCounters, v4GroupCounter, v6GroupCounter)
		case v4Enabled:
			proxier = proxy.NewProxier(nodeConfig.Name, informerFactory, ofClient, false, routeClient, nodePortAddressesIPv4, proxyAll, skipServices, proxyLoadBalancerIPs, v4GroupCounter)
			groupCounters = append(groupCounters, v4GroupCounter)
		case v6Enabled:
			proxier = proxy.NewProxier(nodeConfig.Name, informerFactory, ofClient, true, routeClient, nodePortAddressesIPv6, proxyAll, skipServices, proxyLoadBalancerIPs, v6GroupCounter)
			groupCounters = append(groupCounters, v6GroupCounter)
		default:
			return fmt.Errorf("at least one of IPv4 or IPv6 should be enabled")
		}
	}

	// entityUpdates is a channel for receiving entity updates from CNIServer and
	// notifying NetworkPolicyController to reconcile rules related to the
	// updated entities.
	entityUpdates := make(chan types.EntityReference, 100)
	// We set flow poll interval as the time interval for rule deletion in the async
	// rule cache, which is implemented as part of the idAllocator. This is to preserve
	// the rule info for populating NetworkPolicy fields in the Flow Exporter even
	// after rule deletion.
	asyncRuleDeleteInterval := o.pollInterval
	antreaPolicyEnabled := features.DefaultFeatureGate.Enabled(features.AntreaPolicy)
	antreaProxyEnabled := features.DefaultFeatureGate.Enabled(features.AntreaProxy)
	// In Antrea agent, status manager and audit logging will automatically be enabled
	// if AntreaPolicy feature is enabled.
	statusManagerEnabled := antreaPolicyEnabled
	loggingEnabled := antreaPolicyEnabled

	networkPolicyController, err := networkpolicy.NewNetworkPolicyController(
		antreaClientProvider,
		ofClient,
		ifaceStore,
		nodeConfig.Name,
		entityUpdates,
		groupCounters,
		groupIDUpdates,
		antreaPolicyEnabled,
		antreaProxyEnabled,
		statusManagerEnabled,
		loggingEnabled,
		asyncRuleDeleteInterval,
		o.config.DNSServerOverride)
	if err != nil {
		return fmt.Errorf("error creating new NetworkPolicy controller: %v", err)
	}

	// statsCollector collects stats and reports to the antrea-controller periodically. For now it's only used for
	// NetworkPolicy stats.
	var statsCollector *stats.Collector
	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		statsCollector = stats.NewCollector(antreaClientProvider, ofClient, networkPolicyController)
	}

	var egressController *egress.EgressController
	var nodeTransportIP net.IP
	if nodeConfig.NodeTransportIPv4Addr != nil {
		nodeTransportIP = nodeConfig.NodeTransportIPv4Addr.IP
	} else if nodeConfig.NodeTransportIPv6Addr != nil {
		nodeTransportIP = nodeConfig.NodeTransportIPv6Addr.IP
	} else {
		return fmt.Errorf("invalid Node Transport IPAddr in Node config: %v", nodeConfig)
	}

	var externalIPPoolController *externalippool.ExternalIPPoolController
	var memberlistCluster *memberlist.Cluster
	var localIPDetector ipassigner.LocalIPDetector

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		externalIPPoolController = externalippool.NewExternalIPPoolController(
			crdClient, externalIPPoolInformer,
		)
		localIPDetector = ipassigner.NewLocalIPDetector()
		memberlistCluster, err = memberlist.NewCluster(o.config.ClusterMembershipPort,
			nodeConfig.Name, nodeInformer, externalIPPoolInformer,
		)
		if err != nil {
			return fmt.Errorf("error creating new MemberList cluster: %v", err)
		}
		egressController, err = egress.NewEgressController(
			ofClient, antreaClientProvider, crdClient, ifaceStore, routeClient, nodeConfig.Name, nodeTransportIP,
			memberlistCluster, egressInformer, nodeInformer, localIPDetector,
		)
		if err != nil {
			return fmt.Errorf("error creating new Egress controller: %v", err)
		}
	}

	isChaining := false
	if networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		isChaining = true
	}
	antreaIPAM := features.DefaultFeatureGate.Enabled(features.AntreaIPAM)
	cniServer := cniserver.New(
		o.config.CNISocket,
		o.config.HostProcPathPrefix,
		nodeConfig,
		k8sClient,
		isChaining,
		antreaIPAM,
		routeClient,
		networkReadyCh)

	var cniPodInfoStore cnipodcache.CNIPodInfoStore
	if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
		cniPodInfoStore = cnipodcache.NewCNIPodInfoStore()
		err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, entityUpdates, cniPodInfoStore)
		if err != nil {
			return fmt.Errorf("error initializing CNI server with cniPodInfoStore cache: %v", err)
		}
	} else {
		err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, entityUpdates, nil)
		if err != nil {
			return fmt.Errorf("error initializing CNI server: %v", err)
		}
	}

	var traceflowController *traceflow.Controller
	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		traceflowController = traceflow.NewTraceflowController(
			k8sClient,
			informerFactory,
			crdClient,
			traceflowInformer,
			ofClient,
			networkPolicyController,
			ovsBridgeClient,
			ifaceStore,
			networkConfig,
			nodeConfig,
			serviceCIDRNet)
	}

	// TODO: we should call this after installing flows for initial node routes
	//  and initial NetworkPolicies so that no packets will be mishandled.
	if err := agentInitializer.FlowRestoreComplete(); err != nil {
		return err
	}
	// BridgeUplinkToOVSBridge is required if connectUplinkToBridge is true, and must be run immediately after FlowRestoreComplete
	if connectUplinkToBridge {
		// Restore network config before shutdown. ovsdbConnection must be alive when restore.
		defer agentInitializer.RestoreOVSBridge()
		if err := agentInitializer.BridgeUplinkToOVSBridge(); err != nil {
			return fmt.Errorf("error bridging uplink to OVS bridge: %w", err)
		}
	}

	if err := antreaClientProvider.RunOnce(); err != nil {
		return err
	}

	var flowExporter *exporter.FlowExporter
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		flowExporterOptions := &flowexporter.FlowExporterOptions{
			FlowCollectorAddr:      o.flowCollectorAddr,
			FlowCollectorProto:     o.flowCollectorProto,
			ActiveFlowTimeout:      o.activeFlowTimeout,
			IdleFlowTimeout:        o.idleFlowTimeout,
			StaleConnectionTimeout: o.staleConnectionTimeout,
			PollInterval:           o.pollInterval}
		flowExporter, err = exporter.NewFlowExporter(
			ifaceStore,
			proxier,
			k8sClient,
			nodeRouteController,
			networkConfig.TrafficEncapMode,
			nodeConfig,
			v4Enabled,
			v6Enabled,
			serviceCIDRNet,
			serviceCIDRNetv6,
			ovsDatapathType,
			features.DefaultFeatureGate.Enabled(features.AntreaProxy),
			networkPolicyController,
			flowExporterOptions)
		if err != nil {
			return fmt.Errorf("error when creating IPFIX flow exporter: %v", err)
		}
		networkPolicyController.SetDenyConnStore(flowExporter.GetDenyConnStore())
	}

	// Initialize localPodInformer for NPLAgent and AntreaIPAMController
	var localPodInformer cache.SharedIndexInformer
	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) && o.config.NodePortLocal.Enable || features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		listOptions := func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeConfig.Name).String()
		}
		localPodInformer = coreinformers.NewFilteredPodInformer(
			k8sClient,
			metav1.NamespaceAll,
			resyncPeriodDisabled,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
			listOptions,
		)
	}
	// Initialize the NPL agent.
	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) && o.config.NodePortLocal.Enable {
		nplController, err := npl.InitializeNPLAgent(
			k8sClient,
			informerFactory,
			o.nplStartPort,
			o.nplEndPort,
			nodeConfig.Name,
			localPodInformer)
		if err != nil {
			return fmt.Errorf("failed to start NPL agent: %v", err)
		}
		go nplController.Run(stopCh)
	}
	// Initialize the Antrea IPAM agent.
	if features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		ipamController, err := ipam.InitializeAntreaIPAMController(
			k8sClient,
			crdClient,
			informerFactory,
			localPodInformer,
			crdInformerFactory)
		if err != nil {
			return fmt.Errorf("failed to start Antrea IPAM agent: %v", err)
		}
		go ipamController.Run(stopCh)
	}
	//  Start the localPodInformer
	if localPodInformer != nil {
		go localPodInformer.Run(stopCh)
	}

	log.StartLogFileNumberMonitor(stopCh)

	go routeClient.Run(stopCh)

	go cniServer.Run(stopCh)

	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go antreaClientProvider.Run(stopCh)

	go nodeRouteController.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
		// Create the NetworkAttachmentDefinition client, which handles access to secondary network object definition from the API Server.
		netAttachDefClient, err := k8s.CreateNetworkAttachDefClient(o.config.ClientConnection, o.config.KubeAPIServerOverride)
		if err != nil {
			return fmt.Errorf("NetworkAttachmentDefinition client creation failed. %v", err)
		}
		// Initialize podController to handle secondary network configuration for Pods with k8s.v1.cni.cncf.io/networks Annotation defined.
		podWatchController, err := podwatch.InitializePodController(
			k8sClient,
			netAttachDefClient,
			informerFactory,
			nodeConfig.Name,
			cniPodInfoStore,
			cniServer)
		if err != nil {
			return fmt.Errorf("failed to initialize Pod Controller for secondary network interface management: %v", err)
		}
		go podWatchController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		go externalIPPoolController.Run(stopCh)
		go localIPDetector.Run(stopCh)
		go memberlistCluster.Run(stopCh)
		go egressController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		go statsCollector.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		go traceflowController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		go proxier.GetProxyProvider().Run(stopCh)

		// If AntreaProxy is configured to proxy all Service traffic, we need to wait for it to sync at least once
		// before moving forward. Components that rely on Service availability should run after it, otherwise accessing
		// Service would fail.
		if o.config.AntreaProxy.ProxyAll {
			klog.InfoS("Waiting for AntreaProxy to be ready")
			if err := wait.PollUntil(time.Second, func() (bool, error) {
				klog.V(2).InfoS("Checking if AntreaProxy is ready")
				return proxier.GetProxyProvider().SyncedOnce(), nil
			}, stopCh); err != nil {
				return fmt.Errorf("error when waiting for AntreaProxy to be ready: %v", err)
			}
			klog.InfoS("AntreaProxy is ready")
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Multicast) {
		multicastSocket, err := multicast.CreateMulticastSocket()
		if err != nil {
			return fmt.Errorf("failed to create multicast socket")
		}
		mcastController := multicast.NewMulticastController(
			ofClient,
			nodeConfig,
			ifaceStore,
			multicastSocket,
			sets.NewString(append(o.config.MulticastInterfaces, nodeConfig.NodeTransportInterfaceName)...),
			ovsBridgeClient)
		if err := mcastController.Initialize(); err != nil {
			return err
		}
		go mcastController.Run(stopCh)
	}

	agentQuerier := querier.NewAgentQuerier(
		nodeConfig,
		networkConfig,
		ifaceStore,
		k8sClient,
		ofClient,
		ovsBridgeClient,
		proxier,
		networkPolicyController,
		o.config.APIPort)

	agentMonitor := monitor.NewAgentMonitor(crdClient, legacyCRDClient, agentQuerier)

	go agentMonitor.Run(stopCh)

	cipherSuites, err := cipher.GenerateCipherSuitesList(o.config.TLSCipherSuites)
	if err != nil {
		return fmt.Errorf("error generating Cipher Suite list: %v", err)
	}
	apiServer, err := apiserver.New(
		agentQuerier,
		networkPolicyController,
		o.config.APIPort,
		*o.config.EnablePrometheusMetrics,
		o.config.ClientConnection.Kubeconfig,
		cipherSuites,
		cipher.TLSVersionMap[o.config.TLSMinVersion])
	if err != nil {
		return fmt.Errorf("error when creating agent API server: %v", err)
	}
	go apiServer.Run(stopCh)

	// Start PacketIn for features and specify their own reason.
	var packetInReasons []uint8
	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		packetInReasons = append(packetInReasons, uint8(openflow.PacketInReasonTF))
	}
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		packetInReasons = append(packetInReasons, uint8(openflow.PacketInReasonNP))
	}
	if len(packetInReasons) > 0 {
		go ofClient.StartPacketInHandler(packetInReasons, stopCh)
	}

	// Start the goroutine to periodically export IPFIX flow records.
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		go flowExporter.Run(stopCh)
	}

	<-stopCh
	klog.Info("Stopping Antrea agent")
	return nil
}
