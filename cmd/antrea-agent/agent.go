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
	"context"
	"fmt"
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/apiserver"
	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/egress"
	"antrea.io/antrea/pkg/agent/controller/ipseccertificate"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/controller/serviceexternalip"
	"antrea.io/antrea/pkg/agent/controller/traceflow"
	"antrea.io/antrea/pkg/agent/controller/trafficcontrol"
	"antrea.io/antrea/pkg/agent/externalnode"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/multicast"
	mcroute "antrea.io/antrea/pkg/agent/multicluster"
	npl "antrea.io/antrea/pkg/agent/nodeportlocal"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	"antrea.io/antrea/pkg/agent/secondarynetwork/podwatch"
	"antrea.io/antrea/pkg/agent/servicecidr"
	"antrea.io/antrea/pkg/agent/stats"
	support "antrea.io/antrea/pkg/agent/supportbundlecollection"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	crdv1alpha1informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/monitor"
	ofconfig "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/env"
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
var excludeNodePortDevices = []string{"antrea-egress0", "antrea-ingress0", "kube-ipvs0"}

var ipv4Localhost = net.ParseIP("127.0.0.1")

// run starts Antrea agent with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea agent (version %s)", version.GetFullVersion())

	// Create K8s Clientset, CRD Clientset, Multicluster CRD Clientset and SharedInformerFactory for the given config.
	k8sClient, _, crdClient, _, mcClient, err := k8s.CreateClients(o.config.ClientConnection, o.config.KubeAPIServerOverride)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}

	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	traceflowInformer := crdInformerFactory.Crd().V1alpha1().Traceflows()
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	externalIPPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()
	trafficControlInformer := crdInformerFactory.Crd().V1alpha2().TrafficControls()
	nodeInformer := informerFactory.Core().V1().Nodes()
	serviceInformer := informerFactory.Core().V1().Services()
	endpointsInformer := informerFactory.Core().V1().Endpoints()
	namespaceInformer := informerFactory.Core().V1().Namespaces()

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

	egressEnabled := features.DefaultFeatureGate.Enabled(features.Egress)
	enableAntreaIPAM := features.DefaultFeatureGate.Enabled(features.AntreaIPAM)
	enableBridgingMode := enableAntreaIPAM && o.config.EnableBridgingMode
	enableNodePortLocal := features.DefaultFeatureGate.Enabled(features.NodePortLocal) && o.config.NodePortLocal.Enable
	l7NetworkPolicyEnabled := features.DefaultFeatureGate.Enabled(features.L7NetworkPolicy)
	enableMulticlusterGW := features.DefaultFeatureGate.Enabled(features.Multicluster) && o.config.Multicluster.EnableGateway
	enableMulticlusterNP := features.DefaultFeatureGate.Enabled(features.Multicluster) && o.config.Multicluster.EnableStretchedNetworkPolicy

	// Bridging mode will connect the uplink interface to the OVS bridge.
	connectUplinkToBridge := enableBridgingMode
	ovsDatapathType := ovsconfig.OVSDatapathType(o.config.OVSDatapathType)
	ovsBridgeClient := ovsconfig.NewOVSBridge(o.config.OVSBridge, ovsDatapathType, ovsdbConnection)
	ovsCtlClient := ovsctl.NewClient(o.config.OVSBridge)
	ovsBridgeMgmtAddr := ofconfig.GetMgmtAddress(o.config.OVSRunDir, o.config.OVSBridge)
	multicastEnabled := features.DefaultFeatureGate.Enabled(features.Multicast)
	ofClient := openflow.NewClient(o.config.OVSBridge, ovsBridgeMgmtAddr,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		features.DefaultFeatureGate.Enabled(features.AntreaPolicy),
		l7NetworkPolicyEnabled,
		egressEnabled,
		features.DefaultFeatureGate.Enabled(features.FlowExporter),
		o.config.AntreaProxy.ProxyAll,
		connectUplinkToBridge,
		multicastEnabled,
		features.DefaultFeatureGate.Enabled(features.TrafficControl),
		enableMulticlusterGW,
	)

	var serviceCIDRNet *net.IPNet
	if o.nodeType == config.K8sNode {
		_, serviceCIDRNet, _ = net.ParseCIDR(o.config.ServiceCIDR)
	}
	var serviceCIDRNetv6 *net.IPNet
	if o.config.ServiceCIDRv6 != "" {
		_, serviceCIDRNetv6, _ = net.ParseCIDR(o.config.ServiceCIDRv6)
	}
	serviceCIDRProvider := servicecidr.NewServiceCIDRDiscoverer(serviceInformer)

	_, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	_, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.config.TrafficEncryptionMode)
	if o.config.EnableIPSecTunnel {
		klog.InfoS("enableIPSecTunnel is deprecated, use trafficEncryptionMode instead.")
		encryptionMode = config.TrafficEncryptionModeIPSec
	}
	_, ipsecAuthenticationMode := config.GetIPsecAuthenticationModeFromStr(o.config.IPsec.AuthenticationMode)
	networkConfig := &config.NetworkConfig{
		TunnelType:            ovsconfig.TunnelType(o.config.TunnelType),
		TunnelPort:            o.config.TunnelPort,
		TunnelCsum:            o.config.TunnelCsum,
		TrafficEncapMode:      encapMode,
		TrafficEncryptionMode: encryptionMode,
		TransportIface:        o.config.TransportInterface,
		TransportIfaceCIDRs:   o.config.TransportInterfaceCIDRs,
		IPsecConfig: config.IPsecConfig{
			AuthenticationMode: ipsecAuthenticationMode,
		},
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
	routeClient, err := route.NewClient(networkConfig, o.config.NoSNAT, o.config.AntreaProxy.ProxyAll, connectUplinkToBridge, multicastEnabled, serviceCIDRProvider)
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
	// Generate a context for functions which require one (instead of stopCh).
	// We cancel the context when the function returns, which in the normal case will be when
	// stopCh is closed.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get all available NodePort addresses.
	var nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP
	if o.config.AntreaProxy.ProxyAll {
		nodePortAddressesIPv4, nodePortAddressesIPv6, err = getAvailableNodePortAddresses(o.config.AntreaProxy.NodePortAddresses, append(excludeNodePortDevices, o.config.HostGateway))
		if err != nil {
			return fmt.Errorf("getting available NodePort IP addresses failed: %v", err)
		}
	}
	serviceConfig := &config.ServiceConfig{
		ServiceCIDR:           serviceCIDRNet,
		ServiceCIDRv6:         serviceCIDRNetv6,
		NodePortAddressesIPv4: nodePortAddressesIPv4,
		NodePortAddressesIPv6: nodePortAddressesIPv6,
	}

	// Initialize agent and node network.
	agentInitializer := agent.NewInitializer(
		k8sClient,
		crdClient,
		ovsBridgeClient,
		ovsCtlClient,
		ofClient,
		routeClient,
		ifaceStore,
		o.config.OVSBridge,
		o.config.HostGateway,
		o.config.DefaultMTU,
		networkConfig,
		wireguardConfig,
		egressConfig,
		serviceConfig,
		networkReadyCh,
		stopCh,
		o.nodeType,
		o.config.ExternalNode.ExternalNodeNamespace,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		o.config.AntreaProxy.ProxyAll,
		connectUplinkToBridge,
		l7NetworkPolicyEnabled)
	err = agentInitializer.Initialize()
	if err != nil {
		return fmt.Errorf("error initializing agent: %v", err)
	}
	nodeConfig := agentInitializer.GetNodeConfig()

	var ipsecCertController *ipseccertificate.Controller

	if networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		ipsecCertController = ipseccertificate.NewIPSecCertificateController(k8sClient, ovsBridgeClient, nodeConfig.Name)
	}

	var nodeRouteController *noderoute.Controller
	if o.nodeType == config.K8sNode {
		nodeRouteController = noderoute.NewNodeRouteController(
			k8sClient,
			informerFactory,
			ofClient,
			ovsctl.NewClient(o.config.OVSBridge),
			ovsBridgeClient,
			routeClient,
			ifaceStore,
			networkConfig,
			nodeConfig,
			agentInitializer.GetWireGuardClient(),
			o.config.AntreaProxy.ProxyAll,
			ipsecCertController,
		)
	}

	// podUpdateChannel is a channel for receiving Pod updates from CNIServer and
	// notifying NetworkPolicyController, StretchedNetworkPolicyController and
	// EgressController to reconcile rules related to the updated Pods.
	var podUpdateChannel *channel.SubscribableChannel
	// externalEntityUpdateChannel is a channel for receiving ExternalEntity updates from ExternalNodeController and
	// notifying NetworkPolicyController to reconcile rules related to the updated ExternalEntities.
	var externalEntityUpdateChannel *channel.SubscribableChannel
	if o.nodeType == config.K8sNode {
		podUpdateChannel = channel.NewSubscribableChannel("PodUpdate", 100)
	} else {
		externalEntityUpdateChannel = channel.NewSubscribableChannel("ExternalEntityUpdate", 100)
	}

	// Initialize localPodInformer for NPLAgent, AntreaIPAMController,
	// StretchedNetworkPolicyController, and secondary network controller.
	var localPodInformer cache.SharedIndexInformer
	if enableNodePortLocal || enableBridgingMode || enableMulticlusterNP ||
		features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) ||
		features.DefaultFeatureGate.Enabled(features.TrafficControl) {
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

	var mcRouteController *mcroute.MCRouteController
	var mcStrechedNetworkPolicyController *mcroute.StretchedNetworkPolicyController
	var mcInformerFactory mcinformers.SharedInformerFactory
	if enableMulticlusterGW {
		mcNamespace := env.GetPodNamespace()
		if o.config.Multicluster.Namespace != "" {
			mcNamespace = o.config.Multicluster.Namespace
		}
		mcInformerFactory = mcinformers.NewSharedInformerFactory(mcClient, informerDefaultResync)
		gwInformer := mcInformerFactory.Multicluster().V1alpha1().Gateways()
		ciImportInformer := mcInformerFactory.Multicluster().V1alpha1().ClusterInfoImports()
		mcRouteController = mcroute.NewMCRouteController(
			mcClient,
			gwInformer,
			ciImportInformer,
			ofClient,
			ovsBridgeClient,
			ifaceStore,
			nodeConfig,
			mcNamespace,
			o.config.Multicluster.EnableStretchedNetworkPolicy,
			o.config.Multicluster.EnablePodToPodConnectivity,
		)
	}
	if enableMulticlusterNP {
		labelIDInformer := mcInformerFactory.Multicluster().V1alpha1().LabelIdentities()
		mcStrechedNetworkPolicyController = mcroute.NewMCAgentStretchedNetworkPolicyController(
			ofClient,
			ifaceStore,
			localPodInformer,
			informerFactory.Core().V1().Namespaces(),
			labelIDInformer,
			podUpdateChannel,
		)
	}

	var groupCounters []proxytypes.GroupCounter
	groupIDUpdates := make(chan string, 100)
	v4GroupIDAllocator := openflow.NewGroupAllocator(false)
	v4GroupCounter := proxytypes.NewGroupCounter(v4GroupIDAllocator, groupIDUpdates)
	v6GroupIDAllocator := openflow.NewGroupAllocator(true)
	v6GroupCounter := proxytypes.NewGroupCounter(v6GroupIDAllocator, groupIDUpdates)

	v4Enabled := networkConfig.IPv4Enabled
	v6Enabled := networkConfig.IPv6Enabled
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

	var gwPort, tunPort uint32
	if o.nodeType == config.K8sNode {
		gwPort = nodeConfig.GatewayConfig.OFPort
		tunPort = nodeConfig.TunnelOFPort
	}

	nodeKey := nodeConfig.Name
	if o.nodeType == config.ExternalNode {
		nodeKey = k8s.NamespacedName(o.config.ExternalNode.ExternalNodeNamespace, nodeKey)
	}
	networkPolicyController, err := networkpolicy.NewNetworkPolicyController(
		antreaClientProvider,
		ofClient,
		ifaceStore,
		nodeKey,
		podUpdateChannel,
		externalEntityUpdateChannel,
		groupCounters,
		groupIDUpdates,
		antreaPolicyEnabled,
		l7NetworkPolicyEnabled,
		antreaProxyEnabled,
		statusManagerEnabled,
		multicastEnabled,
		loggingEnabled,
		asyncRuleDeleteInterval,
		o.dnsServerOverride,
		o.nodeType,
		v4Enabled,
		v6Enabled,
		gwPort,
		tunPort,
	)
	if err != nil {
		return fmt.Errorf("error creating new NetworkPolicy controller: %v", err)
	}

	var egressController *egress.EgressController

	var externalIPPoolController *externalippool.ExternalIPPoolController
	var externalIPController *serviceexternalip.ServiceExternalIPController
	var memberlistCluster *memberlist.Cluster

	if egressEnabled || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		externalIPPoolController = externalippool.NewExternalIPPoolController(
			crdClient, externalIPPoolInformer,
		)
		var nodeTransportIP net.IP
		if nodeConfig.NodeTransportIPv4Addr != nil {
			nodeTransportIP = nodeConfig.NodeTransportIPv4Addr.IP
		} else if nodeConfig.NodeTransportIPv6Addr != nil {
			nodeTransportIP = nodeConfig.NodeTransportIPv6Addr.IP
		} else {
			return fmt.Errorf("invalid Node Transport IPAddr in Node config: %v", nodeConfig)
		}
		memberlistCluster, err = memberlist.NewCluster(nodeTransportIP, o.config.ClusterMembershipPort,
			nodeConfig.Name, nodeInformer, externalIPPoolInformer, nil,
		)
		if err != nil {
			return fmt.Errorf("error creating new memberlist cluster: %v", err)
		}
	}
	if egressEnabled {
		egressController, err = egress.NewEgressController(
			ofClient, antreaClientProvider, crdClient, ifaceStore, routeClient, nodeConfig.Name, nodeConfig.NodeTransportInterfaceName,
			memberlistCluster, egressInformer, nodeInformer, podUpdateChannel, o.config.Egress.MaxEgressIPsPerNode,
		)
		if err != nil {
			return fmt.Errorf("error creating new Egress controller: %v", err)
		}
	}
	if features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		externalIPController, err = serviceexternalip.NewServiceExternalIPController(
			nodeConfig.Name,
			nodeConfig.NodeTransportInterfaceName,
			k8sClient,
			memberlistCluster,
			serviceInformer,
			endpointsInformer,
		)
		if err != nil {
			return fmt.Errorf("error creating new ServiceExternalIP controller: %v", err)
		}
	}

	var cniServer *cniserver.CNIServer
	var cniPodInfoStore cnipodcache.CNIPodInfoStore
	var externalNodeController *externalnode.ExternalNodeController
	var localExternalNodeInformer cache.SharedIndexInformer
	if o.nodeType == config.K8sNode {
		isChaining := false
		if networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
			isChaining = true
		}
		cniServer = cniserver.New(
			o.config.CNISocket,
			o.config.HostProcPathPrefix,
			nodeConfig,
			k8sClient,
			routeClient,
			isChaining,
			enableBridgingMode,
			enableAntreaIPAM,
			o.config.DisableTXChecksumOffload,
			networkReadyCh)

		if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
			cniPodInfoStore = cnipodcache.NewCNIPodInfoStore()
			err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, podUpdateChannel, cniPodInfoStore)
			if err != nil {
				return fmt.Errorf("error initializing CNI server with cniPodInfoStore cache: %v", err)
			}
		} else {
			err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, podUpdateChannel, nil)
			if err != nil {
				return fmt.Errorf("error initializing CNI server: %v", err)
			}
		}
	} else {
		listOptions := func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", nodeConfig.Name).String()
		}
		localExternalNodeInformer = crdv1alpha1informers.NewFilteredExternalNodeInformer(
			crdClient,
			o.config.ExternalNode.ExternalNodeNamespace,
			resyncPeriodDisabled,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			listOptions,
		)
		externalNodeController, err = externalnode.NewExternalNodeController(ovsBridgeClient, ofClient, localExternalNodeInformer,
			ifaceStore, externalEntityUpdateChannel, o.config.ExternalNode.ExternalNodeNamespace, o.config.ExternalNode.PolicyBypassRules)
		if err != nil {
			return fmt.Errorf("error creating ExternalNode controller: %v", err)
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
			egressController,
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
	// ConnectUplinkToOVSBridge must be run immediately after FlowRestoreComplete
	if connectUplinkToBridge {
		// Restore network config before shutdown. ovsdbConnection must be alive when restore.
		defer agentInitializer.RestoreOVSBridge()
		if err := agentInitializer.ConnectUplinkToOVSBridge(); err != nil {
			return fmt.Errorf("failed to connect uplink to OVS bridge: %w", err)
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
			PollInterval:           o.pollInterval,
			ConnectUplinkToBridge:  connectUplinkToBridge}
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

	log.StartLogFileNumberMonitor(stopCh)

	if o.nodeType == config.K8sNode {
		go routeClient.Run(stopCh)
		go podUpdateChannel.Run(stopCh)
		go cniServer.Run(stopCh)
		go nodeRouteController.Run(stopCh)
	} else {
		go externalEntityUpdateChannel.Run(stopCh)
		go localExternalNodeInformer.Run(stopCh)
		go externalNodeController.Run(stopCh)
	}

	if networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		go ipsecCertController.Run(stopCh)
	}

	go antreaClientProvider.Run(ctx)

	if networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		go ipsecCertController.Run(stopCh)
	}

	go networkPolicyController.Run(stopCh)
	// Initialize the NPL agent.
	if enableNodePortLocal {
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

	// Antrea IPAM is needed by bridging mode and secondary network IPAM.
	if enableAntreaIPAM {
		ipamController, err := ipam.InitializeAntreaIPAMController(
			crdClient, informerFactory, crdInformerFactory,
			localPodInformer, enableBridgingMode)
		if err != nil {
			return fmt.Errorf("failed to start Antrea IPAM agent: %v", err)
		}
		go ipamController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
		// Create the NetworkAttachmentDefinition client, which handles access to secondary network object definition from the API Server.
		netAttachDefClient, err := k8s.CreateNetworkAttachDefClient(o.config.ClientConnection, o.config.KubeAPIServerOverride)
		if err != nil {
			return fmt.Errorf("NetworkAttachmentDefinition client creation failed. %v", err)
		}
		// Create podController to handle secondary network configuration for Pods with k8s.v1.cni.cncf.io/networks Annotation defined.
		podWatchController := podwatch.NewPodController(
			k8sClient,
			netAttachDefClient,
			localPodInformer,
			nodeConfig.Name,
			cniPodInfoStore,
			// safe to call given that cniServer.Initialize has been called already.
			cniServer.GetPodConfigurator())
		go podWatchController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.TrafficControl) {
		tcController := trafficcontrol.NewTrafficControlController(ofClient,
			ifaceStore,
			ovsBridgeClient,
			ovsCtlClient,
			trafficControlInformer,
			localPodInformer,
			namespaceInformer,
			podUpdateChannel)
		go tcController.Run(stopCh)
	}

	//  Start the localPodInformer
	if localPodInformer != nil {
		go localPodInformer.Run(stopCh)
	}

	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	if egressEnabled || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		go externalIPPoolController.Run(stopCh)
		go memberlistCluster.Run(stopCh)
	}

	if egressEnabled {
		go egressController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		go externalIPController.Run(stopCh)
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
	var mcastController *multicast.Controller
	if multicastEnabled {
		multicastSocket, err := multicast.CreateMulticastSocket()
		if err != nil {
			return fmt.Errorf("failed to create multicast socket")
		}
		var validator agenttypes.McastNetworkPolicyController
		if antreaPolicyEnabled {
			validator = networkPolicyController
		}
		mcastController = multicast.NewMulticastController(
			ofClient,
			v4GroupIDAllocator,
			nodeConfig,
			ifaceStore,
			multicastSocket,
			sets.NewString(append(o.config.Multicast.MulticastInterfaces, nodeConfig.NodeTransportInterfaceName)...),
			ovsBridgeClient,
			podUpdateChannel,
			o.igmpQueryInterval,
			validator,
			networkConfig.TrafficEncapMode.SupportsEncap(),
			informerFactory)
		if err := mcastController.Initialize(); err != nil {
			return err
		}
		go mcastController.Run(stopCh)
	}

	if enableMulticlusterGW {
		mcInformerFactory.Start(stopCh)
		go mcRouteController.Run(stopCh)
	}
	if enableMulticlusterNP {
		go mcStrechedNetworkPolicyController.Run(stopCh)
	}

	// statsCollector collects stats and reports to the antrea-controller periodically. For now it's only used for
	// NetworkPolicy stats and Multicast stats.
	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		statsCollector := stats.NewCollector(antreaClientProvider, ofClient, networkPolicyController, mcastController)
		go statsCollector.Run(stopCh)
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
		o.config.APIPort,
		o.config.NodePortLocal.PortRange,
		memberlistCluster,
		nodeInformer.Lister(),
	)

	agentMonitor := monitor.NewAgentMonitor(crdClient, agentQuerier)

	go agentMonitor.Run(stopCh)

	if features.DefaultFeatureGate.Enabled(features.SupportBundleCollection) {
		nodeNamespace := ""
		nodeType := controlplane.SupportBundleCollectionNodeTypeNode
		if o.nodeType == config.ExternalNode {
			nodeNamespace = o.config.ExternalNode.ExternalNodeNamespace
			nodeType = controlplane.SupportBundleCollectionNodeTypeExternalNode
		}
		supportBundleController := support.NewSupportBundleController(nodeConfig.Name, nodeType, nodeNamespace, antreaClientProvider,
			ovsctl.NewClient(o.config.OVSBridge), agentQuerier, networkPolicyController, v4Enabled, v6Enabled)
		go supportBundleController.Run(stopCh)
	}

	bindAddress := net.IPv4zero
	if o.nodeType == config.ExternalNode {
		bindAddress = ipv4Localhost
	}
	secureServing := options.NewSecureServingOptions().WithLoopback()
	secureServing.BindAddress = bindAddress
	secureServing.BindPort = o.config.APIPort
	secureServing.CipherSuites = o.tlsCipherSuites
	secureServing.MinTLSVersion = o.config.TLSMinVersion
	authentication := options.NewDelegatingAuthenticationOptions()
	authorization := options.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths("/healthz", "/livez", "/readyz")
	apiServer, err := apiserver.New(
		agentQuerier,
		networkPolicyController,
		mcastController,
		externalIPController,
		secureServing,
		authentication,
		authorization,
		*o.config.EnablePrometheusMetrics,
		o.config.ClientConnection.Kubeconfig,
		v4Enabled,
		v6Enabled)
	if err != nil {
		return fmt.Errorf("error when creating agent API server: %v", err)
	}
	go apiServer.Run(stopCh)

	// Start PacketIn
	go ofClient.StartPacketInHandler(stopCh)

	// Start the goroutine to periodically export IPFIX flow records.
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		go flowExporter.Run(stopCh)
	}

	<-stopCh
	klog.Info("Stopping Antrea agent")
	return nil
}
