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
	"os"
	"path"
	"time"

	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	genericopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	csrinformers "k8s.io/client-go/informers/certificates/v1"
	clientset "k8s.io/client-go/kubernetes"
	csrlisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	netutils "k8s.io/utils/net"

	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	antreaapis "antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/apiserver"
	"antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/apiserver/openapi"
	"antrea.io/antrea/pkg/apiserver/storage"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/clusteridentity"
	"antrea.io/antrea/pkg/controller/certificatesigningrequest"
	"antrea.io/antrea/pkg/controller/egress"
	egressstore "antrea.io/antrea/pkg/controller/egress/store"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/controller/externalnode"
	"antrea.io/antrea/pkg/controller/grouping"
	antreaipam "antrea.io/antrea/pkg/controller/ipam"
	"antrea.io/antrea/pkg/controller/labelidentity"
	"antrea.io/antrea/pkg/controller/metrics"
	"antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	"antrea.io/antrea/pkg/controller/querier"
	"antrea.io/antrea/pkg/controller/serviceexternalip"
	"antrea.io/antrea/pkg/controller/stats"
	"antrea.io/antrea/pkg/controller/supportbundlecollection"
	supportbundlecollectionstore "antrea.io/antrea/pkg/controller/supportbundlecollection/store"
	"antrea.io/antrea/pkg/controller/traceflow"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/monitor"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/cipher"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/version"
	"antrea.io/antrea/third_party/ipam/nodeipam"
	"antrea.io/antrea/third_party/ipam/nodeipam/ipam"
)

const (
	// informerDefaultResync is the default resync period if a handler doesn't specify one.
	// Use the same default value as kube-controller-manager:
	// https://github.com/kubernetes/kubernetes/blob/release-1.17/pkg/controller/apis/config/v1alpha1/defaults.go#L120
	informerDefaultResync = 12 * time.Hour

	// serverMinWatchTimeout determines the timeout allocated to watches from Antrea
	// clients. Each watch will be allocated a random timeout between this value and twice this
	// value, to help randomly distribute reconnections over time.
	// This parameter corresponds to the MinRequestTimeout server config parameter in
	// https://godoc.org/k8s.io/apiserver/pkg/server#Config.
	// When the Antrea client re-creates a watch, all relevant NetworkPolicy objects need to be
	// sent again by the controller. It may be a good idea to use a value which is larger than
	// the kube-apiserver default (1800s). The K8s documentation states that clients should be
	// able to handle watch timeouts gracefully but recommends using a large value in
	// production.
	serverMinWatchTimeout = 2 * time.Hour
)

var allowedPaths = []string{
	"/healthz",
	"/livez",
	"/readyz",
	"/mutate/acnp",
	"/mutate/anp",
	"/mutate/namespace",
	"/validate/tier",
	"/validate/acnp",
	"/validate/anp",
	"/validate/clustergroup",
	"/validate/externalippool",
	"/validate/egress",
	"/validate/group",
	"/validate/ippool",
	"/validate/supportbundlecollection",
	"/convert/clustergroup",
}

// run starts Antrea Controller with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea Controller (version %s)", version.GetFullVersion())
	// Create K8s Clientset, Aggregator Clientset, CRD Clientset and SharedInformerFactory for the given config.
	// Aggregator Clientset is used to update the CABundle of the APIServices backed by antrea-controller so that
	// the aggregator can verify its serving certificate.
	client, aggregatorClient, crdClient, apiExtensionClient, mcClient, err := k8s.CreateClients(o.config.ClientConnection, "")
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	serviceInformer := informerFactory.Core().V1().Services()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()
	nodeInformer := informerFactory.Core().V1().Nodes()
	cnpInformer := crdInformerFactory.Crd().V1alpha1().ClusterNetworkPolicies()
	eeInformer := crdInformerFactory.Crd().V1alpha2().ExternalEntities()
	anpInformer := crdInformerFactory.Crd().V1alpha1().NetworkPolicies()
	tierInformer := crdInformerFactory.Crd().V1alpha1().Tiers()
	tfInformer := crdInformerFactory.Crd().V1alpha1().Traceflows()
	cgInformer := crdInformerFactory.Crd().V1alpha3().ClusterGroups()
	grpInformer := crdInformerFactory.Crd().V1alpha3().Groups()
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	externalIPPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()
	externalNodeInformer := crdInformerFactory.Crd().V1alpha1().ExternalNodes()

	clusterIdentityAllocator := clusteridentity.NewClusterIdentityAllocator(
		env.GetAntreaNamespace(),
		clusteridentity.DefaultClusterIdentityConfigMapName,
		client,
	)

	enableMulticlusterNP := features.DefaultFeatureGate.Enabled(features.Multicluster) && o.config.Multicluster.EnableStretchedNetworkPolicy

	// Create Antrea object storage.
	addressGroupStore := store.NewAddressGroupStore()
	appliedToGroupStore := store.NewAppliedToGroupStore()
	networkPolicyStore := store.NewNetworkPolicyStore()
	egressGroupStore := egressstore.NewEgressGroupStore()
	groupStore := store.NewGroupStore()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	groupEntityController := grouping.NewGroupEntityController(groupEntityIndex, podInformer, namespaceInformer, eeInformer)
	labelIdentityIndex := labelidentity.NewLabelIdentityIndex()
	networkPolicyController := networkpolicy.NewNetworkPolicyController(client,
		crdClient,
		groupEntityIndex,
		labelIdentityIndex,
		namespaceInformer,
		serviceInformer,
		networkPolicyInformer,
		nodeInformer,
		cnpInformer,
		anpInformer,
		tierInformer,
		cgInformer,
		grpInformer,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore,
		enableMulticlusterNP)

	var externalNodeController *externalnode.ExternalNodeController
	if features.DefaultFeatureGate.Enabled(features.ExternalNode) {
		externalNodeController = externalnode.NewExternalNodeController(crdClient, externalNodeInformer, eeInformer)
	}

	var bundleCollectionController *supportbundlecollection.Controller
	bundleCollectionStore := supportbundlecollectionstore.NewSupportBundleCollectionStore()
	if features.DefaultFeatureGate.Enabled(features.SupportBundleCollection) {
		bundleCollectionInformer := crdInformerFactory.Crd().V1alpha1().SupportBundleCollections()
		bundleCollectionController = supportbundlecollection.NewSupportBundleCollectionController(client, crdClient, bundleCollectionInformer, nodeInformer, externalNodeInformer, bundleCollectionStore)
	}

	var networkPolicyStatusController *networkpolicy.StatusController
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		networkPolicyStatusController = networkpolicy.NewStatusController(crdClient, networkPolicyStore, cnpInformer, anpInformer)
	}

	endpointQuerier := networkpolicy.NewEndpointQuerier(networkPolicyController)

	controllerQuerier := querier.NewControllerQuerier(networkPolicyController, o.config.APIPort)

	externalNodeEnabled := features.DefaultFeatureGate.Enabled(features.ExternalNode)
	controllerMonitor := monitor.NewControllerMonitor(crdClient, nodeInformer, externalNodeInformer, controllerQuerier, externalNodeEnabled)

	var egressController *egress.EgressController
	var externalIPPoolController *externalippool.ExternalIPPoolController
	var externalIPController *serviceexternalip.ServiceExternalIPController
	if features.DefaultFeatureGate.Enabled(features.Egress) || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		externalIPPoolController = externalippool.NewExternalIPPoolController(
			crdClient, externalIPPoolInformer,
		)
	}

	var csrApprovingController *certificatesigningrequest.CSRApprovingController
	var csrSigningController *certificatesigningrequest.IPsecCSRSigningController
	var csrInformer cache.SharedIndexInformer
	var csrLister csrlisters.CertificateSigningRequestLister
	if features.DefaultFeatureGate.Enabled(features.IPsecCertAuth) {
		csrInformer = csrinformers.NewFilteredCertificateSigningRequestInformer(client, 0, nil, func(listOptions *metav1.ListOptions) {
			listOptions.FieldSelector = fields.OneTermEqualSelector("spec.signerName", antreaapis.AntreaIPsecCSRSignerName).String()
		})
		csrLister = csrlisters.NewCertificateSigningRequestLister(csrInformer.GetIndexer())

		if *o.config.IPsecCSRSignerConfig.AutoApprove {
			csrApprovingController = certificatesigningrequest.NewCSRApprovingController(client, csrInformer, csrLister)
		}
		csrSigningController = certificatesigningrequest.NewIPsecCSRSigningController(client, csrInformer, csrLister, *o.config.IPsecCSRSignerConfig.SelfSignedCA)
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		egressController = egress.NewEgressController(crdClient, groupEntityIndex, egressInformer, externalIPPoolController, egressGroupStore)
	}

	if features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		externalIPController = serviceexternalip.NewServiceExternalIPController(client, serviceInformer, externalIPPoolController)
	}

	var traceflowController *traceflow.Controller
	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		traceflowController = traceflow.NewTraceflowController(crdClient, podInformer, tfInformer)
	}

	// statsAggregator takes stats summaries from antrea-agents, aggregates them, and serves the Stats APIs with the
	// aggregated data. For now it's only used for NetworkPolicy stats.
	var statsAggregator *stats.Aggregator
	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		statsAggregator = stats.NewAggregator(networkPolicyInformer, cnpInformer, anpInformer)
	}

	cipherSuites, err := cipher.GenerateCipherSuitesList(o.config.TLSCipherSuites)
	if err != nil {
		return fmt.Errorf("error generating Cipher Suite list: %v", err)
	}

	var antreaIPAMController *antreaipam.AntreaIPAMController
	if features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		antreaIPAMController = antreaipam.NewAntreaIPAMController(crdClient,
			informerFactory,
			crdInformerFactory)
	}

	apiServerConfig, err := createAPIServerConfig(o.config.ClientConnection.Kubeconfig,
		client,
		aggregatorClient,
		apiExtensionClient,
		*o.config.SelfSignedCert,
		o.config.APIPort,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore,
		egressGroupStore,
		bundleCollectionStore,
		controllerQuerier,
		endpointQuerier,
		networkPolicyController,
		networkPolicyStatusController,
		egressController,
		statsAggregator,
		bundleCollectionController,
		*o.config.EnablePrometheusMetrics,
		cipherSuites,
		cipher.TLSVersionMap[o.config.TLSMinVersion])
	if err != nil {
		return fmt.Errorf("error creating API server config: %v", err)
	}
	apiServer, err := apiServerConfig.Complete(informerFactory).New()
	if err != nil {
		return fmt.Errorf("error creating API server: %v", err)
	}

	err = apiserver.CleanupDeprecatedAPIServices(aggregatorClient)
	if err != nil {
		return fmt.Errorf("failed to clean up the deprecated APIServices: %v", err)
	}

	// Set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()
	// Generate a context for functions which require one (instead of stopCh).
	// We cancel the context when the function returns, which in the normal case will be when
	// stopCh is closed.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.StartLogFileNumberMonitor(stopCh)

	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go clusterIdentityAllocator.Run(stopCh)

	go controllerMonitor.Run(stopCh)

	// It starts dispatching group updates to consumers, should start individually.
	// If it's not running, adding Pods/Entities to groupEntityIndex may be blocked because of full channel.
	go groupEntityIndex.Run(stopCh)

	go groupEntityController.Run(stopCh)

	if enableMulticlusterNP {
		mcInformerFactoty := mcinformers.NewSharedInformerFactory(mcClient, informerDefaultResync)
		labelIdentityInformer := mcInformerFactoty.Multicluster().V1alpha1().LabelIdentities()
		labelIdentityController := labelidentity.NewLabelIdentityController(labelIdentityIndex, labelIdentityInformer)
		mcInformerFactoty.Start(stopCh)

		go labelIdentityIndex.Run(stopCh)
		go labelIdentityController.Run(stopCh)
	}

	go networkPolicyController.Run(stopCh)

	go apiServer.Run(ctx)

	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		go statsAggregator.Run(stopCh)
	}

	if *o.config.EnablePrometheusMetrics {
		metrics.InitializePrometheusMetrics()
	}

	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		go traceflowController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		go networkPolicyStatusController.Run(stopCh)
	}
	if features.DefaultFeatureGate.Enabled(features.NodeIPAM) && o.config.NodeIPAM.EnableNodeIPAM {
		clusterCIDRs, _ := netutils.ParseCIDRs(o.config.NodeIPAM.ClusterCIDRs)
		_, serviceCIDR, _ := net.ParseCIDR(o.config.NodeIPAM.ServiceCIDR)
		_, serviceCIDRv6, _ := net.ParseCIDR(o.config.NodeIPAM.ServiceCIDRv6)
		err = startNodeIPAM(
			client,
			informerFactory,
			clusterCIDRs,
			serviceCIDR,
			serviceCIDRv6,
			o.config.NodeIPAM.NodeCIDRMaskSizeIPv4,
			o.config.NodeIPAM.NodeCIDRMaskSizeIPv6,
			stopCh)
		if err != nil {
			return fmt.Errorf("failed to initialize node IPAM controller: %v", err)
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		go externalIPPoolController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		go egressController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		go externalIPController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.ExternalNode) {
		go externalNodeController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.SupportBundleCollection) {
		go bundleCollectionController.Run(stopCh)
	}

	if antreaIPAMController != nil {
		go antreaIPAMController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.IPsecCertAuth) {
		go csrInformer.Run(stopCh)
		if *o.config.IPsecCSRSignerConfig.AutoApprove {
			go csrApprovingController.Run(stopCh)
		}
		go csrSigningController.Run(stopCh)
	}

	<-stopCh
	klog.Info("Stopping Antrea controller")
	return nil
}

func getNodeCIDRMaskSizes(clusterCIDRs []*net.IPNet, maskSizeIPv4, maskSizeIPv6 int) []int {
	nodeMaskCIDRs := make([]int, len(clusterCIDRs))

	for idx, clusterCIDR := range clusterCIDRs {
		if netutils.IsIPv6CIDR(clusterCIDR) {
			nodeMaskCIDRs[idx] = maskSizeIPv6
		} else {
			nodeMaskCIDRs[idx] = maskSizeIPv4
		}
	}
	return nodeMaskCIDRs
}

func startNodeIPAM(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	clusterCIDRs []*net.IPNet,
	serviceCIDR *net.IPNet,
	serviceCIDRv6 *net.IPNet,
	nodeCIDRMaskSizeIPv4 int,
	nodeCIDRMaskSizeIPv6 int,
	stopCh <-chan struct{}) error {

	nodeCIDRMaskSizes := getNodeCIDRMaskSizes(clusterCIDRs, nodeCIDRMaskSizeIPv4, nodeCIDRMaskSizeIPv6)
	nodeIPAM, err := nodeipam.NewNodeIpamController(
		informerFactory.Core().V1().Nodes(),
		client,
		clusterCIDRs,
		serviceCIDR,
		serviceCIDRv6,
		nodeCIDRMaskSizes,
		ipam.RangeAllocatorType,
	)
	if err != nil {
		return err
	}
	go nodeIPAM.Run(stopCh)
	return nil
}

func createAPIServerConfig(kubeconfig string,
	client clientset.Interface,
	aggregatorClient aggregatorclientset.Interface,
	apiExtensionClient apiextensionclientset.Interface,
	selfSignedCert bool,
	bindPort int,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	networkPolicyStore storage.Interface,
	groupStore storage.Interface,
	egressGroupStore storage.Interface,
	supportBundleCollectionStore storage.Interface,
	controllerQuerier querier.ControllerQuerier,
	endpointQuerier networkpolicy.EndpointQuerier,
	npController *networkpolicy.NetworkPolicyController,
	networkPolicyStatusController *networkpolicy.StatusController,
	egressController *egress.EgressController,
	statsAggregator *stats.Aggregator,
	bundleCollectionStore *supportbundlecollection.Controller,
	enableMetrics bool,
	cipherSuites []uint16,
	tlsMinVersion uint16) (*apiserver.Config, error) {
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths(allowedPaths...)

	caCertController, err := certificate.ApplyServerCert(selfSignedCert, client, aggregatorClient, apiExtensionClient, secureServing, apiserver.DefaultCAConfig())
	if err != nil {
		return nil, fmt.Errorf("error applying server cert: %v", err)
	}

	secureServing.BindPort = bindPort
	secureServing.BindAddress = net.IPv4zero
	// kubeconfig file is useful when antrea-controller is not running as a pod, like during development.
	if len(kubeconfig) > 0 {
		authentication.RemoteKubeConfigFile = kubeconfig
		authorization.RemoteKubeConfigFile = kubeconfig
	}

	serverConfig := genericapiserver.NewConfig(apiserver.Codecs)
	if err := secureServing.ApplyTo(&serverConfig.SecureServing, &serverConfig.LoopbackClientConfig); err != nil {
		return nil, err
	}
	if err := authentication.ApplyTo(&serverConfig.Authentication, serverConfig.SecureServing, nil); err != nil {
		return nil, err
	}
	if err := authorization.ApplyTo(&serverConfig.Authorization); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(path.Dir(apiserver.TokenPath), os.ModeDir); err != nil {
		return nil, fmt.Errorf("error when creating dirs of token file: %v", err)
	}
	if err := os.WriteFile(apiserver.TokenPath, []byte(serverConfig.LoopbackClientConfig.BearerToken), 0600); err != nil {
		return nil, fmt.Errorf("error when writing loopback access token to file: %v", err)
	}
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(
		openapi.GetOpenAPIDefinitions,
		genericopenapi.NewDefinitionNamer(apiserver.Scheme))
	serverConfig.OpenAPIConfig.Info.Title = "Antrea"
	serverConfig.EnableMetrics = enableMetrics
	serverConfig.MinRequestTimeout = int(serverMinWatchTimeout.Seconds())
	serverConfig.SecureServing.CipherSuites = cipherSuites
	serverConfig.SecureServing.MinTLSVersion = tlsMinVersion

	return apiserver.NewConfig(
		serverConfig,
		client,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore,
		egressGroupStore,
		supportBundleCollectionStore,
		caCertController,
		statsAggregator,
		controllerQuerier,
		networkPolicyStatusController,
		endpointQuerier,
		npController,
		egressController,
		bundleCollectionStore), nil
}
