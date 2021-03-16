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
	"io/ioutil"
	"net"
	"os"
	"path"
	"time"

	genericopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/vmware-tanzu/antrea/pkg/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/certificate"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/openapi"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	"github.com/vmware-tanzu/antrea/pkg/clusteridentity"
	"github.com/vmware-tanzu/antrea/pkg/controller/egress"
	egressstore "github.com/vmware-tanzu/antrea/pkg/controller/egress/store"
	"github.com/vmware-tanzu/antrea/pkg/controller/grouping"
	"github.com/vmware-tanzu/antrea/pkg/controller/metrics"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	"github.com/vmware-tanzu/antrea/pkg/controller/querier"
	"github.com/vmware-tanzu/antrea/pkg/controller/stats"
	"github.com/vmware-tanzu/antrea/pkg/controller/traceflow"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/log"
	"github.com/vmware-tanzu/antrea/pkg/monitor"
	"github.com/vmware-tanzu/antrea/pkg/signals"
	"github.com/vmware-tanzu/antrea/pkg/util/cipher"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
	"github.com/vmware-tanzu/antrea/pkg/version"
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
}

// run starts Antrea Controller with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea Controller (version %s)", version.GetFullVersion())
	// Create K8s Clientset, Aggregator Clientset, CRD Clientset and SharedInformerFactory for the given config.
	// Aggregator Clientset is used to update the CABundle of the APIServices backed by antrea-controller so that
	// the aggregator can verify its serving certificate.
	client, aggregatorClient, crdClient, err := k8s.CreateClients(o.config.ClientConnection, "")
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
	cnpInformer := crdInformerFactory.Security().V1alpha1().ClusterNetworkPolicies()
	externalEntityInformer := crdInformerFactory.Core().V1alpha2().ExternalEntities()
	anpInformer := crdInformerFactory.Security().V1alpha1().NetworkPolicies()
	tierInformer := crdInformerFactory.Security().V1alpha1().Tiers()
	traceflowInformer := crdInformerFactory.Ops().V1alpha1().Traceflows()
	cgInformer := crdInformerFactory.Core().V1alpha2().ClusterGroups()
	egressInformer := crdInformerFactory.Egress().V1alpha1().Egresses()

	clusterIdentityAllocator := clusteridentity.NewClusterIdentityAllocator(
		env.GetAntreaNamespace(),
		clusteridentity.DefaultClusterIdentityConfigMapName,
		client,
	)

	// Create Antrea object storage.
	addressGroupStore := store.NewAddressGroupStore()
	appliedToGroupStore := store.NewAppliedToGroupStore()
	networkPolicyStore := store.NewNetworkPolicyStore()
	egressGroupStore := egressstore.NewEgressGroupStore()
	groupStore := store.NewGroupStore()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	groupEntityController := grouping.NewGroupEntityController(groupEntityIndex, podInformer, namespaceInformer, externalEntityInformer)

	networkPolicyController := networkpolicy.NewNetworkPolicyController(client,
		crdClient,
		groupEntityIndex,
		serviceInformer,
		networkPolicyInformer,
		cnpInformer,
		anpInformer,
		tierInformer,
		cgInformer,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore)

	var networkPolicyStatusController *networkpolicy.StatusController
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		networkPolicyStatusController = networkpolicy.NewStatusController(crdClient, networkPolicyStore, cnpInformer, anpInformer)
	}

	endpointQuerier := networkpolicy.NewEndpointQuerier(networkPolicyController)

	controllerQuerier := querier.NewControllerQuerier(networkPolicyController, o.config.APIPort)

	controllerMonitor := monitor.NewControllerMonitor(crdClient, nodeInformer, controllerQuerier)

	egressController := egress.NewEgressGroupController(groupEntityIndex, egressInformer, egressGroupStore)

	var traceflowController *traceflow.Controller
	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		traceflowController = traceflow.NewTraceflowController(crdClient, podInformer, traceflowInformer)
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

	apiServerConfig, err := createAPIServerConfig(o.config.ClientConnection.Kubeconfig,
		client,
		aggregatorClient,
		o.config.SelfSignedCert,
		o.config.APIPort,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore,
		egressGroupStore,
		controllerQuerier,
		endpointQuerier,
		networkPolicyController,
		networkPolicyStatusController,
		statsAggregator,
		o.config.EnablePrometheusMetrics,
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

	log.StartLogFileNumberMonitor(stopCh)

	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go clusterIdentityAllocator.Run(stopCh)

	go controllerMonitor.Run(stopCh)

	go groupEntityController.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	go egressController.Run(stopCh)

	go apiServer.Run(stopCh)

	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		go statsAggregator.Run(stopCh)
	}

	if o.config.EnablePrometheusMetrics {
		metrics.InitializePrometheusMetrics()
	}

	if features.DefaultFeatureGate.Enabled(features.Traceflow) {
		go traceflowController.Run(stopCh)
	}

	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		go networkPolicyStatusController.Run(stopCh)
	}

	<-stopCh
	klog.Info("Stopping Antrea controller")
	return nil
}

func createAPIServerConfig(kubeconfig string,
	client clientset.Interface,
	aggregatorClient aggregatorclientset.Interface,
	selfSignedCert bool,
	bindPort int,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	networkPolicyStore storage.Interface,
	groupStore storage.Interface,
	egressGroupStore storage.Interface,
	controllerQuerier querier.ControllerQuerier,
	endpointQuerier networkpolicy.EndpointQuerier,
	npController *networkpolicy.NetworkPolicyController,
	networkPolicyStatusController *networkpolicy.StatusController,
	statsAggregator *stats.Aggregator,
	enableMetrics bool,
	cipherSuites []uint16,
	tlsMinVersion uint16) (*apiserver.Config, error) {
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths(allowedPaths...)

	caCertController, err := certificate.ApplyServerCert(selfSignedCert, client, aggregatorClient, secureServing)
	if err != nil {
		return nil, fmt.Errorf("error applying server cert: %v", err)
	}

	secureServing.BindPort = bindPort
	secureServing.BindAddress = net.IPv4zero
	// kubeconfig file is useful when antrea-controller isn't not running as a pod, like during development.
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
	if err := ioutil.WriteFile(apiserver.TokenPath, []byte(serverConfig.LoopbackClientConfig.BearerToken), 0600); err != nil {
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
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore,
		egressGroupStore,
		caCertController,
		statsAggregator,
		controllerQuerier,
		networkPolicyStatusController,
		endpointQuerier,
		npController), nil
}
