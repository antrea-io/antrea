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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/openapi"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	"github.com/vmware-tanzu/antrea/pkg/controller/metrics"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	"github.com/vmware-tanzu/antrea/pkg/controller/querier"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/monitor"
	"github.com/vmware-tanzu/antrea/pkg/signals"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

// informerDefaultResync is the default resync period if a handler doesn't specify one.
// Use the same default value as kube-controller-manager:
// https://github.com/kubernetes/kubernetes/blob/release-1.17/pkg/controller/apis/config/v1alpha1/defaults.go#L120
const informerDefaultResync = 12 * time.Hour

// run starts Antrea Controller with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea Controller (version %s)", version.GetFullVersion())
	// Create K8s Clientset, CRD Clientset and SharedInformerFactory for the given config.
	client, crdClient, err := k8s.CreateClients(o.config.ClientConnection)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()
	nodeInformer := informerFactory.Core().V1().Nodes()
	cnpInformer := crdInformerFactory.Security().V1alpha1().ClusterNetworkPolicies()

	// Create Antrea object storage.
	addressGroupStore := store.NewAddressGroupStore()
	appliedToGroupStore := store.NewAppliedToGroupStore()
	networkPolicyStore := store.NewNetworkPolicyStore()

	networkPolicyController := networkpolicy.NewNetworkPolicyController(client,
		crdClient,
		podInformer,
		namespaceInformer,
		networkPolicyInformer,
		cnpInformer,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore)

	controllerQuerier := querier.NewControllerQuerier(networkPolicyController, o.config.APIPort)

	controllerMonitor := monitor.NewControllerMonitor(crdClient, nodeInformer, controllerQuerier)

	apiServerConfig, err := createAPIServerConfig(o.config.ClientConnection.Kubeconfig,
		o.config.APIPort,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		controllerQuerier,
		o.config.EnablePrometheusMetrics)
	if err != nil {
		return fmt.Errorf("error creating API server config: %v", err)
	}
	apiServer, err := apiServerConfig.Complete(informerFactory).New()
	if err != nil {
		return fmt.Errorf("error creating API server: %v", err)
	}

	// Set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	informerFactory.Start(stopCh)
	// Only start watching Security CRDs when config option is set to true.
	if o.config.EnableSecurityCrds {
		crdInformerFactory.Start(stopCh)
	}

	go controllerMonitor.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	go apiServer.GenericAPIServer.PrepareRun().Run(stopCh)

	if o.config.EnablePrometheusMetrics {
		metrics.InitializePrometheusMetrics()
	}

	<-stopCh
	klog.Info("Stopping Antrea controller")
	return nil
}

func createAPIServerConfig(kubeconfig string,
	bindPort int,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	networkPolicyStore storage.Interface,
	controllerQuerier querier.ControllerQuerier,
	enableMetrics bool) (*apiserver.Config, error) {
	// TODO:
	// 1. Support user-provided certificate.
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions()

	// Set the PairName but leave certificate directory blank to generate in-memory by default
	secureServing.ServerCert.CertDirectory = ""
	secureServing.ServerCert.PairName = "antrea-apiserver"
	secureServing.BindPort = bindPort
	secureServing.BindAddress = net.ParseIP("0.0.0.0")
	// kubeconfig file is useful when antrea-controller isn't not running as a pod, like during development.
	if len(kubeconfig) > 0 {
		authentication.RemoteKubeConfigFile = kubeconfig
		authorization.RemoteKubeConfigFile = kubeconfig
	}

	if err := secureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
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

	return apiserver.NewConfig(
		serverConfig,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		controllerQuerier), nil
}
