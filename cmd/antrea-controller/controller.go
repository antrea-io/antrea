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
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	genericopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/openapi"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
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
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()
	nodeInformer := informerFactory.Core().V1().Nodes()

	// Create Antrea object storage.
	addressGroupStore := store.NewAddressGroupStore()
	appliedToGroupStore := store.NewAppliedToGroupStore()
	networkPolicyStore := store.NewNetworkPolicyStore()

	networkPolicyController := networkpolicy.NewNetworkPolicyController(client,
		podInformer,
		namespaceInformer,
		networkPolicyInformer,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore)

	controllerMonitor := monitor.NewControllerMonitor(crdClient, nodeInformer, networkPolicyController)

	apiServerConfig, err := createAPIServerConfig(o.config.ClientConnection.Kubeconfig,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		controllerMonitor,
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

	go controllerMonitor.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	go apiServer.GenericAPIServer.PrepareRun().Run(stopCh)

	if o.config.EnablePrometheusMetrics {
		go initializePrometheusMetrics(
			o.config.EnablePrometheusGoMetrics,
			o.config.EnablePrometheusProcessMetrics)
	}

	<-stopCh
	klog.Info("Stopping Antrea controller")
	return nil
}

// Initialize Prometheus metrics collection.
func initializePrometheusMetrics(
	enablePrometheusGoMetrics bool,
	enablePrometheusProcessMetrics bool) {
	hostname, err := os.Hostname()
	if err != nil {
		klog.Errorf("Failed to retrieve agent node name, %v", err)
	}

	klog.Info("Initializing prometheus")
	gaugeHost := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antrea_controller_host",
		Help: "Antrea controller hostname (as a label), typically used in grouping/aggregating stats; " +
			"the label defaults to the hostname of the host but can be overridden by configuration. " +
			"The value of the gauge is always set to 1.",
		ConstLabels: prometheus.Labels{"host": hostname},
	})
	gaugeHost.Set(1)
	prometheus.MustRegister(gaugeHost)
	http.Handle("/metrics", promhttp.Handler())

	if !enablePrometheusGoMetrics {
		klog.Info("Golang metrics are disabled")
		prometheus.Unregister(prometheus.NewGoCollector())
	}
	if !enablePrometheusProcessMetrics {
		klog.Info("Process metrics are disabled")
		prometheus.Unregister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	}
}

func createAPIServerConfig(kubeconfig string,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	networkPolicyStore storage.Interface,
	controllerQuerier monitor.ControllerQuerier,
	enablePrometheusMetrics bool) (*apiserver.Config, error) {
	// TODO:
	// 1. Support user-provided certificate.
	// 2. Support configurable https port.
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions()

	if enablePrometheusMetrics {
		authorization.WithAlwaysAllowPaths("/metrics")
	}
	// Set the PairName but leave certificate directory blank to generate in-memory by default
	secureServing.ServerCert.CertDirectory = ""
	secureServing.ServerCert.PairName = "antrea-apiserver"
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

	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(
		openapi.GetOpenAPIDefinitions,
		genericopenapi.NewDefinitionNamer(apiserver.Scheme))
	serverConfig.OpenAPIConfig.Info.Title = "Antrea"

	return apiserver.NewConfig(
		serverConfig,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		controllerQuerier), nil
}
