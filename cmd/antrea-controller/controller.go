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

	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl"
	"github.com/vmware-tanzu/antrea/pkg/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/monitor"
	"github.com/vmware-tanzu/antrea/pkg/signals"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

// Determine how often we go through reconciliation (between current and desired state)
// Same as in https://github.com/kubernetes/sample-controller/blob/master/main.go
const informerDefaultResync time.Duration = 30 * time.Second

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

	apiServerConfig, err := createAPIServerConfig(o.config.ClientConnection.Kubeconfig,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore)
	if err != nil {
		return fmt.Errorf("error creating API server config: %v", err)
	}
	apiServer, err := apiServerConfig.Complete(informerFactory).New()
	if err != nil {
		return fmt.Errorf("error creating API server: %v", err)
	}

	antctlServer, err := antctl.NewLocalServer()
	if err != nil {
		return fmt.Errorf("error when creating local antctl server: %w", err)
	}

	// set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	informerFactory.Start(stopCh)

	controllerMonitor := monitor.NewControllerMonitor(crdClient, nodeInformer, networkPolicyController)
	go controllerMonitor.Run(stopCh)

	go networkPolicyController.Run(stopCh)

	preparedAPIServer := apiServer.GenericAPIServer.PrepareRun()
	// Set up the antctl handlers on the controller API server for remote access.
	antctl.CommandList.InstallToAPIServer(preparedAPIServer.GenericAPIServer, controllerMonitor)
	go preparedAPIServer.Run(stopCh)

	// Set up the antctl server for in-pod access.
	antctlServer.Start(nil, controllerMonitor, stopCh)

	<-stopCh
	klog.Info("Stopping Antrea controller")
	return nil
}

func createAPIServerConfig(kubeconfig string,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	networkPolicyStore storage.Interface) (*apiserver.Config, error) {
	// TODO:
	// 1. Support user-provided certificate.
	// 2. Support configurable https port.
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	authentication := genericoptions.NewDelegatingAuthenticationOptions()
	authorization := genericoptions.NewDelegatingAuthorizationOptions()

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

	return &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig:   apiserver.ExtraConfig{addressGroupStore, appliedToGroupStore, networkPolicyStore},
	}, nil
}
