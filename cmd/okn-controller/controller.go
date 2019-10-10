// Copyright 2019 OKN Authors
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
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/klog"

	"okn/pkg/controller/networkpolicy"
	"okn/pkg/k8s"
	"okn/pkg/signals"
)

// Determine how often we go through reconciliation (between current and desired state)
// Same as in https://github.com/kubernetes/sample-controller/blob/master/main.go
const informerDefaultResync time.Duration = 30 * time.Second

// run starts OKN Controller with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Info("Starting OKN Controller")
	// Create a K8s Clientset and SharedInformerFactory for the given config.
	client, err := k8s.CreateClient(o.config.ClientConnection)
	if err != nil {
		return fmt.Errorf("error creating K8s client: %v", err)
	}

	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()

	networkPolicyController := networkpolicy.NewNetworkPolicyController(client, podInformer, namespaceInformer, networkPolicyInformer)

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	informerFactory.Start(stopCh)

	go networkPolicyController.Run(stopCh)

	<-stopCh
	klog.Info("Stopping OKN controller")
	return nil
}
