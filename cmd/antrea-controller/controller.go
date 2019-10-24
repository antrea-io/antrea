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
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/signals"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

// Determine how often we go through reconciliation (between current and desired state)
// Same as in https://github.com/kubernetes/sample-controller/blob/master/main.go
const informerDefaultResync time.Duration = 30 * time.Second

// run starts Antrea Controller with the given options and waits for termination signal.
func run(o *Options) error {
	klog.Infof("Starting Antrea Controller (version %s)", version.GetFullVersion())
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

	// set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	informerFactory.Start(stopCh)

	go networkPolicyController.Run(stopCh)

	<-stopCh
	klog.Info("Stopping Antrea controller")
	return nil
}
