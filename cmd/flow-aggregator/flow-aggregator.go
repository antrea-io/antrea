// Copyright 2020 Antrea Authors
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
	"sync"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	aggregator "antrea.io/antrea/pkg/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/apiserver"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/cipher"
	"antrea.io/antrea/pkg/util/podstore"
)

const informerDefaultResync = 12 * time.Hour

func run(configFile string) error {
	klog.Infof("Flow aggregator starting...")
	// Set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	log.StartLogFileNumberMonitor(stopCh)

	k8sClient, err := createK8sClient()
	if err != nil {
		return fmt.Errorf("error when creating K8s client: %v", err)
	}

	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()
	podStore := podstore.NewPodStore(podInformer.Informer())

	flowAggregator, err := aggregator.NewFlowAggregator(
		k8sClient,
		podStore,
		configFile,
	)

	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flowAggregator.Run(stopCh)
	}()

	cipherSuites, err := cipher.GenerateCipherSuitesList(flowAggregator.APIServer.TLSCipherSuites)
	if err != nil {
		return fmt.Errorf("error generating Cipher Suite list: %v", err)
	}
	apiServer, err := apiserver.New(
		flowAggregator,
		flowAggregator.APIServer.APIPort,
		cipherSuites,
		cipher.TLSVersionMap[flowAggregator.APIServer.TLSMinVersion])
	if err != nil {
		return fmt.Errorf("error when creating flow aggregator API server: %v", err)
	}
	go apiServer.Run(stopCh)

	informerFactory.Start(stopCh)

	<-stopCh
	klog.InfoS("Stopping flow aggregator")
	wg.Wait()
	return nil
}

func createK8sClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return k8sClient, nil
}
