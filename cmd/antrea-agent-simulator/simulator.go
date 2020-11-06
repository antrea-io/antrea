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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/pkg/signals"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
	"github.com/vmware-tanzu/antrea/pkg/version"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

func createOutClusterCli(configFile string) (clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, error) {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", configFile)
	if err != nil {
		klog.Errorf("Failed to get incluster config: %s", err.Error())
		return nil, nil, nil, err
	}
	return createClusterCli(kubeConfig)
}

func createInClusterCli() (clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, error) {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		klog.Errorf("Failed to get incluster config: %s", err.Error())
		return nil, nil, nil, err
	}
	return createClusterCli(kubeConfig)
}

func createClusterCli(kubeConfig *rest.Config) (clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, error) {
	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		klog.Errorf("Failed to create clientset: %s", err.Error())
		return nil, nil, nil, err
	}
	aggregatorClient, err := aggregatorclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	// Create client for crd operations
	crdClient, err := crdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	return client, aggregatorClient, crdClient, nil
}

func run(configFile string) error {
	klog.Infof("Starting Antrea agent simulator (version %s)", version.GetFullVersion())
	k8sClient, _, _, err := createInClusterCli()
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}

	nodeName, err := env.GetNodeName()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %v", err)
	}

	// Create Antrea Clientset for the given config.
	antreaClientProvider := agent.NewAntreaClientProvider(componentbaseconfig.ClientConnectionConfiguration{}, k8sClient)

	if err = antreaClientProvider.RunOnce(); err != nil {
		return err
	}

	// Create the stop chan with signals
	stopCh := signals.RegisterSignalHandlers()

	go antreaClientProvider.Run(stopCh)

	// Add loop to check whether client is ready
	attempts := 0
	if err := wait.PollImmediateUntil(200*time.Millisecond, func() (bool, error) {
		if attempts%10 == 0 {
			klog.Info("Waiting for Antrea client to be ready")
		}
		if _, err := antreaClientProvider.GetAntreaClient(); err != nil {
			attempts++
			return false, nil
		}
		return true, nil
	}, stopCh); err != nil {
		klog.Info("Stopped waiting for Antrea client")
		return err
	}

	klog.Info("Antrea client is ready")

	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", nodeName).String(),
	}
	klog.Infof("nodename: %s", nodeName)

	fullSyncWaitGroup := sync.WaitGroup{}

	// Wrapper watcher to call watch
	networkPolicyControllerWatcher := &watchWrapper{
		func() (watch.Interface, error) {
			antreaClient, err := antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get antrea client: %s", err.Error())
			}
			return antreaClient.ControlplaneV1beta1().NetworkPolicies("").Watch(context.TODO(), options)
		},
		"networkPolicy",
		&fullSyncWaitGroup,
	}
	addressGroupWatcher := &watchWrapper{
		func() (watch.Interface, error) {
			antreaClient, err := antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get antrea client: %s", err.Error())
			}
			return antreaClient.ControlplaneV1beta1().AddressGroups().Watch(context.TODO(), options)
		},
		"addressGroup",
		&fullSyncWaitGroup,
	}
	appliedGroupWatcher := &watchWrapper{
		func() (watch.Interface, error) {
			antreaClient, err := antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get antrea client: %s", err.Error())
			}
			return antreaClient.ControlplaneV1beta1().AppliedToGroups().Watch(context.TODO(), options)
		},
		"appliedGroup",
		&fullSyncWaitGroup,
	}
	fullSyncWaitGroup.Add(3)

	// watch NetworkPolicies, AddressGroups, AppliedToGroups
	go wait.NonSlidingUntil(networkPolicyControllerWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(addressGroupWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(appliedGroupWatcher.watch, 5*time.Second, stopCh)
	fullSyncWaitGroup.Wait()

	<-stopCh
	klog.Info("Stopping Antrea agent simulator")
	return nil
}

type watchWrapper struct {
	watchFunc         func() (watch.Interface, error)
	name              string
	fullSyncWaitGroup *sync.WaitGroup
}

type simulator struct {
	networkPolicyWatcher *watchWrapper
	addressGroupWatcher  *watchWrapper
	appliedGroupWatcher  *watchWrapper
}

func (w *watchWrapper) watch() {
	klog.Infof("Starting watch for %s", w.name)

	// Call the watch func which is initialized in watchWrapper
	watcher, err := w.watchFunc()
	if err != nil {
		klog.Warningf("Failed to start watch for %s: %v", w.name, err)
		return
	}
	eventCount := 0

	// Stop the watcher upon exit
	defer func() {
		klog.Infof("Stopped watch for %s, total items received %d", w.name, eventCount)
		watcher.Stop()
	}()
	initCount := 0
	w.fullSyncWaitGroup.Done()

	// Watch the init events from chan, and log the events
loop:
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.Warningf("Result channel for %s was closed", w.name)
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Info("Added %s (%#v)", w.name, event.Object)
				initCount++
			case watch.Bookmark:
				break loop
			}
		}
	}
	klog.Infof("Received %d init events for %s", initCount, w.name)
	eventCount += initCount

	// Watch the events from chan, and log the events
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Infof("Added %s (%#v)", w.name, event.Object)
			case watch.Modified:
				klog.V(2).Infof("Updated %s (%#v)", w.name, event.Object)
			case watch.Deleted:
				klog.V(2).Infof("Removed %s (%#v)", w.name, event.Object)
			default:
				klog.Errorf("Unknown event: %v", event)
				return
			}
			eventCount++
		}
	}
}
