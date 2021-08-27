// Copyright 2021 Antrea Authors
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

// The simulator binary is responsible for running simulated antrea agent.
// It watches NetworkPolicies, AddressGroups and AppliedToGroups from antrea controller
// and prints the events of these resources to log.
package main

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/version"
)

func run() error {
	klog.Infof("Starting Antrea agent simulator (version %s)", version.GetFullVersion())
	k8sClient, _, _, _, err := k8s.CreateClients(componentbaseconfig.ClientConnectionConfiguration{}, "")
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
	klog.Infof("Nodename: %s", nodeName)

	// Wrapper watcher to call watch
	networkPolicyControllerWatcher := &watchWrapper{
		func() (watch.Interface, error) {
			antreaClient, err := antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get antrea client: %s", err.Error())
			}
			return antreaClient.ControlplaneV1beta2().NetworkPolicies().Watch(context.TODO(), options)
		},
		"networkPolicy",
	}
	addressGroupWatcher := &watchWrapper{
		func() (watch.Interface, error) {
			antreaClient, err := antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get antrea client: %s", err.Error())
			}
			return antreaClient.ControlplaneV1beta2().AddressGroups().Watch(context.TODO(), options)
		},
		"addressGroup",
	}
	appliedGroupWatcher := &watchWrapper{
		func() (watch.Interface, error) {
			antreaClient, err := antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get antrea client: %s", err.Error())
			}
			return antreaClient.ControlplaneV1beta2().AppliedToGroups().Watch(context.TODO(), options)
		},
		"appliedGroup",
	}

	// watch NetworkPolicies, AddressGroups, AppliedToGroups
	go wait.NonSlidingUntil(networkPolicyControllerWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(addressGroupWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(appliedGroupWatcher.watch, 5*time.Second, stopCh)

	<-stopCh
	klog.Info("Stopping Antrea agent simulator")
	return nil
}

type watchWrapper struct {
	watchFunc func() (watch.Interface, error)
	name      string
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
				klog.V(2).Infof("Added %s (%#v)", w.name, event.Object)
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
