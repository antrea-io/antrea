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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"context"
	"fmt"
	"time"

	"antrea.io/antrea/pkg/util/env"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	antreAgentConfigKey      = "antrea-agent.conf"
	antreControllerConfigKey = "antrea-controller.conf"
	fileChangeAnnotation     = "config-update-time"
)

type Watcher struct {
	K8sClient       kubernetes.Interface
	cmInformer      coreinformers.ConfigMapInformer
	configMapSynced cache.InformerSynced
	queue           workqueue.RateLimitingInterface
}

func NewWatcher(client kubernetes.Interface, informerFactory informers.SharedInformerFactory) *Watcher {
	cmInformer := informerFactory.Core().V1().ConfigMaps()
	w := &Watcher{
		K8sClient:       client,
		cmInformer:      cmInformer,
		configMapSynced: cmInformer.Informer().HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(2*time.Second, 2*time.Minute), "configmap"),
	}
	cmInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(old, cur interface{}) {
				w.handleConfigMapUpdateEvent(old, cur)
			},
		},
		5*time.Second,
	)
	return w
}

func (w *Watcher) handleConfigMapUpdateEvent(old, cur interface{}) {
	oldCm := old.(*corev1.ConfigMap)
	newCm := cur.(*corev1.ConfigMap)
	if oldCm.GetName() == "antrea-config" {
		if oldCm.Data[antreControllerConfigKey] != newCm.Data[antreControllerConfigKey] {
			w.queue.Add(antreControllerConfigKey)
		}
		if oldCm.Data[antreAgentConfigKey] != newCm.Data[antreAgentConfigKey] {
			w.queue.Add(antreAgentConfigKey)
		}
	}
}

func (w *Watcher) Run(stopCh <-chan struct{}) {
	defer w.queue.ShutDown()
	klog.Info("Starting Antrea Watcher")
	defer klog.Infof("Shutting down Antrea Watcher")
	if !cache.WaitForNamedCacheSync("antrea-watcher", stopCh, w.configMapSynced) {
		return
	}
	go wait.Until(w.worker, time.Second, stopCh)
	<-stopCh
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (w *Watcher) worker() {
	for w.processNextWorkItem() {
	}
}

func (w *Watcher) processNextWorkItem() bool {
	obj, quit := w.queue.Get()
	if quit {
		return false
	}
	defer w.queue.Done(obj)
	if key, ok := obj.(string); !ok {
		w.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := w.updateAnnotation(key); err == nil {
		w.queue.Forget(key)
	} else {
		w.queue.AddRateLimited(key)
		klog.Errorf("Error syncing ConfigMap %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (w *Watcher) updateAnnotation(key string) error {
	ctx := context.TODO()
	annotations := map[string]string{}
	now := fmt.Sprint(time.Now().Unix())
	if key == antreAgentConfigKey {
		klog.Infof("antrea-agent.conf is updated, update antrea-agent DaemonSet annotation")
		agentds, err := w.K8sClient.AppsV1().DaemonSets(env.GetAntreaNamespace()).Get(ctx, "antrea-agent", metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("unable to get antrea-agent DaemonSet %v", err)
		}
		if agentds.Spec.Template.GetAnnotations() != nil {
			annotations = agentds.Spec.Template.GetAnnotations()
		}
		annotations[fileChangeAnnotation] = now
		agentds.Spec.Template.Annotations = annotations
		_, err = w.K8sClient.AppsV1().DaemonSets(env.GetAntreaNamespace()).Update(ctx, agentds, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("fail to update antrea-agent DaemonSet annotation %v", err)
		}
	}

	if key == antreControllerConfigKey {
		klog.Infof("antrea-controller.conf is updated, update antrea-controller Deployment annotation")
		controller, err := w.K8sClient.AppsV1().Deployments(env.GetAntreaNamespace()).Get(ctx, "antrea-controller", metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("unable to get antrea-controller deployment %v", err)
		}
		if controller.Spec.Template.GetAnnotations() != nil {
			annotations = controller.Spec.Template.GetAnnotations()
		}
		annotations[fileChangeAnnotation] = now
		controller.Spec.Template.Annotations = annotations
		_, err = w.K8sClient.AppsV1().Deployments(env.GetAntreaNamespace()).Update(ctx, controller, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("fail to update antrea-controller Deployment annotation %v", err)
		}
	}
	return nil
}
