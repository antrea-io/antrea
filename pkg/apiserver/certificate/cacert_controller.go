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

package certificate

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

const (
	// Name of the ConfigMap that will hold the CA certificate that signs the TLS
	// certificate of antrea-controller.
	CAConfigMapName = "antrea-ca"
	CAConfigMapKey  = "ca.crt"
)

var (
	// apiServiceNames contains all the APIServices backed by antrea-controller.
	apiServiceNames = []string{
		"v1beta1.networking.antrea.tanzu.vmware.com",
		"v1beta1.system.antrea.tanzu.vmware.com",
	}
)

// CACertController is responsible for taking the CA certificate from the
// caContentProvider and publishing it to the ConfigMap and the APIServices.
type CACertController struct {
	mutex sync.RWMutex

	// caContentProvider provides the very latest content of the ca bundle.
	caContentProvider dynamiccertificates.CAContentProvider
	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface

	client           kubernetes.Interface
	aggregatorClient clientset.Interface
}

var _ dynamiccertificates.Listener = &CACertController{}

func GetCAConfigMapNamespace() string {
	namespace := env.GetPodNamespace()
	if namespace != "" {
		return namespace
	}

	klog.Warningf("Failed to get Pod Namespace from environment. Using \"%s\" as the CA ConfigMap Namespace", defaultAntreaNamespace)
	return defaultAntreaNamespace
}

func newCACertController(caContentProvider dynamiccertificates.CAContentProvider,
	client kubernetes.Interface,
	aggregatorClient clientset.Interface,
) *CACertController {
	c := &CACertController{
		caContentProvider: caContentProvider,
		queue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CACertController"),
		client:            client,
		aggregatorClient:  aggregatorClient,
	}
	if notifier, ok := caContentProvider.(dynamiccertificates.Notifier); ok {
		notifier.AddListener(c)
	}
	return c
}

func (c *CACertController) UpdateCertificate() error {
	if controller, ok := c.caContentProvider.(dynamiccertificates.ControllerRunner); ok {
		if err := controller.RunOnce(); err != nil {
			klog.Warningf("Updating of CA content failed: %v", err)
			c.Enqueue()
			return err
		}
	}

	return nil
}

// getCertificate exposes the certificate for testing.
func (c *CACertController) getCertificate() []byte {
	return c.caContentProvider.CurrentCABundleContent()
}

// Enqueue will be called after CACertController is registered as a listener of CA cert change.
func (c *CACertController) Enqueue() {
	// The key can be anything as we only have single item.
	c.queue.Add("key")
}

func (c *CACertController) syncCACert() error {
	caCert := c.caContentProvider.CurrentCABundleContent()

	if err := c.syncConfigMap(caCert); err != nil {
		return err
	}

	if err := c.syncAPIServices(caCert); err != nil {
		return err
	}
	return nil
}

// syncAPIServices updates the CABundle of the APIServices backed by antrea-controller.
func (c *CACertController) syncAPIServices(caCert []byte) error {
	klog.Info("Syncing CA certificate with APIServices")
	for _, name := range apiServiceNames {
		apiService, err := c.aggregatorClient.ApiregistrationV1().APIServices().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error getting APIService %s: %v", name, err)
		}
		if bytes.Equal(apiService.Spec.CABundle, caCert) {
			continue
		}
		apiService.Spec.CABundle = caCert
		if _, err := c.aggregatorClient.ApiregistrationV1().APIServices().Update(context.TODO(), apiService, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating antrea CA cert of APIService %s: %v", name, err)
		}
	}
	return nil
}

// syncConfigMap updates the ConfigMap that holds the CA bundle, which will be read by API clients, e.g. antrea-agent.
func (c *CACertController) syncConfigMap(caCert []byte) error {
	klog.Info("Syncing CA certificate with ConfigMap")
	// Use the Antrea Pod Namespace for the CA cert ConfigMap.
	caConfigMapNamespace := GetCAConfigMapNamespace()
	caConfigMap, err := c.client.CoreV1().ConfigMaps(caConfigMapNamespace).Get(context.TODO(), CAConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ConfigMap %s: %v", CAConfigMapName, err)
	}
	if caConfigMap.Data != nil && caConfigMap.Data[CAConfigMapKey] == string(caCert) {
		return nil
	}
	caConfigMap.Data = map[string]string{
		CAConfigMapKey: string(caCert),
	}
	if _, err := c.client.CoreV1().ConfigMaps(caConfigMapNamespace).Update(context.TODO(), caConfigMap, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating ConfigMap %s: %v", CAConfigMapName, err)
	}
	return nil
}

// RunOnce runs a single sync step to ensure that we have a valid starting configuration.
func (c *CACertController) RunOnce() error {
	if controller, ok := c.caContentProvider.(dynamiccertificates.ControllerRunner); ok {
		if err := controller.RunOnce(); err != nil {
			klog.Warningf("Initial population of CA content failed: %v", err)
			c.Enqueue()
			return err
		}
	}
	if err := c.syncCACert(); err != nil {
		klog.Warningf("Initial sync of CA content failed: %v", err)
		c.Enqueue()
		return err
	}
	return nil
}

// Run starts the CACertController and blocks until stopCh is closed.
func (c *CACertController) Run(workers int, stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting CACertController")
	defer klog.Infof("Shutting down CACertController")

	if controller, ok := c.caContentProvider.(dynamiccertificates.ControllerRunner); ok {
		go controller.Run(1, stopCh)
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *CACertController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *CACertController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncCACert()
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	klog.Errorf("Error syncing CA cert, requeuing it: %v", err)
	c.queue.AddRateLimited(key)

	return true
}
