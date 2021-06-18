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

	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
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
		"v1alpha1.stats.antrea.tanzu.vmware.com",
		"v1beta1.controlplane.antrea.tanzu.vmware.com",
		"v1beta2.controlplane.antrea.tanzu.vmware.com",
		"v1beta1.networking.antrea.tanzu.vmware.com",
		"v1beta1.system.antrea.tanzu.vmware.com",
		"v1alpha1.stats.antrea.io",
		"v1beta1.system.antrea.io",
		"v1beta2.controlplane.antrea.io",
	}
	// validatingWebhooks contains all the ValidatingWebhookConfigurations backed by antrea-controller.
	validatingWebhooks = []string{
		"crdvalidator.antrea.tanzu.vmware.com",
		"crdvalidator.antrea.io",
	}
	mutationWebhooks = []string{
		"crdmutator.antrea.tanzu.vmware.com",
		"crdmutator.antrea.io",
	}
	optionalMutationWebhooks = []string{
		"labelsmutator.antrea.io",
	}
	crdsWithConversionWebhooks = []string{
		"clustergroups.crd.antrea.io",
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

	client             kubernetes.Interface
	aggregatorClient   clientset.Interface
	apiExtensionClient apiextensionclientset.Interface
}

var _ dynamiccertificates.Listener = &CACertController{}

func GetCAConfigMapNamespace() string {
	return env.GetAntreaNamespace()
}

func newCACertController(caContentProvider dynamiccertificates.CAContentProvider,
	client kubernetes.Interface,
	aggregatorClient clientset.Interface,
	apiExtensionClient apiextensionclientset.Interface,
) *CACertController {
	c := &CACertController{
		caContentProvider:  caContentProvider,
		queue:              workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CACertController"),
		client:             client,
		aggregatorClient:   aggregatorClient,
		apiExtensionClient: apiExtensionClient,
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

	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		if err := c.syncMutatingWebhooks(caCert); err != nil {
			return err
		}
		if err := c.syncValidatingWebhooks(caCert); err != nil {
			return err
		}
		if err := c.syncConversionWebhooks(caCert); err != nil {
			return err
		}
	}
	return nil
}

// syncMutatingWebhooks updates the CABundle of the MutatingWebhookConfiguration backed by antrea-controller.
func (c *CACertController) syncMutatingWebhooks(caCert []byte) error {
	klog.Info("Syncing CA certificate with MutatingWebhookConfigurations")
	for _, name := range mutationWebhooks {
		mWebhook, err := c.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error getting MutatingWebhookConfiguration %s: %v", name, err)
		}
		err = c.patchWebhookWithCACert(mWebhook, caCert)
		if err != nil {
			return fmt.Errorf("error updating antrea CA cert of MutatingWebhookConfiguration %s: %v", name, err)
		}
	}
	for _, name := range optionalMutationWebhooks {
		mWebhook, err := c.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				klog.V(2).Infof("Optional mutation webhook %s not found, skipping its update", name)
				continue
			}
			return fmt.Errorf("error getting MutatingWebhookConfiguration %s: %v", name, err)
		}
		err = c.patchWebhookWithCACert(mWebhook, caCert)
		if err != nil {
			return fmt.Errorf("error updating antrea CA cert of MutatingWebhookConfiguration %s: %v", name, err)
		}
	}
	return nil
}

func (c *CACertController) syncConversionWebhooks(caCert []byte) error {
	klog.Info("Syncing CA certificate with CRDs that have conversion webhooks")
	for _, name := range crdsWithConversionWebhooks {
		crdDef, err := c.apiExtensionClient.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error getting CRD definition for %s: %v", name, err)
		}
		if crdDef.Spec.Conversion == nil || crdDef.Spec.Conversion.Strategy != apiextensionv1.WebhookConverter {
			return fmt.Errorf("CRD %s does not have webhook conversion registered", name)
		}
		updated := false
		if !bytes.Equal(crdDef.Spec.Conversion.Webhook.ClientConfig.CABundle, caCert) {
			updated = true
			crdDef.Spec.Conversion.Webhook.ClientConfig.CABundle = caCert
		}
		if updated {
			if _, err := c.apiExtensionClient.ApiextensionsV1().CustomResourceDefinitions().Update(context.TODO(), crdDef, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *CACertController) patchWebhookWithCACert(webhookCfg *v1.MutatingWebhookConfiguration, caCert []byte) error {
	updated := false
	for idx, webhook := range webhookCfg.Webhooks {
		if bytes.Equal(webhook.ClientConfig.CABundle, caCert) {
			continue
		} else {
			updated = true
			webhook.ClientConfig.CABundle = caCert
			webhookCfg.Webhooks[idx] = webhook
		}
	}
	if updated {
		if _, err := c.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(context.TODO(), webhookCfg, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

// syncValidatingWebhooks updates the CABundle of the ValidatingWebhookConfiguration backed by antrea-controller.
func (c *CACertController) syncValidatingWebhooks(caCert []byte) error {
	klog.Info("Syncing CA certificate with ValidatingWebhookConfigurations")
	for _, name := range validatingWebhooks {
		updated := false
		vWebhook, err := c.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error getting ValidatingWebhookConfiguration %s: %v", name, err)
		}
		for idx, webhook := range vWebhook.Webhooks {
			if bytes.Equal(webhook.ClientConfig.CABundle, caCert) {
				continue
			} else {
				updated = true
				webhook.ClientConfig.CABundle = caCert
				vWebhook.Webhooks[idx] = webhook
			}
		}
		if updated {
			if _, err := c.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(context.TODO(), vWebhook, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("error updating antrea CA cert of ValidatingWebhookConfiguration %s: %v", name, err)
			}
		}
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
	exists := true
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("error getting ConfigMap %s: %v", CAConfigMapName, err)
		}
		exists = false
		caConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      CAConfigMapName,
				Namespace: caConfigMapNamespace,
				Labels: map[string]string{
					"app": "antrea",
				},
			},
		}
	}
	if caConfigMap.Data != nil && caConfigMap.Data[CAConfigMapKey] == string(caCert) {
		return nil
	}
	caConfigMap.Data = map[string]string{
		CAConfigMapKey: string(caCert),
	}
	if exists {
		if _, err := c.client.CoreV1().ConfigMaps(caConfigMapNamespace).Update(context.TODO(), caConfigMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating ConfigMap %s: %v", CAConfigMapName, err)
		}
	} else {
		if _, err := c.client.CoreV1().ConfigMaps(caConfigMapNamespace).Create(context.TODO(), caConfigMap, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating ConfigMap %s: %v", CAConfigMapName, err)
		}
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
