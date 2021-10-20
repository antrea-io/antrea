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

package ipam

import (
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
)

const (
	controllerName = "AntreaIPAMController"
)

// Antrea IPAM Controller maintains map of namespace annotations using
// namespace informer. In future, which Antrea IPAM support expands,
// this controller can be used to store annotations for other objects,
// such as Statefulsets.
type AntreaIPAMController struct {
	kubeClient           clientset.Interface
	crdClient            clientsetversioned.Interface
	namespaceInformer    coreinformers.NamespaceInformer
	namespaceLister      corelisters.NamespaceLister
	namespaceAnnotations sync.Map
}

func NewAntreaIPAMController(kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	informerFactory informers.SharedInformerFactory,
	resyncPeriod time.Duration) *AntreaIPAMController {

	namespaceInformer := informerFactory.Core().V1().Namespaces()
	c := AntreaIPAMController{
		kubeClient:           kubeClient,
		crdClient:            crdClient,
		namespaceInformer:    namespaceInformer,
		namespaceLister:      namespaceInformer.Lister(),
		namespaceAnnotations: sync.Map{},
	}

	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNamespace,
			DeleteFunc: c.deleteNamespace,
		},
		resyncPeriod,
	)

	return &c
}

func InitializeAntreaIPAMController(kubeClient clientset.Interface, crdClient clientsetversioned.Interface, informerFactory informers.SharedInformerFactory) (*AntreaIPAMController, error) {

	antreaIPAMController := NewAntreaIPAMController(kubeClient, crdClient, informerFactory, 0)

	// Order of init causes antreaIPAMDriver to be initialized first
	// After controller is initialized by agent init, we need to make it
	// know to the driver
	if antreaIPAMDriver == nil {
		return nil, fmt.Errorf("Antrea IPAM driver failed to initialize")
	}

	antreaIPAMDriver.setController(antreaIPAMController)

	return antreaIPAMController, nil
}

// Run starts to watch and process Namespace updates for the Node where Antrea Agent
// is running, and maintain a mapping between namespace name and IPAM annotations.
func (c *AntreaIPAMController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.V(2).Infof("Shutting down %s", controllerName)
	}()

	klog.Infof("Starting %s", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.namespaceInformer.Informer().HasSynced) {
		return
	}

	<-stopCh
}

func (c *AntreaIPAMController) addNamespace(obj interface{}) {
	ns, isNamespace := obj.(*corev1.Namespace)
	if !isNamespace {
		return
	}

	// TODO: add validations
	annotations, exists := ns.Annotations[AntreaIPAMAnnotationKey]
	if !exists {
		return
	}
	c.namespaceAnnotations.Store(ns.Name, strings.Split(annotations, AntreaIPAMAnnotationDelimiter))
}

func (c *AntreaIPAMController) deleteNamespace(obj interface{}) {
	ns, isNamespace := obj.(*corev1.Namespace)
	if !isNamespace {
		return
	}

	c.namespaceAnnotations.Delete(ns.Name)
}

func (c *AntreaIPAMController) getIPPoolsByNamespace(namespace string) ([]string, bool) {
	pools, exists := c.namespaceAnnotations.Load(namespace)
	if !exists {
		return nil, false
	}
	return pools.([]string), true
}
