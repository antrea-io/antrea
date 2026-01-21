// Copyright 2024 Antrea Authors
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

package client

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/util/proxy"
	corev1informers "k8s.io/client-go/informers/core/v1"
	discoveryv1informers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoveryv1listers "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/util/env"
)

const (
	// informerDefaultResync is the default resync period if a handler doesn't specify one.
	// Use the same default value as kube-controller-manager:
	// https://github.com/kubernetes/kubernetes/blob/release-1.17/pkg/controller/apis/config/v1alpha1/defaults.go#L120
	informerDefaultResync = 12 * time.Hour

	minRetryDelay = 100 * time.Millisecond
	maxRetryDelay = 30 * time.Second
)

// Listener defines the interface which needs to be implemented by clients which want to subscribe
// to Endpoint updates.
type Listener interface {
	Enqueue()
}

// EndpointResolver is in charge of resolving a specific Service Endpoint, which can then be
// accessed directly instead of depending on the ClusterIP functionality provided by K8s proxies
// (whether it's kube-proxy or AntreaProxy). A new Endpoint is resolved every time the Service's
// Spec or the Endpoints' Subsets are updated, and registered listeners are notified. While this
// EndpointResolver is somewhat generic, at the moment it is only meant to be used for the Antrea
// Service.
type EndpointResolver struct {
	// name is the name of the controller in charge of Endpoint resolution.
	name        string
	namespace   string
	serviceName string
	servicePort int32
	// serviceInformer and endpointSliceInformer are stored here so they can be started in the Run() method.
	serviceInformer       cache.SharedIndexInformer
	endpointSliceInformer cache.SharedIndexInformer
	// serviceLister is used to retrieve the Service when selecting an Endpoint.
	serviceLister       corev1listers.ServiceLister
	serviceListerSynced cache.InformerSynced
	// endpointSliceGetter is used to retrieve the EndpointSlices for the Service during Endpoint selection.
	endpointSliceGetter       proxy.EndpointSliceGetter
	endpointSliceListerSynced cache.InformerSynced
	queue                     workqueue.TypedRateLimitingInterface[string]
	// listeners need to implement the Listerner interface and will get notified when the
	// current Endpoint URL changes.
	listeners   []Listener
	endpointURL atomic.Pointer[url.URL]
}

func NewEndpointResolver(kubeClient kubernetes.Interface, namespace, serviceName string, servicePort int32) *EndpointResolver {
	key := namespace + "/" + serviceName
	controllerName := fmt.Sprintf("ServiceEndpointResolver:%s", key)

	// We only need a specific Service and corresponding EndpointSlices, so we create
	// filtered informers directly without factories for better efficiency.
	serviceInformer := corev1informers.NewFilteredServiceInformer(
		kubeClient,
		namespace,
		informerDefaultResync,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(listOptions *metav1.ListOptions) {
			listOptions.FieldSelector = fields.OneTermEqualSelector("metadata.name", serviceName).String()
		},
	)
	endpointSliceInformer := discoveryv1informers.NewFilteredEndpointSliceInformer(
		kubeClient,
		namespace,
		informerDefaultResync,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: serviceName}).String()
		},
	)

	serviceLister := corev1listers.NewServiceLister(serviceInformer.GetIndexer())
	endpointSliceLister := discoveryv1listers.NewEndpointSliceLister(endpointSliceInformer.GetIndexer())
	// Create an EndpointSliceGetter from the lister for use with proxy.ResolveEndpoint
	endpointSliceGetter, _ := proxy.NewEndpointSliceListerGetter(endpointSliceLister)

	resolver := &EndpointResolver{
		name:                      controllerName,
		namespace:                 namespace,
		serviceName:               serviceName,
		servicePort:               servicePort,
		serviceInformer:           serviceInformer,
		endpointSliceInformer:     endpointSliceInformer,
		serviceLister:             serviceLister,
		serviceListerSynced:       serviceInformer.HasSynced,
		endpointSliceGetter:       endpointSliceGetter,
		endpointSliceListerSynced: endpointSliceInformer.HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: controllerName,
			},
		),
	}

	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resolver.queue.Add(key)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// This should not happen: both objects should be Services in the
			// update event handler.
			oldSvc, ok := oldObj.(*corev1.Service)
			if !ok {
				return
			}
			newSvc, ok := newObj.(*corev1.Service)
			if !ok {
				return
			}
			// Ignore changes to metadata or status.
			if reflect.DeepEqual(newSvc.Spec, oldSvc.Spec) {
				return
			}
			resolver.queue.Add(key)
		},
		DeleteFunc: func(obj interface{}) {
			resolver.queue.Add(key)
		},
	})
	endpointSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			resolver.queue.Add(key)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// This should not happen: both objects should be EndpointSlices in the
			// update event handler.
			oldEndpointSlice, ok := oldObj.(*discoveryv1.EndpointSlice)
			if !ok {
				return
			}
			newEndpointSlice, ok := newObj.(*discoveryv1.EndpointSlice)
			if !ok {
				return
			}
			// Ignore changes to metadata, only look at changes to endpoints or ports.
			if reflect.DeepEqual(newEndpointSlice.Endpoints, oldEndpointSlice.Endpoints) &&
				reflect.DeepEqual(newEndpointSlice.Ports, oldEndpointSlice.Ports) {
				return
			}
			resolver.queue.Add(key)
		},
		DeleteFunc: func(obj interface{}) {
			resolver.queue.Add(key)
		},
	})
	return resolver
}

func (r *EndpointResolver) Run(ctx context.Context) {
	defer r.queue.ShutDown()

	klog.InfoS("Starting controller", "name", r.name)
	defer klog.InfoS("Shutting down controller", "name", r.name)

	go r.serviceInformer.Run(ctx.Done())
	go r.endpointSliceInformer.Run(ctx.Done())

	if !cache.WaitForNamedCacheSync(r.name, ctx.Done(), r.serviceListerSynced, r.endpointSliceListerSynced) {
		return
	}

	// We only start one worker for this controller.
	go wait.Until(r.runWorker, time.Second, ctx.Done())

	<-ctx.Done()
}

func (r *EndpointResolver) runWorker() {
	for r.processNextWorkItem() {
	}
}

func (r *EndpointResolver) processNextWorkItem() bool {
	key, quit := r.queue.Get()
	if quit {
		return false
	}
	defer r.queue.Done(key)

	if err := r.resolveEndpoint(); err == nil {
		r.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Failed to resolve Service Endpoint, requeuing", "key", key)
		r.queue.AddRateLimited(key)
	}

	return true
}

func (r *EndpointResolver) resolveEndpoint() error {
	klog.V(2).InfoS("Resolving Endpoint", "service", klog.KRef(r.namespace, r.serviceName))
	endpointURL, err := proxy.ResolveEndpoint(r.serviceLister, r.endpointSliceGetter, r.namespace, r.serviceName, r.servicePort)
	// Typically we will get one of these 2 errors (unavailable or not found).
	// In this case, it makes sense to reset the Endpoint URL to nil and notify listeners.
	// There is also no need to retry, as we won't find a suitable Endpoint until the Service or
	// the Endpoints resource is updated in a way that will cause this function to be called again.
	if errors.IsServiceUnavailable(err) {
		klog.ErrorS(err, "Cannot resolve endpoint because Service is unavailable", "service", klog.KRef(r.namespace, r.serviceName))
		r.updateEndpointIfNeeded(nil)
		return nil
	}
	if errors.IsNotFound(err) {
		klog.ErrorS(err, "Cannot resolve endpoint because of missing resource", "service", klog.KRef(r.namespace, r.serviceName))
		r.updateEndpointIfNeeded(nil)
		return nil
	}
	if err != nil {
		// Unknown error: we err on the side of caution.
		// Do not reset the URL or notify listeners, and trigger a retry.
		return err
	}
	klog.V(2).InfoS("Resolved Endpoint", "service", klog.KRef(r.namespace, r.serviceName), "url", endpointURL)
	r.updateEndpointIfNeeded(endpointURL)
	return nil
}

func (r *EndpointResolver) updateEndpointIfNeeded(endpointURL *url.URL) {
	// The separate Load and Store calls are safe because there is a single writer for r.endpointURL.
	currentEndpointURL := r.endpointURL.Load()
	updateNeeded := func() bool {
		if endpointURL == nil && currentEndpointURL == nil {
			return false
		}
		if endpointURL == nil || currentEndpointURL == nil {
			return true
		}
		return endpointURL.String() != currentEndpointURL.String()
	}
	if !updateNeeded() {
		klog.V(2).InfoS("No change to Endpoint for Service, no need to notify listeners", "service", klog.KRef(r.namespace, r.serviceName))
		return
	}
	if endpointURL != nil {
		klog.InfoS("Selected a new Endpoint for Service, notifying listeners", "service", klog.KRef(r.namespace, r.serviceName), "url", endpointURL)
	} else {
		klog.InfoS("Selected no Endpoint for Service, notifying listeners", "service", klog.KRef(r.namespace, r.serviceName))
	}
	r.endpointURL.Store(endpointURL)
	for _, listener := range r.listeners {
		listener.Enqueue()
	}
}

func (r *EndpointResolver) AddListener(listener Listener) {
	r.listeners = append(r.listeners, listener)
}

func (r *EndpointResolver) CurrentEndpointURL() *url.URL {
	return r.endpointURL.Load()
}

func NewAntreaServiceEndpointResolver(kubeClient kubernetes.Interface) (*EndpointResolver, error) {
	port := os.Getenv("ANTREA_SERVICE_PORT")
	if len(port) == 0 {
		return nil, fmt.Errorf("unable to create Endpoint resolver for Antrea Service, ANTREA_SERVICE_PORT must be defined for in-cluster config")
	}
	servicePort, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid port number stored in ANTREA_SERVICE_PORT: %w", err)
	}
	endpointResolver := NewEndpointResolver(kubeClient, env.GetAntreaNamespace(), apis.AntreaServiceName, int32(servicePort))
	return endpointResolver, nil
}
