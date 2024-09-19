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
	"reflect"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/util/proxy"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
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
	// informerFactory is stored here so it can be started in the Run() method.
	informerFactory informers.SharedInformerFactory
	// serviceLister is used to retrieve the Service when selecting an Endpoint.
	serviceLister       corev1listers.ServiceLister
	serviceListerSynced cache.InformerSynced
	// endpointLister is used to retrieve the Endpoints for the Service during Endpoint selection.
	endpointsLister       corev1listers.EndpointsLister
	endpointsListerSynced cache.InformerSynced
	queue                 workqueue.TypedRateLimitingInterface[string]
	// listeners need to implement the Listerner interface and will get notified when the
	// current Endpoint URL changes.
	listeners   []Listener
	endpointURL atomic.Pointer[url.URL]
}

func NewEndpointResolver(kubeClient kubernetes.Interface, namespace, serviceName string, servicePort int32) *EndpointResolver {
	key := namespace + "/" + serviceName
	controllerName := fmt.Sprintf("ServiceEndpointResolver:%s", key)

	// We only need a specific Service and corresponding Endpoints resource, so we create our
	// own informer factory, and we filter by namespace and name.
	informerFactory := informers.NewSharedInformerFactoryWithOptions(kubeClient, informerDefaultResync, informers.WithNamespace(namespace), informers.WithTweakListOptions(func(listOptions *metav1.ListOptions) {
		listOptions.FieldSelector = fields.OneTermEqualSelector("metadata.name", serviceName).String()
	}))
	serviceInformer := informerFactory.Core().V1().Services()
	endpointsInformer := informerFactory.Core().V1().Endpoints()

	resolver := &EndpointResolver{
		name:                  controllerName,
		namespace:             namespace,
		serviceName:           serviceName,
		servicePort:           servicePort,
		informerFactory:       informerFactory,
		serviceLister:         serviceInformer.Lister(),
		serviceListerSynced:   serviceInformer.Informer().HasSynced,
		endpointsLister:       endpointsInformer.Lister(),
		endpointsListerSynced: endpointsInformer.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: controllerName,
			},
		),
	}

	serviceInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		// FilterFunc ignores all Service events which do not relate to the named Service.
		// It should be redundant given the filtering that we already do at the informer level.
		FilterFunc: func(obj interface{}) bool {
			if service, ok := obj.(*corev1.Service); ok {
				return service.Namespace == namespace && service.Name == serviceName
			}
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				if service, ok := tombstone.Obj.(*corev1.Service); ok {
					return service.Namespace == namespace && service.Name == serviceName
				}
			}
			return false
		},
		Handler: cache.ResourceEventHandlerFuncs{
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
		},
	})
	endpointsInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		// FilterFunc ignores all Endpoints events which do not relate to the named Service.
		// It should be redundant given the filtering that we already do at the informer level.
		FilterFunc: func(obj interface{}) bool {
			// The Endpoints resource for a Service has the same name as the Service.
			if endpoints, ok := obj.(*corev1.Endpoints); ok {
				return endpoints.Namespace == namespace && endpoints.Name == serviceName
			}
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				if endpoints, ok := tombstone.Obj.(*corev1.Endpoints); ok {
					return endpoints.Namespace == namespace && endpoints.Name == serviceName
				}
			}
			return false
		},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				resolver.queue.Add(key)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				// This should not happen: both objects should be Endpoints in the
				// update event handler.
				oldEndpoints, ok := oldObj.(*corev1.Endpoints)
				if !ok {
					return
				}
				newEndpoints, ok := newObj.(*corev1.Endpoints)
				if !ok {
					return
				}
				// Ignore changes to metadata.
				if reflect.DeepEqual(newEndpoints.Subsets, oldEndpoints.Subsets) {
					return
				}
				resolver.queue.Add(key)
			},
			DeleteFunc: func(obj interface{}) {
				resolver.queue.Add(key)
			},
		},
	})
	return resolver
}

func (r *EndpointResolver) Run(ctx context.Context) {
	defer r.queue.ShutDown()

	klog.InfoS("Starting controller", "name", r.name)
	defer klog.InfoS("Shutting down controller", "name", r.name)

	r.informerFactory.Start(ctx.Done())
	defer r.informerFactory.Shutdown()

	if !cache.WaitForNamedCacheSync(r.name, ctx.Done(), r.serviceListerSynced, r.endpointsListerSynced) {
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
	endpointURL, err := proxy.ResolveEndpoint(r.serviceLister, r.endpointsLister, r.namespace, r.serviceName, r.servicePort)
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
