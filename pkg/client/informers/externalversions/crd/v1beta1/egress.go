// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by informer-gen. DO NOT EDIT.

package v1beta1

import (
	"context"
	time "time"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	versioned "antrea.io/antrea/pkg/client/clientset/versioned"
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
	v1beta1 "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// EgressInformer provides access to a shared informer and lister for
// Egresses.
type EgressInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1beta1.EgressLister
}

type egressInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewEgressInformer constructs a new informer for Egress type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewEgressInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredEgressInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredEgressInformer constructs a new informer for Egress type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredEgressInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CrdV1beta1().Egresses().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CrdV1beta1().Egresses().Watch(context.TODO(), options)
			},
		},
		&crdv1beta1.Egress{},
		resyncPeriod,
		indexers,
	)
}

func (f *egressInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredEgressInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *egressInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&crdv1beta1.Egress{}, f.defaultInformer)
}

func (f *egressInformer) Lister() v1beta1.EgressLister {
	return v1beta1.NewEgressLister(f.Informer().GetIndexer())
}
