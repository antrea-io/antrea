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

package v1alpha1

import (
	"context"
	time "time"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	versioned "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	internalinterfaces "antrea.io/antrea/multicluster/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ClusterPropertyInformer provides access to a shared informer and lister for
// ClusterProperties.
type ClusterPropertyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ClusterPropertyLister
}

type clusterPropertyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewClusterPropertyInformer constructs a new informer for ClusterProperty type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewClusterPropertyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredClusterPropertyInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredClusterPropertyInformer constructs a new informer for ClusterProperty type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredClusterPropertyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.MulticlusterV1alpha1().ClusterProperties(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.MulticlusterV1alpha1().ClusterProperties(namespace).Watch(context.TODO(), options)
			},
		},
		&multiclusterv1alpha1.ClusterProperty{},
		resyncPeriod,
		indexers,
	)
}

func (f *clusterPropertyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredClusterPropertyInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *clusterPropertyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&multiclusterv1alpha1.ClusterProperty{}, f.defaultInformer)
}

func (f *clusterPropertyInformer) Lister() v1alpha1.ClusterPropertyLister {
	return v1alpha1.NewClusterPropertyLister(f.Informer().GetIndexer())
}