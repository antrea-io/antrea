// Copyright 2021 Antrea Authors
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

	clusterinformationv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	versioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	internalinterfaces "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/internalinterfaces"
	v1beta1 "github.com/vmware-tanzu/antrea/pkg/client/listers/clusterinformation/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// AntreaAgentInfoInformer provides access to a shared informer and lister for
// AntreaAgentInfos.
type AntreaAgentInfoInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1beta1.AntreaAgentInfoLister
}

type antreaAgentInfoInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewAntreaAgentInfoInformer constructs a new informer for AntreaAgentInfo type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewAntreaAgentInfoInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredAntreaAgentInfoInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredAntreaAgentInfoInformer constructs a new informer for AntreaAgentInfo type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredAntreaAgentInfoInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ClusterinformationV1beta1().AntreaAgentInfos().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ClusterinformationV1beta1().AntreaAgentInfos().Watch(context.TODO(), options)
			},
		},
		&clusterinformationv1beta1.AntreaAgentInfo{},
		resyncPeriod,
		indexers,
	)
}

func (f *antreaAgentInfoInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredAntreaAgentInfoInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *antreaAgentInfoInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&clusterinformationv1beta1.AntreaAgentInfo{}, f.defaultInformer)
}

func (f *antreaAgentInfoInformer) Lister() v1beta1.AntreaAgentInfoLister {
	return v1beta1.NewAntreaAgentInfoLister(f.Informer().GetIndexer())
}
