// Copyright 2022 Antrea Authors
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

package externalentity

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/controller/externalnode/store"
	"antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

// REST implements rest.Storage for ExternalEntity.
type REST struct {
	externalEntityStore storage.Interface
}

var (
	_ rest.Storage = &REST{}
	_ rest.Watcher = &REST{}
	_ rest.Scoper  = &REST{}
	_ rest.Lister  = &REST{}
	_ rest.Getter  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(externalEntityStore storage.Interface) *REST {
	return &REST{externalEntityStore}
}

func (r *REST) New() runtime.Object {
	return &controlplane.ExternalEntity{}
}

func (r *REST) NewList() runtime.Object {
	return &controlplane.ExternalEntityList{}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	ns, ok := request.NamespaceFrom(ctx)
	if !ok || len(ns) == 0 {
		return nil, errors.NewBadRequest("Get ExternalEntity Namespace parameter required.")
	}

	externalEntity, exists, err := r.externalEntityStore.Get(k8s.NamespacedName(ns, name))
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(controlplane.Resource("externalentity"), name)
	}
	obj := new(controlplane.ExternalEntity)
	store.ToExternalEntityMsg(externalEntity.(*types.ExternalEntity), obj)
	return obj, nil
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	labelSelector := labels.Everything()
	if options != nil && options.LabelSelector != nil {
		labelSelector = options.LabelSelector
	}
	externalEntities := r.externalEntityStore.List()
	items := make([]controlplane.ExternalEntity, 0, len(externalEntities))
	for i := range externalEntities {
		var item controlplane.ExternalEntity
		store.ToExternalEntityMsg(externalEntities[i].(*types.ExternalEntity), &item)
		if labelSelector.Matches(labels.Set(item.Labels)) {
			items = append(items, item)
		}
	}
	list := &controlplane.ExternalEntityList{Items: items}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return true
}

func (r *REST) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	ns, ok := request.NamespaceFrom(ctx)
	if !ok || len(ns) == 0 {
		return nil, errors.NewBadRequest("Watch ExternalEntity Namespace parameter required.")
	}
	namespaceField := fields.OneTermEqualSelector("metadata.namespace", ns)
	key, label, field := networkpolicy.GetSelectors(options)
	selectorSet := fields.AndSelectors(namespaceField, field)
	return r.externalEntityStore.Watch(ctx, key, label, selectorSet)
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(controlplane.Resource("externalentity")).ConvertToTable(ctx, obj, tableOptions)
}
