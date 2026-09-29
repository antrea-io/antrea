// Copyright 2026 Antrea Authors
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

package egressaddressgroup

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	"antrea.io/antrea/v2/pkg/apiserver/registry/networkpolicy"
	"antrea.io/antrea/v2/pkg/apiserver/storage"
	"antrea.io/antrea/v2/pkg/controller/egress/store"
	"antrea.io/antrea/v2/pkg/controller/types"
)

// REST implements rest.Storage for EgressAddressGroups.
type REST struct {
	egressAddressGroupStore storage.Interface
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Watcher              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.Lister               = &REST{}
	_ rest.Getter               = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(egressAddressGroupStore storage.Interface) *REST {
	return &REST{egressAddressGroupStore}
}

func (r *REST) New() runtime.Object {
	return &controlplane.EgressAddressGroup{}
}

func (r *REST) Destroy() {
}

func (r *REST) NewList() runtime.Object {
	return &controlplane.EgressAddressGroupList{}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	egressAddressGroup, exists, err := r.egressAddressGroupStore.Get(name)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(controlplane.Resource("egressaddressgroup"), name)
	}
	obj := new(controlplane.EgressAddressGroup)
	store.ToEgressAddressGroupMsg(egressAddressGroup.(*types.EgressAddressGroup), obj, true)
	return obj, nil
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	labelSelector := labels.Everything()
	if options != nil && options.LabelSelector != nil {
		labelSelector = options.LabelSelector
	}
	egressAddressGroups := r.egressAddressGroupStore.List()
	items := make([]controlplane.EgressAddressGroup, 0, len(egressAddressGroups))
	for i := range egressAddressGroups {
		var item controlplane.EgressAddressGroup
		store.ToEgressAddressGroupMsg(egressAddressGroups[i].(*types.EgressAddressGroup), &item, true)
		if labelSelector.Matches(labels.Set(item.Labels)) {
			items = append(items, item)
		}
	}
	list := &controlplane.EgressAddressGroupList{Items: items}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	key, label, field := networkpolicy.GetSelectors(options)
	ctx = storage.WithInitialEventsEndBookmarkAnnotationFromListOptions(ctx, options)
	return r.egressAddressGroupStore.Watch(ctx, key, label, field)
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(controlplane.Resource("egressaddressgroup")).ConvertToTable(ctx, obj, tableOptions)
}

func (r *REST) GetSingularName() string {
	return "egressaddressgroup"
}
