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

package egressgroup

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/egress/store"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// REST implements rest.Storage for EgressGroups.
type REST struct {
	egressGroupStore storage.Interface
}

var (
	_ rest.Storage = &REST{}
	_ rest.Watcher = &REST{}
	_ rest.Scoper  = &REST{}
	_ rest.Lister  = &REST{}
	_ rest.Getter  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(egressGroupStore storage.Interface) *REST {
	return &REST{egressGroupStore}
}

func (r *REST) New() runtime.Object {
	return &controlplane.EgressGroup{}
}

func (r *REST) NewList() runtime.Object {
	return &controlplane.EgressGroupList{}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	egressGroup, exists, err := r.egressGroupStore.Get(name)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(controlplane.Resource("egressgroup"), name)
	}
	obj := new(controlplane.EgressGroup)
	store.ToEgressGroupMsg(egressGroup.(*types.EgressGroup), obj, true, nil)
	return obj, nil
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	labelSelector := labels.Everything()
	if options != nil && options.LabelSelector != nil {
		labelSelector = options.LabelSelector
	}
	egressGroups := r.egressGroupStore.List()
	items := make([]controlplane.EgressGroup, 0, len(egressGroups))
	for i := range egressGroups {
		var item controlplane.EgressGroup
		store.ToEgressGroupMsg(egressGroups[i].(*types.EgressGroup), &item, true, nil)
		if labelSelector.Matches(labels.Set(item.Labels)) {
			items = append(items, item)
		}
	}
	list := &controlplane.EgressGroupList{Items: items}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	key, label, field := networkpolicy.GetSelectors(options)
	return r.egressGroupStore.Watch(ctx, key, label, field)
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(controlplane.Resource("egressgroup")).ConvertToTable(ctx, obj, tableOptions)
}
