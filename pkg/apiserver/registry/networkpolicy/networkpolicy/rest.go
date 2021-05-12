// Copyright 2019 Antrea Authors
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

package networkpolicy

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	"antrea.io/antrea/pkg/controller/types"
)

// REST implements rest.Storage for NetworkPolicies.
type REST struct {
	networkPolicyStore storage.Interface
}

var (
	_ rest.Storage = &REST{}
	_ rest.Watcher = &REST{}
	_ rest.Scoper  = &REST{}
	_ rest.Lister  = &REST{}
	_ rest.Getter  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(networkPolicyStore storage.Interface) *REST {
	return &REST{networkPolicyStore}
}

func (r *REST) New() runtime.Object {
	return &controlplane.NetworkPolicy{}
}

func (r *REST) NewList() runtime.Object {
	return &controlplane.NetworkPolicyList{}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	networkPolicy, exists, err := r.networkPolicyStore.Get(name)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(controlplane.Resource("networkpolicy"), name)
	}
	obj := new(controlplane.NetworkPolicy)
	store.ToNetworkPolicyMsg(networkPolicy.(*types.NetworkPolicy), obj, true)
	return obj, nil
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	labelSelector := labels.Everything()
	if options != nil && options.LabelSelector != nil {
		labelSelector = options.LabelSelector
	}
	networkPolicies := r.networkPolicyStore.List()
	items := make([]controlplane.NetworkPolicy, 0, len(networkPolicies))
	for i := range networkPolicies {
		var item controlplane.NetworkPolicy
		store.ToNetworkPolicyMsg(networkPolicies[i].(*types.NetworkPolicy), &item, true)
		if labelSelector.Matches(labels.Set(item.Labels)) {
			items = append(items, item)
		}
	}
	list := &controlplane.NetworkPolicyList{Items: items}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	key, label, field := networkpolicy.GetSelectors(options)
	return r.networkPolicyStore.Watch(ctx, key, label, field)
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(controlplane.Resource("networkpolicy")).ConvertToTable(ctx, obj, tableOptions)
}
